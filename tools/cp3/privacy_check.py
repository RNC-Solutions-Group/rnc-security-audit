"""Sanitized-evidence check for generated CP3 artifacts.

Provider fixtures are harmless, but public evidence must not contain raw fixture
values, private paths or live-looking credential material. The check reads every
JSON artifact under artifacts/cp3, compares against independently generated
truth values, and rejects host-specific absolute paths.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from tools.cp3.challenge import build as build_challenge
from tools.cp3.materialize import bundle_files

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "artifacts/cp3"
TRUTHS = (
    ROOT / "tests/cp3/provider-truth-tier2.json",
    ROOT / "tests/cp3/provider-truth-tier3-heldout.json",
)
ABSOLUTE_MARKERS = ("C:\\\\", "C:/", "/home/", "/Users/", "\\Users\\")


def raw_tokens() -> set[bytes]:
    contents = {(tier, path): data for tier, path, data in bundle_files()}
    tokens = set()
    for truth_path in TRUTHS:
        document = json.loads(truth_path.read_text(encoding="utf-8"))
        tier = Path(document["source_root"]).name
        for item in document["items"]:
            data = contents[(tier, item["path"])]
            tokens.add(data[item["start_byte"] : item["end_byte"]])
    with tempfile.TemporaryDirectory(prefix="rnc-cp3-privacy-challenge-") as temporary:
        root, document = build_challenge(Path(temporary))
        for item in document["items"]:
            data = (root / item["path"]).read_bytes()
            tokens.add(data[item["start_byte"] : item["end_byte"]])
    return tokens


def check(artifacts: Path = ARTIFACTS) -> dict:
    if not artifacts.is_dir():
        return {"status": "SKIPPED", "reason": "no artifacts/cp3 directory", "findings": []}
    tokens = raw_tokens()
    findings = []
    files = sorted(path for path in artifacts.rglob("*.json") if path.is_file())
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in tokens:
            if token in text.encode("utf-8"):
                findings.append({"file": str(path.relative_to(ROOT)), "type": "RAW_FIXTURE_VALUE"})
                break
        for marker in ABSOLUTE_MARKERS:
            if marker in text:
                findings.append({"file": str(path.relative_to(ROOT)), "type": "ABSOLUTE_PATH"})
                break
    return {
        "status": "PASS" if not findings else "FAIL",
        "artifacts": len(files),
        "findings": findings,
    }


def main() -> int:
    result = check()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] in {"PASS", "SKIPPED"} else 1


if __name__ == "__main__":
    sys.exit(main())
