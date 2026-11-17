"""Execute the pinned independent harness scoring engine on the CP0 handoff.

This is an integration check for the handoff contract only. It does not run any
external corpus and does not claim scanner precision/recall against real data.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from tools.cp0.corpus import load_v0, load_v1
from tools.cp0.harness_adapter import build_handoff
from tools.cp0.synthetic_stub import build


PINNED_REVISION = "86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f"
DATASET = "RNC-Solutions-Group/gitleaks:test/scan-harness"


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def load_harness(root: Path):
    if not (root / "harness" / "scoring_engine.py").is_file():
        raise RuntimeError(f"{root} is not a scanner-harness checkout")
    if (root / ".git").is_dir():
        revision = _git(root, "rev-parse", "HEAD")
        if revision != PINNED_REVISION:
            raise RuntimeError(f"harness revision {revision} does not match pinned {PINNED_REVISION}")
        if _git(root, "status", "--porcelain"):
            raise RuntimeError("harness checkout is modified; refusing to score against it")
    sys.path.insert(0, str(root))
    from harness import truth as truth_loader  # type: ignore
    from harness.contracts import NormalizedFinding  # type: ignore
    from harness.scoring_engine import score_findings  # type: ignore

    return NormalizedFinding, truth_loader, score_findings


def _convert(handoff: dict, NormalizedFinding, truth_loader):
    truth = truth_loader.from_dict(handoff["truth"])
    findings = [
        NormalizedFinding(
            file=item["file"],
            line=item["line"],
            rule_id=item["rule_id"],
            secret_sha256=item["secret_sha256"],
            match_sha256=item["match_sha256"],
            secret_redacted=item["secret_redacted"],
            finding_id=item["finding_id"],
            target=item["target"],
            scanner=item["scanner"],
            scanner_version=item["scanner_version"],
            metadata=item["metadata"],
        )
        for item in handoff["findings"]
    ]
    return findings, truth


def run(root: Path) -> dict:
    NormalizedFinding, truth_loader, score_findings = load_harness(root)
    cases = []
    for corpus, mode, expected in (
        ("v1", "perfect", {"expected": 25, "matched": 25, "missed": 0, "unexpected": 0, "false_positive": 0, "blocked": 1, "skipped": 1}),
        ("v1", "miss-one", {"expected": 25, "matched": 24, "missed": 1, "unexpected": 0, "false_positive": 0}),
        ("v1", "false-positive", {"expected": 25, "matched": 25, "missed": 0, "unexpected": 0, "false_positive": 1}),
        ("v0", "perfect", {"expected": 13, "matched": 13, "missed": 0, "unexpected": 0, "false_positive": 0, "blocked": 1, "skipped": 0}),
    ):
        loaded = load_v0() if corpus == "v0" else load_v1()
        handoff = build_handoff(build(corpus=corpus, mode=mode), loaded)
        findings, truth = _convert(handoff, NormalizedFinding, truth_loader)
        result = score_findings(findings, truth)
        metrics = result.metrics
        observed = {
            "expected": metrics["expected_count"],
            "matched": metrics["matched_count"],
            "missed": metrics["missed_count"],
            "unexpected": metrics["unexpected_count"],
            "false_positive": metrics["false_positive_count"],
            "blocked": metrics["blocked_count"],
            "skipped": metrics["skipped_count"],
        }
        mismatches = {key: {"expected": value, "observed": observed.get(key)} for key, value in expected.items() if observed.get(key) != value}
        if result.scoring_status != "COMPLETED" or mismatches:
            raise RuntimeError(f"external scoring mismatch for {corpus}/{mode}: {mismatches}")
        cases.append({
            "corpus": corpus,
            "mode": mode,
            "scoring_status": result.scoring_status,
            "execution_status": result.execution_status,
            "metrics": observed,
            "detection_recall_percent": metrics["detection_recall_percent"],
            "precision_percent": metrics["precision_percent"],
            "correct": True,
        })
    return {
        "harness": DATASET,
        "revision": PINNED_REVISION,
        "integration": "scoring-engine handoff only",
        "external_corpora_executed": False,
        "scanner_accuracy_claim": False,
        "cases": cases,
        "all_correct": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root_value = args.harness_root or (Path(os.environ["RNC_HARNESS_ROOT"]) if os.environ.get("RNC_HARNESS_ROOT") else None)
    if root_value is None:
        parser.error("pass --harness-root or set RNC_HARNESS_ROOT")
    document = run(root_value)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(document, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
