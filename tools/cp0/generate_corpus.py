"""Generate a reproducible, explicitly synthetic 1000-target CP0 fixture corpus.

The generated manifest is the ground-truth artifact for an *independent* harness.
No production secret formats or real credentials are generated. This builder is
not a detector and cannot establish the scanner's actual recall or precision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from pathlib import Path


SEED = 20261110
FAMILIES = ("AWS", "GITHUB", "STRIPE", "HTTPS", "GENERIC")
TRUTH_MARKER = re.compile(rb"RNC_SYNTH_KEY_[A-Z0-9_]+")


def build(destination: Path, target_count: int = 1000) -> dict:
    if target_count < 1:
        raise ValueError("target_count must be positive")
    destination.mkdir(parents=True, exist_ok=True)
    rng = random.Random(SEED)
    targets = []
    for index in range(target_count):
        target_id = f"generated-{index:05d}"
        relative = f"sources/part-{index // 100:02d}/{target_id}.txt"
        path = destination / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        newline = b"\r\n" if index % 4 == 0 else b"\n"
        prefix = ("café – unicode prefix" if index % 7 == 0 else "benign fixture")
        content = bytearray(prefix.encode("utf-8") + newline)
        expected = []
        count = index % 5  # 0..4 distinct synthetic markers per file
        for ordinal in range(count):
            family = FAMILIES[(index + ordinal) % len(FAMILIES)]
            marker = f"RNC_SYNTH_KEY_{family}_{index:05d}_{ordinal}".encode("ascii")
            # Independent, unpredictable-but-seeded harmless filler exercises offsets.
            filler = f"field_{ordinal}={rng.randrange(10**6):06d}:".encode("ascii")
            content.extend(filler)
            start = len(content)
            content.extend(marker)
            content.extend(newline)
            expected.append({
                "rule_id": f"synthetic-{family.lower()}",
                "marker": marker.decode("ascii"),
                "start_byte": start,
                "end_byte": start + len(marker),
                "disposition": "EXEMPTED" if (index + ordinal) % 13 == 0 else "ACTIONABLE",
            })
        content.extend(b"RNC_DECOY_NOT_A_CREDENTIAL" + newline)
        path.write_bytes(content)
        # Verify the generated answer key against bytes independently of entries.
        observed = [(m.start(), m.end(), m.group().decode()) for m in TRUTH_MARKER.finditer(content)]
        declared = [(e["start_byte"], e["end_byte"], e["marker"]) for e in expected]
        assert observed == declared, target_id
        targets.append({
            "id": target_id, "relative_path": relative,
            "sha256": hashlib.sha256(content).hexdigest(),
            "scope": "VERIFIED_BLOCKED" if index % 29 == 0 else "INSPECTED",
            "expected_findings": expected,
        })
    manifest = {
        "corpus_version": "generated-synthetic-v0.1",
        "seed": SEED, "target_count": len(targets),
        "meaning": "Synthetic contract/corpus truth; not real credential detection accuracy",
        "targets": targets,
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--targets", type=int, default=1000)
    args = parser.parse_args()
    manifest = build(args.output, args.targets)
    print(json.dumps({"generated_targets": manifest["target_count"],
                      "declared_markers": sum(len(t["expected_findings"]) for t in manifest["targets"]),
                      "manifest": str(args.output / "manifest.json")}, indent=2))


if __name__ == "__main__":
    main()
