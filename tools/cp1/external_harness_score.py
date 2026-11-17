"""Score actual CP1 detector handoff with the pinned external harness engine.

This is scoring-engine integration only; no external corpus is executed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools.cp0.external_harness_check import PINNED_REVISION, _convert, load_harness


def run(harness_root: Path, handoff_path: Path, expected: int) -> dict:
    NormalizedFinding, truth_loader, score_findings = load_harness(harness_root)
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    findings, truth = _convert(handoff, NormalizedFinding, truth_loader)
    result = score_findings(findings, truth)
    metrics = result.metrics
    observed = {
        "expected": metrics["expected_count"],
        "matched": metrics["matched_count"],
        "missed": metrics["missed_count"],
        "unexpected": metrics["unexpected_count"],
        "false_positive": metrics["false_positive_count"],
        "duplicate": metrics["duplicate_count"],
        "blocked": metrics["blocked_count"],
        "skipped": metrics["skipped_count"],
    }
    if result.scoring_status != "COMPLETED" or observed["expected"] != expected or observed["matched"] != expected:
        raise RuntimeError(f"external scoring mismatch: {observed}")
    if observed["missed"] or observed["unexpected"] or observed["false_positive"] or observed["duplicate"]:
        raise RuntimeError(f"external scoring exceptions: {observed}")
    return {
        "harness": "RNC-Solutions-Group/gitleaks:test/scan-harness",
        "revision": PINNED_REVISION,
        "handoff": handoff_path.name,
        "scanner": handoff["scanner"]["key"],
        "metrics": observed,
        "scoring_status": result.scoring_status,
        "execution_status": result.execution_status,
        "external_corpora_executed": False,
        "scanner_accuracy_claim": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness-root", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--expected", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = run(args.harness_root, args.handoff, args.expected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(document, indent=2, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
