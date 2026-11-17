"""Compatibility check against the pinned independent harness.

This does not replace the byte-addressed scorer. It proves that actual RNC
provider findings can be normalized into the external harness contract and that
the known line-addressing ambiguity is visible in the result.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.cp0.external_harness_check import PINNED_REVISION, load_harness
from tools.cp3.adapter import build_handoff


def run(harness_root: Path, private_path: Path, truth_path: Path, rules_path: Path) -> dict:
    NormalizedFinding, truth_loader, score_findings = load_harness(harness_root)
    private_document = json.loads(private_path.read_text(encoding="utf-8"))
    truth_document = json.loads(truth_path.read_text(encoding="utf-8"))
    rules_document = json.loads(rules_path.read_text(encoding="utf-8"))
    handoff = build_handoff(private_document, truth_document, rules_document)
    converted = []
    for item in handoff["findings"]:
        converted.append(
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
        )
    truth = truth_loader.from_dict(handoff["truth"])
    result = score_findings(converted, truth)
    metrics = result.metrics
    observed = {
        "expected": metrics["expected_count"],
        "matched": metrics["matched_count"],
        "missed": metrics["missed_count"],
        "unexpected": metrics["unexpected_count"],
        "false_positive": metrics["false_positive_count"],
        "duplicate": metrics["duplicate_count"],
        "ambiguous": metrics["ambiguous_count"],
        "observed": metrics["observed_count"],
    }
    return {
        "harness": "RNC-Solutions-Group/gitleaks:test/scan-harness",
        "revision": PINNED_REVISION,
        "scoring_status": result.scoring_status,
        "execution_status": result.execution_status,
        "metrics": observed,
        "line_addressed_only": True,
        "byte_addressable": False,
        "same_line_limitation": handoff["external_contract"]["same_line_limitation"],
        "findings_exported": len(handoff["findings"]),
        "truth_items_exported": len(handoff["truth"]["items"]),
        "scanner_accuracy_claim": False,
        "compatibility_note": (
            "This score is not the authoritative provider accuracy measurement. "
            "Use tools/cp3/score.py for exact byte-range classification."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness-root", type=Path, required=True)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run(args.harness_root, args.findings, args.truth, args.rules)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8", newline="\n")
    print(payload, end="")
    return 0 if report["scoring_status"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
