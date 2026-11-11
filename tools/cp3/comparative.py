"""Pinned comparator assessment on the controlled provider corpus.

Gitleaks is run with its native default configuration against filesystem
fixtures. Findings are matched by source path and exact fixture bytes, not by
assuming that Gitleaks rule names are identical to RNC rule names. No Git
history workload is claimed, and Betterleaks is not executed because no pinned
binary is available.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _relative(value: str, root: Path) -> str | None:
    path = Path(value)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def _truth_items(truth_path: Path, root: Path) -> list[dict]:
    document = json.loads(truth_path.read_text(encoding="utf-8"))
    result = []
    for item in document["items"]:
        data = (root / item["path"]).read_bytes()
        token = data[item["start_byte"] : item["end_byte"]]
        result.append(
            {
                "path": item["path"],
                "token": token,
                "family": (item.get("metadata") or {}).get("provider_family", ""),
                "rule_id": item.get("expected_rule_id", ""),
            }
        )
    return result


def run_gitleaks(binary: Path, root: Path, report: Path) -> list[dict]:
    command = [
        str(binary),
        "dir",
        str(root),
        "--report-format",
        "json",
        "--report-path",
        str(report),
        "--redact=0",
        "--exit-code",
        "0",
        "--no-banner",
        "--log-level",
        "error",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    if completed.returncode != 0:
        raise RuntimeError(
            f"Gitleaks failed ({completed.returncode}): {completed.stderr.strip()[:400]}"
        )
    if not report.is_file():
        return []
    document = json.loads(report.read_text(encoding="utf-8"))
    return document or []


def score_gitleaks(gitleaks: list[dict], truth: list[dict], root: Path) -> dict:
    observations = []
    for item in gitleaks:
        path = _relative(item.get("File", ""), root)
        if path is None:
            continue
        observations.append(
            {
                "path": path,
                "rule_id": item.get("RuleID", "unknown"),
                "secret": item.get("Secret", ""),
                "match": item.get("Match", ""),
                "start_line": item.get("StartLine"),
                "end_line": item.get("EndLine"),
            }
        )
    used: set[int] = set()
    claimed: set[int] = set()
    tp = 0
    fn = 0
    duplicates = 0
    by_family: dict[str, dict] = {}
    findings = []
    for index, truth_item in enumerate(truth):
        matches = [
            observed_index
            for observed_index, observed in enumerate(observations)
            if observed["path"] == truth_item["path"]
            and (
                truth_item["token"] in observed["secret"].encode("utf-8")
                or truth_item["token"] in observed["match"].encode("utf-8")
            )
        ]
        family = by_family.setdefault(truth_item["family"], {"expected": 0, "tp": 0, "fn": 0})
        family["expected"] += 1
        if matches:
            tp += 1
            family["tp"] += 1
            used.add(matches[0])
            for extra in matches[1:]:
                if extra not in used:
                    used.add(extra)
                    duplicates += 1
            findings.append(
                {
                    "path": truth_item["path"],
                    "family": truth_item["family"],
                    "rule_id": truth_item["rule_id"],
                    "gitleaks_rule": observations[matches[0]]["rule_id"],
                    "start_line": observations[matches[0]]["start_line"],
                }
            )
        else:
            fn += 1
            family["fn"] += 1
    fp = 0
    unexpected = []
    for index, observed in enumerate(observations):
        if index in used:
            continue
        fp += 1
        unexpected.append(
            {
                "path": observed["path"],
                "rule_id": observed["rule_id"],
                "start_line": observed["start_line"],
            }
        )
    precision = round(100.0 * tp / (tp + fp), 2) if tp + fp else None
    recall = round(100.0 * tp / (tp + fn), 2) if tp + fn else None
    f1 = (
        round(2 * precision * recall / (precision + recall), 2)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "expected": len(truth),
        "observed": len(observations),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "duplicates": duplicates,
        "precision_percent": precision,
        "recall_percent": recall,
        "f1_percent": f1,
        "by_family": by_family,
        "unexpected": unexpected,
        "matched": findings,
        "gitleaks_rule_counts": dict(sorted(Counter(item["rule_id"] for item in observations).items())),
    }


def _rnc_case(integration: dict | None, dataset: str) -> dict | None:
    if not integration:
        return None
    for case in integration.get("cases", []):
        if case.get("dataset") == dataset and case.get("mode") == "whole" and case.get("strategy") == "regex":
            return case["metrics"]
    return None


def run(
    gitleaks_binary: Path,
    expected_sha256: str,
    integration_path: Path | None,
) -> dict:
    actual_sha256 = hashlib.sha256(gitleaks_binary.read_bytes()).hexdigest()
    if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
        raise RuntimeError(
            f"Gitleaks binary hash {actual_sha256} does not match pinned {expected_sha256}"
        )
    integration = (
        json.loads(integration_path.read_text(encoding="utf-8")) if integration_path else None
    )
    cases = []
    with tempfile.TemporaryDirectory(prefix="rnc-cp3-gitleaks-") as temp:
        workspace = Path(temp)
        for name, dataset in (
            ("tier2", "rnc-provider-fixtures-tier2"),
            ("tier3", "rnc-provider-fixtures-tier3-heldout"),
        ):
            root = ROOT / f"tests/fixtures/providers/{name}"
            truth_path = ROOT / (
                "tests/cp3/provider-truth-tier2.json"
                if name == "tier2"
                else "tests/cp3/provider-truth-tier3-heldout.json"
            )
            report = workspace / f"gitleaks-{name}.json"
            gitleaks = run_gitleaks(gitleaks_binary, root, report)
            truth = _truth_items(truth_path, root)
            scored = score_gitleaks(gitleaks, truth, root)
            scored.update(
                {
                    "dataset": dataset,
                    "root": f"tests/fixtures/providers/{name}",
                    "rnc_reference_metrics": _rnc_case(integration, dataset),
                    "scanner": "gitleaks",
                    "scanner_version": "unavailable (local build metadata did not set a version)",
                    "binary_sha256": actual_sha256,
                    "configuration": "native default configuration; no custom config",
                    "source_type": "filesystem working tree",
                    "git_history_compared": False,
                    "betterleaks_compared": False,
                }
            )
            cases.append(scored)
    return {
        "comparison": "CP3 controlled provider fixtures: RNC vs pinned Gitleaks build",
        "validity": {
            "same_source_type": "filesystem working tree only",
            "same_rules": False,
            "same_native_configuration": False,
            "rnc_ruleset": "rnc-providers-v1",
            "gitleaks_ruleset": "native default configuration",
            "claim": (
                "This is a coverage-and-detection comparison on the same controlled fixtures, "
                "not a general product ranking. Gitleaks supports many families outside the RNC "
                "catalog, and RNC does not implement a Git-history adapter."
            ),
        },
        "gitleaks": {
            "binary": "pinned local Gitleaks build",
            "binary_sha256": actual_sha256,
            "version": "unavailable",
            "report_redaction": "temporary report contained fixture values only; it was deleted after normalization",
        },
        "betterleaks": {
            "executed": False,
            "reason": "no pinned Betterleaks binary or image is available in this environment",
        },
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gitleaks", type=Path, required=True)
    parser.add_argument("--gitleaks-sha256", default="")
    parser.add_argument("--rnc-integration", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = run(args.gitleaks, args.gitleaks_sha256, args.rnc_integration)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
