"""Independent CP0 synthetic harness.

The harness owns the answer key, executes no detector, and scores normalized
findings plus execution/policy/classification correctness. It must never import
the production detector. The synthetic stub consumes the same answer key to
manufacture controlled scanner output purely for calibration.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from tools.cp0.contracts import (
    ContractViolation,
    assert_public_safe,
    canonical_json,
    ci_decision,
    record_digest,
    validate_records,
)
from tools.cp0.corpus import load_v0, load_v1, target_unit_id


def _expected_key(item: dict) -> tuple[str, str, int, int]:
    return (item["target_id"], item["rule_id"], item["start_byte"], item["end_byte"])


def _target_id_for_unit(unit_id: str, loaded: dict) -> str | None:
    for target in loaded["targets"]:
        if target_unit_id(target, loaded["summary"]["version"]) == unit_id:
            return target["id"]
    return None


def _percent(numerator: int, denominator: int) -> float | None:
    return round(100.0 * numerator / denominator, 2) if denominator else None


def score_bundle(bundle: dict, loaded: dict) -> dict:
    version = loaded["summary"]["version"]
    targets = {target["id"]: target for target in loaded["targets"]}
    expected_findings = loaded["expected_findings"]
    expected_by_key: dict[tuple[str, str, int, int], dict] = {_expected_key(item): item for item in expected_findings}
    expected_by_target: dict[str, list[dict]] = defaultdict(list)
    for item in expected_findings:
        expected_by_target[item["target_id"]].append(item)
    contents = {
        target_unit_id(target, version): loaded["contents"][target["id"]]
        for target in loaded["targets"]
        if target["scope"] == "INSPECTED"
    }

    contract_valid = True
    contract_error_codes: list[str] = []
    contract_message = ""
    try:
        validate_records(
            bundle["execution"],
            bundle["findings"],
            bundle["policy"],
            bundle["result"],
            bundle["ci"],
            contents=contents,
        )
    except ContractViolation as exc:
        contract_valid = False
        contract_error_codes = [exc.code]
        contract_message = exc.message
    except (KeyError, TypeError) as exc:
        contract_valid = False
        contract_error_codes = ["BUNDLE_SHAPE"]
        contract_message = f"bundle is missing a required record: {exc}"

    units = bundle.get("execution", {}).get("units", [])
    actual_by_unit: dict[str, dict] = {}
    unit_target: dict[str, str | None] = {}
    unexpected_units = 0
    for unit in units:
        unit_id = unit.get("unit_id", "")
        target_id = _target_id_for_unit(unit_id, loaded)
        unit_target[unit_id] = target_id
        if target_id is None:
            unexpected_units += 1
        else:
            actual_by_unit[target_id] = unit
    target_rows: list[dict] = []
    missing_required = 0
    missing_optional = 0
    scope_mismatches = 0
    for target in loaded["targets"]:
        target_id = target["id"]
        unit = actual_by_unit.get(target_id)
        expected_scope = target["scope"]
        actual_scope = unit["disposition"] if unit else "MISSING"
        if unit is None:
            if target["required"]:
                missing_required += 1
            else:
                missing_optional += 1
        mismatch = unit is not None and actual_scope != expected_scope
        if mismatch:
            scope_mismatches += 1
        target_rows.append({
            "target_id": target_id,
            "required": bool(target["required"]),
            "expected_scope": expected_scope,
            "actual_scope": actual_scope,
            "expected_findings": len(expected_by_target.get(target_id, [])),
            "status": "MISSING" if unit is None else ("SCOPE_MISMATCH" if mismatch else "ACCOUNTED"),
        })

    findings = bundle.get("findings", [])
    claimed: set[tuple[str, str, int, int]] = set()
    duplicate_keys: set[tuple[str, str, int, int]] = set()
    matched = 0
    missed = 0
    unexpected = 0
    false_positives = 0
    duplicates = 0
    scope_violations = 0
    target_counts = {
        target["id"]: {"matched": 0, "missed": 0, "unexpected": 0, "duplicates": 0}
        for target in loaded["targets"]
    }
    dispositions = {item["finding_id"]: item for item in bundle.get("policy", {}).get("dispositions", [])}
    disposition_mismatches = 0
    for finding in findings:
        unit_id = finding.get("unit_id", "")
        target_id = unit_target.get(unit_id)
        key = (target_id or "", finding.get("rule_id", ""), finding.get("start_byte", -1), finding.get("end_byte", -1))
        target = targets.get(target_id or "")
        if target is None or target["scope"] != "INSPECTED":
            scope_violations += 1
            false_positives += 1
            continue
        expected = expected_by_key.get(key)
        if expected is None:
            unexpected += 1
            false_positives += 1
            target_counts[target_id]["unexpected"] += 1
            continue
        if key in claimed:
            duplicates += 1
            duplicate_keys.add(key)
            target_counts[target_id]["duplicates"] += 1
            continue
        claimed.add(key)
        matched += 1
        target_counts[target_id]["matched"] += 1
        disposition = dispositions.get(finding.get("finding_id"))
        if disposition is None or disposition["status"] != expected["disposition"]:
            disposition_mismatches += 1
    for item in expected_findings:
        if _expected_key(item) not in claimed:
            missed += 1
            target_counts[item["target_id"]]["missed"] += 1

    expected_blocks = {target["id"] for target in loaded["targets"] if target["scope"] == "VERIFIED_BLOCKED"}
    applied_block_targets: set[str] = set()
    for block in bundle.get("policy", {}).get("applied_blocks", []):
        target_id = unit_target.get(block.get("unit_id", ""))
        if target_id:
            applied_block_targets.add(target_id)
    expected_exemptions = sum(item["disposition"] == "EXEMPTED" for item in expected_findings)
    applied_exemptions = sum(item["status"] == "EXEMPTED" for item in dispositions.values())
    requested_unapplied = sum(
        request.get("status") != "APPLIED" for request in bundle.get("policy", {}).get("requests", [])
    )
    policy_correct = (
        contract_valid
        and bundle.get("policy", {}).get("policy_valid") is True
        and disposition_mismatches == 0
        and expected_blocks == applied_block_targets
        and scope_violations == 0
    )

    reported_findings = len(findings)
    precision_denominator = matched + unexpected + duplicates + scope_violations
    detection = {
        "scored": contract_valid,
        "expected": len(expected_findings),
        "matched": matched,
        "missed": missed,
        "unexpected": unexpected,
        "false_positives": false_positives,
        "duplicates": duplicates,
        "scope_violations": scope_violations,
        "reported": reported_findings,
        "recall_percent": _percent(matched, len(expected_findings)),
        "precision_percent": _percent(matched, precision_denominator),
        "correct": contract_valid and matched == len(expected_findings) and unexpected == 0 and duplicates == 0 and scope_violations == 0,
    }
    policy = {
        "correct": policy_correct,
        "policy_valid": bool(bundle.get("policy", {}).get("policy_valid")),
        "expected_blocks": len(expected_blocks),
        "applied_blocks": len(applied_block_targets),
        "expected_exemptions": expected_exemptions,
        "applied_exemptions": applied_exemptions,
        "disposition_mismatches": disposition_mismatches,
        "requested_unapplied": requested_unapplied,
    }
    state = bundle.get("execution", {}).get("state", "MISSING")
    if not contract_valid:
        execution_status = "CONTRACT_INVALID"
    elif state != "COMPLETED":
        execution_status = state
    elif missing_required or scope_mismatches or unexpected_units:
        execution_status = "INCOMPLETE"
    elif missing_optional:
        execution_status = "PASS_WITH_OPTIONAL_GAPS"
    else:
        execution_status = "PASS"
    execution = {
        "status": execution_status,
        "complete": execution_status == "PASS",
        "targets_expected": len(loaded["targets"]),
        "targets_reported": len(actual_by_unit),
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "unexpected_units": unexpected_units,
        "scope_mismatches": scope_mismatches,
        "contract_valid": contract_valid,
        "contract_error_codes": contract_error_codes,
    }
    result = bundle.get("result", {})
    expected_code = None
    if contract_valid:
        counts = None
        try:
            from tools.cp0.contracts import compute_counts, classify

            counts = compute_counts(
                bundle["execution"]["units"], findings, bundle["policy"]["dispositions"]
            )
            expected_code = classify(bundle["execution"], bundle["policy"], counts)
        except (KeyError, TypeError):
            expected_code = None
    classification = {
        "actual_code": result.get("result_code"),
        "actual": result.get("result"),
        "expected_code": expected_code,
        "correct": contract_valid and expected_code == result.get("result_code"),
        "ci_accepted": bundle.get("ci", {}).get("accepted"),
        "ci_process_exit_code": bundle.get("ci", {}).get("process_exit_code"),
        "ci_correct": False,
    }
    if contract_valid:
        try:
            expected_ci = ci_decision(
                result["result_code"],
                set(bundle.get("ci", {}).get("accepted_result_codes", [])),
                run_id=result["run_id"],
                result_digest=record_digest(result),
            )
            classification["ci_correct"] = expected_ci == bundle.get("ci")
        except (KeyError, ValueError):
            classification["ci_correct"] = False

    for row in target_rows:
        counts = target_counts[row["target_id"]]
        row.update(counts)
        if row["status"] == "MISSING":
            continue
        if row["status"] == "SCOPE_MISMATCH":
            continue
        if row["expected_scope"] != "INSPECTED":
            row["status"] = "ACCOUNTED_" + row["expected_scope"]
        elif counts["missed"] or counts["unexpected"] or counts["duplicates"]:
            row["status"] = "DETECTION_DIFFERENCE"
    document = {
        "adapter": bundle.get("adapter", "unknown"),
        "mode": bundle.get("mode", "unknown"),
        "corpus": loaded["summary"]["version"],
        "manifest_sha256": loaded["summary"]["manifest_sha256"],
        "contract": {
            "valid": contract_valid,
            "error_codes": contract_error_codes,
            "message": contract_message if not contract_valid else "",
        },
        "execution": execution,
        "detection": detection,
        "policy": policy,
        "classification": classification,
        "targets": target_rows,
        "synthetic_stub": True,
        "scanner_accuracy_claim": False,
    }
    assert_public_safe({key: value for key, value in document.items() if key != "targets"})
    return document


def score_path(bundle_path: Path, corpus: str = "v1") -> dict:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    loaded = load_v0() if corpus == "v0" else load_v1()
    return score_bundle(bundle, loaded)


def self_check() -> dict:
    """Run controlled stub modes and compare with independently declared metrics."""
    from tools.cp0.synthetic_stub import build

    cases = [
        {"mode": "perfect", "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 0, "correct": True}, "result": 3, "execution": "PASS", "policy": True},
        {"mode": "all-exempt", "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 0, "correct": True}, "result": 2, "execution": "PASS", "policy": False},
        {"mode": "miss-one", "detection": {"matched": 24, "missed": 1, "unexpected": 0, "duplicates": 0, "correct": False}, "result": 3, "execution": "PASS", "policy": True},
        {"mode": "false-positive", "detection": {"matched": 25, "missed": 0, "unexpected": 1, "duplicates": 0, "correct": False}, "result": 3, "execution": "PASS", "policy": True},
        {"mode": "duplicate-new-id", "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 1, "correct": False}, "result": 3, "execution": "PASS", "policy": True},
        {"mode": "wrong-location", "detection": {"matched": 24, "missed": 1, "unexpected": 1, "duplicates": 0, "correct": False}, "result": 3, "execution": "PASS", "policy": True},
        {"mode": "missing-target", "detection": {"matched": 22, "missed": 3, "unexpected": 0, "duplicates": 0, "correct": False}, "result": 3, "execution": "INCOMPLETE", "policy": True},
        {"mode": "blocked-leak", "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 0, "scope_violations": 1, "correct": False}, "result": 3, "execution": "INCOMPLETE", "policy": False},
        {"mode": "uninspected-required", "detection": {"matched": 22, "missed": 3, "unexpected": 0, "duplicates": 0, "correct": False}, "result": 4, "execution": "INCOMPLETE", "policy": True},
        {"mode": "unverified-block", "detection": {"scored": False}, "execution": "CONTRACT_INVALID", "policy": False, "contract": "SCHEMA_INVALID"},
        {"mode": "duplicate-id", "detection": {"scored": False}, "execution": "CONTRACT_INVALID", "policy": False, "contract": "FINDING_DUPLICATE"},
        {"mode": "bad-evidence", "detection": {"scored": False}, "execution": "CONTRACT_INVALID", "policy": False, "contract": "FINDING_ID_MISMATCH"},
        {"mode": "error", "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 0, "correct": True}, "result": 5, "execution": "ERROR", "policy": True},
        {"mode": "interrupted", "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 0, "correct": True}, "result": 5, "execution": "INTERRUPTED", "policy": True},
        {"mode": "request-unmatched", "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 0, "correct": True}, "result": 3, "execution": "PASS", "policy": True},
        {"mode": "perfect", "accepted": {1, 2, 3}, "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 0, "correct": True}, "result": 3, "execution": "PASS", "policy": True, "ci": {"accepted": True, "process_exit_code": 0}},
        {"mode": "perfect", "accepted": {1, 2}, "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 0, "correct": True}, "result": 3, "execution": "PASS", "policy": True, "ci": {"accepted": False, "process_exit_code": 10}},
        {"mode": "all-exempt", "accepted": {1}, "detection": {"matched": 25, "missed": 0, "unexpected": 0, "duplicates": 0, "correct": True}, "result": 2, "execution": "PASS", "policy": False, "ci": {"accepted": False, "process_exit_code": 10}},
    ]
    loaded = load_v1()
    results = []
    for case in cases:
        bundle = build(corpus="v1", mode=case["mode"], accepted=case.get("accepted"))
        actual = score_bundle(bundle, loaded)
        errors = []
        for key, value in case.get("detection", {}).items():
            if actual["detection"].get(key) != value:
                errors.append(f"detection.{key}={actual['detection'].get(key)!r}, expected {value!r}")
        if "result" in case and actual["classification"]["actual_code"] != case["result"]:
            errors.append(f"result={actual['classification']['actual_code']!r}, expected {case['result']!r}")
        if "execution" in case and actual["execution"]["status"] != case["execution"]:
            errors.append(f"execution={actual['execution']['status']!r}, expected {case['execution']!r}")
        if "policy" in case and actual["policy"]["correct"] != case["policy"]:
            errors.append(f"policy.correct={actual['policy']['correct']!r}, expected {case['policy']!r}")
        for key, value in case.get("ci", {}).items():
            observation = actual["classification"]["ci_accepted"] if key == "accepted" else actual["classification"]["ci_process_exit_code"]
            if observation != value:
                errors.append(f"ci.{key}={observation!r}, expected {value!r}")
        if "contract" in case and case["contract"] not in actual["contract"]["error_codes"]:
            errors.append(f"contract codes={actual['contract']['error_codes']!r}, expected {case['contract']!r}")
        results.append({
            "mode": case["mode"],
            "expected": {
                **case,
                "accepted": sorted(case["accepted"]) if "accepted" in case else None,
            },
            "actual": {
                "execution": actual["execution"]["status"],
                "detection": actual["detection"],
                "policy_correct": actual["policy"]["correct"],
                "result_code": actual["classification"]["actual_code"],
                "contract_error_codes": actual["contract"]["error_codes"],
            },
            "correct": not errors,
            "errors": errors,
        })
    correct = sum(item["correct"] for item in results)
    return {
        "dataset": "synthetic-v1.0",
        "cases": len(results),
        "correct": correct,
        "incorrect": len(results) - correct,
        "scoring_accuracy_percent": round(100.0 * correct / len(results), 2),
        "results": results,
        "scanner_accuracy_claim": False,
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--corpus", choices=("v0", "v1"), default="v1")
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_check:
        document = self_check()
    elif args.bundle:
        document = score_path(args.bundle, args.corpus)
    else:
        parser.error("choose --bundle or --self-check")
    text = canonical_json(document) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {args.output}")
    else:
        print(text, end="")
    if args.self_check and document["incorrect"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
