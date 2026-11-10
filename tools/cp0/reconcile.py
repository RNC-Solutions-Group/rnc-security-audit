"""CP0 reference ledger reconciler used to test *interface integrity*.

This is not a production reporter and must not be packaged in RNC Scanner.
The production result finalizer will be independently implemented in CP2.
"""

from __future__ import annotations

from typing import Mapping

from tools.cp0.contracts import (
    DEFAULT_ACCEPTED,
    RESULT_NAMES,
    SCHEMA_VERSION,
    canonical_json,
    ci_decision,
    classify,
    compute_counts,
    coverage_for,
    reason_codes_for,
    record_digest,
    sorted_findings,
    validate_records,
)


def _normalize(execution: dict, findings: list[dict], policy: dict) -> tuple[dict, list[dict], dict]:
    execution = dict(execution)
    execution["units"] = sorted(execution["units"], key=lambda unit: unit["unit_id"])
    findings = sorted_findings(findings)
    policy = dict(policy)
    policy["effective_policies"] = sorted(policy["effective_policies"], key=lambda entry: entry["policy_id"])
    policy["requests"] = sorted(policy["requests"], key=lambda entry: entry["request_id"])
    policy["applied_blocks"] = sorted(policy["applied_blocks"], key=lambda entry: (entry["unit_id"], entry["request_id"]))
    policy["dispositions"] = sorted(policy["dispositions"], key=lambda entry: entry["finding_id"])
    policy["effective_policy_digest"] = record_digest(policy["effective_policies"])
    return execution, findings, policy


def build_result(execution: dict, findings: list[dict], policy: dict) -> dict:
    counts = compute_counts(execution["units"], findings, policy["dispositions"])
    code = classify(execution, policy, counts)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": execution["run_id"],
        "result_code": code,
        "result": RESULT_NAMES[code],
        "coverage": coverage_for(code, counts),
        "evidence_valid": execution["evidence_valid"],
        "engine_version": execution["engine_version"],
        "ruleset_id": execution["ruleset_id"],
        "ruleset_digest": execution["ruleset_digest"],
        "source_adapter": execution["source_adapter"],
        "counts": counts,
        "reason_codes": reason_codes_for(execution, policy, counts, code),
        "records": {
            "execution_digest": record_digest(execution),
            "findings_digest": record_digest(findings),
            "policy_digest": record_digest(policy),
        },
    }


def reconcile(
    execution: dict,
    findings: list[dict],
    policy: dict,
    *,
    contents: Mapping[str, bytes] | None = None,
) -> dict:
    execution, findings, policy = _normalize(execution, findings, policy)
    result = build_result(execution, findings, policy)
    validate_records(execution, findings, policy, result, contents=contents)
    return result


def reconcile_bundle(
    execution: dict,
    findings: list[dict],
    policy: dict,
    *,
    contents: Mapping[str, bytes] | None = None,
    accepted: set[int] | frozenset[int] = DEFAULT_ACCEPTED,
) -> tuple[dict, dict]:
    execution, findings, policy = _normalize(execution, findings, policy)
    result = build_result(execution, findings, policy)
    decision = ci_decision(
        result["result_code"],
        accepted,
        run_id=result["run_id"],
        result_digest=record_digest(result),
    )
    validate_records(execution, findings, policy, result, decision, contents=contents)
    return result, decision


def canonical_result_document(result: dict) -> str:
    return canonical_json(result) + "\n"
