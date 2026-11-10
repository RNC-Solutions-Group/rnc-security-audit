"""CP0 reference ledger reconciler used to test *interface integrity*.

This is not a production reporter and must not be packaged in RNC Scanner.
The production result finalizer will be independently implemented in CP2.
"""

from __future__ import annotations

from tools.cp0.contract_oracle import RESULT_NAMES, classify


def reconcile(execution: dict, findings: list[dict], policy: dict) -> dict:
    run_id = execution["run_id"]
    if policy["run_id"] != run_id or any(item["run_id"] != run_id for item in findings):
        raise ValueError("run ID mismatch")

    units = execution["units"]
    by_unit = {unit["unit_id"]: unit for unit in units}
    if len(by_unit) != len(units):
        raise ValueError("duplicate source unit")
    finding_ids = [f["finding_id"] for f in findings]
    if len(set(finding_ids)) != len(finding_ids):
        raise ValueError("duplicate finding")
    for finding in findings:
        unit = by_unit.get(finding["unit_id"])
        if not unit or unit["disposition"] != "INSPECTED":
            raise ValueError("finding outside inspected scope")
        if finding["start_byte"] >= finding["end_byte"]:
            raise ValueError("invalid finding byte range")

    blocked_ids = [unit["unit_id"] for unit in units if unit["disposition"] == "VERIFIED_BLOCKED"]
    applied = policy["applied_blocks"]
    applied_ids = [entry["unit_id"] for entry in applied]
    if len(set(applied_ids)) != len(applied_ids) or sorted(applied_ids) != sorted(blocked_ids):
        raise ValueError("blocked units and verified policy events disagree")
    if any(not entry["verified_non_access"] for entry in applied):
        raise ValueError("unverified block cannot be applied")

    dispositions = policy["dispositions"]
    disposition_ids = [entry["finding_id"] for entry in dispositions]
    if len(set(disposition_ids)) != len(disposition_ids) or set(disposition_ids) != set(finding_ids):
        raise ValueError("detection and policy findings do not reconcile")
    exempted = sum(entry["status"] == "EXEMPTED" for entry in dispositions)
    actionable = sum(entry["status"] == "ACTIONABLE" for entry in dispositions)
    if exempted + actionable != len(findings):
        raise ValueError("unrecognized finding disposition")

    inspected = sum(unit["disposition"] == "INSPECTED" for unit in units)
    blocked = len(blocked_ids)
    uninspected = sum(unit["disposition"] == "UNINSPECTED" for unit in units)
    case = {
        "inspected": inspected, "blocked": blocked, "uninspected": uninspected,
        "actionable": actionable, "exempted": exempted,
        "state": execution["state"], "evidence_valid": execution["evidence_valid"],
        "fatal": bool(execution["fatal_errors"]),
    }
    if execution.get("required_scanners_missing", 0) > 0:
        case["uninspected"] += execution["required_scanners_missing"]
    code = classify(case)
    return {
        "schema_version": "0.1.0", "run_id": run_id,
        "result_code": code, "result": RESULT_NAMES[code],
        "reason_codes": [],
        "counts": {
            "discovered": len(units), "inspected": inspected,
            "verified_blocked": blocked, "uninspected": uninspected,
            "detected": len(findings), "actionable": actionable, "exempted": exempted,
        },
    }
