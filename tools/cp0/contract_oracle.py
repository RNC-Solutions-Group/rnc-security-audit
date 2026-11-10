"""CP0 reference *contract oracle*, not a production scanner or harness scorer.

The expected labels are independently declared in outcome-cases.json. This
module provides a tiny deterministic interpretation for validating CP0 design
consistency; production code must be independently implemented and tested.
"""

from __future__ import annotations


RESULT_NAMES = {
    1: "CLEAN",
    2: "POLICY_APPLIED",
    3: "ACTIONABLE",
    4: "INCOMPLETE",
    5: "FAILED",
}
DEFAULT_ACCEPTED = frozenset({1, 2})


def classify(case: dict) -> int:
    """Apply the documented priority to a constructed synthetic outcome case."""
    for field in ("inspected", "blocked", "uninspected", "actionable", "exempted"):
        if not isinstance(case.get(field), int) or case[field] < 0:
            raise ValueError(f"invalid count: {field}")

    if case["fatal"] or case["state"] in ("ERROR", "INTERRUPTED"):
        return 5
    if (case["uninspected"] > 0 or not case["evidence_valid"]
            or case["inspected"] + case["blocked"] == 0):
        return 4
    if case["actionable"] > 0:
        return 3
    if case["exempted"] > 0 or case["blocked"] > 0:
        return 2
    return 1


def ci_decision(result_code: int, accepted: set[int] | frozenset[int] = DEFAULT_ACCEPTED) -> dict:
    """Translate an immutable result to OS exit semantics, without reclassifying."""
    if not accepted.issubset({1, 2, 3}):
        raise ValueError("only completed result codes 1-3 may be accepted")
    if result_code not in RESULT_NAMES:
        raise ValueError("unknown result code")
    if result_code == 4:
        process_exit = 20
    elif result_code == 5:
        process_exit = 30
    else:
        process_exit = 0 if result_code in accepted else 10
    return {
        "result_code": result_code,
        "accepted_result_codes": sorted(accepted),
        "accepted": process_exit == 0,
        "process_exit_code": process_exit,
    }
