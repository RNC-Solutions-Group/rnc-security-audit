"""Version-aware baseline comparisons for normalized scoring results."""

from __future__ import annotations

from .contracts import (
    AMBIGUOUS_MATCH,
    DUPLICATE,
    EXPECTED_DETECTION,
    FALSE_POSITIVE,
    MISSED_EXPECTATION,
    PARTIAL_MATCH,
    UNEXPECTED_FINDING,
    UNMAPPED,
    UNMATCHED_PENDING_REVIEW,
    UNVERIFIED_EVIDENCE,
)


def _as_dict(result) -> dict:
    if isinstance(result, dict):
        return result
    return result.safe_dict()


def _evaluations(result: dict) -> list[dict]:
    return list(result.get("evaluations", []))


def _expected_map(result: dict) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in _evaluations(result):
        expected_id = item.get("expected_id")
        classification = item.get("classification")
        if expected_id and classification in (
            EXPECTED_DETECTION,
            MISSED_EXPECTATION,
            PARTIAL_MATCH,
            DUPLICATE,
        ):
            if mapping.get(expected_id) != EXPECTED_DETECTION:
                mapping[expected_id] = classification
    return mapping


def _unexpected_map(result: dict) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for item in _evaluations(result):
        if item.get("classification") not in (
            UNEXPECTED_FINDING,
            FALSE_POSITIVE,
            UNMATCHED_PENDING_REVIEW,
            UNVERIFIED_EVIDENCE,
            AMBIGUOUS_MATCH,
            UNMAPPED,
            PARTIAL_MATCH,
        ):
            continue
        observed = item.get("observed") or {}
        key = "|".join(
            str(observed.get(field, ""))
            for field in ("file", "line", "rule_id", "secret_sha256")
        )
        mapping[key] = item.get("classification")
    return mapping


def compare_documents(previous: dict, current: dict) -> dict:
    previous_suites = previous.get("suites") or {}
    current_suites = current.get("suites") or {}
    comparisons: dict[str, dict] = {}
    for key, current_suite in current_suites.items():
        previous_suite = previous_suites.get(key)
        if previous_suite is None:
            comparisons[key] = {
                "status": "NOT_COMPARABLE",
                "reason": "suite is absent from the baseline",
            }
            continue
        current_rich = _first_rich(current_suite)
        previous_rich = _first_rich(previous_suite)
        if current_rich is not None and previous_rich is not None:
            comparisons[key] = compare_results(previous_rich, current_rich)
        else:
            prev_metrics = previous_suite.get("metrics") or {}
            curr_metrics = current_suite.get("metrics") or {}
            changed = {
                name: {"previous": prev_metrics.get(name), "current": curr_metrics.get(name)}
                for name in sorted(set(prev_metrics) | set(curr_metrics))
                if prev_metrics.get(name) != curr_metrics.get(name)
            }
            comparisons[key] = {
                "status": "METRIC_ONLY",
                "reason": "baseline has no normalized scoring evaluations for this suite",
                "changed_metrics": changed,
            }
    statuses = {item.get("status") for item in comparisons.values()}
    if "INCOMPATIBLE" in statuses:
        status = "INCOMPATIBLE"
    elif "FAIL" in statuses:
        status = "FAIL"
    elif "PASS" in statuses:
        status = "PASS"
    elif statuses == {"METRIC_ONLY"}:
        status = "METRIC_ONLY"
    elif statuses:
        status = "NOT_COMPARABLE"
    else:
        status = "NOT_COMPARABLE"
    return {
        "status": status,
        "baseline_generated_at": previous.get("generated_at"),
        "baseline_run_id": previous.get("run_id"),
        "suites": comparisons,
    }


def _first_rich(suite: dict) -> dict | None:
    lanes = (suite.get("details") or {}).get("lanes") or {}
    for lane in lanes.values():
        if isinstance(lane, dict) and lane.get("rich"):
            return lane["rich"]
    return None


def compare_results(previous, current) -> dict:
    previous = _as_dict(previous)
    current = _as_dict(current)
    for key in ("manifest_id", "manifest_version", "dataset_id", "dataset_version", "policy_id", "policy_version"):
        if previous.get(key) != current.get(key):
            return {
                "status": "INCOMPATIBLE",
                "reason": f"{key} differs: {previous.get(key)!r} != {current.get(key)!r}",
                "existing_gaps": [],
                "new_misses": [],
                "recovered": [],
                "new_unexpected": [],
                "resolved_unexpected": [],
            }
    prev_expected = _expected_map(previous)
    curr_expected = _expected_map(current)
    prev_unexpected = _unexpected_map(previous)
    curr_unexpected = _unexpected_map(current)
    expected_ids = sorted(set(prev_expected) | set(curr_expected))
    existing_gaps = [
        item for item in expected_ids
        if prev_expected.get(item) == MISSED_EXPECTATION
        and curr_expected.get(item) == MISSED_EXPECTATION
    ]
    new_misses = [
        item for item in expected_ids
        if prev_expected.get(item) == EXPECTED_DETECTION
        and curr_expected.get(item) != EXPECTED_DETECTION
    ]
    recovered = [
        item for item in expected_ids
        if prev_expected.get(item) != EXPECTED_DETECTION
        and curr_expected.get(item) == EXPECTED_DETECTION
    ]
    new_unexpected = sorted(set(curr_unexpected) - set(prev_unexpected))
    resolved_unexpected = sorted(set(prev_unexpected) - set(curr_unexpected))
    changed_classification = [
        {"finding_id": item, "previous": prev_expected.get(item), "current": curr_expected.get(item)}
        for item in expected_ids
        if prev_expected.get(item) != curr_expected.get(item)
        and item not in new_misses
        and item not in recovered
    ]
    status = "FAIL" if new_misses or new_unexpected else "PASS"
    return {
        "status": status,
        "reason": None,
        "existing_gaps": existing_gaps,
        "new_misses": new_misses,
        "recovered": recovered,
        "new_unexpected": new_unexpected,
        "resolved_unexpected": resolved_unexpected,
        "changed_classification": changed_classification,
        "summary": (
            f"{len(existing_gaps)} existing gaps, {len(new_misses)} new misses, "
            f"{len(recovered)} recovered, {len(new_unexpected)} new unexpected, "
            f"{len(resolved_unexpected)} resolved unexpected"
        ),
    }
