"""Canonical execution-status vocabulary for the consolidated matrix.

Every executable, Docker, fixture, corpus, and evidence lane reports one of the
five statuses below.  ``NOT_APPLICABLE`` is used when a target or lane was not
selected, or when a platform-specific capability is unavailable.  It is never
counted as a pass or as a failure for an applicable lane.
"""

from __future__ import annotations

PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED"
NOT_RUN = "NOT_RUN"
NOT_APPLICABLE = "NOT_APPLICABLE"

CANONICAL = (PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE)
_INCOMPLETE = {BLOCKED, NOT_RUN}

COMPLETED_AND_SCORED = "COMPLETED_AND_SCORED"
COMPLETED_UNSCORED = "COMPLETED_UNSCORED"
FAILED = "FAILED"
OUTCOMES = (
    COMPLETED_AND_SCORED,
    COMPLETED_UNSCORED,
    NOT_APPLICABLE,
    FAILED,
    BLOCKED,
)


def outcome(status: str, *, scored: bool = True) -> str:
    if status == PASS:
        return COMPLETED_AND_SCORED if scored else COMPLETED_UNSCORED
    if status == FAIL:
        return FAILED
    if status == NOT_APPLICABLE:
        return NOT_APPLICABLE
    return BLOCKED



def validate(status: str) -> str:
    if status not in CANONICAL:
        raise ValueError(f"non-canonical status: {status!r}")
    return status


def combine(statuses) -> str:
    """Combine lane statuses without hiding a failure behind a limitation."""
    values = [validate(status) for status in statuses if status is not None]
    if not values:
        return NOT_APPLICABLE
    applicable = [value for value in values if value != NOT_APPLICABLE]
    if not applicable:
        return NOT_APPLICABLE
    if FAIL in applicable:
        return FAIL
    if BLOCKED in applicable:
        return BLOCKED
    if NOT_RUN in applicable:
        return NOT_RUN
    if all(status == PASS for status in applicable):
        return PASS
    return NOT_RUN


def overall(statuses, *, coverage_complete: bool) -> str:
    """Return the compatibility overall result for a consolidated run.

    ``FAIL`` and ``BLOCKED``/``NOT_RUN`` remain distinct.  A run whose
    applicable lanes all pass but whose evidence coverage is incomplete is
    ``COMPLETE_WITH_LIMITATIONS`` rather than ``PASS``.
    """
    values = [validate(status) for status in statuses if status is not None]
    applicable = [value for value in values if value != NOT_APPLICABLE]
    if FAIL in applicable:
        return "FAIL"
    if any(status in _INCOMPLETE for status in applicable):
        return "INCOMPLETE"
    if not applicable or not all(status == PASS for status in applicable):
        return "INCOMPLETE"
    return "COMPLETE" if coverage_complete else "COMPLETE_WITH_LIMITATIONS"
