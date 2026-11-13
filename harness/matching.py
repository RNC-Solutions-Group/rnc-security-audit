"""Explicit, conservative matching between a finding and an expected value.

A finding is credited only when its extracted evidence is a complete match or a
supported normalized match. Line numbers are never used as evidence: a finding
that merely points at a line containing a credential is not a detection.

Supported normalizations are deliberately small and testable:

* CRLF/CR line endings become LF;
* outer whitespace is trimmed;
* one matching surrounding quote pair (single, double, or backtick) is removed;
* Unicode text is NFC-normalized.

Partial matches (one normalized value is a proper substring of the other) are
reported separately and never credited as true positives. Case folding is not
performed: credentials are case-sensitive.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from .model import Finding

COMPLETE = "complete"
NORMALIZED = "normalized"
PARTIAL = "partial"
NONE = "none"

_QUOTES = ('"', "'", "`")
_RANK = {COMPLETE: 3, NORMALIZED: 2, PARTIAL: 1, NONE: 0}


@dataclass(frozen=True)
class Match:
    classification: str
    field: str
    relation: str
    expected_length: int
    evidence_length: int

    @property
    def eligible(self) -> bool:
        return self.classification in (COMPLETE, NORMALIZED)


def normalize_text(value: str) -> str:
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = unicodedata.normalize("NFC", value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in _QUOTES:
        inner = value[1:-1].strip()
        if inner:
            value = inner
    return value


def classify(expected: str, evidence: str, field: str = "secret") -> Match:
    if not evidence:
        return Match(NONE, field, "no_evidence", len(expected), 0)
    if evidence == expected:
        return Match(COMPLETE, field, "equal", len(expected), len(evidence))
    normalized_expected = normalize_text(expected)
    normalized_evidence = normalize_text(evidence)
    if normalized_expected and normalized_expected == normalized_evidence:
        return Match(NORMALIZED, field, "normalized_equal", len(expected), len(evidence))
    if normalized_expected and normalized_expected in normalized_evidence:
        return Match(PARTIAL, field, "finding_contains_expected", len(expected), len(evidence))
    if normalized_expected and normalized_evidence and normalized_evidence in normalized_expected:
        return Match(PARTIAL, field, "expected_contains_finding", len(expected), len(evidence))
    return Match(NONE, field, "different", len(expected), len(evidence))


def best_match(expected: str, finding: Finding) -> Match:
    """Return the strongest match across the finding's supported evidence fields."""
    candidates: list[Match] = []
    seen: set[str] = set()
    for field, value in (("secret", finding.secret), ("match", finding.match)):
        if not value or value in seen:
            continue
        seen.add(value)
        candidate = classify(expected, value, field)
        if candidate.classification != NONE:
            candidates.append(candidate)
    if not candidates:
        return Match(NONE, "-", "no_evidence", len(expected), 0)
    return max(candidates, key=lambda item: (_RANK[item.classification], item.field == "secret"))
