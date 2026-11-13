"""Normalized, scanner-independent scoring contracts.

These dataclasses are the only bridge between scanner adapters, truth
manifests, the scoring engine, and reporters.  Nothing here imports a scanner
adapter, a scanner parser, or the legacy execution layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA_VERSION = 1

_UNSAFE_METADATA_KEYS = {
    "secret",
    "secret_text",
    "secret_value",
    "match",
    "match_text",
    "raw",
    "raw_text",
    "line_text",
    "plaintext",
    "password",
    "token",
}


def safe_metadata_value(value: Any) -> Any:
    """Recursively retain only report-safe metadata values.

    Scanner metadata is untrusted for redaction purposes.  Key names that could
    carry matched bytes are removed, and arbitrary objects are stringified rather
    than serialized.  The normalized finding's transient fields are never
    included in this projection.
    """
    if isinstance(value, dict):
        return {
            str(key): safe_metadata_value(item)
            for key, item in value.items()
            if str(key).lower() not in _UNSAFE_METADATA_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [safe_metadata_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)

EXPECTED_DETECTION = "EXPECTED_DETECTION"
MISSED_EXPECTATION = "MISSED_EXPECTATION"
UNEXPECTED_FINDING = "UNEXPECTED_FINDING"
UNMATCHED_PENDING_REVIEW = "UNMATCHED_PENDING_REVIEW"
UNVERIFIED_EVIDENCE = "UNVERIFIED_EVIDENCE"
REVIEWED_NEGATIVE = "REVIEWED_NEGATIVE"
INFORMATIVE_REFERENCE = "INFORMATIVE_REFERENCE"
INFORMATIVE_MATCH = "INFORMATIVE_MATCH"
FALSE_POSITIVE = "FALSE_POSITIVE"
PARTIAL_MATCH = "PARTIAL_MATCH"
DUPLICATE = "DUPLICATE"
UNMAPPED = "UNMAPPED"
AMBIGUOUS_MATCH = "AMBIGUOUS_MATCH"
SKIPPED = "SKIPPED"
NOT_APPLICABLE = "NOT_APPLICABLE"
BLOCKED = "BLOCKED"
EXECUTION_ERROR = "EXECUTION_ERROR"

CLASSIFICATIONS = (
    EXPECTED_DETECTION,
    MISSED_EXPECTATION,
    UNEXPECTED_FINDING,
    UNMATCHED_PENDING_REVIEW,
    UNVERIFIED_EVIDENCE,
    REVIEWED_NEGATIVE,
    INFORMATIVE_REFERENCE,
    INFORMATIVE_MATCH,
    FALSE_POSITIVE,
    PARTIAL_MATCH,
    DUPLICATE,
    UNMAPPED,
    AMBIGUOUS_MATCH,
    SKIPPED,
    NOT_APPLICABLE,
    BLOCKED,
    EXECUTION_ERROR,
)


@dataclass(frozen=True)
class NormalizedFinding:
    """Portable finding contract.

    ``secret_text`` and ``match_text`` are transient matching context only and
    are deliberately excluded from ``repr``. They are never serialized.
    """

    file: str
    line: int | None
    rule_id: str
    secret_sha256: str | None = None
    match_sha256: str | None = None
    secret_redacted: bool = False
    finding_id: str | None = None
    target: str | None = None
    scanner: str | None = None
    scanner_version: str | None = None
    commit: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict, repr=False)
    secret_text: str | None = field(default=None, repr=False)
    match_text: str | None = field(default=None, repr=False)

    def safe_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "secret_sha256": self.secret_sha256,
            "match_sha256": self.match_sha256,
            "secret_redacted": self.secret_redacted,
            "target": self.target,
            "scanner": self.scanner,
            "scanner_version": self.scanner_version,
            "commit": self.commit,
            "metadata": safe_metadata_value(self.metadata),
        }


@dataclass(frozen=True)
class TruthItem:
    finding_id: str
    dataset_id: str
    dataset_version: str
    path: str
    classification: str = EXPECTED_DETECTION
    category: str = ""
    risk_bearing: bool | None = None
    line_start: int | None = None
    line_end: int | None = None
    location: str | None = None
    commit: str | None = None
    fingerprint_sha256: str | None = None
    source_reference: str | None = None
    matching_policy: str = "line_range"
    category_conflict: bool = False
    notes: str = ""
    expected_text: str | None = field(default=None, repr=False)
    expected_rule_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def safe_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "dataset_id": self.dataset_id,
            "dataset_version": self.dataset_version,
            "path": self.path,
            "classification": self.classification,
            "category": self.category,
            "risk_bearing": self.risk_bearing,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "location": self.location,
            "commit": self.commit,
            "fingerprint_sha256": self.fingerprint_sha256,
            "source_reference": self.source_reference,
            "matching_policy": self.matching_policy,
            "category_conflict": self.category_conflict,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class TruthManifest:
    manifest_id: str
    manifest_version: str
    dataset_id: str
    dataset_version: str
    items: tuple[TruthItem, ...]
    schema_version: int = SCHEMA_VERSION
    scoring_policy: dict[str, Any] = field(default_factory=dict)
    category_reconciliation: dict[str, Any] = field(default_factory=dict)
    counts: dict[str, Any] = field(default_factory=dict)
    integrity: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def by_path(self) -> dict[str, list[TruthItem]]:
        result: dict[str, list[TruthItem]] = {}
        for item in self.items:
            result.setdefault(item.path.replace("\\", "/"), []).append(item)
        return result


@dataclass(frozen=True)
class ScoringPolicy:
    policy_id: str = "line-range-v1"
    policy_version: str = "1"
    line_tolerance: int = 0
    partial_line_tolerance: int = 0
    require_line: bool = True
    allow_partial: bool = False
    negative_oracle: bool = False
    one_to_one: bool = True
    duplicate_policy: str = "report"
    # A truth item without a value fingerprint may still be credited by location
    # only when the applicable policy explicitly authorizes it.  Real credential
    # corpora should leave this false so a location-only hit remains visible as
    # UNVERIFIED_EVIDENCE rather than becoming a silent true positive.
    allow_line_only: bool = False


@dataclass(frozen=True)
class FindingEvaluation:
    classification: str
    expected_id: str | None = None
    path: str | None = None
    line: int | None = None
    observed: dict[str, Any] | None = None
    expected: dict[str, Any] | None = None
    reason: str = ""
    identity_confidence: str = "line"
    review_status: str = "NOT_APPLICABLE"

    def safe_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "expected_id": self.expected_id,
            "path": self.path,
            "line": self.line,
            "observed": self.observed,
            "expected": self.expected,
            "reason": self.reason,
            "identity_confidence": self.identity_confidence,
            "review_status": self.review_status,
        }


@dataclass(frozen=True)
class ScoringResult:
    scoring_status: str
    execution_status: str
    metrics: dict[str, Any]
    evaluations: tuple[FindingEvaluation, ...]
    exceptions: tuple[FindingEvaluation, ...]
    warnings: tuple[str, ...]
    manifest_id: str
    manifest_version: str
    dataset_id: str
    dataset_version: str
    policy_id: str
    policy_version: str
    schema_version: int = SCHEMA_VERSION

    @property
    def ready(self) -> bool:
        return self.scoring_status == "COMPLETED"

    def safe_dict(self, include_evaluations: bool = True) -> dict[str, Any]:
        document = {
            "schema_version": self.schema_version,
            "scoring_status": self.scoring_status,
            "execution_status": self.execution_status,
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "dataset_id": self.dataset_id,
            "dataset_version": self.dataset_version,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "metrics": self.metrics,
            "warnings": list(self.warnings),
            "exceptions": [item.safe_dict() for item in self.exceptions],
        }
        if include_evaluations:
            document["evaluations"] = [item.safe_dict() for item in self.evaluations]
        return document
