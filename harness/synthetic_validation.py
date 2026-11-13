"""Synthetic scanner adapter and scoring-engine validation.

The adapter emits controlled normalized findings; it has no Gitleaks imports,
rules, parser, or executable behavior. Expected answers in this module are
static values established independently of the scoring implementation.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from . import baseline as baseline_module
from . import leaky_repo as leaky_module
from . import reporting
from . import scoring_engine
from . import __version__
from .config import HarnessConfig, ReportConfig
from .contracts import (
    AMBIGUOUS_MATCH,
    BLOCKED,
    DUPLICATE,
    EXPECTED_DETECTION,
    FALSE_POSITIVE,
    MISSED_EXPECTATION,
    NOT_APPLICABLE,
    NormalizedFinding,
    PARTIAL_MATCH,
    ScoringPolicy,
    SKIPPED,
    TruthItem,
    TruthManifest,
    UNEXPECTED_FINDING,
    UNMAPPED,
)

ROOT = Path(__file__).resolve().parents[1]
DATASET_ID = "synthetic-scoring"
DATASET_VERSION = "synthetic-v1"


class SyntheticAdapter:
    """Controlled adapter output; deliberately independent of Gitleaks."""

    key = "synthetic"
    display_name = "Synthetic scoring validator"
    supported_suites = ("synthetic",)

    def emit(self, specs: list[dict]) -> list[NormalizedFinding]:
        findings = []
        for spec in specs:
            findings.append(
                NormalizedFinding(
                    file=spec.get("file", ""),
                    line=spec.get("line"),
                    rule_id=spec.get("rule_id", "synthetic-rule"),
                    secret_sha256=spec.get("secret_sha256"),
                    match_sha256=spec.get("match_sha256"),
                    finding_id=spec.get("finding_id"),
                    target=spec.get("target"),
                    scanner="synthetic",
                )
            )
        return findings


def _truth_item(
    finding_id: str,
    path: str,
    line: int,
    category: str = "risk",
    *,
    classification: str = EXPECTED_DETECTION,
    line_end: int | None = None,
    expected_rule_id: str | None = None,
) -> TruthItem:
    return TruthItem(
        finding_id=finding_id,
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        path=path,
        classification=classification,
        category=category,
        risk_bearing=category == "risk",
        line_start=line,
        line_end=line_end,
        location="line",
        fingerprint_sha256="0" * 64,
        source_reference=f"synthetic:{path}:{line}",
        expected_rule_id=expected_rule_id,
    )


def _reviewed_negative_item(finding_id: str, path: str, line: int, fingerprint: str) -> TruthItem:
    return replace(
        _truth_item(
            finding_id,
            path,
            line,
            category="negative",
            classification="REVIEWED_NEGATIVE",
        ),
        metadata={
            "value_fingerprints": [fingerprint],
            "requires_value": True,
            "source_verified": True,
        },
    )


def _base_truth() -> TruthManifest:
    items = [
        _truth_item("A1", "alpha.txt", 1),
        _truth_item("A2", "alpha.txt", 2),
        _truth_item("A3", "alpha.txt", 3, "informative"),
        _truth_item("A4", "alpha.txt", 4, line_end=5),
        _truth_item("A5", "alpha.txt", 6, expected_rule_id="rule-good"),
        _truth_item("B1", "beta.txt", 10),
        _truth_item("B2", "beta.txt", 11, "informative"),
        _truth_item("C1", "gamma.txt", 30),
        _truth_item("S1", "skipped.txt", 1, classification=SKIPPED),
        _truth_item("U1", "unavailable.txt", 1, classification=NOT_APPLICABLE),
        _truth_item("X1", "blocked.txt", 1, classification=BLOCKED),
    ]
    return TruthManifest(
        manifest_id="synthetic-truth",
        manifest_version="synthetic-v1",
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        items=tuple(items),
        scoring_policy={
            "id": "synthetic-line-v1",
            "version": "1",
            "negative_oracle": False,
            "allow_line_only": True,
        },
        integrity={"status": "PASS"},
    )


def _findings(*specs) -> list[NormalizedFinding]:
    return SyntheticAdapter().emit(list(specs))


def _spec(file: str, line: int | None, rule_id: str = "synthetic-rule", **extra) -> dict:
    return {"file": file, "line": line, "rule_id": rule_id, **extra}


def _all_specs() -> list[dict]:
    return [
        _spec("alpha.txt", 1),
        _spec("alpha.txt", 2),
        _spec("alpha.txt", 3),
        _spec("alpha.txt", 4),
        _spec("alpha.txt", 6, "rule-good"),
        _spec("beta.txt", 10),
        _spec("beta.txt", 11),
        _spec("gamma.txt", 30),
    ]


def _expected(
    *,
    status: str = "COMPLETED",
    matched: int,
    missed: int,
    unexpected: int = 0,
    false_positive: int = 0,
    unverified: int = 0,
    partial: int = 0,
    duplicate: int = 0,
    ambiguous: int = 0,
    unmapped: int = 0,
    skipped: int = 1,
    not_applicable: int = 1,
    blocked: int = 1,
    observed: int = 8,
    recall: float | None = 100.0,
    precision: float | None = None,
    f1: float | None = None,
) -> dict:
    return {
        "scoring_status": status,
        "metrics": {
            "matched_count": matched,
            "missed_count": missed,
            "unexpected_count": unexpected,
            "false_positive_count": false_positive,
            "unverified_evidence_count": unverified,
            "partial_count": partial,
            "duplicate_count": duplicate,
            "ambiguous_count": ambiguous,
            "unmapped_count": unmapped,
            "skipped_count": skipped,
            "not_applicable_count": not_applicable,
            "blocked_count": blocked,
            "observed_count": observed,
            "detection_recall_percent": recall,
            "precision_percent": precision,
            "f1_percent": f1,
        },
    }


def cases() -> list[dict]:
    truth = _base_truth()
    policy = ScoringPolicy(
        policy_id="synthetic-line-v1",
        policy_version="1",
        allow_partial=True,
        partial_line_tolerance=1,
        allow_line_only=True,
    )
    all_specs = _all_specs()
    no_skip = replace(truth, items=tuple(item for item in truth.items if item.classification == EXPECTED_DETECTION))
    return [
        {
            "id": "all-expected",
            "description": "100% expected detection with all categories",
            "truth": truth,
            "policy": policy,
            "findings": _findings(*all_specs),
            "expected": _expected(matched=8, missed=0, skipped=1, not_applicable=1, blocked=1),
        },
        {
            "id": "zero-detection",
            "description": "0% expected detection with no findings",
            "truth": truth,
            "policy": policy,
            "findings": [],
            "expected": _expected(matched=0, missed=8, observed=0, recall=0.0),
        },
        {
            "id": "partial-match",
            "description": "off-by-one line is partial, not credited",
            "truth": truth,
            "policy": policy,
            "findings": _findings(*all_specs[:-1], _spec("gamma.txt", 31)),
            "expected": _expected(matched=7, missed=1, partial=1, recall=87.5),
        },
        {
            "id": "missing-one",
            "description": "one expected finding is missing",
            "truth": truth,
            "policy": policy,
            "findings": _findings(*(all_specs[:1] + all_specs[2:])),
            "expected": _expected(matched=7, missed=1, observed=7, recall=87.5),
        },
        {
            "id": "unexpected-finding",
            "description": "finding outside truth is unexpected, not crudely a false positive",
            "truth": truth,
            "policy": policy,
            "findings": _findings(*all_specs, _spec("unknown.txt", 1)),
            "expected": _expected(matched=8, missed=0, unexpected=1, observed=9),
        },
        {
            "id": "false-positive-negative-oracle",
            "description": "negative-oracle finding is a verified false positive",
            "truth": replace(
                truth,
                items=truth.items
                + (_reviewed_negative_item("N1", "negative.txt", 1, "b" * 64),),
            ),
            "policy": replace(policy, negative_oracle=True),
            "findings": _findings(
                *all_specs,
                _spec("negative.txt", 1, secret_sha256="b" * 64),
            ),
            "expected": _expected(
                matched=8,
                missed=0,
                false_positive=1,
                observed=9,
                precision=88.89,
                f1=94.12,
            ),
        },
        {
            "id": "duplicate",
            "description": "duplicate finding does not double-credit",
            "truth": truth,
            "policy": policy,
            "findings": _findings(*all_specs, _spec("alpha.txt", 1)),
            "expected": _expected(matched=8, missed=0, duplicate=1, observed=9),
        },
        {
            "id": "multiple-same-file",
            "description": "multiple expected findings in one file",
            "truth": truth,
            "policy": policy,
            "findings": _findings(*[spec for spec in all_specs if spec["file"] == "alpha.txt"][:5]),
            "expected": _expected(matched=5, missed=3, observed=5, recall=62.5),
        },
        {
            "id": "wrong-file",
            "description": "correct line identity in the wrong file is not credited",
            "truth": truth,
            "policy": policy,
            "findings": _findings(_spec("beta.txt", 1)),
            "expected": _expected(matched=0, missed=8, unexpected=1, observed=1, recall=0.0),
        },
        {
            "id": "wrong-classification",
            "description": "wrong rule classification is not credited",
            "truth": truth,
            "policy": replace(policy, allow_partial=False),
            "findings": _findings(*(all_specs[:4] + [_spec("alpha.txt", 6, "rule-wrong")] + all_specs[5:])),
            "expected": _expected(matched=7, missed=1, unexpected=1, recall=87.5),
        },
        {
            "id": "overlapping-range",
            "description": "range match plus duplicate in same overlapping range",
            "truth": truth,
            "policy": policy,
            "findings": _findings(*all_specs, _spec("alpha.txt", 5)),
            "expected": _expected(matched=8, missed=0, duplicate=1, observed=9),
        },
        {
            "id": "skipped-truth",
            "description": "skipped truth item is not a miss",
            "truth": truth,
            "policy": policy,
            "findings": _findings(*all_specs),
            "expected": _expected(matched=8, missed=0, skipped=1),
        },
        {
            "id": "unavailable-truth",
            "description": "not-applicable truth item is not a miss",
            "truth": truth,
            "policy": policy,
            "findings": _findings(*all_specs),
            "expected": _expected(matched=8, missed=0, not_applicable=1),
        },
        {
            "id": "blocked-execution",
            "description": "blocked target is not a detection result",
            "truth": truth,
            "policy": policy,
            "findings": [],
            "execution_status": "BLOCKED",
            "expected": {
                "scoring_status": "BLOCKED",
                "metrics": {"expected_count": 8, "execution_error": True},
            },
        },
        {
            "id": "execution-error",
            "description": "execution error separated from detection quality",
            "truth": truth,
            "policy": policy,
            "findings": [],
            "execution_status": "ERROR",
            "expected": {
                "scoring_status": "EXECUTION_ERROR",
                "metrics": {"expected_count": 8, "execution_error": True},
            },
        },
        {
            "id": "empty-dataset",
            "description": "empty truth and empty output do not crash",
            "truth": TruthManifest(
                manifest_id="empty",
                manifest_version="1",
                dataset_id=DATASET_ID,
                dataset_version=DATASET_VERSION,
                items=(),
                scoring_policy={"id": "synthetic-line-v1", "version": "1"},
                integrity={"status": "PASS"},
            ),
            "policy": policy,
            "findings": [],
            "expected": {
                "scoring_status": "COMPLETED",
                "metrics": {"expected_count": 0, "matched_count": 0, "missed_count": 0, "observed_count": 0},
            },
        },
        {
            "id": "empty-output",
            "description": "empty scanner output is a complete zero-detection score",
            "truth": truth,
            "policy": policy,
            "findings": [],
            "expected": _expected(matched=0, missed=8, observed=0, recall=0.0),
        },
        {
            "id": "malformed-finding",
            "description": "finding without file identity is unmapped",
            "truth": truth,
            "policy": policy,
            "findings": _findings(_spec("", None)),
            "expected": _expected(matched=0, missed=8, unmapped=1, observed=1, recall=0.0),
        },
        {
            "id": "ambiguous-truth",
            "description": "one finding matching two truth items is ambiguous",
            "truth": TruthManifest(
                manifest_id="ambiguous",
                manifest_version="1",
                dataset_id=DATASET_ID,
                dataset_version=DATASET_VERSION,
                items=(
                    _truth_item("Y1", "ambig.txt", 20),
                    _truth_item("Y2", "ambig.txt", 20),
                ),
                scoring_policy={"id": "synthetic-line-v1", "version": "1"},
                integrity={"status": "PASS"},
            ),
            "policy": policy,
            "findings": _findings(_spec("ambig.txt", 20)),
            "expected": {
                "scoring_status": "COMPLETED",
                "metrics": {
                    "matched_count": 0,
                    "missed_count": 2,
                    "ambiguous_count": 1,
                    "observed_count": 1,
                    "detection_recall_percent": 0.0,
                },
            },
        },
        {
            "id": "not-ready-integrity",
            "description": "invalid truth integrity cannot be scored",
            "truth": replace(truth, integrity={"status": "FAIL", "reason": "synthetic invalid manifest"}),
            "policy": policy,
            "findings": _findings(*all_specs),
            "expected": {
                "scoring_status": "NOT_READY",
                "metrics": {"expected_count": 11, "reason": "synthetic invalid manifest"},
            },
        },
    ]


def _check_expected(actual: dict, expected: dict) -> list[str]:
    errors: list[str] = []
    if actual.get("scoring_status") != expected.get("scoring_status"):
        errors.append(f"scoring_status {actual.get('scoring_status')!r} != {expected.get('scoring_status')!r}")
    for key, value in (expected.get("metrics") or {}).items():
        if (actual.get("metrics") or {}).get(key) != value:
            errors.append(f"metric {key}: {actual.get('metrics', {}).get(key)!r} != {value!r}")
    expected_evaluations = expected.get("evaluations")
    if expected_evaluations is not None:
        actual_evaluations = actual.get("evaluations") or []
        if len(actual_evaluations) != len(expected_evaluations):
            errors.append(
                f"evaluation count {len(actual_evaluations)} != {len(expected_evaluations)}"
            )
        for expectation in expected_evaluations:
            if not any(
                all(actual_eval.get(key) == value for key, value in expectation.items())
                for actual_eval in actual_evaluations
            ):
                errors.append(f"missing expected evaluation {expectation!r}")
    return errors


def _identity_cases() -> list[dict]:
    policy = ScoringPolicy(policy_id="synthetic-identity-v1", policy_version="1")
    good = "1" * 64
    bad = "2" * 64
    other = "3" * 64

    def manifest(items: tuple[TruthItem, ...]) -> TruthManifest:
        return TruthManifest(
            manifest_id="identity",
            manifest_version="1",
            dataset_id=DATASET_ID,
            dataset_version=DATASET_VERSION,
            items=items,
            scoring_policy={"id": "synthetic-identity-v1", "version": "1"},
            integrity={"status": "PASS"},
        )

    def item(fid: str, line: int, fps=(good,), rule: str | None = None, requires=False) -> TruthItem:
        return TruthItem(
            fid,
            DATASET_ID,
            DATASET_VERSION,
            "identity.txt",
            line_start=line,
            line_end=line,
            category="risk",
            matching_policy="line_range",
            metadata={
                "value_fingerprints": list(fps),
                "requires_value": requires,
            },
            expected_rule_id=rule,
        )

    def finding(line: int, secret_sha=good, rule="synthetic-rule") -> NormalizedFinding:
        return NormalizedFinding(
            file="identity.txt",
            line=line,
            rule_id=rule,
            secret_sha256=secret_sha,
            secret_text="synthetic",
        )

    return [
        {
            "id": "identity-value-verified",
            "description": "correct file, line, and value fingerprint",
            "truth": manifest((item("V1", 1),)),
            "policy": policy,
            "findings": [finding(1)],
            "expected": {
                "scoring_status": "COMPLETED",
                "metrics": {
                    "matched_count": 1,
                    "missed_count": 0,
                    "unexpected_count": 0,
                    "value_verified_count": 1,
                    "line_only_count": 0,
                },
                "evaluations": [
                    {
                        "classification": EXPECTED_DETECTION,
                        "expected_id": "V1",
                        "path": "identity.txt",
                        "line": 1,
                        "identity_confidence": "value",
                    }
                ],
            },
        },
        {
            "id": "identity-value-mismatch",
            "description": "correct file and line, incorrect secret value",
            "truth": manifest((item("V2", 2),)),
            "policy": policy,
            "findings": [finding(2, bad)],
            "expected": {
                "scoring_status": "COMPLETED",
                "metrics": {
                    "matched_count": 0,
                    "missed_count": 1,
                    "unexpected_count": 0,
                    "unverified_evidence_count": 1,
                },
                "evaluations": [
                    {
                        "classification": MISSED_EXPECTATION,
                        "expected_id": "V2",
                        "path": "identity.txt",
                        "line": 2,
                    },
                    {
                        "classification": "UNVERIFIED_EVIDENCE",
                        "path": "identity.txt",
                        "line": 2,
                    },
                ],
            },
        },
        {
            "id": "identity-swapped",
            "description": "swapped finding identities do not match",
            "truth": manifest((item("V3", 3), item("V4", 4, fps=(other,)))),
            "policy": policy,
            "findings": [finding(3, other), finding(4, good)],
            "expected": {
                "scoring_status": "COMPLETED",
                "metrics": {
                    "matched_count": 0,
                    "missed_count": 2,
                    "unexpected_count": 0,
                    "unverified_evidence_count": 2,
                },
                "evaluations": [
                    {
                        "classification": MISSED_EXPECTATION,
                        "expected_id": "V3",
                        "path": "identity.txt",
                        "line": 3,
                    },
                    {
                        "classification": MISSED_EXPECTATION,
                        "expected_id": "V4",
                        "path": "identity.txt",
                        "line": 4,
                    },
                    {
                        "classification": "UNVERIFIED_EVIDENCE",
                        "path": "identity.txt",
                        "line": 3,
                    },
                    {
                        "classification": "UNVERIFIED_EVIDENCE",
                        "path": "identity.txt",
                        "line": 4,
                    },
                ],
            },
        },
        {
            "id": "identity-duplicate-same-key",
            "description": "duplicate findings at the same file and line are not double-credited",
            "truth": manifest((item("V5", 5),)),
            "policy": policy,
            "findings": [finding(5), finding(5)],
            "expected": {
                "scoring_status": "COMPLETED",
                "metrics": {
                    "matched_count": 1,
                    "missed_count": 0,
                    "duplicate_count": 1,
                },
                "evaluations": [
                    {
                        "classification": EXPECTED_DETECTION,
                        "expected_id": "V5",
                        "path": "identity.txt",
                        "line": 5,
                    },
                    {
                        "classification": DUPLICATE,
                        "expected_id": "V5",
                        "path": "identity.txt",
                        "line": 5,
                    },
                ],
            },
        },
        {
            "id": "identity-wrong-rule",
            "description": "correct location but wrong classification/rule",
            "truth": manifest((item("V6", 6, rule="rule-good"),)),
            "policy": policy,
            "findings": [finding(6, good, "rule-wrong")],
            "expected": {
                "scoring_status": "COMPLETED",
                "metrics": {
                    "matched_count": 0,
                    "missed_count": 1,
                    "unexpected_count": 1,
                    "unmatched_pending_review_count": 1,
                },
                "evaluations": [
                    {
                        "classification": MISSED_EXPECTATION,
                        "expected_id": "V6",
                        "path": "identity.txt",
                        "line": 6,
                    },
                    {
                        "classification": "UNMATCHED_PENDING_REVIEW",
                        "path": "identity.txt",
                        "line": 6,
                    },
                ],
            },
        },
        {
            "id": "identity-redacted-unverified",
            "description": "redacted scanner output cannot verify a required value fingerprint",
            "truth": manifest((item("V7", 7, requires=True),)),
            "policy": policy,
            "findings": [finding(7, None)],
            "expected": {
                "scoring_status": "COMPLETED",
                "metrics": {
                    "matched_count": 0,
                    "missed_count": 1,
                    "unexpected_count": 0,
                    "unverified_evidence_count": 1,
                },
                "evaluations": [
                    {
                        "classification": MISSED_EXPECTATION,
                        "expected_id": "V7",
                        "path": "identity.txt",
                        "line": 7,
                    },
                    {
                        "classification": "UNVERIFIED_EVIDENCE",
                        "path": "identity.txt",
                        "line": 7,
                    },
                ],
            },
        },
    ]


def run() -> dict:
    results = []
    for case in cases() + _identity_cases():
        actual = scoring_engine.score_findings(
            case["findings"],
            case["truth"],
            policy=case["policy"],
            execution_status=case.get("execution_status", "PASS"),
        )
        actual_doc = actual.safe_dict()
        errors = _check_expected(actual_doc, case["expected"])
        results.append(
            {
                "id": case["id"],
                "description": case["description"],
                "expected": case["expected"],
                "actual": {
                    "scoring_status": actual_doc["scoring_status"],
                    "metrics": actual_doc["metrics"],
                    "classifications": {
                        name: sum(
                            item["classification"] == name
                            for item in actual_doc.get("evaluations", [])
                        )
                        for name in (
                            EXPECTED_DETECTION,
                            MISSED_EXPECTATION,
                            UNEXPECTED_FINDING,
                            FALSE_POSITIVE,
                            PARTIAL_MATCH,
                            DUPLICATE,
                            AMBIGUOUS_MATCH,
                            UNMAPPED,
                        )
                    },
                },
                "correct": not errors,
                "errors": errors,
            }
        )

    # Independent baseline regression/improvement and parity checks.
    truth = _base_truth()
    policy = ScoringPolicy(
        policy_id="synthetic-line-v1",
        policy_version="1",
        allow_line_only=True,
    )
    all_result = scoring_engine.score_findings(_findings(*_all_specs()), truth, policy=policy)
    missing_result = scoring_engine.score_findings(
        _findings(*_all_specs()[:1], *_all_specs()[2:]), truth, policy=policy
    )
    regression = baseline_module.compare_results(all_result, missing_result)
    improvement = baseline_module.compare_results(missing_result, all_result)
    left = scoring_engine.score_findings(
        _findings(_spec("alpha.txt", 1), _spec("alpha.txt", 2)), truth, policy=policy
    )
    right = scoring_engine.score_findings(
        _findings(_spec("alpha.txt", 2), _spec("alpha.txt", 3)), truth, policy=policy
    )
    parity = baseline_module.compare_results(left, right)
    baseline_cases = [
        {
            "id": "baseline-regression",
            "correct": regression.get("status") == "FAIL"
            and "A2" in regression.get("new_misses", []),
            "actual": regression,
            "expected": {"status": "FAIL", "new_misses": ["A2"]},
        },        {
            "id": "baseline-improvement",
            "correct": improvement.get("status") == "PASS"
            and "A2" in improvement.get("recovered", []),
            "actual": improvement,
            "expected": {"status": "PASS", "recovered": ["A2"]},
        },
        {
            "id": "identical-counts-different-identities",
            "correct": parity.get("status") == "FAIL"
            and bool(parity.get("new_misses"))
            and bool(parity.get("recovered")),
            "actual": parity,
            "expected": {"status": "FAIL", "new_misses": ["A1"], "recovered": ["A3"]},
        },
    ]

    legacy_prepared = SimpleNamespace(
        rows=[
            {"path": "a.txt", "risk": 1, "informative": 1, "total": 2},
            {"path": "b.txt", "risk": 1, "informative": 0, "total": 1},
        ],
        spec=SimpleNamespace(counting_unit="synthetic count units"),
    )
    legacy_findings = SyntheticAdapter().emit(
        [
            _spec("a.txt", 1),
            _spec("a.txt", 2),
            _spec("unlisted.txt", 1),
        ]
    )
    legacy_result = leaky_module.score(legacy_findings, legacy_prepared, Path("."))
    baseline_cases.append(
        {
            "id": "legacy-count-scoring",
            "correct": (
                legacy_result["expected_count"] == 3
                and legacy_result["covered_count"] == 2
                and legacy_result["files_covered"] == 1
                and legacy_result["excess_findings"] == 0
                and legacy_result["unlisted_findings"] == 1
            ),
            "actual": {
                key: legacy_result[key]
                for key in (
                    "expected_count",
                    "covered_count",
                    "files_covered",
                    "excess_findings",
                    "unlisted_findings",
                )
            },
            "expected": {
                "expected_count": 3,
                "covered_count": 2,
                "files_covered": 1,
                "excess_findings": 0,
                "unlisted_findings": 1,
            },
        }
    )

    # Sanitized/unsanitized reporting path check.
    with tempfile.TemporaryDirectory() as tmp:
        config = HarnessConfig(
            reports=ReportConfig(
                sanitized=True,
                raw=True,
                output_dir=Path(tmp) / "sanitized",
                raw_output_dir=Path(tmp) / "unsanitized",
                naming="synthetic",
            )
        )
        document = {
            "report_type": "scanner-harness/matrix",
            "harness_version": __version__,
            "generated_at": "2026-01-01T00:00:00Z",
            "run_id": "synthetic",
            "scanner": {"key": "synthetic", "name": "Synthetic", "version": "1"},
            "source": {"repository": "synthetic", "branch": "main", "commit": "a" * 40},
            "builds": {},
            "datasets": {},
            "suites": {},
            "comparisons": {},
            "summary": {
                "overall": "COMPLETE",
                "matrix_status": "PASS",
                "suites": {},
                "builds": {},
                "counts": {"pass": 0, "fail": 0, "blocked": 0, "not_run": 0, "not_applicable": 0},
                "coverage_complete": True,
                "tested_platforms": [],
            },
            "limitations": [],
            "reports": {},
        }
        paths = reporting.write_matrix_reports(
            document,
            config,
            run_id="synthetic",
            suites=["synthetic"],
            raw_artifacts=[
                {"name": "raw.txt", "data": b"synthetic-sensitive-value", "content_type": "text/plain"}
            ],
        )
        sanitized_text = "\n".join(
            Path(path).read_text(encoding="utf-8") for path in paths["sanitized"]
        )
        raw_text = ""
        if paths["raw"]:
            raw_text = (Path(paths["raw"]) / "raw.txt").read_text(encoding="utf-8")
        reporting_ok = (
            "synthetic-sensitive-value" not in sanitized_text
            and "synthetic-sensitive-value" in raw_text
        )
        baseline_cases.append(
            {
                "id": "sanitized-unsanitized-reporting",
                "correct": reporting_ok,
                "actual": {
                    "sanitized_reports": [Path(path).name for path in paths["sanitized"]],
                    "raw_report": "raw-export-directory",
                },
                "expected": {"sanitized_omits_value": True, "raw_contains_value": True},
            }
        )

    all_cases = results + baseline_cases
    correct = sum(item["correct"] for item in all_cases)
    total = len(all_cases)
    document = {
        "report_type": "scanner-harness/synthetic-scoring-validation",
        "dataset_id": DATASET_ID,
        "dataset_version": DATASET_VERSION,
        "cases": all_cases,
        "summary": {
            "cases": total,
            "correct": correct,
            "incorrect": total - correct,
            "scoring_accuracy_percent": round(100.0 * correct / total, 2) if total else 0.0,
            "unexpected_classifications": [item["id"] for item in all_cases if not item["correct"]],
        },
    }
    return document


def markdown(document: dict) -> str:
    lines = [
        "# Synthetic Scoring-Engine Validation",
        "",
        f"> Dataset: `{document['dataset_id']}` / `{document['dataset_version']}`",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Synthetic test cases | {document['summary']['cases']} |",
        f"| Correct outcomes | {document['summary']['correct']} |",
        f"| Incorrect outcomes | {document['summary']['incorrect']} |",
        f"| Scoring accuracy | **{document['summary']['scoring_accuracy_percent']}%** |",
        f"| Unexpected classifications | {len(document['summary']['unexpected_classifications'])} |",
        f"| Unresolved discrepancies | {document['summary']['incorrect']} |",
        "",
        "## Cases",
        "",
        "| Case | Expected | Actual | Correct |",
        "| --- | --- | --- | --- |",
    ]
    for case in document["cases"]:
        expected = case.get("expected", {})
        actual = case.get("actual", {})
        lines.append(
            f"| {case['id']} | `{expected.get('scoring_status', expected)}` | "
            f"`{actual.get('scoring_status', actual)}` | {case['correct']} |"
        )
    lines.extend(
        [
            "",
            "## Independence",
            "",
            "- Findings are emitted by the synthetic adapter through the normalized contract.",
            "- The expected answers are static values in the validation module, not values computed by the scorer.",
            "- The synthetic adapter imports no Gitleaks parser, rule, executable, or result model.",
            "",
            "A passing result requires exact expected-versus-actual agreement; the process exit code alone is not evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def write(path: Path | str, document: dict | None = None) -> Path:
    document = document or run()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return path


def write_reports(json_path: Path | str, markdown_path: Path | str | None = None) -> tuple[Path, Path | None]:
    document = run()
    json_path = write(json_path, document)
    if markdown_path is None:
        return json_path, None
    markdown_path = Path(markdown_path)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    with markdown_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(markdown(document))
    return json_path, markdown_path
