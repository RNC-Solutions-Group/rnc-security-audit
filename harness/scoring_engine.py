"""Scanner-independent scoring engine.

The engine consumes the normalized finding contract and a versioned truth
manifest. It has no imports from scanner adapters, scanner parsers, or the
legacy execution layer.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .contracts import (
    AMBIGUOUS_MATCH,
    BLOCKED,
    DUPLICATE,
    EXECUTION_ERROR,
    EXPECTED_DETECTION,
    FALSE_POSITIVE,
    REVIEWED_NEGATIVE,
    INFORMATIVE_REFERENCE,
    INFORMATIVE_MATCH,
    UNMATCHED_PENDING_REVIEW,
    UNVERIFIED_EVIDENCE,
    FindingEvaluation,
    MISSED_EXPECTATION,
    NormalizedFinding,
    PARTIAL_MATCH,
    ScoringPolicy,
    ScoringResult,
    SKIPPED,
    TruthItem,
    TruthManifest,
    UNEXPECTED_FINDING,
    UNMAPPED,
    NOT_APPLICABLE,
)


def _normalized_path(value: str) -> str:
    normalized = str(value).replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _resolve_path(value: str, truth_paths: dict[str, str]) -> str:
    normalized = _normalized_path(value)
    if normalized.lower() in truth_paths:
        return truth_paths[normalized.lower()]
    matches = [
        original
        for original in truth_paths.values()
        if normalized.lower().endswith("/" + original.lower())
    ]
    if len(matches) == 1:
        return matches[0]
    return normalized


def _item_matches_location(item: TruthItem, finding: NormalizedFinding, policy: ScoringPolicy) -> bool:
    """Location/commit eligibility before checking the extracted value."""
    if item.expected_rule_id and finding.rule_id != item.expected_rule_id:
        return False
    if item.commit and finding.commit != item.commit:
        return False
    if item.matching_policy == "file":
        return True
    if item.line_start is None:
        return not policy.require_line
    if finding.line is None:
        return False
    end = item.line_end if item.line_end is not None else item.line_start
    if item.line_start <= finding.line <= end:
        return True
    if policy.line_tolerance > 0:
        distance = min(abs(finding.line - item.line_start), abs(finding.line - end))
        return distance <= policy.line_tolerance
    return False


def _item_matches_line(item: TruthItem, finding: NormalizedFinding, policy: ScoringPolicy) -> bool:
    if not _item_matches_location(item, finding, policy):
        return False
    fingerprints = item.metadata.get("value_fingerprints") if item.metadata else None
    if fingerprints:
        # A location plus a missing/contrary value fingerprint is never a
        # verified match.  It stays available as an unverified review item.
        if not finding.secret_sha256:
            return False
        return finding.secret_sha256 in fingerprints
    if (item.metadata or {}).get("requires_value", False):
        return False
    # No value oracle exists for this truth item.  Location-only credit is an
    # explicit policy choice, never an implicit fallback.
    return policy.allow_line_only

def _line_distance(item: TruthItem, finding: NormalizedFinding) -> int | None:
    if item.line_start is None or finding.line is None:
        return None
    end = item.line_end if item.line_end is not None else item.line_start
    if item.line_start <= finding.line <= end:
        return 0
    return min(abs(finding.line - item.line_start), abs(finding.line - end))


def _finding_dict(finding: NormalizedFinding) -> dict:
    return finding.safe_dict()


def _item_dict(item: TruthItem) -> dict:
    return item.safe_dict()


def score_findings(
    findings: list[NormalizedFinding] | tuple[NormalizedFinding, ...],
    truth: TruthManifest,
    *,
    execution_status: str = "PASS",
    policy: ScoringPolicy | None = None,
    warnings: tuple[str, ...] = (),
) -> ScoringResult:
    policy = policy or ScoringPolicy(
        policy_id=str(truth.scoring_policy.get("id", "line-range-v1")),
        policy_version=str(truth.scoring_policy.get("version", "1")),
        negative_oracle=bool(truth.scoring_policy.get("negative_oracle", False)),
        allow_line_only=bool(truth.scoring_policy.get("allow_line_only", False)),
    )
    base = {
        "manifest_id": truth.manifest_id,
        "manifest_version": truth.manifest_version,
        "dataset_id": truth.dataset_id,
        "dataset_version": truth.dataset_version,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
    }
    if truth.integrity.get("status", "PASS") != "PASS":
        reason = truth.integrity.get("reason", "truth manifest integrity is not verified")
        return ScoringResult(
            scoring_status="NOT_READY",
            execution_status=execution_status,
            metrics={"expected_count": len(truth.items), "reason": reason},
            evaluations=(),
            exceptions=(
                FindingEvaluation(
                    classification=BLOCKED,
                    reason=reason,
                ),
            ),
            warnings=tuple(warnings) + (reason,),
            **base,
        )
    if execution_status != "PASS":
        classification = EXECUTION_ERROR if execution_status == "ERROR" else BLOCKED
        return ScoringResult(
            scoring_status=classification,
            execution_status=execution_status,
            metrics={
                "expected_count": sum(
                    item.classification == EXPECTED_DETECTION for item in truth.items
                ),
                "execution_error": True,
            },
            evaluations=(),
            exceptions=(
                FindingEvaluation(
                    classification=classification,
                    reason=f"execution status was {execution_status}",
                ),
            ),
            warnings=tuple(warnings),
            **base,
        )

    truth_paths: dict[str, str] = {}
    for item in truth.items:
        truth_paths[item.path.lower()] = item.path
    by_path: dict[str, list[TruthItem]] = {}
    for item in truth.items:
        by_path.setdefault(item.path, []).append(item)

    claimed: set[str] = set()
    evaluations: list[FindingEvaluation] = []
    observed: list[dict] = []

    for index, finding in enumerate(findings):
        path = _resolve_path(finding.file, truth_paths)
        observed_dict = _finding_dict(finding) | {"index": index}
        observed.append(observed_dict)
        if not path.strip() or path == ".":
            evaluations.append(
                FindingEvaluation(
                    classification=UNMAPPED,
                    observed=observed_dict,
                    reason="finding has no usable file identity; mandatory source review",
                    review_status="UNMATCHED_PENDING_REVIEW",
                )
            )
            continue
        item_paths = by_path.get(path, [])
        location_candidates = [
            item
            for item in item_paths
            if item.classification == EXPECTED_DETECTION
            and _item_matches_location(item, finding, policy)
        ]
        if len(location_candidates) > 1:
            evaluations.append(
                FindingEvaluation(
                    classification=AMBIGUOUS_MATCH,
                    path=path,
                    line=finding.line,
                    observed=observed_dict,
                    reason=f"finding location matches {len(location_candidates)} expected items",
                    review_status="UNMATCHED_PENDING_REVIEW",
                )
            )
            continue
        candidates = [
            item
            for item in location_candidates
            if _item_matches_line(item, finding, policy)
        ]
        if not item_paths:
            evaluations.append(
                FindingEvaluation(
                    classification=UNMATCHED_PENDING_REVIEW,
                    path=path,
                    line=finding.line,
                    observed=observed_dict,
                    reason="path absent from source oracle; mandatory investigation, not verified false positive",
                    review_status="UNMATCHED_PENDING_REVIEW",
                )
            )
            continue
        if not candidates:
            # Explicit negative/informative references are diagnostic, not primary TP.
            # A line-only coincidence can never prove that a reported value is benign.
            references = [
                item for item in item_paths
                if item.classification in (REVIEWED_NEGATIVE, INFORMATIVE_REFERENCE)
                and _item_matches_line(item, finding, policy)
            ]
            if len(references) == 1:
                reference = references[0]
                fingerprints = (reference.metadata or {}).get("value_fingerprints")
                verified = bool(
                    (reference.metadata or {}).get("source_verified")
                    and fingerprints
                    and finding.secret_sha256 in fingerprints
                )
                if verified:
                    kind = FALSE_POSITIVE if reference.classification == REVIEWED_NEGATIVE else INFORMATIVE_MATCH
                    state = "VERIFIED_FALSE_POSITIVE" if kind == FALSE_POSITIVE else "INFORMATIVE_MATCH"
                else:
                    kind, state = UNVERIFIED_EVIDENCE, "UNVERIFIED_EVIDENCE"
                evaluations.append(
                    FindingEvaluation(
                        classification=kind,
                        expected_id=reference.finding_id,
                        path=path,
                        line=finding.line,
                        observed=observed_dict,
                        expected=_item_dict(reference),
                        reason=(
                            "source-verified non-secret value" if kind == FALSE_POSITIVE
                            else "source-verified informative value" if kind == INFORMATIVE_MATCH
                            else "negative/informative source reference lacks verified matching evidence"
                        ),
                        identity_confidence="value" if verified else "unverified",
                        review_status=state,
                    )
                )
                continue
            if len(references) > 1:
                evaluations.append(
                    FindingEvaluation(
                        classification=AMBIGUOUS_MATCH,
                        path=path,
                        line=finding.line,
                        observed=observed_dict,
                        reason="finding maps to multiple reviewed non-secret/informative references",
                        review_status="UNMATCHED_PENDING_REVIEW",
                    )
                )
                continue
            unresolved = [
                item for item in item_paths
                if item.classification == EXPECTED_DETECTION
                and _item_matches_location(item, finding, policy)
            ]
            if unresolved:
                evaluations.append(
                    FindingEvaluation(
                        classification=UNVERIFIED_EVIDENCE,
                        expected_id=unresolved[0].finding_id if len(unresolved) == 1 else None,
                        path=path,
                        line=finding.line,
                        observed=observed_dict,
                        expected=_item_dict(unresolved[0]) if len(unresolved) == 1 else None,
                        reason="correct location but extracted value is missing or conflicts with expected value; mandatory investigation",
                        identity_confidence="unverified",
                        review_status="UNVERIFIED_EVIDENCE",
                    )
                )
                continue
            nearest = min(
                (
                    (distance, item)
                    for item in item_paths
                    if item.classification == EXPECTED_DETECTION
                    for distance in [_line_distance(item, finding)]
                    if distance is not None
                ),
                key=lambda pair: pair[0],
                default=None,
            )
            if (
                policy.allow_partial
                and nearest is not None
                and nearest[0] <= policy.partial_line_tolerance
            ):
                classification = PARTIAL_MATCH
                expected_item = nearest[1]
                reason = "finding location is near, but outside, the expected range"
            else:
                classification = UNMATCHED_PENDING_REVIEW
                expected_item = None
                reason = "finding location does not match an expected source line; mandatory investigation"
            evaluations.append(
                FindingEvaluation(
                    classification=classification,
                    expected_id=expected_item.finding_id if expected_item else None,
                    path=path,
                    line=finding.line,
                    observed=observed_dict,
                    expected=_item_dict(expected_item) if expected_item else None,
                    reason=reason,
                    review_status="UNMATCHED_PENDING_REVIEW",
                )
            )
            continue
        if len(candidates) > 1:
            evaluations.append(
                FindingEvaluation(
                    classification=AMBIGUOUS_MATCH,
                    path=path,
                    line=finding.line,
                    observed=observed_dict,
                    reason=f"finding matches {len(candidates)} expected items",
                    review_status="UNMATCHED_PENDING_REVIEW",
                )
            )
            continue
        item = candidates[0]
        if item.finding_id in claimed:
            evaluations.append(
                FindingEvaluation(
                    classification=DUPLICATE,
                    expected_id=item.finding_id,
                    path=path,
                    line=finding.line,
                    observed=observed_dict,
                    expected=_item_dict(item),
                    reason="expected item was already matched",
                )
            )
            continue
        claimed.add(item.finding_id)
        value_verified = bool(
            item.metadata.get("value_fingerprints")
            and finding.secret_sha256 in item.metadata["value_fingerprints"]
        )
        evaluations.append(
            FindingEvaluation(
                classification=EXPECTED_DETECTION,
                expected_id=item.finding_id,
                path=path,
                line=finding.line,
                observed=observed_dict,
                expected=_item_dict(item),
                reason="file, line, and value fingerprint match"
                if value_verified
                else "file and line match under the explicit line-only truth policy",
                identity_confidence="value" if value_verified else "line",
                review_status="VERIFIED" if value_verified else "ACCEPTED_LINE_ONLY",
            )
        )

    for item in truth.items:
        if item.classification != EXPECTED_DETECTION:
            evaluations.append(
                FindingEvaluation(
                    classification=item.classification,
                    expected_id=item.finding_id,
                    path=item.path,
                    line=item.line_start,
                    expected=_item_dict(item),
                    reason=f"truth item is {item.classification}",
                )
            )
        elif item.finding_id not in claimed:
            evaluations.append(
                FindingEvaluation(
                    classification=MISSED_EXPECTATION,
                    expected_id=item.finding_id,
                    path=item.path,
                    line=item.line_start,
                    expected=_item_dict(item),
                    reason="no observed finding matched this expected item",
                )
            )

    classifications = Counter(item.classification for item in evaluations)
    expected_items = [
        item for item in truth.items if item.classification == EXPECTED_DETECTION
    ]
    expected_count = len(expected_items)
    matched = classifications[EXPECTED_DETECTION]
    value_verified = sum(
        item.classification == EXPECTED_DETECTION
        and item.identity_confidence == "value"
        for item in evaluations
    )
    line_only = sum(
        item.classification == EXPECTED_DETECTION
        and item.identity_confidence == "line"
        for item in evaluations
    )
    pending_review = sum(
        e.observed is not None
        and (
            e.review_status in ("UNMATCHED_PENDING_REVIEW", "UNVERIFIED_EVIDENCE")
            or e.classification
            in (
                UNEXPECTED_FINDING,
                UNMAPPED,
                AMBIGUOUS_MATCH,
                PARTIAL_MATCH,
            )
        )
        for e in evaluations
    )
    informative_observed = classifications[INFORMATIVE_MATCH]
    accounted_observed = sum(e.observed is not None for e in evaluations)
    precision = None
    recall = None
    f1 = None
    if expected_count:
        recall = round(100.0 * matched / expected_count, 2)
    # Precision/F1 are meaningful only when no alerts are awaiting investigation
    # and an explicit reviewed negative oracle was selected. Informative-alert
    # denominator treatment is intentionally not inferred.
    precision_ready = bool(policy.negative_oracle and pending_review == 0 and informative_observed == 0)
    if precision_ready:
        false_positives = classifications[FALSE_POSITIVE]
        denominator = matched + false_positives
        if denominator:
            precision = round(100.0 * matched / denominator, 2)
        if precision is not None and recall is not None:
            f1 = (
                round(2 * precision * recall / (precision + recall), 2)
                if precision + recall else 0.0
            )
    category_metrics: dict[str, dict] = {}
    for item in expected_items:
        bucket = category_metrics.setdefault(
            item.category or "unspecified", {"expected": 0, "matched": 0, "missed": 0}
        )
        bucket["expected"] += 1
        if item.finding_id in claimed:
            bucket["matched"] += 1
        else:
            bucket["missed"] += 1
    metrics = {
        "expected_count": expected_count,
        "matched_count": matched,
        "value_verified_count": value_verified,
        "line_only_count": line_only,
        "missed_count": classifications[MISSED_EXPECTATION],
        "unexpected_count": classifications[UNEXPECTED_FINDING] + classifications[UNMATCHED_PENDING_REVIEW],
        "unmatched_pending_review_count": classifications[UNMATCHED_PENDING_REVIEW] + classifications[UNMAPPED],
        "unverified_evidence_count": classifications[UNVERIFIED_EVIDENCE],
        "informative_match_count": classifications[INFORMATIVE_MATCH],
        "verified_false_positive_count": classifications[FALSE_POSITIVE],
        "finding_review_pending_count": pending_review,
        "accounted_observed_count": accounted_observed,
        "finding_accounting_reconciled": accounted_observed == len(findings),
        "false_positive_count": classifications[FALSE_POSITIVE],
        "partial_count": classifications[PARTIAL_MATCH],
        "duplicate_count": classifications[DUPLICATE],
        "ambiguous_count": classifications[AMBIGUOUS_MATCH],
        "unmapped_count": classifications[UNMAPPED],
        "skipped_count": classifications[SKIPPED],
        "not_applicable_count": classifications[NOT_APPLICABLE],
        "blocked_count": classifications[BLOCKED],
        "execution_error_count": classifications[EXECUTION_ERROR],
        "observed_count": len(findings),
        "detection_recall_percent": recall,
        "precision_percent": precision,
        "f1_percent": f1,
        "category_metrics": category_metrics,
        "category_conflict_items": sum(item.category_conflict for item in truth.items),
        "negative_oracle": policy.negative_oracle,
        "precision_certification_status": (
            "ELIGIBLE" if precision_ready else
            "BLOCKED_PENDING_REVIEW" if policy.negative_oracle else "NOT_REQUESTED"
        ),
        "execution_status": "PASS",
    }
    exception_classes = {
        MISSED_EXPECTATION,
        UNEXPECTED_FINDING,
        UNMATCHED_PENDING_REVIEW,
        UNVERIFIED_EVIDENCE,
        FALSE_POSITIVE,
        INFORMATIVE_MATCH,
        PARTIAL_MATCH,
        DUPLICATE,
        AMBIGUOUS_MATCH,
        UNMAPPED,
        SKIPPED,
        NOT_APPLICABLE,
        BLOCKED,
        EXECUTION_ERROR,
    }
    exceptions = tuple(
        item for item in evaluations if item.classification in exception_classes
    )
    category_status = truth.category_reconciliation.get("status")
    warnings_out = list(warnings)
    if category_status == "CONFLICT":
        warnings_out.append(
            "Upstream Leaky Repo risk/informative aggregate categories conflict "
            "with source-line review; detection scoring remains line-based."
        )
    return ScoringResult(
        scoring_status="COMPLETED",
        execution_status="PASS",
        metrics=metrics,
        evaluations=tuple(evaluations),
        exceptions=exceptions,
        warnings=tuple(warnings_out),
        **base,
    )


def score_file(
    findings: list[NormalizedFinding],
    truth_path: Path | str,
    **kwargs,
) -> ScoringResult:
    from .truth import load

    return score_findings(findings, load(truth_path), **kwargs)
