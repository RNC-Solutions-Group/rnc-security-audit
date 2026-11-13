"""Normalized scoring-contract and engine tests."""

from __future__ import annotations

import unittest

from harness import scoring_engine
from harness.contracts import (
    DUPLICATE,
    EXPECTED_DETECTION,
    MISSED_EXPECTATION,
    NormalizedFinding,
    ScoringPolicy,
    TruthItem,
    TruthManifest,
    UNEXPECTED_FINDING,
    UNMAPPED,
    PARTIAL_MATCH,
)


def truth(items: tuple[TruthItem, ...]) -> TruthManifest:
    return TruthManifest(
        manifest_id="test",
        manifest_version="1",
        dataset_id="test",
        dataset_version="1",
        items=items,
        scoring_policy={
            "id": "test-line",
            "version": "1",
            "allow_line_only": True,
        },
        integrity={"status": "PASS"},
    )


class ScoringEngineTests(unittest.TestCase):
    def test_expected_and_missed(self):
        manifest = truth(
            (
                TruthItem("a", "test", "1", "a.txt", line_start=1, line_end=1),
                TruthItem("b", "test", "1", "a.txt", line_start=2, line_end=2),
            )
        )
        result = scoring_engine.score_findings(
            [NormalizedFinding(file="scan/a.txt", line=1, rule_id="r")],
            manifest,
            policy=ScoringPolicy(allow_line_only=True),
        )
        self.assertEqual(result.metrics["matched_count"], 1)
        self.assertEqual(result.metrics["missed_count"], 1)
        self.assertEqual(result.metrics["detection_recall_percent"], 50.0)
        classifications = [entry.classification for entry in result.evaluations]
        self.assertIn(EXPECTED_DETECTION, classifications)
        self.assertIn(MISSED_EXPECTATION, classifications)

    def test_duplicate_is_not_double_credited(self):
        manifest = truth((TruthItem("a", "test", "1", "a.txt", line_start=1, line_end=1),))
        result = scoring_engine.score_findings(
            [
                NormalizedFinding(file="a.txt", line=1, rule_id="r"),
                NormalizedFinding(file="a.txt", line=1, rule_id="r"),
            ],
            manifest,
        )
        self.assertEqual(result.metrics["matched_count"], 1)
        self.assertEqual(result.metrics["duplicate_count"], 1)

    def test_unexpected_and_unmapped(self):
        manifest = truth((TruthItem("a", "test", "1", "a.txt", line_start=1, line_end=1),))
        result = scoring_engine.score_findings(
            [
                NormalizedFinding(file="other.txt", line=1, rule_id="r"),
                NormalizedFinding(file="", line=1, rule_id="r"),
            ],
            manifest,
            policy=ScoringPolicy(negative_oracle=False),
        )
        self.assertEqual(result.metrics["unexpected_count"], 1)
        self.assertEqual(result.metrics["unmapped_count"], 1)
        self.assertEqual(result.metrics["matched_count"], 0)

    def test_partial_requires_policy(self):
        manifest = truth((TruthItem("a", "test", "1", "a.txt", line_start=10, line_end=10),))
        findings = [NormalizedFinding(file="a.txt", line=11, rule_id="r")]
        without = scoring_engine.score_findings(findings, manifest)
        self.assertEqual(without.metrics["partial_count"], 0)
        self.assertEqual(without.metrics["unexpected_count"], 1)
        with_partial = scoring_engine.score_findings(
            findings,
            manifest,
            policy=ScoringPolicy(allow_partial=True, partial_line_tolerance=1),
        )
        self.assertEqual(with_partial.metrics["partial_count"], 1)
        self.assertEqual(with_partial.metrics["matched_count"], 0)

    def test_unknown_is_not_automatically_false_positive(self):
        manifest = truth((TruthItem("a", "test", "1", "a.txt", line_start=1),))
        result = scoring_engine.score_findings(
            [NormalizedFinding(file="unlisted.txt", line=10, rule_id="generic")],
            manifest,
            policy=ScoringPolicy(negative_oracle=True),
        )
        observed = [e for e in result.evaluations if e.observed is not None]
        self.assertEqual(observed[0].classification, "UNMATCHED_PENDING_REVIEW")
        self.assertEqual(observed[0].review_status, "UNMATCHED_PENDING_REVIEW")
        self.assertEqual(result.metrics["false_positive_count"], 0)
        self.assertEqual(result.metrics["unmatched_pending_review_count"], 1)
        self.assertIsNone(result.metrics["precision_percent"])

    def test_unverified_value_does_not_receive_tp(self):
        item = TruthItem(
            "expected", "test", "1", "secret.env", line_start=2,
            metadata={"value_fingerprints": ["a" * 64], "requires_value": True},
        )
        result = scoring_engine.score_findings(
            [NormalizedFinding(file="secret.env", line=2, rule_id="generic")],
            truth((item,)),
        )
        self.assertEqual(result.metrics["matched_count"], 0)
        self.assertEqual(result.metrics["unverified_evidence_count"], 1)
        self.assertEqual(result.metrics["missed_count"], 1)
        self.assertEqual(
            [e for e in result.evaluations if e.observed is not None][0].classification,
            "UNVERIFIED_EVIDENCE",
        )

    def test_verified_negative_requires_identity_and_review(self):
        reference = TruthItem(
            "negative", "test", "1", "config.env",
            classification="REVIEWED_NEGATIVE", line_start=3,
            metadata={"value_fingerprints": ["b" * 64], "requires_value": True, "source_verified": True},
        )
        reported = NormalizedFinding(
            file="config.env", line=3, rule_id="generic", secret_sha256="b" * 64,
        )
        result = scoring_engine.score_findings([reported], truth((reference,)),
                                               policy=ScoringPolicy(negative_oracle=True))
        self.assertEqual(result.metrics["verified_false_positive_count"], 1)
        self.assertEqual(result.metrics["finding_review_pending_count"], 0)
        self.assertEqual(result.metrics["false_positive_count"], 1)
        self.assertEqual(result.metrics["precision_certification_status"], "ELIGIBLE")

    def test_informative_reference_has_no_primary_tp(self):
        reference = TruthItem(
            "info", "test", "1", "config.env",
            classification="INFORMATIVE_REFERENCE", line_start=4,
            metadata={"value_fingerprints": ["c" * 64], "source_verified": True},
        )
        result = scoring_engine.score_findings(
            [NormalizedFinding(file="config.env", line=4, rule_id="r",
                               secret_sha256="c" * 64)],
            truth((reference,)),
        )
        self.assertEqual(result.metrics["informative_match_count"], 1)
        self.assertEqual(result.metrics["matched_count"], 0)

    def test_line_only_is_not_automatic_without_policy(self):
        manifest = truth((TruthItem("a", "test", "1", "a.txt", line_start=1, line_end=1),))
        result = scoring_engine.score_findings(
            [NormalizedFinding(file="a.txt", line=1, rule_id="r")],
            manifest,
            policy=ScoringPolicy(allow_line_only=False),
        )
        self.assertEqual(result.metrics["matched_count"], 0)
        self.assertEqual(result.metrics["unverified_evidence_count"], 1)
        observed = [e for e in result.evaluations if e.observed is not None][0]
        self.assertEqual(observed.classification, "UNVERIFIED_EVIDENCE")

    def test_line_only_requires_explicit_policy(self):
        manifest = truth((TruthItem("a", "test", "1", "a.txt", line_start=1, line_end=1),))
        result = scoring_engine.score_findings(
            [NormalizedFinding(file="a.txt", line=1, rule_id="r")],
            manifest,
            policy=ScoringPolicy(allow_line_only=True),
        )
        self.assertEqual(result.metrics["matched_count"], 1)
        self.assertEqual(result.metrics["line_only_count"], 1)
        observed = [e for e in result.evaluations if e.observed is not None][0]
        self.assertEqual(observed.review_status, "ACCEPTED_LINE_ONLY")

    def test_every_observed_finding_is_accounted_for(self):
        manifest = truth((TruthItem("a", "test", "1", "a.txt", line_start=1),))
        findings = [
            NormalizedFinding(file=f"unknown-{index}.txt", line=index, rule_id="r")
            for index in range(10)
        ]
        result = scoring_engine.score_findings(findings, manifest)
        self.assertEqual(result.metrics["observed_count"], 10)
        self.assertEqual(result.metrics["accounted_observed_count"], 10)
        self.assertTrue(result.metrics["finding_accounting_reconciled"])
        self.assertEqual(
            sum(e.observed is not None for e in result.evaluations),
            10,
        )

    def test_safe_metadata_drops_transient_secret_keys(self):
        finding = NormalizedFinding(
            file="a.txt",
            line=1,
            rule_id="r",
            metadata={
                "description": "safe",
                "secret": "do-not-emit",
                "nested": {"raw": "do-not-emit", "fingerprint": "abc"},
            },
            secret_text="do-not-emit",
        )
        projection = finding.safe_dict()
        self.assertNotIn("do-not-emit", repr(projection))
        self.assertEqual(projection["metadata"]["nested"]["fingerprint"], "abc")


        manifest = TruthManifest(
            manifest_id="bad",
            manifest_version="1",
            dataset_id="test",
            dataset_version="1",
            items=(),
            integrity={"status": "FAIL", "reason": "tampered"},
        )
        result = scoring_engine.score_findings([], manifest)
        self.assertEqual(result.scoring_status, "NOT_READY")
        self.assertEqual(result.metrics["reason"], "tampered")

    def test_execution_error_is_not_a_detection_score(self):
        manifest = truth((TruthItem("a", "test", "1", "a.txt", line_start=1, line_end=1),))
        result = scoring_engine.score_findings([], manifest, execution_status="ERROR")
        self.assertEqual(result.scoring_status, "EXECUTION_ERROR")
        self.assertEqual(result.metrics["execution_error"], True)


if __name__ == "__main__":
    unittest.main()
