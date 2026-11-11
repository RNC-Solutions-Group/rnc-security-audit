"""Negative controls and byte-accuracy tests for the independent scorer."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.cp3.score import Finding, Truth, score


ROOT = Path(__file__).resolve().parents[2]
AWS_ONE = b"AKIA" + b"Q7Z3K5M2N4P6R8T0"
AWS_TWO = b"AKIA" + b"Q7Z3K5M2N4P6R8T1"
SOURCE = b"first=" + AWS_ONE + b" second=" + AWS_TWO + b"\n"
FIRST_START = SOURCE.index(b"AKIA")
FIRST_END = FIRST_START + 20
SECOND_START = SOURCE.index(b"AKIA", FIRST_START + 1)
SECOND_END = SECOND_START + 20
RULE_MAP = {
    "aws-access-key-id": {
        "family": "aws-credentials",
        "provider": "aws",
        "credential_type": "access-key-id",
        "confidence": "high",
    },
    "google-api-key": {
        "family": "google-cloud-api-key",
        "provider": "google-cloud",
        "credential_type": "api-key",
        "confidence": "high",
    },
}


def truth_item(identifier: str, start: int, end: int, *, rule="aws-access-key-id", family="aws-credentials") -> Truth:
    token = SOURCE[start:end]
    import hashlib

    return Truth(
        path="fixture.env",
        finding_id=identifier,
        expected_rule_id=rule,
        family=family,
        credential_type="access-key-id",
        start_byte=start,
        end_byte=end,
        line_start=1,
        line_end=1,
        secret_sha256=hashlib.sha256(token).hexdigest(),
    )


def finding(identifier: str, start: int, end: int, *, rule="aws-access-key-id", path="fixture.env") -> Finding:
    return Finding(
        path=path,
        line=1,
        rule_id=rule,
        family="unclassified",
        start_byte=start,
        end_byte=end,
        confidence="high",
        finding_id=identifier,
        validation=("FORMAT_VALID",),
    )


def private_document(*, state="COMPLETED", result_code=3, evidence_valid=True, inspected=True, required=True) -> dict:
    return {
        "execution": {
            "state": state,
            "evidence_valid": evidence_valid,
            "ruleset_id": "provider-test",
            "ruleset_digest": "sha256:" + "0" * 64,
            "units": [
                {
                    "unit_id": "u-" + "1" * 64,
                    "locator": "fixture.env",
                    "disposition": "INSPECTED" if inspected else "UNINSPECTED",
                    "required_scope": required,
                }
            ],
        },
        "result": {"result_code": result_code},
    }


class ScorerNegativeControlTests(unittest.TestCase):
    def run_score(self, findings, truths, document=None, source_root=None):
        return score(
            document or private_document(),
            {},
            truths,
            findings,
            RULE_MAP,
            source_root=source_root,
            backend="regex",
            mode="whole",
            platform="test",
        )

    def test_perfect_detection_is_one_to_one(self):
        report = self.run_score(
            [finding("f-1", FIRST_START, FIRST_END)],
            [truth_item("t-1", FIRST_START, FIRST_END)],
        )
        self.assertEqual(report["scoring_status"], "COMPLETED")
        self.assertEqual(report["metrics"]["tp"], 1)
        self.assertEqual(report["metrics"]["fp"], 0)
        self.assertEqual(report["metrics"]["fn"], 0)
        self.assertEqual(report["metrics"]["precision_percent"], 100.0)
        self.assertEqual(report["metrics"]["recall_percent"], 100.0)

    def test_scanner_that_reports_nothing_has_undefined_precision(self):
        report = self.run_score([], [truth_item("t-1", FIRST_START, FIRST_END)])
        self.assertEqual(report["metrics"]["tp"], 0)
        self.assertEqual(report["metrics"]["fn"], 1)
        self.assertIsNone(report["metrics"]["precision_percent"])
        self.assertEqual(report["metrics"]["recall_percent"], 0.0)
        self.assertIsNone(report["metrics"]["f1_percent"])

    def test_scanner_that_reports_every_string_is_penalized(self):
        report = self.run_score(
            [
                finding("f-1", FIRST_START, FIRST_END),
                finding("f-2", 0, 5),
            ],
            [truth_item("t-1", FIRST_START, FIRST_END)],
        )
        self.assertEqual(report["metrics"]["tp"], 1)
        self.assertEqual(report["metrics"]["fp"], 1)
        self.assertEqual(report["metrics"]["precision_percent"], 50.0)
        self.assertEqual(report["metrics"]["recall_percent"], 100.0)

    def test_repeated_finding_is_duplicate_not_a_second_true_positive(self):
        report = self.run_score(
            [
                finding("f-1", FIRST_START, FIRST_END),
                finding("f-2", FIRST_START, FIRST_END),
            ],
            [truth_item("t-1", FIRST_START, FIRST_END)],
        )
        self.assertEqual(report["metrics"]["tp"], 1)
        self.assertEqual(report["metrics"]["duplicates"], 1)
        self.assertEqual(report["metrics"]["precision_percent"], 100.0)

    def test_only_first_occurrence_misses_the_second(self):
        report = self.run_score(
            [finding("f-1", FIRST_START, FIRST_END)],
            [
                truth_item("t-1", FIRST_START, FIRST_END),
                truth_item("t-2", SECOND_START, SECOND_END),
            ],
        )
        self.assertEqual(report["metrics"]["tp"], 1)
        self.assertEqual(report["metrics"]["fn"], 1)
        self.assertEqual(report["metrics"]["recall_percent"], 50.0)

    def test_shifted_offsets_are_not_true_positives(self):
        report = self.run_score(
            [finding("f-1", FIRST_START + 1, FIRST_END)],
            [truth_item("t-1", FIRST_START, FIRST_END)],
        )
        self.assertEqual(report["metrics"]["tp"], 0)
        self.assertEqual(report["metrics"]["misaligned"], 1)
        self.assertEqual(report["metrics"]["fn"], 1)
        self.assertEqual(report["metrics"]["precision_percent"], 0.0)
        self.assertEqual(report["metrics"]["recall_percent"], 0.0)

    def test_incorrect_source_is_unmapped(self):
        report = self.run_score(
            [finding("f-1", FIRST_START, FIRST_END, path="other.env")],
            [truth_item("t-1", FIRST_START, FIRST_END)],
        )
        self.assertEqual(report["metrics"]["unmapped"], 1)
        self.assertEqual(report["metrics"]["tp"], 0)
        self.assertEqual(report["metrics"]["fn"], 1)

    def test_wrong_credential_family_is_not_a_true_positive(self):
        report = self.run_score(
            [finding("f-1", FIRST_START, FIRST_END, rule="google-api-key")],
            [truth_item("t-1", FIRST_START, FIRST_END)],
        )
        self.assertEqual(report["metrics"]["wrong_family"], 1)
        self.assertEqual(report["metrics"]["tp"], 0)
        self.assertEqual(report["metrics"]["fp"], 1)
        self.assertEqual(report["metrics"]["fn"], 1)

    def test_wrong_rule_same_family_is_not_strict_tp(self):
        report = self.run_score(
            [finding("f-1", FIRST_START, FIRST_END, rule="google-api-key")],
            [truth_item("t-1", FIRST_START, FIRST_END, family="google-cloud-api-key")],
        )
        self.assertEqual(report["metrics"]["wrong_rule"], 1)
        self.assertEqual(report["metrics"]["tp"], 0)
        self.assertEqual(report["metrics"]["fp"], 1)

    def test_same_line_distinct_byte_ranges_are_both_true_positives(self):
        report = self.run_score(
            [
                finding("f-1", FIRST_START, FIRST_END),
                finding("f-2", SECOND_START, SECOND_END),
            ],
            [
                truth_item("t-1", FIRST_START, FIRST_END),
                truth_item("t-2", SECOND_START, SECOND_END),
            ],
        )
        self.assertEqual(report["metrics"]["tp"], 2)
        self.assertEqual(report["metrics"]["ambiguous"], 0)
        self.assertEqual(report["metrics"]["recall_percent"], 100.0)

    def test_ambiguous_same_span_truth_is_separate_from_tp(self):
        report = self.run_score(
            [finding("f-1", FIRST_START, FIRST_END)],
            [
                truth_item("t-1", FIRST_START, FIRST_END),
                truth_item("t-2", FIRST_START, FIRST_END),
            ],
        )
        self.assertEqual(report["metrics"]["ambiguous"], 1)
        self.assertEqual(report["metrics"]["tp"], 0)
        self.assertEqual(report["metrics"]["fn"], 0)

    def test_missing_required_inspection_blocks_accuracy_claim(self):
        report = self.run_score(
            [],
            [truth_item("t-1", FIRST_START, FIRST_END)],
            private_document(inspected=False),
        )
        self.assertEqual(report["scoring_status"], "INCOMPLETE")
        self.assertIsNone(report["metrics"]["precision_percent"])

    def test_failed_execution_is_never_scored_as_clean(self):
        report = self.run_score(
            [],
            [truth_item("t-1", FIRST_START, FIRST_END)],
            private_document(state="ERROR", result_code=5, evidence_valid=False),
        )
        self.assertEqual(report["scoring_status"], "FAILED")

    def test_truth_integrity_is_checked_against_source_bytes(self):
        import tempfile

        from tools.cp3.materialize import materialize
        from tools.cp3.score import load_truth

        truth_path = ROOT / "tests/cp3/provider-truth-tier2.json"
        with tempfile.TemporaryDirectory(prefix="rnc-cp3-score-") as temp:
            source_root = materialize("tier2", Path(temp))
            document, items, contents = load_truth(truth_path, source_root)
            self.assertEqual(document["counts"]["expected_items"], len(items))
            self.assertEqual(len(contents), document["counts"]["files"])
            self.assertTrue(all(item.secret_sha256 for item in items))

    def test_all_checks_run_without_raw_secret_material(self):
        report = self.run_score(
            [finding("f-1", FIRST_START, FIRST_END)],
            [truth_item("t-1", FIRST_START, FIRST_END)],
        )
        serialized = str(report)
        self.assertNotIn(AWS_ONE.decode("ascii"), serialized)
        self.assertNotIn(AWS_TWO.decode("ascii"), serialized)


if __name__ == "__main__":
    unittest.main()
