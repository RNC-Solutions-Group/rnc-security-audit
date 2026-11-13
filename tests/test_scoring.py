"""Deterministic scoring, control, and run-status tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.control import CONTROL_FILE, control_result, secret_values
from harness.model import Finding
from harness.scoring import (
    ScanTarget,
    assess_findings,
    assess_run,
    materialize,
    overall_status,
    score_negative,
    score_positive,
)
from tests.support import fake_invocation, section

NEG = (
    section(
        "ordinary-log",
        "GET / 200\nuser=alice\n",
        personal=("alice",),
        filename="001-ordinary-log.log",
        lines=2,
    ),
    section("build-output", "BUILD OK\nnone\n", filename="002-build-output.log", lines=2),
)

POS = (
    section(
        "core-env",
        "unit-secret-alpha\nunit-secret-beta\n",
        secrets=(("alpha", "unit-secret-alpha"), ("beta", "unit-secret-beta")),
        filename="001-core-env.log",
        lines=2,
    ),
    section(
        "hard-prose",
        "correct horse\n",
        secrets=(("hard-password", "correct horse"),),
        hard=True,
        filename="002-hard-prose.log",
        lines=1,
    ),
)


def finding(file: str, line: int | None, secret: str, rule: str = "test.rule") -> Finding:
    return Finding(file=file, line=line, rule_id=rule, secret=secret, match=secret)


class NegativeScoringTests(unittest.TestCase):
    def test_clean_result(self):
        results = score_negative(NEG, [])
        self.assertTrue(results["clean"])
        self.assertEqual(results["false_positives"], 0)
        self.assertEqual(results["expected_secrets"], 0)
        self.assertIsNone(results["true_negatives"])

    def test_false_positive_and_personal_data_are_separated(self):
        findings = [
            finding("001-ordinary-log.log", 1, "GET / 200"),
            finding("001-ordinary-log.log", 2, "alice"),
            finding("002-build-output.log", 1, "BUILD OK"),
        ]
        results = score_negative(NEG, findings)
        self.assertEqual(results["false_positives"], 2)
        self.assertEqual(results["personal_data_matches"], 1)
        self.assertEqual(results["sections_tripped"], 2)
        self.assertEqual(len(results["examples"]), 2)
        self.assertNotIn("GET / 200", json.dumps(results))

    def test_duplicate_findings_are_counted_but_not_hidden(self):
        findings = [
            finding("001-ordinary-log.log", 1, "noise"),
            finding("001-ordinary-log.log", 1, "noise"),
        ]
        results = score_negative(NEG, findings)
        self.assertEqual(results["false_positives"], 2)
        self.assertEqual(results["duplicates"], 1)


class PositiveScoringTests(unittest.TestCase):
    def test_recall_misses_duplicates_and_unexpected_findings(self):
        findings = [
            finding("001-core-env.log", 1, "unit-secret-alpha"),
            finding("001-core-env.log", 2, "unit-secret-beta"),
            finding("001-core-env.log", 2, "unit-secret-beta"),
            finding("002-hard-prose.log", 1, "unrelated noise"),
        ]
        results = score_positive(POS, findings)
        self.assertEqual(results["expected_secrets"], 3)
        self.assertEqual(results["true_positives"], 2)
        self.assertEqual(results["false_negatives"], 1)
        self.assertEqual(results["core_true_positives"], 2)
        self.assertEqual(results["hard_true_positives"], 0)
        self.assertEqual(results["core_recall_percent"], 100.0)
        self.assertEqual(results["hard_recall_percent"], 0.0)
        self.assertEqual(results["duplicates"], 1)
        self.assertEqual(results["unexpected_findings"], 1)
        self.assertEqual(results["partial_matches"], 0)
        self.assertEqual(results["ambiguous_findings"], 0)
        self.assertEqual(results["match_classification"]["complete"], 2)
        self.assertEqual(results["missed_secrets"][0]["kind"], "hard-password")
        self.assertNotIn("unit-secret-alpha", json.dumps(results))
        self.assertNotIn("correct horse", json.dumps(results))

    def test_partial_line_finding_is_not_a_true_positive(self):
        findings = [finding("001-core-env.log", 1, "TOKEN=unit-secret-alpha")]
        results = score_positive(POS, findings)
        self.assertEqual(results["true_positives"], 0)
        self.assertEqual(results["partial_matches"], 1)
        self.assertEqual(results["false_positives"], 1)
        self.assertEqual(results["missed_secrets"][0]["classification"], "partial")
        self.assertNotIn("unit-secret-alpha", json.dumps(results))

    def test_line_number_alone_never_credits_a_finding(self):
        findings = [finding("001-core-env.log", 1, "")]
        results = score_positive(POS, findings)
        self.assertEqual(results["true_positives"], 0)
        self.assertEqual(results["findings_without_evidence"], 1)
        self.assertEqual(results["false_positives"], 1)

    def test_a_finding_cannot_satisfy_multiple_credentials(self):
        sections = (
            section(
                "overlap",
                "alpha\n",
                secrets=(("first", "alpha"), ("second", " alpha ")),
                filename="001-overlap.log",
                lines=1,
            ),
        )
        results = score_positive(sections, [finding("001-overlap.log", 1, "alpha")])
        self.assertEqual(results["true_positives"], 0)
        self.assertEqual(results["ambiguous_findings"], 1)
        self.assertEqual(results["false_negatives"], 2)

    def test_one_finding_containing_two_credentials_is_not_credited(self):
        sections = (
            section(
                "overlap",
                "alpha beta\n",
                secrets=(("first", "alpha"), ("second", "beta")),
                filename="001-overlap.log",
                lines=1,
            ),
        )
        results = score_positive(sections, [finding("001-overlap.log", 1, "alpha beta")])
        self.assertEqual(results["true_positives"], 0)
        self.assertEqual(results["partial_matches"], 1)
        self.assertEqual(results["partial_match_details"][0]["candidate_kinds"], ["first", "second"])

    def test_supported_normalizations_are_credited(self):
        sections = (
            section(
                "normalized",
                "alpha\n",
                secrets=(("quoted", "alpha"), ("multiline", "line-one\nline-two")),
                filename="001-normalized.log",
                lines=2,
            ),
        )
        findings = [
            finding("001-normalized.log", 1, '"alpha"'),
            finding("001-normalized.log", 2, "line-one\r\nline-two"),
        ]
        results = score_positive(sections, findings)
        self.assertEqual(results["true_positives"], 2)
        self.assertEqual(results["match_classification"]["normalized"], 2)

    def test_a_finding_can_satisfy_a_multiline_secret(self):
        sections = (
            section(
                "wrapped",
                "prefix\nunit-secret-value\n",
                secrets=(("wrapped-token", "unit-secret-value"),),
                filename="001-wrapped.log",
                lines=2,
            ),
        )
        findings = [finding("001-wrapped.log", 2, "unit-secret-value")]
        results = score_positive(sections, findings)
        self.assertEqual(results["true_positives"], 1)


class ControlTests(unittest.TestCase):
    def test_control_finding_is_detected_only_with_expected_credential(self):
        result = control_result([finding(CONTROL_FILE, 6, secret_values()[0])], ("",))
        self.assertTrue(result.reported)
        self.assertTrue(result.file_encountered)
        self.assertEqual(result.findings_on_file, 1)
        self.assertEqual(result.kinds_detected, ("aws-access-key-id",))

    def test_arbitrary_finding_on_control_file_is_not_a_detection(self):
        result = control_result([finding(CONTROL_FILE, 1, "ordinary line")], ("",))
        self.assertFalse(result.reported)
        self.assertTrue(result.file_encountered)
        self.assertEqual(result.findings_on_file, 1)
        self.assertEqual(result.unmatched_findings, 1)

    def test_control_value_echoed_in_raw_output_is_not_a_detection(self):
        result = control_result([], ("output: " + secret_values()[0],))
        self.assertFalse(result.reported)
        self.assertIn("aws-access-key-id", result.kinds_echoed)
        self.assertTrue(any("not a structured detection" in note for note in result.notes))

    def test_full_pem_block_detects_the_private_key_control(self):
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + "c3ludGhldGljLWtleS1ib2R5\n"
            + "-----END RSA PRIVATE KEY-----"
        )
        result = control_result([finding(CONTROL_FILE, 7, block)], ("",))
        self.assertTrue(result.reported)
        self.assertIn("private-key", result.kinds_detected)

    def test_pem_header_alone_is_not_a_control_echo(self):
        result = control_result([], ("-----BEGIN RSA PRIVATE KEY-----",))
        self.assertNotIn("private-key", result.kinds_echoed)

    def test_missing_control_is_not_reported(self):
        result = control_result([finding("001-ordinary-log.log", 1, "noise")], ("noise",))
        self.assertFalse(result.reported)
        self.assertFalse(result.file_encountered)


class CoverageScoringTests(unittest.TestCase):
    def test_verified_coverage_allows_empty_negative_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = ScanTarget(Path(tmp), "negative", {}, True)
            result = assess_findings(
                fake_invocation(b'{"findings": []}'),
                [],
                target,
                (),
                coverage={
                    "applicable": True,
                    "verified": True,
                    "notes": ["all required units inspected"],
                },
            )
            self.assertEqual(result.status, "COMPLETED_COVERAGE_VERIFIED")
            self.assertIsNotNone(result.results)
            self.assertEqual(result.results["false_positives"], 0)
            self.assertTrue(result.coverage["verified"])

    def test_unverified_coverage_blocks_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = ScanTarget(Path(tmp), "negative", {}, True)
            result = assess_findings(
                fake_invocation(b'{"findings": []}'),
                [],
                target,
                (),
                coverage={
                    "applicable": True,
                    "verified": False,
                    "notes": ["one required unit was uninspected"],
                },
            )
            self.assertEqual(result.status, "COVERAGE_UNVERIFIED")
            self.assertIsNone(result.results)

    def test_no_coverage_keeps_existing_control_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = ScanTarget(Path(tmp), "negative", {}, True)
            result = assess_findings(
                fake_invocation(b'{"findings": []}'),
                [],
                target,
                (),
            )
            self.assertEqual(result.status, "NOT_RUN_UNSCORABLE")
            self.assertIsNone(result.results)


class RunStatusTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _target(self):
        return materialize(NEG, self.directory, corpus="negative", include_control=True)

    def _invocation(self, entries: list[dict], **kwargs):
        return fake_invocation(json.dumps(entries).encode("utf-8"), **kwargs)

    def _control_entry(self) -> dict:
        return {
            "File": str(self.directory / CONTROL_FILE),
            "StartLine": 6,
            "RuleID": "stub",
            "Secret": secret_values()[0],
        }

    def test_empty_report_without_control_is_not_run(self):
        target = self._target()
        result = assess_run(self._invocation([]), target, NEG)
        self.assertEqual(result.status, "NOT_RUN_UNSCORABLE")
        self.assertIsNone(result.results)

    def test_control_only_is_a_real_clean_result(self):
        target = self._target()
        result = assess_run(self._invocation([self._control_entry()]), target, NEG)
        self.assertEqual(result.status, "COMPLETED")
        self.assertTrue(result.control.reported)
        self.assertEqual(result.results["false_positives"], 0)

    def test_findings_without_control_produce_a_warning(self):
        target = self._target()
        entry = {
            "File": str(self.directory / "001-ordinary-log.log"),
            "StartLine": 1,
            "RuleID": "stub",
            "Secret": "noise",
        }
        result = assess_run(self._invocation([entry]), target, NEG)
        self.assertEqual(result.status, "COMPLETED_CONTROL_WARNING")
        self.assertEqual(result.results["false_positives"], 1)

    def test_invocation_failure_is_not_scored(self):
        target = self._target()
        result = assess_run(self._invocation([], exit_code=2), target, NEG)
        self.assertEqual(result.status, "INVOCATION_FAILED")
        self.assertIsNone(result.results)

    def test_overall_status_prefers_failure_then_not_run(self):
        completed = assess_run(self._invocation([self._control_entry()]), self._target(), NEG)
        not_run = assess_run(self._invocation([]), self._target(), NEG)
        failed = assess_run(self._invocation([], exit_code=9), self._target(), NEG)
        self.assertEqual(overall_status([completed]), "COMPLETED")
        self.assertEqual(overall_status([completed, not_run]), "NOT_RUN")
        self.assertEqual(overall_status([completed, failed]), "INVOCATION_FAILED")


if __name__ == "__main__":
    unittest.main()
