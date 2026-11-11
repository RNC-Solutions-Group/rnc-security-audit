"""Independent harness calibration tests: exact known scoring, not scanner accuracy."""

from __future__ import annotations

import unittest

from tools.cp0.corpus import load_v0, load_v1
from tools.cp0.harness import score_bundle, self_check
from tools.cp0.synthetic_stub import build


class CP0HarnessTests(unittest.TestCase):
    def test_self_check_is_exactly_100_percent(self):
        report = self_check()
        self.assertEqual(report["cases"], 18)
        self.assertEqual(report["correct"], 18)
        self.assertEqual(report["incorrect"], 0)
        self.assertEqual(report["scoring_accuracy_percent"], 100.0)
        self.assertEqual([item["mode"] for item in report["results"] if not item["correct"]], [])

    def test_perfect_v1_scores_all_targets_and_findings(self):
        report = score_bundle(build(corpus="v1", mode="perfect"), load_v1())
        self.assertTrue(report["contract"]["valid"])
        self.assertEqual(report["execution"]["status"], "PASS")
        self.assertEqual(report["execution"]["targets_expected"], 21)
        self.assertEqual(report["execution"]["targets_reported"], 21)
        self.assertEqual(report["detection"]["expected"], 25)
        self.assertEqual(report["detection"]["matched"], 25)
        self.assertEqual(report["detection"]["missed"], 0)
        self.assertEqual(report["detection"]["unexpected"], 0)
        self.assertEqual(report["detection"]["duplicates"], 0)
        self.assertEqual(report["detection"]["recall_percent"], 100.0)
        self.assertEqual(report["detection"]["precision_percent"], 100.0)
        self.assertEqual(report["classification"]["actual_code"], 3)
        self.assertFalse(report["classification"]["ci_accepted"])
        self.assertEqual(report["classification"]["ci_process_exit_code"], 10)
        self.assertTrue(report["policy"]["correct"])
        self.assertEqual(len(report["targets"]), 21)
        self.assertEqual({row["status"] for row in report["targets"] if row["expected_scope"] != "INSPECTED"},
                         {"ACCOUNTED_VERIFIED_BLOCKED", "ACCOUNTED_UNINSPECTED"})

    def test_perfect_v0_scores_baseline(self):
        report = score_bundle(build(corpus="v0", mode="perfect"), load_v0())
        self.assertTrue(report["contract"]["valid"])
        self.assertEqual(report["execution"]["targets_expected"], 9)
        self.assertEqual(report["detection"]["matched"], 13)
        self.assertEqual(report["classification"]["actual_code"], 3)

    def test_missed_finding_is_accounted_not_called_clean(self):
        report = score_bundle(build(corpus="v1", mode="miss-one"), load_v1())
        self.assertEqual(report["detection"]["matched"], 24)
        self.assertEqual(report["detection"]["missed"], 1)
        self.assertFalse(report["detection"]["correct"])
        self.assertEqual(report["detection"]["precision_percent"], 100.0)

    def test_false_positive_reduces_precision(self):
        report = score_bundle(build(corpus="v1", mode="false-positive"), load_v1())
        self.assertEqual(report["detection"]["unexpected"], 1)
        self.assertEqual(report["detection"]["false_positives"], 1)
        self.assertEqual(report["detection"]["precision_percent"], 96.15)

    def test_duplicate_emission_is_not_double_credited(self):
        report = score_bundle(build(corpus="v1", mode="duplicate-new-id"), load_v1())
        self.assertEqual(report["detection"]["matched"], 25)
        self.assertEqual(report["detection"]["duplicates"], 1)
        self.assertFalse(report["detection"]["correct"])

    def test_blocked_scope_leak_is_a_scope_violation(self):
        report = score_bundle(build(corpus="v1", mode="blocked-leak"), load_v1())
        self.assertEqual(report["detection"]["scope_violations"], 1)
        self.assertEqual(report["execution"]["status"], "INCOMPLETE")
        self.assertFalse(report["policy"]["correct"])
        # The result correctly classifies the records it was given; the defect is
        # the records' scope, which the execution/policy lanes expose.
        self.assertTrue(report["classification"]["correct"])

    def test_missing_required_target_is_incomplete(self):
        report = score_bundle(build(corpus="v1", mode="missing-target"), load_v1())
        self.assertEqual(report["execution"]["missing_required"], 1)
        self.assertEqual(report["execution"]["status"], "INCOMPLETE")
        self.assertEqual(report["detection"]["missed"], 3)
        self.assertEqual(report["classification"]["actual_code"], 3)

    def test_invalid_contract_is_not_scored_as_detection_accuracy(self):
        report = score_bundle(build(corpus="v1", mode="unverified-block"), load_v1())
        self.assertFalse(report["contract"]["valid"])
        self.assertFalse(report["detection"]["scored"])
        self.assertEqual(report["execution"]["status"], "CONTRACT_INVALID")

    def test_operational_error_is_failed_and_detection_stays_separate(self):
        report = score_bundle(build(corpus="v1", mode="error"), load_v1())
        self.assertEqual(report["classification"]["actual_code"], 5)
        self.assertEqual(report["execution"]["status"], "ERROR")
        self.assertTrue(report["detection"]["correct"])

    def test_requested_unmatched_policy_does_not_become_applied(self):
        report = score_bundle(build(corpus="v1", mode="request-unmatched"), load_v1())
        self.assertEqual(report["policy"]["requested_unapplied"], 1)
        self.assertEqual(report["classification"]["actual_code"], 3)
        self.assertTrue(report["policy"]["correct"])


if __name__ == "__main__":
    unittest.main()
