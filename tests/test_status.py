"""Canonical status vocabulary and aggregation tests."""

from __future__ import annotations

import unittest

from harness import status as statuses


class StatusTests(unittest.TestCase):
    def test_combine_ignores_not_applicable(self):
        self.assertEqual(
            statuses.combine(
                [statuses.PASS, statuses.NOT_APPLICABLE, statuses.PASS]
            ),
            statuses.PASS,
        )

    def test_combine_failure_dominates(self):
        self.assertEqual(
            statuses.combine([statuses.PASS, statuses.BLOCKED, statuses.FAIL]),
            statuses.FAIL,
        )

    def test_combine_blocked_dominates_not_run(self):
        self.assertEqual(
            statuses.combine([statuses.PASS, statuses.NOT_RUN, statuses.BLOCKED]),
            statuses.BLOCKED,
        )

    def test_combine_all_not_applicable(self):
        self.assertEqual(
            statuses.combine([statuses.NOT_APPLICABLE, statuses.NOT_APPLICABLE]),
            statuses.NOT_APPLICABLE,
        )

    def test_overall_distinguishes_all_outcomes(self):
        self.assertEqual(
            statuses.overall([statuses.PASS], coverage_complete=True), "COMPLETE"
        )
        self.assertEqual(
            statuses.overall([statuses.PASS], coverage_complete=False),
            "COMPLETE_WITH_LIMITATIONS",
        )
        self.assertEqual(
            statuses.overall([statuses.PASS, statuses.NOT_RUN], coverage_complete=True),
            "INCOMPLETE",
        )
        self.assertEqual(
            statuses.overall([statuses.PASS, statuses.BLOCKED], coverage_complete=True),
            "INCOMPLETE",
        )
        self.assertEqual(
            statuses.overall([statuses.FAIL, statuses.PASS], coverage_complete=True),
            "FAIL",
        )

    def test_non_canonical_status_is_rejected(self):
        with self.assertRaises(ValueError):
            statuses.combine(["COMPLETED"])


if __name__ == "__main__":
    unittest.main()
