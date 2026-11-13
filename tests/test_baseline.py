"""Baseline comparison tests."""

from __future__ import annotations

import unittest

from harness import baseline, scoring_engine
from harness.contracts import NormalizedFinding, ScoringPolicy, TruthItem, TruthManifest


def truth(version: str = "1") -> TruthManifest:
    return TruthManifest(
        manifest_id="test",
        manifest_version=version,
        dataset_id="test",
        dataset_version="1",
        items=(
            TruthItem("a", "test", "1", "a.txt", line_start=1, line_end=1),
            TruthItem("b", "test", "1", "b.txt", line_start=2, line_end=2),
        ),
        scoring_policy={"id": "test", "version": "1", "allow_line_only": True},
        integrity={"status": "PASS"},
    )


def result(matched: set[str]):
    findings = [
        NormalizedFinding(file=f"{name}.txt", line=1 if name == "a" else 2, rule_id="r")
        for name in matched
    ]
    return scoring_engine.score_findings(findings, truth())


class BaselineTests(unittest.TestCase):
    def test_new_miss_and_recovery(self):
        previous = result({"a", "b"})
        current = result({"a"})
        comparison = baseline.compare_results(previous, current)
        self.assertEqual(comparison["status"], "FAIL")
        self.assertEqual(comparison["new_misses"], ["b"])
        self.assertEqual(comparison["recovered"], [])

        recovered = baseline.compare_results(current, previous)
        self.assertEqual(recovered["status"], "PASS")
        self.assertEqual(recovered["recovered"], ["b"])

    def test_new_unexpected(self):
        previous = result({"a", "b"})
        current = scoring_engine.score_findings(
            [
                NormalizedFinding(file="a.txt", line=1, rule_id="r"),
                NormalizedFinding(file="b.txt", line=2, rule_id="r"),
                NormalizedFinding(file="x.txt", line=3, rule_id="r"),
            ],
            truth(),
        )
        comparison = baseline.compare_results(previous, current)
        self.assertEqual(comparison["status"], "FAIL")
        self.assertTrue(comparison["new_unexpected"])

    def test_incompatible_manifest_version(self):
        previous = result({"a", "b"})
        current = scoring_engine.score_findings(
            [NormalizedFinding(file="a.txt", line=1, rule_id="r")], truth("2")
        )
        comparison = baseline.compare_results(previous, current)
        self.assertEqual(comparison["status"], "INCOMPATIBLE")
        self.assertIn("manifest_version", comparison["reason"])

    def test_identical_counts_different_identities_fail_parity(self):
        left = result({"a"})
        right = result({"b"})
        comparison = baseline.compare_results(left, right)
        self.assertEqual(comparison["status"], "FAIL")
        self.assertEqual(comparison["new_misses"], ["a"])
        self.assertEqual(comparison["recovered"], ["b"])


if __name__ == "__main__":
    unittest.main()
