"""Synthetic Git-history corpus and history scoring tests."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from harness import history, history_fixture, scoring_engine
from harness.contracts import NormalizedFinding, ScoringPolicy, EXPECTED_DETECTION


class HistoryTests(unittest.TestCase):
    def test_controlled_corpus_and_occurrence_scoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = history_fixture.build(Path(tmp) / "repo")
            self.assertEqual(len(corpus.commits), 5)
            self.assertEqual(len(corpus.manifest.items), 5)
            self.assertEqual(corpus.scope["unique_secret_count"], 3)
            findings = [
                NormalizedFinding(
                    file=item.path,
                    line=item.line_start,
                    rule_id="rnc-synthetic-history-token",
                    commit=item.commit,
                    secret_sha256=hashlib.sha256(
                        history_fixture.SECRETS[
                            item.metadata["unique_secret_id"]
                        ].encode()
                    ).hexdigest(),
                )
                for item in corpus.manifest.items
            ]
            result = scoring_engine.score_findings(
                findings,
                corpus.manifest,
                policy=ScoringPolicy(policy_id="history", policy_version="1"),
            )
            self.assertEqual(result.metrics["matched_count"], 5)
            self.assertEqual(result.metrics["unexpected_count"], 0)
            self.assertEqual(result.metrics["value_verified_count"], 5)

    def test_wrong_commit_does_not_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = history_fixture.build(Path(tmp) / "repo")
            item = corpus.manifest.items[0]
            finding = NormalizedFinding(
                file=item.path,
                line=item.line_start,
                rule_id="rnc-synthetic-history-token",
                commit="0" * 40,
                secret_sha256=hashlib.sha256(
                    history_fixture.SECRETS[
                        item.metadata["unique_secret_id"]
                    ].encode()
                ).hexdigest(),
            )
            result = scoring_engine.score_findings([finding], corpus.manifest)
            self.assertEqual(result.metrics["matched_count"], 0)
            self.assertEqual(result.metrics["unexpected_count"], 1)

    def test_history_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = history_fixture.build(Path(tmp) / "repo")
            scope = history.discover(corpus.root)
            self.assertEqual(scope["head"], corpus.commits["c5"])
            self.assertEqual(scope["history_truth_status"], "BLOCKED")
            self.assertGreaterEqual(scope["commit_count"], 5)
            self.assertIn("removed/legacy.env", scope["historical_only_paths"])


if __name__ == "__main__":
    unittest.main()
