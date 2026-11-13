"""Controlled filesystem fixture and end-to-end scoring-control tests."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from harness import filesystem_fixture, scoring_engine
from harness.contracts import ScoringPolicy


class FilesystemControlTests(unittest.TestCase):
    def test_controlled_fixture_scores_from_normalized_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = filesystem_fixture.build(Path(tmp) / "target")
            findings = [
                _finding(
                    item.path,
                    item.line_start,
                    filesystem_fixture.SECRETS[item.metadata["unique_secret_id"]],
                )
                for item in corpus.manifest.items
            ]
            result = scoring_engine.score_findings(
                findings,
                corpus.manifest,
                policy=ScoringPolicy(
                    policy_id="filesystem-controlled-v1",
                    policy_version="1",
                    negative_oracle=True,
                ),
            )
            self.assertEqual(result.metrics["matched_count"], 4)
            self.assertEqual(result.metrics["unexpected_count"], 0)
            self.assertEqual(result.metrics["precision_percent"], 100.0)
            self.assertEqual(result.metrics["detection_recall_percent"], 100.0)

    def test_zero_detection_is_not_scoring_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = filesystem_fixture.build(Path(tmp) / "target")
            result = scoring_engine.score_findings(
                [],
                corpus.manifest,
                policy=ScoringPolicy(
                    policy_id="filesystem-controlled-v1",
                    policy_version="1",
                    negative_oracle=True,
                ),
            )
            self.assertEqual(result.metrics["matched_count"], 0)
            self.assertEqual(result.metrics["detection_recall_percent"], 0.0)
            self.assertEqual(result.metrics["missed_count"], 4)


def _finding(path: str, line: int, secret: str):
    from harness.contracts import NormalizedFinding

    return NormalizedFinding(
        file=path,
        line=line,
        rule_id="rnc-synthetic-filesystem-token",
        secret_sha256=hashlib.sha256(secret.encode()).hexdigest(),
        secret_text=secret,
    )


if __name__ == "__main__":
    unittest.main()
