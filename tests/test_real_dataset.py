"""Read-only integration check against the real pinned Levain cache.

Skipped when the ignored cache has not been prepared. This test never touches
the network and never writes to the dataset checkout.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.dataset import DEFAULT_CACHE, load_corpora, prepare
from harness.execution import execute
from harness.scoring import assess_run, materialize
from tests.support import make_stub_wrapper

REVISION = "c130c321aa9046af17a6c876cb97e2ed71397110"
CACHE_SOURCE = DEFAULT_CACHE / "levain" / REVISION / "source"


@unittest.skipUnless(CACHE_SOURCE.is_dir(), "pinned Levain cache is not prepared")
class RealDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = prepare(offline=True)
        cls.corpora = load_corpora(cls.prepared)
        cls._tmp = tempfile.TemporaryDirectory()
        cls.wrapper = make_stub_wrapper(Path(cls._tmp.name) / "bin")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_published_counts(self):
        self.assertEqual(self.corpora.negative_counts["sections"], 116)
        self.assertEqual(self.corpora.negative_counts["lines"], 866)
        self.assertEqual(self.corpora.negative_counts["secrets"], 0)
        self.assertEqual(self.corpora.negative_counts["personal_data"], 57)
        self.assertEqual(self.corpora.positive_counts["sections"], 45)
        self.assertEqual(self.corpora.positive_counts["lines"], 368)
        self.assertEqual(self.corpora.positive_counts["secrets"], 85)
        self.assertEqual(self.corpora.positive_counts["hard_secrets"], 3)

    def test_control_only_scan_is_a_clean_negative_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = materialize(
                self.corpora.negative,
                Path(tmp) / "negative",
                corpus="negative",
                include_control=True,
            )
            invocation = execute(
                self.wrapper,
                target.directory,
                Path(tmp) / "report.json",
                env={"STUB_MODE": "control-only"},
            )
            result = assess_run(invocation, target, self.corpora.negative)
            self.assertEqual(result.status, "COMPLETED")
            self.assertEqual(result.results["false_positives"], 0)
            self.assertEqual(result.results["sections_scanned"], 116)

    def test_oracle_exact_secrets_are_scored_with_strict_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = materialize(
                self.corpora.positive,
                Path(tmp) / "positive",
                corpus="positive",
                include_control=True,
            )
            invocation = execute(
                self.wrapper,
                target.directory,
                Path(tmp) / "report.json",
                env={
                    "STUB_MODE": "oracle",
                    "STUB_ANSWER_KEY": str(self.prepared.derived / "tp-corpus.json"),
                },
            )
            result = assess_run(invocation, target, self.corpora.positive)
            self.assertEqual(result.status, "COMPLETED")
            self.assertEqual(result.results["true_positives"], 85)
            self.assertEqual(result.results["core_true_positives"], 82)
            self.assertEqual(result.results["hard_true_positives"], 3)
            self.assertEqual(result.results["partial_matches"], 0)
            self.assertEqual(result.results["ambiguous_findings"], 0)
            self.assertEqual(result.results["false_positives"], 0)


if __name__ == "__main__":
    unittest.main()
