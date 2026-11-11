"""Static CI guardrail checks for the CP0 workflow."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/cp0-contracts.yml"


class CP0WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_bash_pipeline_failure_propagation_is_enabled(self):
        self.assertIn("shell: bash", self.text)
        self.assertGreaterEqual(self.text.count("set -o pipefail"), 3)

    def test_controlled_negative_pipeline_probe_exists(self):
        self.assertIn("pipeline_probe", self.text)
        self.assertIn('test "${{ steps.pipeline_probe.outcome }}" = "failure"', self.text)
        self.assertIn("continue-on-error: true", self.text)

    def test_required_jobs_are_still_present(self):
        for job in (
            "contracts-corpus-harness",
            "representative-benchmarks",
            "external-harness-contract",
        ):
            self.assertIn(f"  {job}:", self.text)


if __name__ == "__main__":
    unittest.main()
