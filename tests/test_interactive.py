"""Interactive registered-artifact selection tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import interactive
from harness.config import ArtifactDefaults, HarnessConfig


MANIFEST = """
schema_version = 1

[[builds]]
id = "fake-1"
scanner = "gitleaks"
version = "test"
source_commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
executable = "scanner.exe"
executable_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
capabilities = ["filesystem"]
"""


def fake_document() -> dict:
    return {
        "scanner": {"key": "gitleaks", "name": "Gitleaks", "version": "test"},
        "registered_build": {"id": "fake-1"},
        "source": {
            "repository": "https://example.invalid/repo",
            "commit": "a" * 40,
        },
        "profile": {"name": "default", "config_sha256": None},
        "builds": {},
        "suites": {},
        "performance": {"products": []},
        "cleanup": {"status": "PASS", "retained": False},
        "summary": {"overall": "COMPLETE"},
        "reports": {"sanitized": ["reports/experiments/run.json"], "raw": None},
    }


class InteractiveTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        (self.run_dir / "manifest.toml").write_text(MANIFEST, encoding="utf-8")
        self.config = HarnessConfig(
            artifact=ArtifactDefaults(manifest=self.run_dir / "manifest.toml")
        )

    def tearDown(self):
        self._tmp.cleanup()

    def _call(self, answers, fake_run=None):
        calls = []

        def record(**kwargs):
            calls.append(kwargs)
            return fake_document()

        with (
            patch.object(interactive, "load_config", return_value=self.config),
            patch.object(interactive, "run_experiment", side_effect=fake_run or record),
        ):
            code = interactive.run_interactive(
                input_func=lambda prompt: next(answers),
                output=lambda *args, **kwargs: None,
            )
        return code, calls

    def test_build_selection_suites_and_confirmation(self):
        answers = iter(["fake-1", "", "gitleaks,levain", "host", "y"])
        code, calls = self._call(answers)
        self.assertEqual(code, 0)
        self.assertEqual(calls[0]["build"], "fake-1")
        self.assertEqual(calls[0]["suites"], ["gitleaks", "levain"])
        self.assertEqual(calls[0]["platforms"], ["host"])

    def test_cancellation_does_not_run(self):
        answers = iter(["fake-1", "", "all", "host", "n"])
        code, calls = self._call(answers)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])

    def test_unknown_suite_is_rejected(self):
        answers = iter(["fake-1", "", "not-a-suite"])
        with self.assertRaises(ValueError):
            self._call(answers)

    def test_manifest_is_required(self):
        self.config = HarnessConfig(
            artifact=ArtifactDefaults(manifest=self.root / "missing.toml")
        )
        with patch.object(interactive, "load_config", return_value=self.config):
            with self.assertRaises(Exception):
                interactive.run_interactive(
                    input_func=lambda prompt: "",
                    output=lambda *args, **kwargs: None,
                )


if __name__ == "__main__":
    unittest.main()
