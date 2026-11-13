"""Interactive CLI selection tests."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from harness import interactive


def fake_document() -> dict:
    return {
        "scanner": {"key": "gitleaks", "name": "Gitleaks", "version": "v1"},
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
    def test_multiple_suite_selection_and_confirmation(self):
        answers = iter(["", "", "a" * 40, "", "gitleaks,levain", "host", "y"])
        calls = []

        def fake_run(**kwargs):
            calls.append(kwargs)
            return fake_document()

        with patch.object(interactive, "run_experiment", side_effect=fake_run):
            code = interactive.run_interactive(
                config_path="harness.toml.example",
                input_func=lambda prompt: next(answers),
                output=lambda *args, **kwargs: None,
            )
        self.assertEqual(code, 0)
        self.assertEqual(calls[0]["suites"], ["gitleaks", "levain"])
        self.assertEqual(calls[0]["platforms"], ["host"])
        self.assertEqual(calls[0]["commit"], "a" * 40)

    def test_cancellation_does_not_run(self):
        answers = iter(["", "", "a" * 40, "", "all", "host", "n"])
        with patch.object(interactive, "run_experiment") as fake:
            code = interactive.run_interactive(
                config_path="harness.toml.example",
                input_func=lambda prompt: next(answers),
                output=lambda *args, **kwargs: None,
            )
        self.assertEqual(code, 0)
        fake.assert_not_called()

    def test_unknown_suite_is_rejected(self):
        answers = iter(["", "", "a" * 40, "", "not-a-suite"])
        with patch.object(interactive, "run_experiment"):
            with self.assertRaises(ValueError):
                interactive.run_interactive(
                    config_path="harness.toml.example",
                    input_func=lambda prompt: next(answers),
                    output=lambda *args, **kwargs: None,
                )


if __name__ == "__main__":
    unittest.main()
