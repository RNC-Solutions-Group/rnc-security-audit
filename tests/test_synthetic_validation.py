"""Synthetic scoring-engine validation and independence checks."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from harness import synthetic_validation


class SyntheticValidationTests(unittest.TestCase):
    def test_all_controlled_cases_have_100_percent_accuracy(self):
        document = synthetic_validation.run()
        summary = document["summary"]
        self.assertEqual(summary["incorrect"], 0, document["cases"])
        self.assertEqual(summary["scoring_accuracy_percent"], 100.0)
        self.assertEqual(summary["unexpected_classifications"], [])
        self.assertEqual(summary["cases"], 31)

    def test_synthetic_adapter_has_no_gitleaks_dependency(self):
        tree = ast.parse(Path("harness/synthetic_validation.py").read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        forbidden = [
            name
            for name in imported
            if "gitleaks" in name or "execution" in name or "native_fixtures" in name
        ]
        self.assertEqual(forbidden, [])


if __name__ == "__main__":
    unittest.main()
