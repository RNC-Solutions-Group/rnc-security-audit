"""Architecture-boundary tests for scoring/adapter separation."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


def imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.append(node.module or "")
    return found


class ArchitectureTests(unittest.TestCase):
    def test_scoring_engine_has_no_adapter_or_parser_dependency(self):
        names = imports(Path("harness/scoring_engine.py"))
        forbidden = [
            name
            for name in names
            if "gitleaks" in name
            or "execution" in name
            or "native_fixtures" in name
            or "docker" in name
        ]
        self.assertEqual(forbidden, [])

    def test_shared_scoring_has_no_top_level_execution_dependency(self):
        names = imports(Path("harness/scoring.py"))
        self.assertNotIn("harness.execution", names)
        self.assertNotIn(".execution", names)

    def test_suites_do_not_import_scanner_parsers(self):
        for path in Path("harness/suites").glob("*.py"):
            names = imports(path)
            forbidden = [
                name
                for name in names
                if "gitleaks_parse" in name or "execution" in name
            ]
            self.assertEqual(forbidden, [], path)

    def test_synthetic_validation_has_no_gitleaks_dependency(self):
        names = imports(Path("harness/synthetic_validation.py"))
        forbidden = [name for name in names if "gitleaks" in name or "execution" in name]
        self.assertEqual(forbidden, [])

    def test_performance_is_independent_of_scoring(self):
        names = imports(Path("harness/performance.py"))
        forbidden = [name for name in names if "scoring" in name or "gitleaks_parse" in name]
        self.assertEqual(forbidden, [])
        engine_names = imports(Path("harness/scoring_engine.py"))
        self.assertNotIn("harness.performance", engine_names)
        self.assertNotIn("harness.telemetry", engine_names)

    def test_active_experiment_has_no_go_contract_obligation(self):
        for name in (
            "harness/adapters/gitleaks.py",
            "harness/adapters/gitleaks_fixtures.py",
            "harness/suites/gitleaks_fixtures.py",
            "harness/experiment.py",
        ):
            text = Path(name).read_text(encoding="utf-8")
            self.assertNotIn("INTERNAL_GO", text, name)
            self.assertNotIn("internal_go", text, name)
            self.assertNotIn("unmapped_contracts", text, name)

    def test_comparative_orchestration_is_not_part_of_the_harness(self):
        for name in (
            "harness/comparative.py",
            "harness/matrix.py",
            "harness/product_comparison.py",
            "harness/benchmark_runner.py",
        ):
            self.assertFalse(Path(name).exists(), name)

    def test_generic_orchestration_and_reporting_are_scanner_independent(self):
        for name in (
            "harness/experiment.py",
            "harness/reporting.py",
            "harness/scoring_engine.py",
        ):
            text = Path(name).read_text(encoding="utf-8").lower()
            self.assertNotIn("gitleaks", text, name)
            self.assertNotIn("betterleaks", text, name)


if __name__ == "__main__":
    unittest.main()
