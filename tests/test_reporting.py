"""Configurable sanitized, raw, and console report tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from harness.config import HarnessConfig, ReportConfig, validate_raw_destination
from harness.reporting import (
    render_console,
    render_markdown,
    report_stem,
    write_matrix_reports,
)


def document() -> dict:
    return {
        "schema_version": 1,
        "report_type": "scanner-harness/matrix",
        "harness_version": "0.3.0",
        "generated_at": "2026-01-01T00:00:00Z",
        "run_id": "20260101T000000Z",
        "scanner": {"key": "gitleaks", "name": "Gitleaks", "version": "v8"},
        "source": {
            "repository": "https://example.invalid/repo",
            "branch": "main",
            "commit": "a" * 40,
            "path": "/tmp/source",
        },
        "platforms": [],
        "builds": {},
        "suites": {
            "go": {
                "key": "go",
                "title": "Go",
                "status": "PASS",
                "applicable": True,
                "reason": None,
                "summary": {},
                "metrics": {"tests_passed": 10},
                "targets": {"source": {"status": "PASS"}},
                "comparisons": {},
                "limitations": [],
                "details": {},
            }
        },
        "comparisons": {},
        "summary": {
            "overall": "COMPLETE",
            "matrix_status": "PASS",
            "suites": {"go": "PASS"},
            "builds": {},
            "counts": {"pass": 1, "fail": 0, "blocked": 0, "not_run": 0, "not_applicable": 0},
            "coverage_complete": True,
            "tested_platforms": ["source"],
        },
        "limitations": [],
        "reports": {"sanitized": [], "raw": None},
    }


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _config(self, **overrides) -> HarnessConfig:
        reports = replace(
            ReportConfig(
                console=True,
                sanitized=True,
                raw=False,
                output_dir=self.root / "reports",
                raw_output_dir=self.root / "raw",
                naming="run-{timestamp}",
            ),
            **overrides,
        )
        return HarnessConfig(reports=reports)

    def test_sanitized_reports_are_written_and_paths_are_included(self):
        doc = document()
        paths = write_matrix_reports(
            doc, self._config(), run_id="20260101T000000Z", suites=["go"]
        )
        self.assertEqual(len(paths["sanitized"]), 2)
        self.assertTrue(all(Path(item).is_file() for item in paths["sanitized"]))
        loaded = json.loads(Path(paths["sanitized"][0]).read_text(encoding="utf-8"))
        self.assertEqual(loaded["summary"]["overall"], "COMPLETE")
        self.assertEqual(loaded["reports"]["sanitized"], paths["sanitized"])

    def test_raw_reports_are_independent_and_not_in_console(self):
        doc = document()
        config = self._config(raw=True)
        paths = write_matrix_reports(
            doc,
            config,
            run_id="20260101T000000Z",
            suites=["go"],
            raw_artifacts=[
                {"name": "scanner.json", "data": b'{"Secret":"raw-synthetic-value"}'}
            ],
        )
        self.assertIsNotNone(paths["raw"])
        raw_file = Path(paths["raw"]) / "scanner.json"
        self.assertIn("raw-synthetic-value", raw_file.read_text(encoding="utf-8"))
        console = render_console(doc)
        self.assertNotIn("raw-synthetic-value", console)

    def test_raw_destination_inside_tracked_source_is_rejected(self):
        config = replace(
            self._config(raw=True),
            reports=replace(self._config(raw=True).reports, raw_output_dir=Path("reports/cp1c")),
        )
        with self.assertRaises(Exception):
            validate_raw_destination(config)

    def test_markdown_contains_statuses_and_totals(self):
        text = render_markdown(document())
        self.assertIn("PASS", text)
        self.assertIn("go", text)
        self.assertIn("Totals", render_console(document()))

    def test_naming_rejects_unknown_placeholder(self):
        with self.assertRaises(ValueError):
            report_stem(
                self._config(naming="{unknown}"),
                run_id="20260101T000000Z",
                scanner="gitleaks",
                suites=["go"],
            )


if __name__ == "__main__":
    unittest.main()
