"""Redacted report generation and end-to-end stub report tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.dataset import load_corpora, prepare
from harness.execution import execute
from harness.report import build_report, render_markdown, write_reports
from harness.scoring import assess_run, materialize
from tests.support import make_stub_wrapper, write_mini_repo


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.fixture = write_mini_repo(root / "fixture")
        cls.prepared = prepare(cls.fixture.manifest, root / "cache")
        cls.corpora = load_corpora(cls.prepared)
        cls.wrapper = make_stub_wrapper(root / "bin")
        cls.work = root / "work"
        cls.work.mkdir()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _run(self, corpus: str, mode: str):
        sections = self.corpora.negative if corpus == "negative" else self.corpora.positive
        target = materialize(sections, self.work / corpus, corpus=corpus, include_control=True)
        report_path = self.work / f"{corpus}-report.json"
        invocation = execute(
            self.wrapper,
            target.directory,
            report_path,
            env={"STUB_MODE": mode},
        )
        return assess_run(invocation, target, sections)

    def _report(self, runs, kind="stub"):
        return build_report(
            self.prepared,
            self.corpora,
            runs,
            scanner_kind=kind,
            source_revision=None,
            config_path=None,
            config_sha256=None,
        )

    def test_redacted_json_and_markdown(self):
        runs = [self._run("negative", "control-only"), self._run("positive", "all-lines")]
        report = self._report(runs)
        self.assertEqual(report["summary"]["overall_status"], "COMPLETED")
        self.assertEqual(report["summary"]["scanner_kind"], "stub")
        self.assertEqual(report["summary"]["gitleaks_integration"], "STUB_VALIDATION_ONLY")
        self.assertEqual(report["summary"]["gitleaks_execution"], "BLOCKED")
        self.assertEqual(report["runs"][0]["results"]["false_positives"], 0)
        self.assertEqual(report["runs"][1]["results"]["true_positives"], 3)
        self.assertEqual(report["target"]["integration_status"], "STUB_VALIDATION_ONLY")
        self.assertEqual(report["config"]["mode"], "builtin-default")
        self.assertFalse(report["detection_scope"]["available"])

        payload = json.dumps(report)
        markdown = render_markdown(report)
        for sensitive in self.fixture.sensitive_strings():
            self.assertNotIn(sensitive, payload)
            self.assertNotIn(sensitive, markdown)
        self.assertIn("HARNESS VALIDATION REPORT", markdown)
        self.assertIn("controlled test double", markdown)
        self.assertIn("not Gitleaks", markdown)

    def test_not_run_is_reported_as_not_run(self):
        runs = [self._run("negative", "silent")]
        report = self._report(runs)
        self.assertEqual(report["summary"]["overall_status"], "NOT_RUN")
        self.assertIsNone(report["runs"][0]["results"])
        self.assertIn("NOT_RUN_UNSCORABLE", render_markdown(report))

    def test_write_reports_round_trip(self):
        runs = [self._run("negative", "control-only")]
        report = self._report(runs)
        with tempfile.TemporaryDirectory() as tmp:
            json_path, markdown_path = write_reports(report, Path(tmp), "sample")
            self.assertTrue(json_path.is_file())
            self.assertTrue(markdown_path.is_file())
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["summary"]["overall_status"], "COMPLETED")

    def test_gitleaks_kind_without_scored_run_is_blocked(self):
        runs = [self._run("negative", "silent")]
        report = self._report(runs, kind="gitleaks")
        self.assertEqual(report["summary"]["overall_status"], "NOT_RUN")
        self.assertEqual(report["summary"]["gitleaks_integration"], "BLOCKED")
        self.assertEqual(report["summary"]["detection_accuracy"], "NOT_MEASURED")


if __name__ == "__main__":
    unittest.main()
