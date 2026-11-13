"""Scanner execution, report parsing, and failure-detection tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.control import CONTROL_FILE, control_text
from harness.errors import ExecutionError, ReportError
from harness.execution import (
    build_command,
    execute,
    invocation_problem,
    parse_report,
    report_findings,
)
from tests.support import make_stub_wrapper


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "001-example.log").write_text("ordinary line\n", encoding="utf-8")
        (self.target / CONTROL_FILE).write_text(control_text(), encoding="utf-8")
        self.wrapper = make_stub_wrapper(self.root / "bin")
        self.report = self.root / "report.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _execute(self, mode: str, **kwargs):
        return execute(
            self.wrapper,
            self.target,
            self.report,
            env={"STUB_MODE": mode},
            **kwargs,
        )

    def test_all_lines_report_is_parsed_and_hashed(self):
        invocation = self._execute("all-lines")
        self.assertIsNone(invocation_problem(invocation))
        self.assertEqual(invocation.exit_code, 0)
        self.assertIsNotNone(invocation.report_sha256)
        findings = report_findings(invocation)
        self.assertTrue(any(finding.file == CONTROL_FILE for finding in findings))
        self.assertTrue(any(finding.file == "001-example.log" for finding in findings))
        self.assertGreater(invocation.duration_seconds, 0)

    def test_nonzero_exit_is_an_invocation_failure(self):
        invocation = self._execute("fail")
        self.assertEqual(invocation_problem(invocation), "INVOCATION_FAILED")
        self.assertEqual(invocation.exit_code, 2)

    def test_empty_report_is_distinct_from_failure(self):
        invocation = self._execute("silent")
        self.assertIsNone(invocation_problem(invocation))
        self.assertEqual(report_findings(invocation), [])

    def test_missing_report_is_detected(self):
        invocation = self._execute("no-report")
        self.assertEqual(invocation_problem(invocation), "REPORT_MISSING")

    def test_malformed_report_is_detected(self):
        invocation = self._execute("malformed")
        self.assertEqual(invocation_problem(invocation), "REPORT_INVALID")

    def test_timeout_is_detected(self):
        invocation = self._execute("hang", timeout_seconds=0.4)
        self.assertEqual(invocation_problem(invocation), "TIMEOUT")
        self.assertTrue(invocation.timed_out)

    def test_missing_binary_is_reported_before_execution(self):
        with self.assertRaises(ExecutionError):
            execute(self.root / "does-not-exist", self.target, self.report)

    def test_detect_mode_uses_source_flag(self):
        command = build_command(
            Path("gitleaks"),
            self.target,
            self.report,
            mode="detect",
            config=Path("config.toml"),
        )
        self.assertEqual(command[1], "detect")
        self.assertIn("--source", command)
        self.assertIn("--config", command)


class ReportParsingTests(unittest.TestCase):
    def test_accepts_wrapped_findings_object(self):
        data = json.dumps(
            {
                "findings": [
                    {
                        "RuleID": "generic",
                        "File": "C:\\work\\001-example.log",
                        "StartLine": 3,
                        "Secret": "synthetic-value",
                    }
                ]
            }
        ).encode("utf-8")
        findings = parse_report(data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file, "001-example.log")
        self.assertEqual(findings[0].line, 3)

    def test_accepts_pure_json_lines(self):
        data = (
            '{"File":"001-example.log","StartLine":1,"Secret":"x"}\n'
            '{"File":"002-example.log","StartLine":2,"Secret":"y"}\n'
        ).encode("utf-8")
        findings = parse_report(data)
        self.assertEqual([finding.file for finding in findings], ["001-example.log", "002-example.log"])

    def test_rejects_surrounding_text_or_truncated_output(self):
        data = (
            'scanner says hello\n{"File":"001-example.log","StartLine":1,"Secret":"x"}\n'
        ).encode("utf-8")
        with self.assertRaises(ReportError):
            parse_report(data)
        with self.assertRaises(ReportError):
            parse_report(b'[{"File":"a","StartLine":1,"Secret":"x"}')

    def test_rejects_report_without_file_paths(self):
        with self.assertRaises(ReportError):
            parse_report(b'[{"StartLine": 1, "Secret": "x"}]')

    def test_rejects_empty_report(self):
        with self.assertRaises(ReportError):
            parse_report(b"")


if __name__ == "__main__":
    unittest.main()
