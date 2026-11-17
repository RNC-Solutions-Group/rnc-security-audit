"""Execution provenance, argument policy, and safe rendering tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.adapters import get_adapter
from harness.adapters.base import BuildArtifact
from harness.adapters.base import PLATFORMS
from harness.execution import Invocation
from harness.provenance import (
    ArgumentPolicyError,
    build_argument_policy,
    normalize_command,
    redact_argv,
    render_command,
    split_arguments,
)
from harness.safe_text import (
    csv_cell,
    markdown_cell,
    markdown_code,
    redact_text,
    safe_path,
)


class ArgumentSplitterTests(unittest.TestCase):
    def test_preserves_windows_paths_and_spaces(self) -> None:
        parsed = split_arguments(r'--config "C:\Program Files\scanner\rules.json" --workers 1')
        self.assertEqual(
            parsed,
            ("--config", r"C:\Program Files\scanner\rules.json", "--workers", "1"),
        )

    def test_equals_and_quotes(self) -> None:
        self.assertEqual(
            split_arguments("--name='a b' --token=x --path \"C:\\a b\\c\""),
            ("--name=a b", "--token=x", "--path", r"C:\a b\c"),
        )

    def test_empty_quoted_argument_and_unterminated_quote(self) -> None:
        self.assertEqual(split_arguments('--x ""'), ("--x", ""))
        with self.assertRaises(ArgumentPolicyError):
            split_arguments('--x "unterminated')


class ArgumentPolicyTests(unittest.TestCase):
    def test_workers_auto_is_performance_only(self) -> None:
        policy = build_argument_policy("rnc", ("--workers", "auto"))
        self.assertEqual(policy.detection_configuration, "DEFAULT")
        self.assertEqual(policy.execution_configuration, "EXPLICIT")
        self.assertTrue(policy.baseline_detection_comparable)
        self.assertEqual(policy.comparability, "PERFORMANCE_TUNED_BASELINE_DETECTION")
        self.assertEqual(policy.arguments[0].category, "PERFORMANCE")
        self.assertIsNone(policy.arguments[0].effective)

    def test_workers_one_is_not_a_detection_override(self) -> None:
        policy = build_argument_policy("rnc", ("--workers", "1"))
        self.assertTrue(policy.baseline_detection_comparable)
        self.assertEqual(policy.arguments[0].value, "1")

    def test_default_policy_is_baseline_comparable(self) -> None:
        policy = build_argument_policy("gitleaks", ())
        self.assertEqual(policy.comparability, "BASELINE_COMPARABLE")
        self.assertTrue(policy.baseline_metrics_included)

    def test_scope_change_is_not_baseline_comparable(self) -> None:
        policy = build_argument_policy("gitleaks", ("--log-opts", "HEAD~3..HEAD"))
        self.assertFalse(policy.baseline_detection_comparable)
        self.assertFalse(policy.baseline_metrics_included)
        self.assertEqual(policy.comparability, "NOT_BASELINE_COMPARABLE")
        self.assertEqual(policy.source_scope_configuration, "EXPLICIT")

    def test_unknown_flag_is_forwardable_but_experimental(self) -> None:
        policy = build_argument_policy("gitleaks", ("--future-flag", "value"))
        self.assertEqual(policy.comparability, "EXPERIMENTAL_UNVERIFIED")
        self.assertFalse(policy.baseline_metrics_included)
        self.assertEqual(policy.arguments[0].category, "UNKNOWN")

    def test_custom_profile_is_not_baseline_comparable(self) -> None:
        policy = build_argument_policy("rnc", (), profile="custom")
        self.assertEqual(policy.detection_configuration, "CUSTOM")
        self.assertFalse(policy.baseline_metrics_included)

    def test_reserved_harness_flags_are_rejected(self) -> None:
        for adapter, args in (
            ("rnc", ("--root", "elsewhere")),
            ("rnc", ("--rules", "other.json")),
            ("rnc", ("--output", "report.json")),
            ("gitleaks", ("--report-path", "report.json")),
            ("gitleaks", ("--config", "other.toml")),
            ("betterleaks", ("--exit-code", "0")),
        ):
            with self.assertRaises(ArgumentPolicyError, msg=(adapter, args)):
                build_argument_policy(adapter, args)

    def test_duplicate_and_positional_arguments_are_rejected(self) -> None:
        with self.assertRaises(ArgumentPolicyError):
            build_argument_policy("rnc", ("--workers", "1", "--workers", "2"))
        with self.assertRaises(ArgumentPolicyError):
            build_argument_policy("rnc", ("scan",))

    def test_sensitive_values_are_redacted_in_argv(self) -> None:
        argv, indexes = redact_argv(
            [
                "scanner",
                "--password",
                "synthetic-secret",
                "--header=Authorization: Bearer abc123",
                "https://user:password@example.invalid/path",
            ]
        )
        self.assertEqual(argv[2], "<redacted>")
        self.assertIn("--header=<redacted>", argv[3])
        self.assertIn("user:<redacted>@", argv[4])
        self.assertEqual(indexes, [2, 3, 4])

    def test_nested_scanner_args_are_redacted_in_harness_command(self) -> None:
        argv, indexes = redact_argv(
            ["python", "-m", "harness", "experiment", "--scanner-args=--token synthetic-nested"]
        )
        self.assertNotIn("synthetic-nested", argv[-1])
        self.assertIn("<redacted>", argv[-1])
        self.assertEqual(indexes, [4])


class RenderingTests(unittest.TestCase):
    def test_shell_rendering_quotes_spaces_and_apostrophes(self) -> None:
        self.assertEqual(
            render_command(["scanner", "--path", r"C:\a b\c"]),
            "scanner --path 'C:\\a b\\c'",
        )
        self.assertIn("'it''s'", render_command(["scanner", "it's"]))

    def test_normalized_template_is_not_literal(self) -> None:
        rendered = normalize_command(
            ["scanner", "--root", r"C:\work\scan", "--output", r"C:\work\report.json"],
            [(r"C:\work\scan", "<TARGET>"), (r"C:\work\report.json", "<REPORT>")],
        )
        self.assertEqual(rendered, "scanner --root <TARGET> --output <REPORT>")
        self.assertNotEqual(rendered, "scanner --root C:\\work\\scan --output C:\\work\\report.json")

    def test_csv_formula_neutralisation(self) -> None:
        for value in ("=cmd", "+cmd", "-cmd", "@cmd", "\t=cmd", " \r\n=cmd"):
            self.assertTrue(csv_cell(value).startswith("'"), value)
        self.assertEqual(csv_cell("-12"), "-12")
        self.assertEqual(csv_cell("-12.5"), "-12.5")
        self.assertEqual(csv_cell("ordinary"), "ordinary")

    def test_markdown_cell_and_code_are_structurally_safe(self) -> None:
        self.assertEqual(markdown_cell("a|b\nc"), "a\\|b<br>c")
        self.assertEqual(markdown_code("a`b"), "``a`b``")
        self.assertEqual(markdown_code("`a`"), "`` `a` ``")

    def test_text_redaction_and_path_redaction(self) -> None:
        self.assertNotIn("secret", redact_text("https://u:secret@example.invalid/x"))
        self.assertIn("database_password=<redacted>", redact_text("database_password=hunter2"))
        self.assertNotIn(
            "synthetic", redact_text("unknown option --token synthetic-value")
        )
        redacted_path = safe_path(r"C:\work\token=abcdef\config.json")
        self.assertNotIn("abcdef", redacted_path)
        self.assertIn("config.json", redacted_path)
        self.assertTrue(safe_path(r"C:\Users\developer\private\report.json").startswith("<external>/"))


class InvocationRecordTests(unittest.TestCase):
    def _artifact(self) -> BuildArtifact:
        return BuildArtifact(
            platform=PLATFORMS["windows-amd64"],
            status="PASS",
            command=(),
            exit_code=None,
            duration_seconds=0.0,
            artifact_path="run/scanner.exe",
            artifact_sha256="a" * 64,
            image_id=None,
            image_tag=None,
            version="1.0",
            version_status="PASS",
            stdout_sha256="",
            stderr_sha256="",
            error=None,
            metadata={
                "build_id": "scanner-build",
                "source_commit": "b" * 40,
                "manifest": {"sha256": "c" * 64},
                "source_identity": "manifest-metadata",
            },
        )

    def _invocation(self) -> Invocation:
        return Invocation(
            binary_path="run/scanner.exe",
            binary_sha256="a" * 64,
            argv=(
                "run/scanner.exe",
                "scan",
                "--root",
                "target",
                "--workers",
                "auto",
                "--password",
                "secret-value",
            ),
            mode="dir",
            report_path="report.json",
            exit_code=0,
            timed_out=False,
            duration_seconds=1.0,
            timeout_seconds=10,
            stdout=b"",
            stderr=b"",
            report_bytes=b"[]",
            invocation_type="measured",
            suite="rnclab",
            workload="rnclab-filesystem",
            cwd="target",
            environment_cleared=("RNC_CONFIG",),
            environment_overrides={},
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:00:01Z",
        )

    def test_record_contains_phase_identity_argv_and_redaction(self) -> None:
        adapter = get_adapter("rnc")
        adapter.argument_policy = build_argument_policy("rnc", ("--workers", "auto"))
        record = adapter.record_invocation(
            self._invocation(),
            self._artifact(),
            supplied_args=("--workers", "auto"),
        )
        self.assertEqual(record["phase"], "measured")
        self.assertEqual(record["invocation_type"], "measured")
        self.assertEqual(record["workload_context"]["lane"], "filesystem")
        self.assertEqual(record["artifact_identity"]["build_id"], "scanner-build")
        self.assertIn("<redacted>", record["command"])
        self.assertNotIn("secret-value", json.dumps(record))
        self.assertTrue(record["command_sha256"])
        self.assertIn("not the literal executed command", record["command_template_label"])
        self.assertEqual(record["supplied_arguments"][0]["flag"], "--workers")
        self.assertFalse(record["supplied_arguments"][0]["redacted"])
        self.assertIn("RNC_CONFIG", record["environment"]["cleared_config_keys"])

    def test_process_not_started_is_explicit(self) -> None:
        adapter = get_adapter("gitleaks")
        invocation = Invocation(
            **{
                **self._invocation().__dict__,
                "process_started": False,
                "error_code": "INVOCATION_FAILED",
                "error_message": "could not start",
                "exit_code": None,
            }
        )
        record = adapter.record_invocation(invocation)
        self.assertFalse(record["process_started"])
        self.assertEqual(record["status"], "BLOCKED")
        self.assertFalse(record["supplied_arguments"])


if __name__ == "__main__":
    unittest.main()
