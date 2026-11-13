"""One-scanner experiment orchestration tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from harness import experiment, status as statuses
from harness.adapters.base import BuildArtifact, PLATFORMS
from harness.config import HarnessConfig, ReportConfig
from harness.profile import CUSTOM
from harness.source import SourceCheckout


def source_checkout(tmp: Path, commit: str) -> SourceCheckout:
    path = Path(tempfile.mkdtemp(prefix="source-", dir=tmp))
    (path / "main.go").write_text("package main\n", encoding="utf-8")
    return SourceCheckout(
        repository="https://example.invalid/scanner",
        commit=commit,
        path=path,
        requested_commit=commit,
        head=commit,
        clone_command=("git", "clone"),
        fetch_command=None,
        clone_duration_seconds=0.1,
        fetch_duration_seconds=None,
        clone_stdout_sha256="a" * 64,
        clone_stderr_sha256="b" * 64,
        fetch_stdout_sha256=None,
        fetch_stderr_sha256=None,
    )


def build_artifact(platform_key: str = "windows-amd64") -> BuildArtifact:
    platform = PLATFORMS[platform_key]
    return BuildArtifact(
        platform=platform,
        status=statuses.PASS,
        command=("go", "build"),
        exit_code=0,
        duration_seconds=1.2,
        artifact_path="C:/run/scanner.exe",
        artifact_sha256="c" * 64,
        image_id=None,
        image_tag=None,
        version="v-test",
        version_status=statuses.PASS,
        stdout_sha256="d" * 64,
        stderr_sha256="e" * 64,
        error=None,
        metadata={"source_commit": "a" * 40, "execution_method": "native"},
    )


class FakeAdapter:
    key = "fake"
    display_name = "Fake"
    default_repository = "https://example.invalid/scanner"
    supported_suites = ("alpha",)
    platforms = (PLATFORMS["windows-amd64"],)

    def __init__(self):
        self.run_id = None

    def bind_run(self, run_id):
        self.run_id = run_id

    def default_configuration(self):
        return {
            "mode": "bundled-default",
            "isolated_working_directory": True,
            "removed_environment": [],
            "verifiable": True,
        }

    def config_environment_keys(self):
        return ("FAKE_CONFIG",)

    def validate_config(self, path):
        resolved = Path(path).resolve()
        import hashlib

        return resolved, hashlib.sha256(resolved.read_bytes()).hexdigest()

    def build(self, source, platform, output_dir):
        return build_artifact(platform.key)

    def can_execute(self, platform):
        return True


class FakeSuite:
    key = "alpha"
    title = "Alpha"
    required_capabilities = ()

    def run(self, context):
        return {
            "key": "alpha",
            "title": "Alpha",
            "status": statuses.PASS,
            "outcome": statuses.COMPLETED_AND_SCORED,
            "applicable": True,
            "baseline_metric": True,
            "summary": {},
            "metrics": {"expected_count": 1, "matched_count": 1},
            "targets": {"windows-amd64": {"status": statuses.PASS, "metrics": {}}},
            "results": [{"dimension": "alpha", "platform": "windows-amd64", "outcome": statuses.COMPLETED_AND_SCORED}],
            "comparisons": {},
            "limitations": [],
            "details": {},
        }


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.config = HarnessConfig(
            reports=ReportConfig(
                output_dir=self.root / "reports",
                naming="{scanner}-{commit}-{profile}",
                console=False,
            )
        )
        self.adapter = FakeAdapter()
        self.commit = "a" * 40

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, **kwargs):
        with (
            patch.object(experiment, "get_adapter", return_value=self.adapter),
            patch.object(experiment, "acquire", return_value=source_checkout(self.root, self.commit)),
            patch.object(experiment, "resolve_suites", return_value=[("alpha", FakeSuite(), None)]),
            patch.object(experiment, "_run_performance", return_value={"status": statuses.PASS, "products": []}),
        ):
            return experiment.run(
                scanner="fake",
                repository="https://example.invalid/scanner",
                commit=self.commit,
                platforms=["windows-amd64"],
                suites=["alpha"],
                config=self.config,
                **kwargs,
            )

    def test_one_commit_produces_one_independently_usable_report(self):
        document = self._run()
        self.assertEqual(document["source"]["commit"], self.commit)
        self.assertTrue(document["source"]["head_verified"])
        self.assertEqual(document["scanner"]["key"], "fake")
        self.assertEqual(document["summary"]["overall"], "COMPLETE")
        json_path = Path(document["reports"]["sanitized"][0])
        markdown_path = Path(document["reports"]["sanitized"][1])
        self.assertTrue(json_path.is_file())
        self.assertTrue(markdown_path.is_file())
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["source"]["commit"], self.commit)
        self.assertEqual(payload["profile"]["name"], "default")
        self.assertEqual(payload["cleanup"]["status"], statuses.PASS)

    def test_default_and_custom_profiles_are_not_confused(self):
        custom = self.root / "custom.toml"
        custom.write_text("title = 'controlled'\n", encoding="utf-8")
        document = self._run(profile_name=CUSTOM, scanner_config=custom)
        self.assertEqual(document["profile"]["name"], "custom")
        self.assertEqual(document["profile"]["config_sha256"], __import__("hashlib").sha256(custom.read_bytes()).hexdigest())
        self.assertFalse(document["summary"]["baseline_metrics_included"])

    def test_source_failure_still_writes_a_failure_report(self):
        with (
            patch.object(experiment, "get_adapter", return_value=self.adapter),
            patch.object(experiment, "acquire", side_effect=RuntimeError("commit not found")),
        ):
            document = experiment.run(
                scanner="fake",
                repository="https://example.invalid/scanner",
                commit=self.commit,
                platforms=["windows-amd64"],
                suites=["alpha"],
                config=self.config,
            )
        self.assertEqual(document["summary"]["overall"], "FAIL")
        self.assertFalse(document["source"]["head_verified"])
        self.assertTrue(document["summary"]["fatal_error"])
        self.assertTrue(Path(document["reports"]["sanitized"][0]).is_file())

    def test_cancellation_still_cleans_up_and_writes_report(self):
        with (
            patch.object(experiment, "get_adapter", return_value=self.adapter),
            patch.object(experiment, "acquire", side_effect=KeyboardInterrupt),
        ):
            document = experiment.run(
                scanner="fake",
                repository="https://example.invalid/scanner",
                commit=self.commit,
                platforms=["windows-amd64"],
                suites=["alpha"],
                config=self.config,
            )
        self.assertEqual(document["summary"]["overall"], "FAIL")
        self.assertIn("KeyboardInterrupt", document["summary"]["fatal_error"])
        self.assertEqual(document["cleanup"]["status"], statuses.PASS)
        self.assertTrue(Path(document["reports"]["sanitized"][0]).is_file())

    def test_performance_blocked_is_a_limitation_not_a_pass(self):
        with (
            patch.object(experiment, "get_adapter", return_value=self.adapter),
            patch.object(experiment, "acquire", return_value=source_checkout(self.root, self.commit)),
            patch.object(experiment, "resolve_suites", return_value=[("alpha", FakeSuite(), None)]),
            patch.object(
                experiment,
                "_run_performance",
                return_value={"status": statuses.BLOCKED, "products": [], "reason": "no telemetry"},
            ),
        ):
            document = experiment.run(
                scanner="fake",
                repository="https://example.invalid/scanner",
                commit=self.commit,
                platforms=["windows-amd64"],
                suites=["alpha"],
                config=self.config,
            )
        self.assertEqual(document["summary"]["overall"], "COMPLETE_WITH_LIMITATIONS")
        self.assertTrue(
            any("Performance section status" in item for item in document["limitations"])
        )

    def test_repeated_reports_do_not_overwrite(self):
        first = self._run()
        second = self._run()
        self.assertNotEqual(first["reports"]["sanitized"], second["reports"]["sanitized"])
        self.assertTrue(all(Path(item).is_file() for item in first["reports"]["sanitized"]))
        self.assertTrue(all(Path(item).is_file() for item in second["reports"]["sanitized"]))


if __name__ == "__main__":
    unittest.main()
