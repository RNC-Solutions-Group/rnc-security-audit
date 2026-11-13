"""One-registered-artifact experiment orchestration tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from harness import experiment, status as statuses
from harness.adapters.base import BuildArtifact, PLATFORMS
from harness.artifacts import ArtifactManifest, RegisteredBuild
from harness.config import HarnessConfig, ReportConfig
from harness.profile import CUSTOM


def registered_build(root: Path, build_id: str = "fake-1") -> RegisteredBuild:
    return RegisteredBuild(
        id=build_id,
        scanner="gitleaks",
        source_commit="a" * 40,
        version="v-test",
        source_repository="https://example.invalid/scanner",
        executable="scanner.exe",
        executable_sha256="c" * 64,
        docker_image="example/scanner:test",
        docker_image_id="sha256:" + "d" * 64,
        rules_file=None,
        rules_sha256=None,
        capabilities=("filesystem",),
        run_dir=root / "run",
        manifest_path=root / "run" / "manifest.toml",
        manifest_sha256="e" * 64,
    )


def build_artifact(platform_key: str = "windows-amd64") -> BuildArtifact:
    platform = PLATFORMS[platform_key]
    metadata = {
        "build_id": "fake-1",
        "scanner": "gitleaks",
        "source_commit": "a" * 40,
        "manifest": {"path": "run/manifest.toml", "sha256": "e" * 64},
    }
    return BuildArtifact(
        platform=platform,
        status=statuses.PASS,
        command=(),
        exit_code=None,
        duration_seconds=0.0,
        artifact_path=str(Path("run/scanner.exe")),
        artifact_sha256="c" * 64,
        image_id=None,
        image_tag=None,
        version="v-test",
        version_status=statuses.PASS,
        stdout_sha256="",
        stderr_sha256="",
        error=None,
        metadata=metadata,
    )


def fake_manifest(root: Path) -> ArtifactManifest:
    build = registered_build(root)
    return ArtifactManifest(
        path=build.manifest_path,
        run_dir=build.run_dir,
        sha256=build.manifest_sha256,
        builds=(build,),
    )


class FakeAdapter:
    key = "fake"
    display_name = "Fake"
    default_repository = "https://example.invalid/scanner"
    supported_suites = ("alpha",)
    platforms = (PLATFORMS["windows-amd64"],)

    def __init__(self):
        self.run_id = None
        self.invocations = []

    def bind_run(self, run_id):
        self.run_id = run_id

    def default_configuration(self):
        return {
            "mode": "registered-default",
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

    def resolve_artifact(self, build, platform, work_dir=None):
        artifact = build_artifact(platform.key)
        return replace(artifact, metadata={**artifact.metadata, "build_id": build.id})

    def can_execute(self, platform):
        return True

    def supports_mode(self, mode):
        return mode in {"dir", "git"}


class FakeSuite:
    key = "alpha"
    title = "Alpha"
    required_capabilities = ()

    def run(self, context):
        context.adapter.invocations.append(
            {
                "sequence": 1,
                "scanner": "fake",
                "build_id": context.build.id,
                "platform": "windows-amd64",
                "invocation_type": "detection",
                "suite": "alpha",
                "workload": "alpha-filesystem",
                "command": ["run/scanner.exe", "dir", "target"],
                "exit_code": 0,
                "duration_seconds": 0.1,
                "timed_out": False,
                "status": statuses.PASS,
            }
        )
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
        self.manifest = fake_manifest(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def _run(self, **kwargs):
        with (
            patch.object(experiment, "get_adapter", return_value=self.adapter),
            patch.object(experiment, "load_manifest", return_value=self.manifest),
            patch.object(experiment, "resolve_suites", return_value=[("alpha", FakeSuite(), None)]),
            patch.object(experiment, "_run_performance", return_value={"status": statuses.PASS, "products": []}),
        ):
            return experiment.run(
                build="fake-1",
                platforms=["windows-amd64"],
                suites=["alpha"],
                config=self.config,
                **kwargs,
            )

    def test_one_registered_build_produces_one_independently_usable_report(self):
        document = self._run()
        self.assertEqual(document["source"]["commit"], "a" * 40)
        self.assertFalse(document["source"]["head_verified"])
        self.assertTrue(document["source"]["metadata_only"])
        self.assertEqual(document["registered_build"]["id"], "fake-1")
        self.assertEqual(document["artifact_manifest"]["sha256"], "e" * 64)
        self.assertEqual(document["scanner"]["key"], "fake")
        self.assertEqual(document["summary"]["overall"], "COMPLETE")
        self.assertEqual(document["summary"]["build_id"], "fake-1")
        self.assertEqual(document["summary"]["invocation_count"], 1)
        self.assertEqual(len(document["invocations"]), 1)
        json_path = Path(document["reports"]["sanitized"][0])
        markdown_path = Path(document["reports"]["sanitized"][1])
        self.assertTrue(json_path.is_file())
        self.assertTrue(markdown_path.is_file())
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["registered_build"]["id"], "fake-1")
        self.assertEqual(payload["registered_build"]["source_commit"], "a" * 40)
        self.assertEqual(payload["profile"]["name"], "default")
        self.assertEqual(payload["cleanup"]["status"], statuses.PASS)
        text = markdown_path.read_text(encoding="utf-8")
        self.assertIn("fake-1", text)
        self.assertIn("Scanner invocations", text)

    def test_default_and_custom_profiles_are_not_confused(self):
        custom = self.root / "custom.toml"
        custom.write_text("title = 'controlled'\n", encoding="utf-8")
        document = self._run(profile_name=CUSTOM, scanner_config=custom)
        self.assertEqual(document["profile"]["name"], "custom")
        self.assertEqual(document["profile"]["config_sha256"], __import__("hashlib").sha256(custom.read_bytes()).hexdigest())
        self.assertFalse(document["summary"]["baseline_metrics_included"])

    def test_blocked_artifact_still_writes_a_blocked_report(self):
        blocked = replace(
            build_artifact(),
            status=statuses.BLOCKED,
            error="executable SHA-256 mismatch",
            artifact_path=None,
            artifact_sha256=None,
        )
        self.adapter.resolve_artifact = lambda build, platform, work_dir=None: blocked
        document = self._run()
        self.assertEqual(document["summary"]["builds"]["windows-amd64"], statuses.BLOCKED)
        self.assertEqual(document["builds"]["windows-amd64"]["error"], "executable SHA-256 mismatch")
        self.assertIn("executable SHA-256 mismatch", json.dumps(document))
        self.assertTrue(Path(document["reports"]["sanitized"][0]).is_file())

    def test_cancellation_still_cleans_up_and_writes_report(self):
        def interrupted(build, platform, work_dir=None):
            raise KeyboardInterrupt

        self.adapter.resolve_artifact = interrupted
        document = self._run()
        self.assertEqual(document["summary"]["overall"], "FAIL")
        self.assertIn("KeyboardInterrupt", document["summary"]["fatal_error"])
        self.assertEqual(document["cleanup"]["status"], statuses.PASS)
        self.assertTrue(Path(document["reports"]["sanitized"][0]).is_file())

    def test_performance_blocked_is_a_limitation_not_a_pass(self):
        with (
            patch.object(experiment, "get_adapter", return_value=self.adapter),
            patch.object(experiment, "load_manifest", return_value=self.manifest),
            patch.object(experiment, "resolve_suites", return_value=[("alpha", FakeSuite(), None)]),
            patch.object(
                experiment,
                "_run_performance",
                return_value={"status": statuses.BLOCKED, "products": [], "reason": "no telemetry"},
            ),
        ):
            document = experiment.run(
                build="fake-1",
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
