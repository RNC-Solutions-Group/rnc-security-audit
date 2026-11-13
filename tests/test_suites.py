"""Testing-suite registry and applicability tests."""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness import status as statuses
from harness.adapters.base import BuildArtifact, PLATFORMS
from harness.suites import resolve_suites, suite_keys
from harness.suites.base import combine_targets, platform_status
from harness.suites.leaky_repo import LeakyRepoSuite


class RegistryTests(unittest.TestCase):
    def test_initial_suite_catalog(self):
        self.assertEqual(
            set(suite_keys()),
            {
                "gitleaks",
                "git-history",
                "levain",
                "leaky-repo",
                "rnclab",
                "synthetic-filesystem",
            },
        )

    def test_all_resolves_to_adapter_supported_suites(self):
        adapter = SimpleNamespace(key="gitleaks", supported_suites=("gitleaks", "levain", "leaky-repo"))
        resolved = resolve_suites(["all"], adapter)
        self.assertEqual(
            [item[0] for item in resolved],
            ["levain", "leaky-repo"],
        )
        self.assertTrue(all(item[1] is not None for item in resolved))
        self.assertEqual(len(resolved), 2)

    def test_synthetic_history_control_remains_explicit_only(self):
        adapter = SimpleNamespace(key="gitleaks", supported_suites=("git-history",))
        resolved = resolve_suites(["git-history"], adapter)
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0][0], "git-history")
        self.assertIsNotNone(resolved[0][1])

    def test_gitleaks_legacy_fixture_remains_explicit_only(self):
        adapter = SimpleNamespace(key="gitleaks", supported_suites=("gitleaks",))
        resolved = resolve_suites(["gitleaks"], adapter)
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0][0], "gitleaks")
        self.assertIsNotNone(resolved[0][1])

    def test_unsupported_suite_is_reported_not_omitted(self):
        adapter = SimpleNamespace(key="gitleaks", supported_suites=("go",))
        resolved = resolve_suites(["gitleaks"], adapter)
        self.assertEqual(resolved[0][0], "gitleaks")
        self.assertIsNone(resolved[0][1])
        self.assertIn("does not support", resolved[0][2])

    def test_rnclab_is_opt_in_and_standalone(self):
        self.assertIn("rnclab", suite_keys())
        adapter = SimpleNamespace(
            key="gitleaks", supported_suites=("levain", "leaky-repo", "rnclab")
        )
        resolved = resolve_suites(["rnclab"], adapter)
        self.assertEqual(resolved[0][0], "rnclab")
        self.assertIsNotNone(resolved[0][1])
        all_resolved = resolve_suites(["all"], adapter)
        self.assertEqual([item[0] for item in all_resolved], ["levain", "leaky-repo"])

    def test_unknown_suite_is_reported(self):
        adapter = SimpleNamespace(key="gitleaks", supported_suites=("gitleaks",))
        resolved = resolve_suites(["not-a-suite"], adapter)
        self.assertIsNone(resolved[0][1])
        self.assertIn("unknown suite", resolved[0][2])


class StatusTests(unittest.TestCase):
    def test_combine_targets(self):
        self.assertEqual(
            combine_targets({"a": {"status": statuses.PASS}, "b": {"status": statuses.NOT_APPLICABLE}}),
            statuses.PASS,
        )
        self.assertEqual(
            combine_targets({"a": {"status": statuses.PASS}, "b": {"status": statuses.BLOCKED}}),
            statuses.BLOCKED,
        )

    def test_platform_status_for_build_failure(self):
        context = SimpleNamespace(adapter=SimpleNamespace(can_execute=lambda p: True))
        artifact = BuildArtifact(
            platform=PLATFORMS["windows-amd64"],
            status=statuses.FAIL,
            command=(),
            exit_code=1,
            duration_seconds=0.0,
            artifact_path=None,
            artifact_sha256=None,
            image_id=None,
            image_tag=None,
            version=None,
            version_status=statuses.NOT_APPLICABLE,
            stdout_sha256="",
            stderr_sha256="",
            error="build failed",
        )
        status, reason = platform_status(artifact, context=context)
        self.assertEqual(status, statuses.BLOCKED)
        self.assertIn("artifact", reason)


class ScoringReadinessTests(unittest.TestCase):
    def test_leaky_automatically_runs_history_when_supported(self):
        platform = PLATFORMS["windows-amd64"]
        artifact = BuildArtifact(
            platform=platform,
            status=statuses.PASS,
            command=(),
            exit_code=0,
            duration_seconds=1.0,
            artifact_path="gitleaks.exe",
            artifact_sha256="a" * 64,
            image_id=None,
            image_tag=None,
            version="v1",
            version_status=statuses.PASS,
            stdout_sha256="b" * 64,
            stderr_sha256="c" * 64,
            error=None,
        )
        prepared = SimpleNamespace(
            spec=SimpleNamespace(
                expected_count=175,
                expected_files=44,
                truth_manifest_path=Path("truth.json"),
                truth_manifest_sha256="d" * 64,
                truth_manifest_version="test",
                history_scope_path=None,
                history_scope_sha256=None,
                history_scope_version=None,
                revision="a" * 40,
                name="test",
                license_sha256="b" * 64,
            ),
            inventory={},
            source=Path("."),
            inventory_sha256="c" * 64,
        )
        context = SimpleNamespace(
            builds={platform.key: artifact},
            adapter=SimpleNamespace(
                can_execute=lambda p: True,
                supports_mode=lambda mode: mode == "git",
            ),
            config=SimpleNamespace(cache_dir=Path(".")),
            work_dir=Path("."),
            offline=True,
            timeout=1,
            cached=lambda key, factory: prepared,
        )
        lane = {
            "status": statuses.PASS,
            "legacy": {"expected_count": 175},
            "rich": {"metrics": {}, "exceptions": []},
            "rich_status": "COMPLETED",
            "metrics": {},
        }
        history_lane = {
            "status": statuses.PASS,
            "execution_status": statuses.PASS,
            "truth_status": "BLOCKED",
            "observed_findings": 1,
        }
        suite = LeakyRepoSuite()
        with (
            patch.object(suite, "_run_one", return_value=lane),
            patch.object(suite, "_run_history", return_value=history_lane) as history,
            patch("harness.suites.leaky_repo.leaky_truth.load_validated", side_effect=RuntimeError("bad truth")),
        ):
            result = suite.run(context)
        history.assert_called_once()
        self.assertEqual(result["summary"]["capabilities_auto"], ["filesystem", "history"])
        self.assertTrue(result["summary"]["history_selected"])


    def test_legacy_success_does_not_hide_rich_not_ready(self):
        platform = PLATFORMS["windows-amd64"]
        artifact = BuildArtifact(
            platform=platform,
            status=statuses.PASS,
            command=(),
            exit_code=0,
            duration_seconds=1.0,
            artifact_path="gitleaks.exe",
            artifact_sha256="a" * 64,
            image_id=None,
            image_tag=None,
            version="v1",
            version_status=statuses.PASS,
            stdout_sha256="b" * 64,
            stderr_sha256="c" * 64,
            error=None,
        )
        prepared = SimpleNamespace(
            spec=SimpleNamespace(
                expected_count=175,
                expected_files=44,
                truth_manifest_path=Path("truth.json"),
                truth_manifest_sha256="d" * 64,
                truth_manifest_version="test",
                history_scope_path=None,
                history_scope_sha256=None,
                history_scope_version=None,
                revision="a" * 40,
                name="test",
                license_sha256="b" * 64,
            ),
            inventory={},
            source=Path("."),
            inventory_sha256="c" * 64,
        )
        context = SimpleNamespace(
            builds={platform.key: artifact},
            adapter=SimpleNamespace(
                can_execute=lambda p: True,
                supports_mode=lambda mode: False,
            ),
            config=SimpleNamespace(cache_dir=Path(".")),
            work_dir=Path("."),
            offline=True,
            timeout=1,
            cached=lambda key, factory: prepared,
        )
        lane = {
            "status": statuses.PASS,
            "legacy": {"expected_count": 175},
            "rich": None,
            "rich_status": "NOT_READY",
            "metrics": {},
            "runs": [],
        }
        suite = LeakyRepoSuite()
        with (
            patch.object(suite, "_run_one", return_value=lane),
            patch("harness.suites.leaky_repo.leaky_truth.load_validated", side_effect=RuntimeError("bad truth")),
        ):
            result = suite.run(context)
        self.assertEqual(result["status"], statuses.PASS)
        self.assertEqual(result["targets"][platform.key]["status"], statuses.PASS)
        self.assertEqual(result["targets"][platform.key]["outcome"], "COMPLETED_UNSCORED")
        self.assertEqual(result["summary"]["legacy_score_status"], "COMPLETED")
        self.assertEqual(result["summary"]["rich_score_status"], "NOT_READY")


if __name__ == "__main__":
    unittest.main()
