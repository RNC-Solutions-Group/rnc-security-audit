"""Local operator artifact manifest and verification tests."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness import status as statuses
from harness.adapters import get_adapter
from harness.adapters.base import PLATFORMS
from harness.artifacts import (
    ArtifactManifestError,
    load_manifest,
    verify_artifact,
)
from harness.util import sha256_file


def _toml(builds: list[dict]) -> str:
    lines = ["schema_version = 1", ""]
    for build in builds:
        lines.append("[[builds]]")
        for key, value in build.items():
            if isinstance(value, list):
                rendered = ", ".join(f'"{item}"' for item in value)
                lines.append(f"{key} = [{rendered}]")
            else:
                lines.append(f'{key} = "{value}"')
        lines.append("")
    return "\n".join(lines)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, builds: list[dict], *, name: str = "manifest.toml") -> Path:
        path = self.run_dir / name
        path.write_text(_toml(builds), encoding="utf-8")
        return path

    def _executable_build(self, **overrides) -> dict:
        executable = self.run_dir / "scanner.exe"
        executable.write_bytes(b"operator-provided scanner")
        build = {
            "id": "scanner-cp4a",
            "scanner": "rnc",
            "version": "0.1.0",
            "source_commit": "93b4dda909cb3b41606a4d0f36c8ef9d06b77fde",
            "executable": "scanner.exe",
            "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "capabilities": ["filesystem", "git-history"],
        }
        build.update(overrides)
        return build

    def _docker_build(self, **overrides) -> dict:
        build = {
            "id": "scanner-cp4a",
            "scanner": "rnc",
            "version": "0.1.0",
            "source_commit": "93b4dda909cb3b41606a4d0f36c8ef9d06b77fde",
            "docker_image": "rnc-scanner:cp4a",
            "docker_image_id": "sha256:" + "a" * 64,
            "capabilities": ["filesystem"],
        }
        build.update(overrides)
        return build

    def test_manifest_parses_multiple_registered_revisions(self):
        self._write(
            [
                self._executable_build(id="rnc-cp3", capabilities=["filesystem"]),
                self._executable_build(id="rnc-cp4a"),
                self._executable_build(
                    id="gitleaks-5f6ec56",
                    scanner="gitleaks",
                    source_commit="5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c",
                ),
            ]
        )
        manifest = load_manifest(self.run_dir / "manifest.toml")
        self.assertEqual([item.id for item in manifest.builds], ["rnc-cp3", "rnc-cp4a", "gitleaks-5f6ec56"])
        self.assertEqual(manifest.select("rnc-cp3").capabilities, ("filesystem",))
        self.assertTrue(manifest.select("rnc-cp4a").supports("git-history"))
        self.assertEqual(manifest.sha256, sha256_file(self.run_dir / "manifest.toml"))
        with self.assertRaises(ArtifactManifestError):
            manifest.select("missing")
        with self.assertRaises(ArtifactManifestError):
            manifest.select(None)

    def test_duplicate_build_id_is_rejected(self):
        self._write([self._executable_build(), self._executable_build()])
        with self.assertRaises(ArtifactManifestError):
            load_manifest(self.run_dir / "manifest.toml")

    def test_manifest_path_cannot_escape_run_directory(self):
        self._write([self._executable_build(executable="../outside.exe")])
        with self.assertRaises(ArtifactManifestError):
            load_manifest(self.run_dir / "manifest.toml")

    def test_executable_verification_passes_and_reports_identity(self):
        self._write([self._executable_build()])
        manifest = load_manifest(self.run_dir / "manifest.toml")
        build = manifest.select("scanner-cp4a")
        verified = verify_artifact(build, PLATFORMS["windows-amd64"])
        self.assertEqual(verified.status, statuses.PASS)
        self.assertEqual(verified.executable_sha256, build.executable_sha256)
        artifact = get_adapter("gitleaks").resolve_artifact(
            build, PLATFORMS["windows-amd64"]
        )
        self.assertEqual(artifact.status, statuses.PASS)
        self.assertEqual(artifact.metadata["build_id"], "scanner-cp4a")
        self.assertTrue(artifact.metadata["executable_hash_verified"])
        self.assertEqual(
            artifact.metadata["source_commit"],
            "93b4dda909cb3b41606a4d0f36c8ef9d06b77fde",
        )

    def test_missing_executable_is_blocked(self):
        build = self._executable_build()
        (self.run_dir / "scanner.exe").unlink()
        self._write([build])
        manifest = load_manifest(self.run_dir / "manifest.toml")
        verified = verify_artifact(
            manifest.select("scanner-cp4a"), PLATFORMS["windows-amd64"]
        )
        self.assertEqual(verified.status, statuses.BLOCKED)
        self.assertIn("missing", verified.error)

    def test_incorrect_executable_hash_is_blocked_with_both_values(self):
        build = self._executable_build(executable_sha256="0" * 64)
        self._write([build])
        manifest = load_manifest(self.run_dir / "manifest.toml")
        verified = verify_artifact(
            manifest.select("scanner-cp4a"), PLATFORMS["windows-amd64"]
        )
        self.assertEqual(verified.status, statuses.BLOCKED)
        self.assertIn("SHA-256 mismatch", verified.error)
        self.assertIn("0" * 64, verified.error)
        self.assertIn(sha256_file(self.run_dir / "scanner.exe"), verified.error)

    def test_docker_verification_passes_without_pull(self):
        self._write([self._docker_build()])
        manifest = load_manifest(self.run_dir / "manifest.toml")
        build = manifest.select("scanner-cp4a")
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(
                returncode=0,
                stdout="sha256:" + "a" * 64 + "|linux/amd64\n",
                stderr="",
            )

        with (
            patch("harness.artifacts.shutil.which", return_value="/usr/bin/docker"),
            patch("harness.artifacts.subprocess.run", side_effect=fake_run),
        ):
            verified = verify_artifact(build, PLATFORMS["docker-linux-amd64"])
        self.assertEqual(verified.status, statuses.PASS)
        self.assertEqual(verified.image_id, "sha256:" + "a" * 64)
        self.assertEqual(verified.image_architecture, "linux/amd64")
        self.assertEqual(calls[0][:4], ["docker", "image", "inspect", "rnc-scanner:cp4a"])
        self.assertFalse(any("pull" in item for argv in calls for item in argv))

    def test_missing_docker_image_is_blocked(self):
        self._write([self._docker_build()])
        manifest = load_manifest(self.run_dir / "manifest.toml")
        with (
            patch("harness.artifacts.shutil.which", return_value="/usr/bin/docker"),
            patch(
                "harness.artifacts.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=1, stdout="", stderr="Error: No such image"
                ),
            ),
        ):
            verified = verify_artifact(
                manifest.select("scanner-cp4a"), PLATFORMS["docker-linux-amd64"]
            )
        self.assertEqual(verified.status, statuses.BLOCKED)
        self.assertIn("not present", verified.error)
        self.assertIn("no pull", verified.error)

    def test_incorrect_docker_image_id_is_blocked(self):
        self._write([self._docker_build(docker_image_id="sha256:" + "b" * 64)])
        manifest = load_manifest(self.run_dir / "manifest.toml")
        with (
            patch("harness.artifacts.shutil.which", return_value="/usr/bin/docker"),
            patch(
                "harness.artifacts.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout="sha256:" + "a" * 64 + "|linux/amd64\n",
                    stderr="",
                ),
            ),
        ):
            verified = verify_artifact(
                manifest.select("scanner-cp4a"), PLATFORMS["docker-linux-amd64"]
            )
        self.assertEqual(verified.status, statuses.BLOCKED)
        self.assertIn("image ID mismatch", verified.error)
        self.assertIn("sha256:" + "b" * 64, verified.error)

    def test_wrong_docker_architecture_is_blocked(self):
        self._write([self._docker_build()])
        manifest = load_manifest(self.run_dir / "manifest.toml")
        with (
            patch("harness.artifacts.shutil.which", return_value="/usr/bin/docker"),
            patch(
                "harness.artifacts.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=0,
                    stdout="sha256:" + "a" * 64 + "|linux/arm64\n",
                    stderr="",
                ),
            ),
        ):
            verified = verify_artifact(
                manifest.select("scanner-cp4a"), PLATFORMS["docker-linux-amd64"]
            )
        self.assertEqual(verified.status, statuses.BLOCKED)
        self.assertIn("architecture", verified.error)

    def test_rnc_requires_and_verifies_registered_rules(self):
        rules = self.run_dir / "rules" / "rnc-providers-v1.json"
        rules.parent.mkdir()
        rules.write_text(
            '{"ruleset_id":"rnc-providers-v1","ruleset_version":"1",'
            '"rules":[{"rule_id":"r"}]}\n',
            encoding="utf-8",
        )
        build = self._executable_build(
            rules_file="rules/rnc-providers-v1.json",
            rules_sha256=sha256_file(rules),
        )
        self._write([build])
        manifest = load_manifest(self.run_dir / "manifest.toml")
        adapter = get_adapter("rnc")
        artifact = adapter.resolve_artifact(
            manifest.select("scanner-cp4a"), PLATFORMS["windows-amd64"]
        )
        self.assertEqual(artifact.status, statuses.PASS)
        self.assertEqual(artifact.metadata["rules_sha256"], sha256_file(rules))
        self.assertEqual(artifact.metadata["ruleset"]["ruleset_id"], "rnc-providers-v1")

    def test_rnc_without_rules_is_blocked(self):
        self._write([self._executable_build()])
        manifest = load_manifest(self.run_dir / "manifest.toml")
        artifact = get_adapter("rnc").resolve_artifact(
            manifest.select("scanner-cp4a"), PLATFORMS["windows-amd64"]
        )
        self.assertEqual(artifact.status, statuses.BLOCKED)
        self.assertIn("rules_file", artifact.error)

    def test_mismatched_rules_hash_is_blocked(self):
        rules = self.run_dir / "rules" / "rnc-providers-v1.json"
        rules.parent.mkdir()
        rules.write_text('{"rules":[{"rule_id":"r"}]}\n', encoding="utf-8")
        self._write(
            [
                self._executable_build(
                    rules_file="rules/rnc-providers-v1.json",
                    rules_sha256="0" * 64,
                )
            ]
        )
        manifest = load_manifest(self.run_dir / "manifest.toml")
        verified = verify_artifact(
            manifest.select("scanner-cp4a"), PLATFORMS["windows-amd64"]
        )
        self.assertEqual(verified.status, statuses.BLOCKED)
        self.assertIn("rules/configuration SHA-256 mismatch", verified.error)

    def test_tracked_example_manifest_is_well_formed(self):
        manifest = load_manifest(Path("run-manifest.example.toml"))
        self.assertEqual(
            [item.id for item in manifest.builds],
            ["gitleaks-5f6ec56", "betterleaks-5eab483", "rnc-cp3", "rnc-cp4a"],
        )
        self.assertTrue(manifest.select("rnc-cp4a").supports("git-history"))


if __name__ == "__main__":
    unittest.main()
