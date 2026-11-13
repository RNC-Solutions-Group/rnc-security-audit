"""Run-owned workspace and scoped cleanup tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness import status as statuses
from harness.workspace import RunWorkspace, new_run_id


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_run_ids_and_workspaces_are_unique(self):
        one = RunWorkspace.create(new_run_id())
        two = RunWorkspace.create(new_run_id())
        try:
            self.assertNotEqual(one.root, two.root)
            self.assertTrue(one.created)
            self.assertTrue(two.created)
        finally:
            one.cleanup()
            two.cleanup()

    def test_successful_cleanup_removes_run_owned_workspace(self):
        workspace = RunWorkspace.create(f"cleanup-success-{new_run_id()}")
        workspace.prepare()
        workspace.evidence.mkdir(exist_ok=True)
        (workspace.evidence / "marker").write_text("owned", encoding="utf-8")
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch("harness.workspace.subprocess.run", return_value=completed):
            report = workspace.cleanup()
        self.assertEqual(report["status"], statuses.PASS)
        self.assertTrue(report["workspace_removed"])
        self.assertFalse(workspace.root.exists())

    def test_debug_retention_keeps_workspace_and_skips_docker(self):
        workspace = RunWorkspace.create(
            f"cleanup-retain-{new_run_id()}", retain=True
        )
        workspace.prepare()
        workspace.evidence.mkdir(exist_ok=True)
        (workspace.evidence / "marker").write_text("owned", encoding="utf-8")
        with patch("harness.workspace.subprocess.run") as docker:
            report = workspace.cleanup()
        self.assertTrue(report["retained"])
        self.assertTrue(workspace.root.exists())
        docker.assert_not_called()
        workspace.retain = False
        with patch("harness.workspace.subprocess.run") as docker:
            workspace.cleanup()

    def test_cleanup_removes_containers_but_never_images(self):
        workspace = RunWorkspace.create(f"cleanup-scoped-{new_run_id()}")
        workspace.prepare()
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if "ps" in argv:
                return SimpleNamespace(returncode=0, stdout="container-id\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            patch("harness.workspace.shutil.which", return_value="/usr/bin/docker"),
            patch("harness.workspace.subprocess.run", side_effect=fake_run),
        ):
            report = workspace.cleanup()
        self.assertEqual(report["containers_removed"], ["container-id"])
        self.assertEqual(report["images_removed"], [])
        self.assertTrue(any(f"label={workspace.docker_label}" in item for argv in calls for item in argv))
        self.assertFalse(any("image" in argv[:2] for argv in calls))
        self.assertFalse(any("rmi" in argv for argv in calls))
        self.assertFalse(any("prune" in item for argv in calls for item in argv))
        self.assertFalse(any("volume" in item for argv in calls for item in argv))

    def test_cleanup_failure_is_reported_blocked(self):
        workspace = RunWorkspace.create(f"cleanup-failure-{new_run_id()}")
        workspace.prepare()

        def fake_run(argv, **kwargs):
            if "ps" in argv:
                raise OSError("docker unavailable")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            patch("harness.workspace.shutil.which", return_value="/usr/bin/docker"),
            patch("harness.workspace.subprocess.run", side_effect=fake_run),
        ):
            report = workspace.cleanup()
        self.assertEqual(report["status"], statuses.BLOCKED)
        self.assertTrue(report["failures"])
        self.assertFalse(workspace.root.exists())


if __name__ == "__main__":
    unittest.main()
