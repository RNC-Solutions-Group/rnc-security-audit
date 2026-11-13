"""Exact-commit disposable source acquisition tests."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from harness.errors import HarnessError
from harness.source import acquire, ensure_version_tag
from harness.util import remove_tree


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout.strip()


def make_repo(root: Path) -> tuple[str, str, str]:
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "user.email", "test@example.invalid")
    (root / "main.go").write_text("package main\n", encoding="utf-8")
    (root / "README.md").write_text("one\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "one")
    first = _git(root, "rev-parse", "HEAD")
    (root / "README.md").write_text("two\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "two")
    second = _git(root, "rev-parse", "HEAD")
    (root / "README.md").write_text("three\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-m", "three")
    third = _git(root, "rev-parse", "HEAD")
    return first, second, third


class SourceTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = self.root / "repo"
        self.first, self.second, self.third = make_repo(self.repo)

    def tearDown(self):
        self._tmp.cleanup()

    def test_acquires_exact_commit_and_verifies_head(self):
        checkout = acquire(str(self.repo), self.second, self.root / "checkout")
        self.assertEqual(checkout.commit, self.second)
        self.assertEqual(checkout.head, self.second)
        self.assertTrue(checkout.head_verified)
        self.assertEqual(_git(checkout.path, "rev-parse", "HEAD"), self.second)
        self.assertEqual(_git(checkout.path, "status", "--porcelain"), "")

    def test_different_commits_are_separate_disposable_checkouts(self):
        one = acquire(str(self.repo), self.first, self.root / "one")
        two = acquire(str(self.repo), self.second, self.root / "two")
        self.assertNotEqual(one.path, two.path)
        self.assertEqual(one.commit, self.first)
        self.assertEqual(two.commit, self.second)
        self.assertNotEqual(
            (one.path / "README.md").read_text(encoding="utf-8"),
            (two.path / "README.md").read_text(encoding="utf-8"),
        )

    def test_incorrect_commit_fails_cleanly_and_never_substitutes_head(self):
        with self.assertRaises(HarnessError):
            acquire(str(self.repo), "0" * 40, self.root / "bad")
        self.assertFalse((self.root / "bad" / "main.go").exists())

    def test_short_or_moving_identity_is_rejected(self):
        with self.assertRaises(HarnessError):
            acquire(str(self.repo), "main", self.root / "branch")
        with self.assertRaises(HarnessError):
            acquire(str(self.repo), self.third[:12], self.root / "short")

    def test_invalid_repository_fails_cleanly(self):
        with self.assertRaises(HarnessError):
            acquire(str(self.root / "missing-repo"), self.third, self.root / "none")

    def test_version_tag_fallback_does_not_modify_tracked_files(self):
        checkout = acquire(str(self.repo), self.third, self.root / "tagged")
        tag = ensure_version_tag(checkout, "v0.0.0-test")
        self.assertTrue(tag)
        self.assertEqual(_git(checkout.path, "status", "--porcelain"), "")
        self.assertEqual(_git(checkout.path, "rev-parse", "HEAD"), self.third)


if __name__ == "__main__":
    unittest.main()
