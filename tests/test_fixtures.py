"""Pinned Gitleaks fixture acquisition and integrity tests (offline)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.errors import DatasetError
from harness.fixtures import DEFAULT_CACHE, prepare, summary
from harness.util import sha256_file

REVISION = "5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c"
CACHE_SOURCE = DEFAULT_CACHE / "gitleaks-fixtures" / REVISION / "source"


@unittest.skipUnless(CACHE_SOURCE.is_dir(), "pinned Gitleaks fixture cache is not prepared")
class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = prepare(offline=True)
        cls.summary = summary(cls.prepared)

    def test_expected_inventory_and_scenario_counts(self):
        self.assertEqual(self.prepared.revision, REVISION)
        self.assertEqual(self.summary["entries"], 228)
        self.assertEqual(self.summary["scenarios"], 23)
        self.assertEqual(self.summary["docker_applicable_fixtures"], 33)
        self.assertEqual(self.summary["physical_entries"], 223)
        self.assertEqual(self.summary["symlinks"], 1)
        self.assertEqual(
            self.prepared.lock["inventory_digest"],
            "cd7f05e76b4590ee738d4573f3ddb3c493142ecd1204bc15754a21d0e66f7345",
        )

    def test_manifest_and_lock_hashes_are_pinned(self):
        self.assertEqual(
            sha256_file(self.prepared.spec.manifest_path),
            self.prepared.spec.manifest_sha256,
        )
        self.assertEqual(
            sha256_file(self.prepared.spec.inventory_lock_path),
            self.prepared.spec.inventory_lock_sha256,
        )

    def test_modified_fixture_checkout_is_rejected(self):
        target = self.prepared.root / "testdata" / "repos" / "nogit" / "main.go"
        original = target.read_bytes()
        try:
            target.write_bytes(original + b"\n// tampered\n")
            with self.assertRaises(DatasetError):
                prepare(offline=True)
        finally:
            import subprocess

            subprocess.run(
                ["git", "-C", str(self.prepared.root), "checkout", "--", "testdata/repos/nogit/main.go"],
                check=True,
            )

    def test_offline_missing_cache_fails_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(DatasetError):
                prepare(cache_dir=Path(tmp) / "cache", offline=True)


if __name__ == "__main__":
    unittest.main()
