"""Pinned Leaky Repo dataset and count-based scoring tests."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from harness import leaky_repo
from harness.errors import DatasetError

CACHE = leaky_repo.DEFAULT_CACHE / "leaky-repo" / "2e951359cac53addbee56437da3ffb546e3dfe24" / "source"


@unittest.skipUnless(CACHE.is_dir(), "pinned Leaky Repo cache is not prepared")
class LeakyRepoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = leaky_repo.prepare(offline=True)

    def test_pinned_counts_and_inventory(self):
        self.assertEqual(self.prepared.revision, "2e951359cac53addbee56437da3ffb546e3dfe24")
        self.assertEqual(self.prepared.spec.expected_count, 175)
        self.assertEqual(self.prepared.spec.expected_risk, 96)
        self.assertEqual(self.prepared.spec.expected_informative, 79)
        self.assertEqual(self.prepared.spec.expected_files, 44)
        self.assertEqual(len(self.prepared.rows), 44)
        self.assertEqual(
            self.prepared.inventory["inventory_digest"],
            leaky_repo._canonical_inventory_digest(self.prepared.inventory),
        )

    def test_scan_tree_excludes_git_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = leaky_repo.copy_scan_tree(self.prepared, Path(tmp) / "scan")
            self.assertTrue((root / ".bashrc").is_file())
            self.assertFalse((root / ".git").exists())

    def test_count_scoring_separates_covered_excess_and_unlisted(self):
        findings = []
        for _ in range(2):
            findings.append(SimpleNamespace(file=".bashrc", rule_id="r"))
        for _ in range(12):
            findings.append(SimpleNamespace(file="db/dump.sql", rule_id="r"))
        findings.append(SimpleNamespace(file="not-labeled.txt", rule_id="r"))
        result = leaky_repo.score(
            findings, self.prepared, self.prepared.source
        )
        self.assertEqual(result["expected_count"], 175)
        self.assertEqual(result["observed_findings"], 15)
        self.assertEqual(result["covered_count"], 12)
        self.assertEqual(result["files_covered"], 2)
        self.assertEqual(result["excess_findings"], 2)
        self.assertEqual(result["unlisted_findings"], 1)
        self.assertNotIn("true_positives", result)
        self.assertNotIn("false_positives", result)

    def test_tampered_cached_file_is_rejected(self):
        target = self.prepared.source / ".bashrc"
        original = target.read_bytes()
        try:
            target.write_bytes(original + b"\n# tamper\n")
            with self.assertRaises(DatasetError):
                leaky_repo.prepare(offline=True)
        finally:
            subprocess.run(
                ["git", "-C", str(self.prepared.source), "checkout", "--", ".bashrc"],
                check=True,
            )

    def test_offline_missing_cache_fails_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(DatasetError):
                leaky_repo.prepare(cache_dir=Path(tmp) / "cache", offline=True)


if __name__ == "__main__":
    unittest.main()
