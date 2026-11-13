"""Prepare/cache/verify tests using a local Git repository (no network)."""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from harness.dataset import load_corpora, prepare
from harness.errors import DatasetError
from harness.util import sha256_bytes, sha256_file
from tests.support import write_mini_repo


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.fixture = write_mini_repo(self.root / "fixture")
        self.cache = self.root / "cache"

    def tearDown(self):
        self._tmp.cleanup()

    def _prepare(self, **kwargs):
        return prepare(self.fixture.manifest, self.cache, **kwargs)

    def test_prepare_verifies_and_loads_published_counts(self):
        prepared = self._prepare()
        self.assertEqual(prepared.spec.revision, self.fixture.revision)
        self.assertEqual(
            prepared.manifest_sha256,
            hashlib.sha256(
                self.fixture.manifest.read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest(),
        )
        corpora = load_corpora(prepared)
        self.assertEqual(corpora.negative_counts["sections"], 2)
        self.assertEqual(corpora.negative_counts["lines"], 4)
        self.assertEqual(corpora.positive_counts["secrets"], 3)
        self.assertEqual(corpora.positive_counts["hard_secrets"], 1)
        self.assertEqual(prepared.derived_hashes["tp-corpus.json"], prepared.spec.derived_sha256["tp-corpus.json"])

    def test_fresh_clone_checks_out_pinned_commit_when_default_branch_advanced(self):
        # Simulate upstream advancing after the manifest was pinned.
        (self.fixture.repo / "upstream-only.txt").write_text("newer\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.fixture.repo), "add", "-A"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(self.fixture.repo),
                "-c",
                "user.name=CP1 Fixture",
                "-c",
                "user.email=cp1@example.invalid",
                "commit",
                "-q",
                "-m",
                "upstream advance",
            ],
            check=True,
        )
        advanced = subprocess.run(
            ["git", "-C", str(self.fixture.repo), "rev-parse", "HEAD"],
            capture_output=True,
            check=True,
            text=True,
        ).stdout.strip()
        self.assertNotEqual(advanced, self.fixture.revision)
        prepared = self._prepare()
        self.assertEqual(self._git_head(prepared.source), self.fixture.revision)
        self.assertFalse((prepared.source / "upstream-only.txt").exists())
        corpora = load_corpora(prepared)
        self.assertEqual(corpora.positive_counts["secrets"], 3)

    @staticmethod
    def _git_head(source: Path) -> str:
        import subprocess

        return subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            capture_output=True,
            check=True,
            text=True,
        ).stdout.strip()

    def test_second_prepare_works_offline(self):
        self._prepare()
        prepared = self._prepare(offline=True)
        self.assertEqual(prepared.spec.revision, self.fixture.revision)

    def test_offline_without_cache_fails_without_cloning(self):
        with self.assertRaises(DatasetError):
            self._prepare(offline=True)
        self.assertFalse((self.cache / "levain" / self.fixture.revision / "source").exists())

    def test_corrupted_derived_artifact_is_repaired_from_pinned_blob(self):
        prepared = self._prepare()
        derived = prepared.derived / "tp-corpus.json"
        derived.write_bytes(b'{"corrupted": true}')
        repaired = self._prepare(offline=True)
        from harness.util import sha256_file

        self.assertEqual(
            sha256_file(repaired.derived / "tp-corpus.json"),
            repaired.spec.derived_sha256["tp-corpus.json"],
        )

    def test_modified_source_tree_is_detected_offline(self):
        prepared = self._prepare()
        (prepared.source / "fp-corpus.json").write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(DatasetError):
            self._prepare(offline=True)

    def test_tampered_manifest_hash_is_rejected(self):
        self._prepare()
        text = self.fixture.manifest.read_text(encoding="utf-8")
        original = self.fixture.revision
        # Alter the fp-corpus artifact hash, leaving a syntactically valid manifest.
        lines = []
        for line in text.splitlines():
            if line.startswith('"fp-corpus.json" = "'):
                line = '"fp-corpus.json" = "' + "0" * 64 + '"'
            lines.append(line)
        tampered = self.root / "tampered.toml"
        tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(DatasetError):
            prepare(tampered, self.cache, offline=True)
        self.assertEqual(self.fixture.revision, original)

    def test_refresh_recovers_a_modified_cache(self):
        prepared = self._prepare()
        (prepared.source / "README.md").write_text("tampered\n", encoding="utf-8")
        refreshed = self._prepare(refresh=True)
        self.assertEqual(
            sha256_bytes(refreshed.read_blob("README.md")),
            refreshed.spec.artifact_sha256["README.md"],
        )
        self.assertEqual(sha256_file(refreshed.source / "README.md"), refreshed.spec.artifact_sha256["README.md"])


if __name__ == "__main__":
    unittest.main()
