"""Manifest validation tests against the real pinned manifest and deliberate faults."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.errors import ManifestError
from harness.manifest import load_leaky_repo, load_levain


class ManifestTests(unittest.TestCase):
    def test_real_manifest_is_pinned_and_consistent(self):
        manifest, spec = load_levain()
        self.assertEqual(spec.revision, "c130c321aa9046af17a6c876cb97e2ed71397110")
        self.assertEqual(spec.revision_tag, "v1")
        self.assertEqual(spec.license, "MIT")
        self.assertTrue(spec.enabled)
        self.assertEqual(spec.expected.negative_sections, 116)
        self.assertEqual(spec.expected.negative_lines, 866)
        self.assertEqual(spec.expected.positive_sections, 45)
        self.assertEqual(spec.expected.positive_secrets, 85)
        self.assertEqual(spec.expected.positive_hard_secrets, 3)
        self.assertIn("LICENSE", spec.artifact_sha256)
        self.assertIn("tp-corpus.json", spec.derived_sha256)
        self.assertEqual(manifest.schema_version, 1)

    def test_leaky_repo_manifest_is_pinned(self):
        manifest, spec = load_leaky_repo()
        self.assertEqual(spec.revision, "2e951359cac53addbee56437da3ffb546e3dfe24")
        self.assertEqual(spec.license, "MIT")
        self.assertEqual(spec.expected_count, 175)
        self.assertEqual(spec.expected_risk, 96)
        self.assertEqual(spec.expected_informative, 79)
        self.assertEqual(spec.expected_files, 44)
        self.assertTrue(spec.inventory_path.is_file())
        self.assertTrue(spec.truth_manifest_path.is_file())
        self.assertTrue(spec.history_scope_path.is_file())
        self.assertEqual(spec.truth_manifest_version, "rnc-leaky-truth-v1")
        self.assertEqual(spec.history_scope_version, "leaky-history-scope-v1")
        self.assertEqual(manifest.leaky_repo, spec)

    def test_disabled_entry_is_rejected(self):
        text = Path("datasets/manifest.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.toml"
            path.write_text(text.replace("enabled = true", "enabled = false"), encoding="utf-8")
            with self.assertRaises(ManifestError):
                load_levain(path)

    def test_short_revision_is_rejected(self):
        text = Path("datasets/manifest.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.toml"
            path.write_text(
                text.replace(
                    'revision = "c130c321aa9046af17a6c876cb97e2ed71397110"',
                    'revision = "abc123"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ManifestError):
                load_levain(path)

    def test_non_mit_license_is_rejected(self):
        text = Path("datasets/manifest.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.toml"
            path.write_text(text.replace('license = "MIT"', 'license = "Apache-2.0"', 1), encoding="utf-8")
            with self.assertRaises(ManifestError):
                load_levain(path)


if __name__ == "__main__":
    unittest.main()
