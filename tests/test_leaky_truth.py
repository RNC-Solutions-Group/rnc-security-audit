"""RNC Leaky Repo truth-manifest validation tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from harness import leaky_truth
from harness.util import sha256_file

ROOT = Path("datasets/cache/leaky-repo/2e951359cac53addbee56437da3ffb546e3dfe24/source")
MANIFEST = Path("datasets/leaky-repo.rnc-truth.json")


@unittest.skipUnless(ROOT.is_dir(), "pinned Leaky Repo cache is not prepared")
class LeakyTruthTests(unittest.TestCase):
    def test_manifest_is_pinned_and_line_complete(self):
        manifest = leaky_truth.load_validated(MANIFEST, ROOT)
        self.assertEqual(manifest.integrity["status"], "PASS")
        self.assertEqual(manifest.integrity["verified_item_count"], 175)
        self.assertEqual(manifest.integrity["verified_file_count"], 44)
        self.assertEqual(manifest.integrity["verified_risk"], 88)
        self.assertEqual(manifest.integrity["verified_informative"], 87)
        self.assertEqual(manifest.integrity["category_reconciliation"]["status"], "CONFLICT")
        self.assertEqual(len(manifest.category_reconciliation["conflict_rows"]), 6)
        self.assertEqual(sum(item.category_conflict for item in manifest.items), 31)
        self.assertEqual(
            sha256_file(MANIFEST),
            "621d3ad39929b7143e0c799883da03123d8ca6da2f174ef330aec3590365c8a9",
        )

    def test_fingerprint_tamper_is_rejected(self):
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        document["items"][0]["fingerprint_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "truth.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            manifest = leaky_truth.load_validated(path, ROOT)
            self.assertEqual(manifest.integrity["status"], "FAIL")
            self.assertIn("fingerprint mismatch", manifest.integrity["reason"])

    def test_missing_source_file_is_rejected(self):
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        document["items"][0]["path"] = "not-present.txt"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "truth.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            manifest = leaky_truth.load_validated(path, ROOT)
            self.assertEqual(manifest.integrity["status"], "FAIL")
            self.assertIn("missing source file", manifest.integrity["reason"])


if __name__ == "__main__":
    unittest.main()
