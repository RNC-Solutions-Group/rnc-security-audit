"""Integrity tests for the independently authored challenge corpus."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.cp3.challenge import build
from tools.cp3.materialize import materialize

ROOT = Path(__file__).resolve().parents[2]
TRUTH = ROOT / "tests/cp3/independent-challenge-truth.json"


class IndependentChallengeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="rnc-cp3-challenge-test-")
        cls.root, cls.document = build(Path(cls.temp.name))
        cls.committed = json.loads(TRUTH.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_manifest_is_reproducible_and_not_detector_generated(self):
        self.assertEqual(self.document, self.committed)
        self.assertFalse(self.document["provenance"]["detector_output_used"])
        self.assertIn("independently", self.document["provenance"]["authorship"])
        self.assertEqual(self.document["counts"]["expected_items"], 14)
        self.assertEqual(self.document["counts"]["files"], 9)

    def test_every_truth_hash_matches_the_authored_source(self):
        for item in self.document["items"]:
            data = (self.root / item["path"]).read_bytes()
            token = data[item["start_byte"] : item["end_byte"]]
            import hashlib

            self.assertEqual(hashlib.sha256(token).hexdigest(), item["secret_sha256"])
            self.assertEqual(item["line_start"], self.document_line(data, item["start_byte"]))
            self.assertTrue(item["finding_id"].startswith("challenge-"))

    @staticmethod
    def document_line(data: bytes, offset: int) -> int:
        line = 1
        for index, byte in enumerate(data):
            if index >= offset:
                break
            if byte == 10:
                line += 1
        return line

    def test_benign_lookalikes_are_present_and_not_expected(self):
        lookalikes = (self.root / "lookalikes.md").read_text(encoding="utf-8")
        self.assertIn("AKIAIOSFODNN7EXAMPLE", lookalikes)
        self.assertIn("BEGIN PUBLIC KEY", lookalikes)
        self.assertIn("JWT without context", lookalikes)
        self.assertEqual(
            [item["path"] for item in self.document["items"] if item["path"] == "lookalikes.md"],
            [],
        )

    def test_repeated_credentials_are_distinct_occurrences(self):
        repeated = [
            item for item in self.document["items"] if item["path"] == "repeated.txt"
        ]
        self.assertEqual(len(repeated), 2)
        self.assertNotEqual(
            (repeated[0]["start_byte"], repeated[0]["end_byte"]),
            (repeated[1]["start_byte"], repeated[1]["end_byte"]),
        )
        self.assertEqual(repeated[0]["secret_sha256"], repeated[1]["secret_sha256"])

    def test_resource_identifiers_are_never_expected_as_credentials(self):
        resource_prefixes = ("AIDA", "AGPA", "AIPA", "ANPA", "ANVA", "APKA", "AROA", "ASCA")
        for item in self.document["items"]:
            data = (self.root / item["path"]).read_bytes()
            token = data[item["start_byte"] : item["end_byte"]]
            self.assertFalse(
                any(token.startswith(prefix.encode()) for prefix in resource_prefixes),
                token,
            )

    def test_challenge_does_not_reuse_tier_fixture_tokens(self):
        with tempfile.TemporaryDirectory(prefix="rnc-cp3-tier-compare-") as temporary:
            tier2 = materialize("tier2", Path(temporary))
            tier3 = materialize("tier3", Path(temporary))
            known = set()
            for root in (tier2, tier3):
                for path in root.rglob("*"):
                    if path.is_file():
                        known.add(path.read_bytes())
            for item in self.document["items"]:
                data = (self.root / item["path"]).read_bytes()
                self.assertNotIn(data[item["start_byte"] : item["end_byte"]], known)


if __name__ == "__main__":
    unittest.main()
