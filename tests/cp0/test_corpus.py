"""Independent synthetic truth, generator reproducibility and edge-corpus tests."""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.cp0.contracts import ContractViolation, sha256_bytes
from tools.cp0.corpus import (
    load_v0,
    load_v1,
    manifest_digest,
    target_findings,
    validate_manifest,
)
from tools.cp0.generate_corpus import build
from tools.cp0.generate_edge_corpus import build as build_edge


ROOT = Path(__file__).resolve().parents[2]
V1 = ROOT / "tests/fixtures/synthetic-v1"


class CP0CorpusTests(unittest.TestCase):
    def test_v0_baseline_claims(self):
        loaded = load_v0()
        self.assertEqual(loaded["summary"]["targets"], 9)
        self.assertEqual(loaded["summary"]["known_markers"], 14)
        self.assertEqual(loaded["summary"]["expected_findings"], 13)
        self.assertEqual(loaded["summary"]["verified_blocked_targets"], 1)

    def test_v1_expanded_claims(self):
        loaded = load_v1()
        self.assertEqual(loaded["summary"]["targets"], 21)
        self.assertEqual(loaded["summary"]["known_markers"], 26)
        self.assertEqual(loaded["summary"]["expected_findings"], 25)
        self.assertEqual(loaded["summary"]["expected_exempted"], 2)
        self.assertEqual(loaded["summary"]["uninspected_targets"], 1)
        labels = {label for target in loaded["targets"] for label in target["labels"]}
        for required in (
            "unicode", "crlf", "cr-only", "binary", "malformed-utf8", "empty",
            "overlapping-rules", "duplicate-occurrences", "pre-scan-block",
            "post-scan-exemption", "multiline", "nested-path", "eof",
        ):
            self.assertIn(required, labels)

    def test_blocked_and_uninspected_truth_is_not_scored_as_expected(self):
        loaded = load_v1()
        targets = {target["id"]: target for target in loaded["targets"]}
        blocked = target_findings(targets["blocked"], loaded["contents"]["blocked"], loaded["summary"]["version"])
        uninspected = target_findings(targets["uninspected-optional"], loaded["contents"]["uninspected-optional"], loaded["summary"]["version"])
        self.assertEqual(len(blocked), 1)
        self.assertEqual(len(uninspected), 1)
        self.assertNotIn("blocked", {item["target_id"] for item in loaded["expected_findings"]})
        self.assertNotIn("uninspected-optional", {item["target_id"] for item in loaded["expected_findings"]})

    def test_overlap_produces_two_accountable_findings(self):
        loaded = load_v1()
        target = next(target for target in loaded["targets"] if target["id"] == "overlapping-rules")
        findings = target_findings(target, loaded["contents"][target["id"]], loaded["summary"]["version"])
        self.assertEqual(len(findings), 2)
        self.assertEqual({item["rule_id"] for item in findings}, {"synthetic-generic", "synthetic-overlap"})
        self.assertEqual(len({(item["start_byte"], item["end_byte"]) for item in findings}), 1)

    def test_manifest_digest_is_stable(self):
        loaded = load_v1()
        self.assertEqual(manifest_digest(loaded["manifest"]), loaded["summary"]["manifest_sha256"])

    def test_generated_full_corpus_is_reproducible_and_complete(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = build(Path(first), 1000)
            two = build(Path(second), 1000)
            self.assertEqual(one, two)
            self.assertEqual(one["target_count"], 1000)
            self.assertEqual(sum(len(target["expected_findings"]) for target in one["targets"]), 2000)
            self.assertEqual(sum(target["scope"] == "VERIFIED_BLOCKED" for target in one["targets"]), 35)
            for target in one["targets"]:
                data = (Path(first) / target["relative_path"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), target["sha256"])
                for expected in target["expected_findings"]:
                    self.assertEqual(
                        data[expected["start_byte"]:expected["end_byte"]].decode("ascii"),
                        expected["marker"],
                    )

    def test_generated_corpus_truth_is_independent_of_scanner_output(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = build(Path(temp), 50)
            for target in manifest["targets"]:
                data = (Path(temp) / target["relative_path"]).read_bytes()
                self.assertEqual(
                    hashlib.sha256(data).hexdigest(),
                    target["sha256"],
                )
            self.assertEqual(sum(len(target["expected_findings"]) for target in manifest["targets"]), 100)

    def test_corpus_tamper_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / "synthetic-v1"
            shutil.copytree(V1, copied)
            clean = copied / "clean.txt"
            clean.write_bytes(clean.read_bytes() + b"RNC_SYNTH_KEY_UNACCOUNTED\n")
            with self.assertRaises(ContractViolation):
                validate_manifest(copied / "manifest.json", require_floor=True)

    def test_edge_corpus_is_deterministic_and_declares_oversize_gap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = build_edge(root)
            second = build_edge(root)
            self.assertEqual(first, second)
            loaded = validate_manifest(root / "manifest.json")
            self.assertEqual(loaded["summary"]["targets"], 2)
            self.assertEqual(loaded["summary"]["uninspected_targets"], 1)
            self.assertEqual(loaded["summary"]["expected_findings"], 3)
            large = next(target for target in loaded["targets"] if target["id"] == "large-2m")
            self.assertEqual(large["byte_length"], 2 * 1024 * 1024)
            self.assertEqual(len(loaded["contents"]["large-2m"]), large["byte_length"])
            self.assertEqual(sha256_bytes(loaded["contents"]["large-2m"]), "sha256:" + large["sha256"])

    def test_marker_values_are_harmless_synthetic_prefixes(self):
        for loaded in (load_v0(), load_v1()):
            for target in loaded["targets"]:
                for expected in target["expected"]:
                    self.assertTrue(expected["marker"].startswith("RNC_SYNTH_KEY_"))


if __name__ == "__main__":
    unittest.main()
