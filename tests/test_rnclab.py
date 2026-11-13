"""Certified RNC Synthetic Secrets Lab v3 integration and identity tests."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from harness import rnclab
from harness.contracts import NormalizedFinding

CACHE = Path("datasets/cache/rnc-synth-lab")


def _finding(item, text: str, *, path: str | None = None, line: int | None = None):
    return NormalizedFinding(
        file=path if path is not None else item.source_path,
        line=line if line is not None else item.line,
        rule_id="test-rule",
        secret_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        match_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        secret_text=text,
        match_text=text,
    )


@unittest.skipUnless(CACHE.is_dir(), "certified RNC Lab cache is not prepared")
class RncLabLoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = rnclab.load(CACHE)

    def test_manifest_oracle_and_source_identity(self):
        self.assertEqual(self.dataset.manifest_sha256, rnclab.EXPECTED_MANIFEST_SHA256)
        self.assertEqual(self.dataset.oracle_sha256, rnclab.EXPECTED_ORACLE_SHA256)
        self.assertEqual(len(self.dataset.items), 1602)
        self.assertEqual(self.dataset.counts("filesystem"), {
            "POSITIVE": 640,
            "NEGATIVE_ORDINARY": 330,
            "NEGATIVE_TRAP": 162,
            "INFORMATIVE": 150,
            "TOTAL": 1282,
        })
        self.assertEqual(self.dataset.counts("git"), {
            "POSITIVE": 160,
            "NEGATIVE_ORDINARY": 70,
            "NEGATIVE_TRAP": 40,
            "INFORMATIVE": 50,
            "TOTAL": 320,
        })
        validation = self.dataset.source_validation
        self.assertEqual(validation["status"], "PASS")
        self.assertEqual(validation["checked_items"], 1602)
        self.assertEqual(validation["checked_spans"], 1602)
        self.assertEqual(len({item.group_id for item in self.dataset.positives("filesystem")}), 366)
        self.assertEqual(len({item.group_id for item in self.dataset.positives("git")}), 130)

    def test_frozen_verification_is_independent(self):
        verified = rnclab.verify_frozen(self.dataset)
        self.assertEqual(verified["status"], "PASS")
        self.assertTrue(verified["manifest_unchanged"])
        self.assertTrue(verified["oracle_unchanged"])
        self.assertTrue(verified["corpus_unchanged"])


@unittest.skipUnless(CACHE.is_dir(), "certified RNC Lab cache is not prepared")
class RncLabIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = rnclab.load(CACHE)
        cls.items = {item.item_id: item for item in cls.dataset.items}

    def _value(self, item):
        if item.lane == "git":
            raise unittest.SkipTest("filesystem source item required")
        data = (self.dataset.filesystem_root / item.source_path).read_bytes()
        return data[item.byte_start : item.byte_end].decode("utf-8")

    def test_exact_positive_is_tp_and_repeat_is_duplicate(self):
        item = self.items["RNC-SL-POS-000001"]
        value = self._value(item)
        first = _finding(item, value)
        repeat = _finding(item, value)
        result = rnclab.score_findings(
            self.dataset, "filesystem", [first, repeat]
        )
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertEqual(result["metrics"]["duplicate_count"], 1)
        self.assertEqual(result["metrics"]["observed_findings"], 2)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_exact_negative_is_fp_not_tp(self):
        item = next(
            value
            for value in self.dataset.items
            if value.lane == "filesystem"
            and value.classification == "NEGATIVE_TRAP"
            and value.normalization == "identity_direct"
            and value.container_kind == "file"
        )
        finding = _finding(item, self._value(item))
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["verified_false_positive_alert_count"], 1)
        self.assertEqual(result["metrics"]["unique_verified_nonsecret_exposures"], 1)

    def test_public_only_material_cannot_earn_private_key_tp(self):
        item = next(
            value
            for value in self.dataset.items
            if value.lane == "filesystem"
            and value.is_positive
            and value.match_policy == "private_key_material_required"
            and value.public_identity_sha256
            and value.container_kind == "file"
        )
        public_text = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="private-key",
            secret_sha256=item.public_identity_sha256,
            match_sha256=item.public_identity_sha256,
            secret_text=public_text,
            match_text=public_text,
        )
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertGreaterEqual(result["metrics"]["unverified_evidence_count"], 1)
        self.assertNotIn(item.item_id, result["matched_positive_ids"])

    def test_docker_scan_path_prefix_is_the_lane_root(self):
        item = self.items["RNC-SL-POS-000001"]
        finding = _finding(
            item,
            self._value(item),
            path=f"/scan/{item.source_path}",
        )
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_unknown_path_stays_pending(self):
        item = self.items["RNC-SL-POS-000001"]
        finding = _finding(item, self._value(item), path="not/in/lab.env")
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["unmatched_pending_review_count"], 1)

    def test_all_observed_findings_are_accounted(self):
        item = self.items["RNC-SL-POS-000001"]
        finding = _finding(item, self._value(item))
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(
            result["metrics"]["accounted_finding_count"],
            result["metrics"]["observed_findings"],
        )


if __name__ == "__main__":
    unittest.main()
