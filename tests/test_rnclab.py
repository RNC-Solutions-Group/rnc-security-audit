"""Certified RNC Synthetic Secrets Lab v3 integration and identity tests."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from harness import rnclab
from harness.contracts import NormalizedFinding

CACHE = Path("datasets/cache/rnc-synth-lab")


def _finding(
    item,
    text: str,
    *,
    path: str | None = None,
    line: int | None = None,
    byte_start: int | None = None,
    byte_end: int | None = None,
):
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return NormalizedFinding(
        file=path if path is not None else item.source_path,
        line=line if line is not None else item.line,
        rule_id="test-rule",
        secret_sha256=digest,
        match_sha256=digest,
        byte_start=byte_start,
        byte_end=byte_end,
        secret_text=text,
        match_text=text,
    )


def _span(dataset, item) -> bytes:
    if item.lane == "git":
        import subprocess

        blob = subprocess.check_output(
            [
                "git",
                "-C",
                str(dataset.history_root),
                "show",
                f"{item.source_commit}:{item.source_path}",
            ]
        )
        return blob[item.byte_start : item.byte_end]
    data = (dataset.filesystem_root / item.source_path).read_bytes()
    return data[item.byte_start : item.byte_end]


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

    def test_unknown_path_is_source_occurrence_near_miss(self):
        item = self.items["RNC-SL-POS-000001"]
        finding = _finding(item, self._value(item), path="not/in/lab.env")
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["near_miss_count"], 1)
        self.assertEqual(result["metrics"]["near_miss_reason_counts"], {
            "SOURCE_OCCURRENCE_MISMATCH": 1
        })
        self.assertEqual(result["metrics"]["unmatched_pending_review_count"], 0)

    def test_all_observed_findings_are_accounted(self):
        item = self.items["RNC-SL-POS-000001"]
        finding = _finding(item, self._value(item))
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(
            result["metrics"]["accounted_finding_count"],
            result["metrics"]["observed_findings"],
        )

    def test_base64_exact_span_is_tp_without_plaintext(self):
        item = next(
            value
            for value in self.dataset.items
            if value.lane == "filesystem"
            and value.is_positive
            and value.normalization == "base64_decode_text"
            and value.container_kind == "file"
        )
        span = _span(self.dataset, item)
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="test-base64",
            secret_sha256=hashlib.sha256(span).hexdigest(),
            match_sha256=hashlib.sha256(span).hexdigest(),
        )
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_pem_terminal_newline_variation_is_tp(self):
        item = self.items["RNC-SL-POS-000420"]
        span = _span(self.dataset, item)
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="pem-private-key",
            secret_sha256=hashlib.sha256(span.rstrip()).hexdigest(),
            match_sha256=hashlib.sha256(span.rstrip()).hexdigest(),
        )
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_kubernetes_base64_private_key_is_tp(self):
        item = self.items["RNC-SL-POS-000411"]
        span = _span(self.dataset, item)
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="pem-private-key-base64",
            secret_sha256=hashlib.sha256(span).hexdigest(),
            match_sha256=hashlib.sha256(span).hexdigest(),
        )
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_wrong_line_is_near_miss_not_tp(self):
        item = self.items["RNC-SL-POS-000001"]
        finding = _finding(item, self._value(item), line=(item.line or 0) + 1)
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["near_miss_count"], 1)
        self.assertEqual(result["metrics"]["near_miss_reason_counts"], {
            "LOCATION_LINE_MISMATCH": 1
        })
        self.assertIn(item.item_id, result["missed_positive_ids"])

    def test_wrong_byte_offset_is_near_miss_not_tp(self):
        item = self.items["RNC-SL-POS-000001"]
        finding = _finding(
            item,
            self._value(item),
            byte_start=item.byte_start + 1,
            byte_end=item.byte_end + 1,
        )
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["near_miss_reason_counts"], {
            "LOCATION_OFFSET_MISMATCH": 1
        })

    def test_truncated_value_is_near_miss(self):
        item = self.items["RNC-SL-POS-000001"]
        span = _span(self.dataset, item)
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="test-truncated",
            secret_sha256=hashlib.sha256(span[:-1]).hexdigest(),
            match_sha256=hashlib.sha256(span[:-1]).hexdigest(),
        )
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["near_miss_reason_counts"], {
            "VALUE_TRUNCATED": 1
        })

    def test_unrelated_same_line_value_is_unverified_not_near_miss(self):
        item = self.items["RNC-SL-POS-000001"]
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="test-unrelated",
            secret_sha256=hashlib.sha256(b"unrelated-value").hexdigest(),
            match_sha256=hashlib.sha256(b"unrelated-value").hexdigest(),
        )
        result = rnclab.score_findings(self.dataset, "filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["near_miss_count"], 0)
        self.assertEqual(result["metrics"]["unverified_evidence_count"], 1)

    def test_reversing_findings_does_not_change_attribution(self):
        first = self.items["RNC-SL-POS-000001"]
        second = next(
            item
            for item in self.dataset.positives("filesystem")
            if item.item_id != first.item_id
            and item.container_kind == "file"
            and item.normalization == "identity_direct"
        )
        a = _finding(first, self._value(first))
        b = _finding(second, self._value(second))
        forward = rnclab.score_findings(self.dataset, "filesystem", [a, b])
        reverse = rnclab.score_findings(self.dataset, "filesystem", [b, a])
        self.assertEqual(
            sorted(forward["matched_positive_ids"]),
            sorted(reverse["matched_positive_ids"]),
        )
        self.assertEqual(forward["metrics"]["true_positive_occurrences"], 2)
        self.assertEqual(reverse["metrics"]["true_positive_occurrences"], 2)

    def test_exception_ledger_reports_truncation(self):
        item = self.items["RNC-SL-POS-000001"]
        findings = [
            NormalizedFinding(
                file=f"unknown/{index}.txt",
                line=1,
                rule_id="test",
                secret_sha256=hashlib.sha256(f"value-{index}".encode()).hexdigest(),
            )
            for index in range(260)
        ]
        result = rnclab.score_findings(self.dataset, "filesystem", findings)
        self.assertEqual(len(result["exceptions"]), 250)
        self.assertTrue(result["exceptions_truncated"])
        self.assertGreater(result["exception_count"], 250)



if __name__ == "__main__":
    unittest.main()
