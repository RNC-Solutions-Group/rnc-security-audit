"""Independent scoring calibration.

These tests pair deliberately constructed findings with predetermined outcomes.
They do not rely on a scanner executable, and they fail if a correction permits
incorrect evidence to become a true positive.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import unittest
from pathlib import Path

from harness import rnclab
from harness.contracts import NormalizedFinding
from harness.model import Finding
from harness.scoring import score_positive
from harness.scoring_engine import score_findings as score_truth_findings
from harness.contracts import (
    EXPECTED_DETECTION,
    REVIEWED_NEGATIVE,
    ScoringPolicy,
    TruthItem,
    TruthManifest,
)
from tests.support import section

CACHE = Path("datasets/cache/rnc-synth-lab")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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


def _exact(item, value: bytes, **kwargs) -> NormalizedFinding:
    return NormalizedFinding(
        file=kwargs.get("path", item.source_path),
        line=kwargs.get("line", item.line),
        rule_id=kwargs.get("rule_id", "calibration.rule"),
        secret_sha256=kwargs.get("secret_sha256", _digest(value)),
        match_sha256=kwargs.get("match_sha256", _digest(value)),
        commit=kwargs.get("commit", item.source_commit),
        byte_start=kwargs.get("byte_start", item.byte_start),
        byte_end=kwargs.get("byte_end", item.byte_end),
        secret_text=kwargs.get("secret_text"),
        match_text=kwargs.get("match_text"),
    )


@unittest.skipUnless(CACHE.is_dir(), "certified RNC Lab cache is not prepared")
class RncLabCalibrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = rnclab.load(CACHE)
        cls.items = {item.item_id: item for item in cls.dataset.items}

    def _score(self, lane, findings):
        return rnclab.score_findings(self.dataset, lane, findings)

    def test_exact_identity_is_tp(self):
        item = self.items["RNC-SL-POS-000001"]
        result = self._score("filesystem", [_exact(item, _span(self.dataset, item))])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_exact_digest_without_text_is_tp(self):
        item = next(
            item
            for item in self.dataset.positives("filesystem")
            if item.container_kind == "file" and item.normalization == "base64_decode_text"
        )
        span = _span(self.dataset, item)
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="calibration.base64",
            secret_sha256=_digest(span),
            match_sha256=_digest(span),
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_pem_terminal_newline_is_tp(self):
        item = self.items["RNC-SL-POS-000420"]
        span = _span(self.dataset, item)
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="pem-private-key",
            secret_sha256=_digest(span.rstrip()),
            match_sha256=_digest(span.rstrip()),
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_pem_crlf_variation_is_tp(self):
        item = self.items["RNC-SL-POS-000420"]
        span = _span(self.dataset, item)
        variant = span.replace(b"\n", b"\r\n")
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="pem-private-key",
            secret_sha256=_digest(variant),
            match_sha256=_digest(variant),
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)

    def test_public_key_only_is_not_tp(self):
        item = next(
            item
            for item in self.dataset.positives("filesystem")
            if item.match_policy == "private_key_material_required"
            and item.public_identity_sha256
        )
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="private-key",
            secret_sha256=item.public_identity_sha256,
            match_sha256=item.public_identity_sha256,
            secret_text="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertNotIn(item.item_id, result["matched_positive_ids"])

    def test_pem_missing_footer_is_partial_material_not_tp(self):
        item = self.items["RNC-SL-POS-000420"]
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="pem-private-key",
            secret_sha256=_digest(b"not-a-complete-key"),
            match_sha256=_digest(b"not-a-complete-key"),
            secret_text="-----BEGIN EC PRIVATE KEY-----\nTRUNCATED",
            match_text="-----BEGIN EC PRIVATE KEY-----\nTRUNCATED",
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(
            result["metrics"]["near_miss_reason_counts"].get("PARTIAL_MATERIAL"), 1
        )

    def test_contained_credential_component_span_is_tp(self):
        item = self.items["RNC-SL-POS-000105"]
        data = (self.dataset.filesystem_root / item.source_path).read_bytes()
        start = data.index(b"etl_loader:")
        end = data.index(b"@", start)
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="database-connection-credential",
            secret_sha256=item.identity_sha256,
            match_sha256=item.identity_sha256,
            byte_start=start,
            byte_end=end,
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_archive_wrong_member_is_not_tp(self):
        item = next(
            value
            for value in self.dataset.positives("filesystem")
            if value.container_kind == "archive" and value.source_member
        )
        finding = NormalizedFinding(
            file=item.source_path + "!wrong/member",
            line=item.line,
            rule_id="calibration.archive",
            secret_sha256=_digest(b"wrong"),
            match_sha256=_digest(b"wrong"),
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["verified_false_positive_alert_count"], 0)

    def test_decoded_kubernetes_private_key_alias_is_tp(self):
        item = self.items["RNC-SL-POS-000419"]
        import base64

        decoded = base64.b64decode(_span(self.dataset, item))
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="private-key",
            secret_sha256=_digest(decoded.rstrip()),
            match_sha256=_digest(decoded.rstrip()),
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_wrong_key_identity_is_not_tp(self):
        item = self.items["RNC-SL-POS-000420"]
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="pem-private-key",
            secret_sha256=_digest(b"another-private-key"),
            match_sha256=_digest(b"another-private-key"),
            secret_text="-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----",
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)

    def test_wrong_line_is_near_miss_and_target_remains_fn(self):
        item = self.items["RNC-SL-POS-000001"]
        span = _span(self.dataset, item)
        finding = _exact(item, span, line=(item.line or 0) + 1)
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(
            result["metrics"]["near_miss_reason_counts"], {"LOCATION_LINE_MISMATCH": 1}
        )
        self.assertIn(item.item_id, result["missed_positive_ids"])

    def test_wrong_byte_offset_is_near_miss(self):
        item = self.items["RNC-SL-POS-000001"]
        span = _span(self.dataset, item)
        finding = _exact(
            item,
            span,
            byte_start=item.byte_start + 1,
            byte_end=item.byte_end + 1,
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(
            result["metrics"]["near_miss_reason_counts"], {"LOCATION_OFFSET_MISMATCH": 1}
        )

    def test_truncated_value_is_near_miss(self):
        item = self.items["RNC-SL-POS-000001"]
        span = _span(self.dataset, item)
        finding = _exact(item, span[:-1])
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(
            result["metrics"]["near_miss_reason_counts"], {"VALUE_TRUNCATED": 1}
        )

    def test_unrelated_same_line_is_unverified_not_near_miss(self):
        item = self.items["RNC-SL-POS-000001"]
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="calibration.unrelated",
            secret_sha256=_digest(b"unrelated"),
            match_sha256=_digest(b"unrelated"),
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["near_miss_count"], 0)
        self.assertEqual(result["metrics"]["unverified_evidence_count"], 1)

    def test_unmatched_is_not_false_positive(self):
        finding = NormalizedFinding(
            file="unknown/path.txt",
            line=1,
            rule_id="calibration.unknown",
            secret_sha256=_digest(b"unknown"),
            match_sha256=_digest(b"unknown"),
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["verified_false_positive_alert_count"], 0)

    def test_verified_negative_is_fp(self):
        item = next(
            item
            for item in self.dataset.items
            if item.lane == "filesystem"
            and item.classification == "NEGATIVE_TRAP"
            and item.normalization == "identity_direct"
            and item.container_kind == "file"
        )
        result = self._score("filesystem", [_exact(item, _span(self.dataset, item))])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["verified_false_positive_alert_count"], 1)

    def test_duplicate_never_increases_tp(self):
        item = self.items["RNC-SL-POS-000001"]
        span = _span(self.dataset, item)
        result = self._score(
            "filesystem",
            [_exact(item, span), _exact(item, span)],
        )
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertEqual(result["metrics"]["duplicate_count"], 1)

    def test_finding_order_does_not_change_metrics(self):
        selected = [
            item
            for item in self.dataset.positives("filesystem")
            if item.container_kind == "file"
            and item.normalization == "identity_direct"
            and item.line is not None
        ][:3]
        if len(selected) < 3:
            self.skipTest("not enough calibration items")
        findings = [_exact(item, _span(self.dataset, item)) for item in selected]
        signatures = set()
        for permutation in itertools.permutations(findings):
            result = self._score("filesystem", list(permutation))
            signatures.add(
                (
                    tuple(sorted(result["matched_positive_ids"])),
                    result["metrics"]["true_positive_occurrences"],
                    result["metrics"]["false_negative_occurrences"],
                    result["metrics"]["duplicate_count"],
                    result["metrics"]["near_miss_count"],
                    result["metrics"]["verified_false_positive_alert_count"],
                )
            )
        self.assertEqual(len(signatures), 1)

    def test_oracle_order_does_not_change_metrics(self):
        item = self.items["RNC-SL-POS-000001"]
        span = _span(self.dataset, item)
        finding = _exact(item, span)
        forward = self._score("filesystem", [finding])
        reversed_dataset = dataclasses.replace(
            self.dataset, items=tuple(reversed(self.dataset.items))
        )
        reverse = rnclab.score_findings(reversed_dataset, "filesystem", [finding])
        self.assertEqual(
            sorted(forward["matched_positive_ids"]),
            sorted(reverse["matched_positive_ids"]),
        )
        self.assertEqual(
            forward["metrics"]["true_positive_occurrences"],
            reverse["metrics"]["true_positive_occurrences"],
        )

    def test_exception_truncation_is_explicit(self):
        findings = [
            NormalizedFinding(
                file=f"unknown/{index}.txt",
                line=1,
                rule_id="calibration.unknown",
                secret_sha256=_digest(f"unknown-{index}".encode()),
            )
            for index in range(260)
        ]
        result = self._score("filesystem", findings)
        self.assertEqual(len(result["exceptions"]), 250)
        self.assertTrue(result["exceptions_truncated"])
        self.assertGreater(result["exception_count"], 250)


class LevainCalibrationTests(unittest.TestCase):
    def test_partial_buckets_are_additive_and_not_fp(self):
        cases = (
            section(
                "partial-case",
                "TOKEN=unit-secret-alpha\nunit-secret-beta\n",
                secrets=(("partial", "unit-secret-alpha"), ("missed", "unit-secret-beta")),
                filename="001-calibration.log",
                lines=2,
            ),
        )
        result = score_positive(
            cases,
            [Finding(file="001-calibration.log", line=1, rule_id="test", secret="TOKEN=unit-secret-alpha", match="TOKEN=unit-secret-alpha")],
        )
        self.assertEqual(result["true_positives"], 0)
        self.assertEqual(result["partial_matches"], 1)
        self.assertEqual(result["partial_findings"], 1)
        self.assertEqual(result["false_positives"], 0)
        self.assertEqual(result["false_negatives"], 2)
        classification = result["match_classification"]
        self.assertEqual(
            classification["complete"]
            + classification["normalized"]
            + classification["partial"]
            + classification["miss"],
            result["expected_secrets"],
        )
        self.assertEqual(classification["partial"], 1)
        self.assertTrue(result["target_accounting"]["reconciled"])


class ScoringEngineCalibrationTests(unittest.TestCase):
    def test_target_and_finding_accounting(self):
        truth = TruthManifest(
            manifest_id="calibration",
            manifest_version="1",
            dataset_id="calibration",
            dataset_version="1",
            items=(
                TruthItem(
                    finding_id="pos",
                    dataset_id="calibration",
                    dataset_version="1",
                    path="p.txt",
                    classification=EXPECTED_DETECTION,
                    line_start=1,
                    line_end=1,
                    metadata={"value_fingerprints": ["a" * 64]},
                ),
                TruthItem(
                    finding_id="neg",
                    dataset_id="calibration",
                    dataset_version="1",
                    path="n.txt",
                    classification=REVIEWED_NEGATIVE,
                    line_start=1,
                    line_end=1,
                    metadata={"source_verified": True, "value_fingerprints": ["b" * 64]},
                ),
            ),
            integrity={"status": "PASS"},
            scoring_policy={"negative_oracle": True},
        )
        findings = [
            NormalizedFinding(
                file="p.txt",
                line=1,
                rule_id="cal",
                secret_sha256="a" * 64,
                match_sha256="a" * 64,
            ),
            NormalizedFinding(
                file="n.txt",
                line=1,
                rule_id="cal",
                secret_sha256="b" * 64,
                match_sha256="b" * 64,
            ),
            NormalizedFinding(
                file="unknown.txt",
                line=1,
                rule_id="cal",
                secret_sha256="c" * 64,
                match_sha256="c" * 64,
            ),
        ]
        result = score_truth_findings(findings, truth, policy=ScoringPolicy(negative_oracle=True))
        self.assertTrue(result.metrics["target_accounting"]["reconciled"])
        self.assertTrue(result.metrics["finding_accounting"]["reconciled"])
        self.assertEqual(result.metrics["matched_count"], 1)
        self.assertEqual(result.metrics["verified_false_positive_count"], 1)
        self.assertEqual(result.metrics["unmatched_pending_review_count"], 1)


if __name__ == "__main__":
    unittest.main()
