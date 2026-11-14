"""Independent scoring calibration.

These tests pair deliberately constructed findings with predetermined outcomes.
They do not rely on a scanner executable, and they fail if a correction permits
incorrect evidence to become a true positive.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from harness import archive, rnclab
from harness.contracts import NormalizedFinding
from harness.evidence import IDENTITY_DIGEST, EvidenceAlias
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


class _FakeFinding:
    def __init__(self, index: int):
        self.index = index
        self.file = f"calibration-{index}.txt"
        self.line = 1
        self.commit = None
        self.rule_id = "calibration.rule"
        self.secret_sha256 = f"digest-{index}"
        self.match_sha256 = f"digest-{index}"
        self.byte_start = None
        self.byte_end = None


class _FakeItem:
    def __init__(self, item_id: str, *, positive: bool = True):
        self.item_id = item_id
        self.is_positive = positive
        self.group_id = f"group-{item_id}"


def _candidate(finding, item, *, priority: int = 50) -> dict:
    candidate = {
        "finding_index": finding.index,
        "finding_key": f"finding-{finding.index}",
        "item": item,
        "alias": EvidenceAlias(IDENTITY_DIGEST, f"digest-{item.item_id}", "calibration"),
        "priority": priority,
        "line_distance": 0,
        "byte_distance": 0,
    }
    candidate["weight"] = rnclab._candidate_weight(candidate)
    return candidate


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

    def test_stronger_identity_alias_survives_digest_order(self):
        item = self.items["RNC-SL-POS-000105"]
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="calibration.alias",
            # Deliberately put the weaker exact-span digest first. The oracle
            # identity digest must still be the retained proof.
            secret_sha256=_digest(_span(self.dataset, item)),
            match_sha256=item.identity_sha256,
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        outcome = next(
            value for value in result["findings"] if value["index"] == 0
        )
        self.assertEqual(outcome["evidence_kind"], "identity_digest")

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

    def test_archive_member_mismatch_is_explicit(self):
        item = self.items["RNC-SL-POS-000029"]
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="calibration.archive",
            secret_sha256=item.span_sha256,
            match_sha256=item.span_sha256,
            container_member="wrong/member",
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(
            result["metrics"]["near_miss_reason_counts"].get("MEMBER_MISMATCH"), 1
        )

    def test_archive_explicit_member_is_tp(self):
        item = self.items["RNC-SL-POS-000029"]
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="calibration.archive",
            secret_sha256=item.span_sha256,
            match_sha256=item.span_sha256,
            container_member=item.source_member,
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_archive_embedded_nested_member_is_tp(self):
        item = self.items["RNC-SL-POS-000029"]
        finding = NormalizedFinding(
            file=item.source_path + "!" + item.source_member,
            line=item.line,
            rule_id="calibration.archive",
            secret_sha256=item.span_sha256,
            match_sha256=item.span_sha256,
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)

    def test_archive_missing_member_is_not_tp(self):
        item = self.items["RNC-SL-POS-000029"]
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="calibration.archive",
            secret_sha256=item.span_sha256,
            match_sha256=item.span_sha256,
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)

    def test_archive_wrong_archive_correct_member_is_not_tp(self):
        item = self.items["RNC-SL-POS-000029"]
        finding = NormalizedFinding(
            file="other-archive.zip",
            line=item.line,
            rule_id="calibration.archive",
            secret_sha256=item.span_sha256,
            match_sha256=item.span_sha256,
            container_member=item.source_member,
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)

    def test_archive_embedded_and_explicit_member_conflict_is_not_tp(self):
        item = self.items["RNC-SL-POS-000029"]
        finding = NormalizedFinding(
            file=item.source_path + "!" + item.source_member,
            line=item.line,
            rule_id="calibration.archive",
            secret_sha256=item.span_sha256,
            match_sha256=item.span_sha256,
            container_member="wrong/member",
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)

    def test_gzip_path_only_is_supported_single_member(self):
        item = self.items["RNC-SL-POS-000038"]
        finding = NormalizedFinding(
            file=item.source_path,
            line=item.line,
            rule_id="calibration.archive",
            secret_sha256=item.span_sha256,
            match_sha256=item.span_sha256,
        )
        result = self._score("filesystem", [finding])
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])

    def test_different_archive_members_are_not_interchangeable(self):
        item = self.items["RNC-SL-POS-000029"]
        alternate = dataclasses.replace(item, item_id="alternate", source_member="other/member")
        finding = SimpleNamespace(
            file=item.source_path,
            container_member=item.source_member,
        )
        self.assertTrue(rnclab._path_matches(item, finding, self.dataset.filesystem_root))
        self.assertFalse(
            rnclab._path_matches(alternate, finding, self.dataset.filesystem_root)
        )
        unsafe = SimpleNamespace(file=item.source_path, container_member="../escape")
        self.assertFalse(
            rnclab._path_matches(item, unsafe, self.dataset.filesystem_root)
        )
        self.assertTrue(archive.is_gzip_path("single-member.log.gz"))
        self.assertFalse(archive.is_gzip_path("multi-member.tar.gz"))
        self.assertFalse(archive.is_gzip_path("multi-member.tgz"))

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

    def _kubernetes_finding(self, item, line, *, digest=None, rule="kubernetes-secret-yaml"):
        return NormalizedFinding(
            file=item.source_path,
            line=line,
            rule_id=rule,
            secret_sha256=digest or item.identity_sha256,
            match_sha256=digest or item.identity_sha256,
        )

    def test_kubernetes_kind_line_is_a_bounded_valid_location(self):
        item = self.items["RNC-SL-POS-000411"]
        result = self._score(
            "filesystem", [self._kubernetes_finding(item, 2)]
        )
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)

    def test_unrelated_earlier_kubernetes_line_is_not_tp(self):
        item = self.items["RNC-SL-POS-000411"]
        result = self._score(
            "filesystem", [self._kubernetes_finding(item, 1)]
        )
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(
            result["metrics"]["near_miss_reason_counts"].get("LOCATION_LINE_MISMATCH"),
            1,
        )

    def test_kubernetes_wrong_field_location_is_not_tp(self):
        item = self.items["RNC-SL-POS-000411"]
        result = self._score(
            "filesystem", [self._kubernetes_finding(item, 4)]
        )
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)

    def test_kubernetes_correct_location_wrong_digest_is_not_tp(self):
        item = self.items["RNC-SL-POS-000411"]
        result = self._score(
            "filesystem",
            [self._kubernetes_finding(item, 2, digest=_digest(b"wrong-secret"))],
        )
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
        self.assertEqual(result["metrics"]["unverified_evidence_count"], 1)

    def test_multiple_encoded_credentials_in_one_document(self):
        item = self.items["RNC-SL-POS-000012"]
        result = self._score(
            "filesystem", [self._kubernetes_finding(item, 2)]
        )
        self.assertEqual(result["metrics"]["true_positive_occurrences"], 1)
        self.assertIn(item.item_id, result["matched_positive_ids"])
        self.assertNotIn("RNC-SL-POS-000013", result["matched_positive_ids"])

    def test_structured_location_policy_is_bounded_to_the_item_document(self):
        import base64

        value = base64.b64encode(b"calibration-value").decode()
        text = (
            "---\n"
            "apiVersion: v1\n"
            "kind: Secret\n"
            "metadata:\n"
            "  name: first\n"
            "data:\n"
            f"  alpha: {value}\n"
            "---\n"
            "apiVersion: v1\n"
            "kind: Secret\n"
            "metadata:\n"
            "  name: second\n"
            "data:\n"
            f"  beta: {value}\n"
            f"  gamma: {value}\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "secret.yaml").write_text(text, encoding="utf-8")
            dataset = SimpleNamespace(filesystem_root=root, history_root=root)
            first = SimpleNamespace(
                item_id="first",
                lane="filesystem",
                container_kind="file",
                source_path="secret.yaml",
                line=14,
                representation="kubernetes_secret_data",
                source_blob=None,
            )
            second = SimpleNamespace(
                item_id="second",
                lane="filesystem",
                container_kind="file",
                source_path="secret.yaml",
                line=15,
                representation="kubernetes_secret_data",
                source_blob=None,
            )
            allowed = rnclab._kubernetes_allowed_lines(dataset, first, {})
            self.assertIn(10, allowed)  # second document kind line
            self.assertIn(13, allowed)  # data block
            self.assertIn(14, allowed)  # item key/value
            self.assertNotIn(1, allowed)  # document separator
            self.assertNotIn(3, allowed)  # unrelated earlier document kind
            self.assertNotIn(5, allowed)  # metadata field
            self.assertNotIn(11, allowed)  # unrelated metadata key
            self.assertTrue(
                rnclab._line_matches(
                    first,
                    SimpleNamespace(line=10, rule_id="kubernetes-secret-yaml"),
                    dataset,
                    {},
                )
            )
            self.assertFalse(
                rnclab._line_matches(
                    first,
                    SimpleNamespace(line=3, rule_id="kubernetes-secret-yaml"),
                    dataset,
                    {},
                )
            )
            # Both repeated values are in the same data block and share the
            # document location; one finding cannot uniquely select either.
            self.assertIn(
                10,
                rnclab._kubernetes_allowed_lines(dataset, second, {}),
            )

    def test_repeated_identical_kubernetes_values_are_ambiguous(self):
        import base64

        value = base64.b64encode(b"repeated-calibration-value").decode()
        digest = _digest(base64.b64decode(value))
        text = (
            "apiVersion: v1\n"
            "kind: Secret\n"
            "metadata:\n"
            "  name: repeated\n"
            "data:\n"
            f"  first: {value}\n"
            f"  second: {value}\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus" / "filesystem"
            corpus.mkdir(parents=True)
            (corpus / "secret.yaml").write_text(text, encoding="utf-8")

            def item(item_id: str, line: int) -> rnclab.LabItem:
                return rnclab.LabItem(
                    item_id=item_id,
                    occurrence_id=item_id,
                    classification="POSITIVE",
                    lane="filesystem",
                    category="credential",
                    subtype="password",
                    scenario="calibration",
                    container_kind="file",
                    source_path="secret.yaml",
                    source_member=None,
                    source_commit=None,
                    source_blob=None,
                    source_table=None,
                    source_rowid=None,
                    source_column=None,
                    source_format=None,
                    line=line,
                    byte_start=0,
                    byte_end=len(value),
                    identity_id=f"id-{item_id}",
                    identity_sha256=digest,
                    span_sha256=digest,
                    normalization="identity_direct",
                    representation="kubernetes_secret_data",
                    match_policy=None,
                    group_id=f"group-{item_id}",
                    public_identity_sha256=None,
                    raw={"container": {"kind": "file"}},
                )

            dataset = rnclab.LabDataset(
                root=root,
                manifest={"corpus": {"filesystem_root": "corpus/filesystem", "history_root": "corpus/history"}},
                oracle_document=(),
                items=(item("first", 6), item("second", 7)),
                manifest_sha256="",
                oracle_sha256="",
                corpus_sha256="",
                source_validation={},
                git_head="",
                git_commit_count=0,
            )
            finding = NormalizedFinding(
                file="secret.yaml",
                line=2,
                rule_id="kubernetes-secret-yaml",
                secret_sha256=digest,
                match_sha256=digest,
            )
            result = rnclab.score_findings(dataset, "filesystem", [finding])
            self.assertEqual(result["metrics"]["true_positive_occurrences"], 0)
            self.assertEqual(result["metrics"]["ambiguous_count"], 1)
            self.assertEqual(result["metrics"]["false_negative_occurrences"], 2)

    def test_global_assignment_uses_a_second_shared_kubernetes_field(self):
        import base64

        value = base64.b64encode(b"shared-calibration-value").decode()
        digest = _digest(base64.b64decode(value))
        text = (
            "apiVersion: v1\n"
            "kind: Secret\n"
            "metadata:\n"
            "  name: shared\n"
            "data:\n"
            f"  first: {value}\n"
            f"  second: {value}\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus" / "filesystem"
            corpus.mkdir(parents=True)
            (corpus / "secret.yaml").write_text(text, encoding="utf-8")

            def item(item_id: str, line: int) -> rnclab.LabItem:
                return rnclab.LabItem(
                    item_id=item_id,
                    occurrence_id=item_id,
                    classification="POSITIVE",
                    lane="filesystem",
                    category="credential",
                    subtype="password",
                    scenario="calibration",
                    container_kind="file",
                    source_path="secret.yaml",
                    source_member=None,
                    source_commit=None,
                    source_blob=None,
                    source_table=None,
                    source_rowid=None,
                    source_column=None,
                    source_format=None,
                    line=line,
                    byte_start=0,
                    byte_end=len(value),
                    identity_id=f"id-{item_id}",
                    identity_sha256=digest,
                    span_sha256=digest,
                    normalization="identity_direct",
                    representation="kubernetes_secret_data",
                    match_policy=None,
                    group_id=f"group-{item_id}",
                    public_identity_sha256=None,
                    raw={"container": {"kind": "file"}},
                )

            dataset = rnclab.LabDataset(
                root=root,
                manifest={"corpus": {"filesystem_root": "corpus/filesystem", "history_root": "corpus/history"}},
                oracle_document=(),
                items=(item("first", 6), item("second", 7)),
                manifest_sha256="",
                oracle_sha256="",
                corpus_sha256="",
                source_validation={},
                git_head="",
                git_commit_count=0,
            )
            flexible = NormalizedFinding(
                file="secret.yaml",
                line=2,
                rule_id="kubernetes-secret-yaml",
                secret_sha256=digest,
                match_sha256=digest,
            )
            only_first = NormalizedFinding(
                file="secret.yaml",
                line=6,
                rule_id="calibration.exact",
                secret_sha256=digest,
                match_sha256=digest,
            )
            result = rnclab.score_findings(
                dataset, "filesystem", [flexible, only_first]
            )
            self.assertEqual(result["metrics"]["true_positive_occurrences"], 2)
            self.assertEqual(
                set(result["matched_positive_ids"]), {"first", "second"}
            )

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


class AssignmentCalibrationTests(unittest.TestCase):
    def test_shared_target_does_not_create_avoidable_false_negative(self):
        findings = [_FakeFinding(0), _FakeFinding(1)]
        target_one = _FakeItem("target-1")
        target_two = _FakeItem("target-2")
        candidates = {
            0: [_candidate(findings[0], target_one), _candidate(findings[0], target_two)],
            1: [_candidate(findings[1], target_one)],
        }
        assignment, ambiguous, _total = rnclab._select_assignment(candidates, findings)
        self.assertEqual(ambiguous, set())
        self.assertEqual(assignment[0]["item"].item_id, "target-2")
        self.assertEqual(assignment[1]["item"].item_id, "target-1")

    def test_unique_stronger_evidence_is_not_ambiguous(self):
        findings = [_FakeFinding(0)]
        target_one = _FakeItem("target-1")
        target_two = _FakeItem("target-2")
        candidates = {
            0: [
                _candidate(findings[0], target_one, priority=30),
                _candidate(findings[0], target_two, priority=50),
            ]
        }
        assignment, ambiguous, _total = rnclab._select_assignment(candidates, findings)
        self.assertEqual(ambiguous, set())
        self.assertEqual(assignment[0]["item"].item_id, "target-2")

    def test_equal_strength_cycle_remains_ambiguous(self):
        findings = [_FakeFinding(0), _FakeFinding(1)]
        target_one = _FakeItem("target-1")
        target_two = _FakeItem("target-2")
        candidates = {
            0: [_candidate(findings[0], target_one), _candidate(findings[0], target_two)],
            1: [_candidate(findings[1], target_one), _candidate(findings[1], target_two)],
        }
        assignment, ambiguous, _total = rnclab._select_assignment(candidates, findings)
        self.assertEqual(ambiguous, {0, 1})
        self.assertEqual(assignment, {})

    def test_assignment_is_candidate_order_invariant(self):
        findings = [_FakeFinding(0), _FakeFinding(1)]
        target_one = _FakeItem("target-1")
        target_two = _FakeItem("target-2")
        forward = {
            0: [_candidate(findings[0], target_one), _candidate(findings[0], target_two)],
            1: [_candidate(findings[1], target_one)],
        }
        reverse = {
            1: [_candidate(findings[1], target_one)],
            0: [_candidate(findings[0], target_two), _candidate(findings[0], target_one)],
        }
        first, first_ambiguous, _ = rnclab._select_assignment(forward, findings)
        second, second_ambiguous, _ = rnclab._select_assignment(reverse, findings)
        self.assertEqual(first_ambiguous, second_ambiguous)
        self.assertEqual(
            {key: value["item"].item_id for key, value in first.items()},
            {key: value["item"].item_id for key, value in second.items()},
        )


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
