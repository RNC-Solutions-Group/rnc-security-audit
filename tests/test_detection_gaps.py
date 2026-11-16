"""Regression tests for the detection-gap analysis helpers and reconciliation."""

from __future__ import annotations

import base64
import unittest
from pathlib import Path

from harness.detection_gaps.analysis import classify_miss, load_cp4c_rules
from harness.detection_gaps.model import (
    Context,
    Observation,
    Target,
    redact_span,
    safe_identifier,
)
from harness.detection_gaps.sources import (
    SourceResolver,
    find_report,
    load_canonical_targets,
    load_scanner_evidence,
)

ROOT = Path(__file__).resolve().parents[1]


def _target(**overrides) -> Target:
    values = dict(
        target_id="T-001",
        dataset="RNC Synthetic Secrets Lab v3",
        lane="rnclab_filesystem",
        category="password",
        subtype="database_password",
        provider="Database service",
        provider_confidence="MEDIUM",
        provider_markers=[],
        purpose="authentication",
        group_id="GRP-1",
        occurrence_id="OCC-1",
        risk_bearing=True,
        informative=False,
        primary_tp=True,
        path="app/.env",
        line=1,
        byte_start=0,
        byte_end=10,
        commit="",
        container_kind="ordinary_file",
        container_format="",
        archive_member="",
        archive_depth=0,
        database_table="",
        database_column="",
        database_rowid="",
        file_type="env",
        representation="dotenv_value",
        normalization="identity_direct",
        scenario="test",
        difficulty="easy",
        source={},
        value={},
        context=Context(identifier="DB_PASSWORD", identifier_family="DATABASE_PASSWORD"),
    )
    values.update(overrides)
    return Target(**values)


class RedactionTests(unittest.TestCase):
    def test_safe_identifier_redacts_encoded_basic_credential(self) -> None:
        encoded = base64.b64encode(b"deploy:very-secret").decode()
        self.assertEqual(safe_identifier(encoded), "ENCODED_VALUE_REDACTED")

    def test_safe_identifier_keeps_normal_field_name(self) -> None:
        self.assertEqual(safe_identifier("MONGO-0002_PASSWORD"), "MONGO-0002_PASSWORD")

    def test_redact_xml_value_attribute(self) -> None:
        rendered = redact_span('  <add key="SqlPassword" value="leaky-value" />', None, None)
        self.assertNotIn("leaky-value", rendered)
        self.assertIn("SqlPassword", rendered)

    def test_redact_php_variable_and_log_password(self) -> None:
        php = redact_span("$dbpasswd = 'pass123';", None, None)
        self.assertNotIn("pass123", php)
        log = redact_span("2025-03-12 DEBUG smtp login [user] password=4j~mclZZ0VJm", None, None)
        self.assertNotIn("4j~mclZZ0VJm", log)

    def test_redact_netrc_password_directive(self) -> None:
        rendered = redact_span("machine db login deploy password hRnUcCFYD0S", None, None)
        self.assertNotIn("hRnUcCFYD0S", rendered)


class ClassificationTests(unittest.TestCase):
    def test_source_unsupported_is_confirmed_when_container_has_no_credit(self) -> None:
        target = _target(
            category="private_key",
            subtype="tls_private_key_pkcs8",
            container_kind="archive_member",
            archive_member="keys/client.pem",
            representation="pem_pkcs8",
        )
        code, confidence, layer, _evidence, _reproduction = classify_miss(
            target,
            Observation(matched=False, source_inspected="UNSUPPORTED_CONTAINER"),
            {},
            scanner_key="cp4c",
            container_tp=0,
            same_subtype_matches=0,
            same_representation_matches=0,
            cross=[],
        )
        self.assertEqual(code, "SOURCE_UNSUPPORTED")
        self.assertEqual(confidence, "CONFIRMED")
        self.assertEqual(layer, "SOURCE_ACQUISITION")

    def test_informative_reference_is_not_a_development_gap(self) -> None:
        target = _target(informative=True, risk_bearing=False, category="api_key")
        code, confidence, layer, _evidence, _reproduction = classify_miss(
            target,
            Observation(matched=False),
            {},
            scanner_key="cp4c",
            container_tp=0,
            same_subtype_matches=0,
            same_representation_matches=0,
            cross=[],
        )
        self.assertEqual(code, "INFORMATIVE_REFERENCE")
        self.assertEqual(confidence, "CONFIRMED")
        self.assertEqual(layer, "ORACLE_CLASSIFICATION")

    def test_cp4c_rule_inventory_is_loaded(self) -> None:
        path = ROOT / "run" / "rules" / "rnc-cp4c-providers-v1.json"
        if not path.is_file():
            self.skipTest("local CP4C rule bundle is not present")
        rules = load_cp4c_rules(path)
        ids = {rule["rule_id"] for rule in rules["rules"]}
        self.assertIn("generic-secret-assignment", ids)
        self.assertIn("database-connection-credential", ids)
        self.assertNotIn("hmac-key", ids)


def _retained_reports_available() -> bool:
    base = ROOT / "run" / "reports" / "all-windows-baselines"
    directories = (
        "rnc-cp4c",
        "gl-rnc-mod-v14",
        "gl-rnc-mod-v16",
        "gitleaks-master",
        "betterleaks-lts",
    )
    return all(any((base / directory).glob("*.json")) for directory in directories)


@unittest.skipUnless(
    _retained_reports_available(),
    "retained local baseline reports are not present",
)
class RetainedEvidenceTests(unittest.TestCase):
    def test_all_scanner_metrics_reconcile_and_target_partitions_hold(self) -> None:
        cache = ROOT / "datasets" / "cache"
        leaky_sources = sorted((cache / "leaky-repo").glob("*/source"))
        if not leaky_sources:
            self.skipTest("Leaky Repo cache is not present")
        resolver = SourceResolver(
            rnclab_root=cache / "rnc-synth-lab",
            leaky_root=leaky_sources[-1],
            levain_root=cache / "levain",
        )
        targets = load_canonical_targets(
            rnclab_root=cache / "rnc-synth-lab",
            leaky_root=leaky_sources[-1],
            levain_root=cache / "levain",
            leaky_truth=ROOT / "datasets" / "leaky-repo.rnc-truth.json",
            leaky_oracle=ROOT / "datasets" / "leaky-repo.history-oracle.json",
            resolver=resolver,
        )
        self.assertEqual(len(targets), 1125)
        counts = {
            lane: sum(1 for target in targets if target.lane == lane)
            for lane in ("levain", "leaky_filesystem", "leaky_git", "rnclab_filesystem", "rnclab_git")
        }
        self.assertEqual(
            counts,
            {
                "levain": 85,
                "leaky_filesystem": 175,
                "leaky_git": 65,
                "rnclab_filesystem": 640,
                "rnclab_git": 160,
            },
        )
        self.assertEqual(len({target.group_id for target in targets if target.lane == "leaky_git" and target.group_id}), 53)
        self.assertEqual(len({target.group_id for target in targets if target.lane.startswith("rnclab") and target.group_id}), 496)
        for key, expected in (
            ("cp4c", {"levain": 43, "leaky_filesystem": 32, "leaky_git": 28, "rnclab_filesystem": 347, "rnclab_git": 120}),
            ("v14", {"levain": 49, "leaky_filesystem": 22, "leaky_git": 21, "rnclab_filesystem": 369, "rnclab_git": 130}),
            ("v16", {"levain": 50, "leaky_filesystem": 22, "leaky_git": 21, "rnclab_filesystem": 369, "rnclab_git": 130}),
        ):
            evidence = load_scanner_evidence(key, find_report(key), targets)
            actual = {
                lane: sum(1 for target in targets if target.lane == lane and evidence.observations[target.target_id].matched)
                for lane in expected
            }
            self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
