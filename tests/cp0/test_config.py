"""Configuration schema and explicit legacy-migration tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.cp0.config_migration import (
    DEFAULT_LIMITS,
    config_digest,
    default_config,
    load_project_config,
    migrate_legacy,
    validate_config,
)
from tools.cp0.contracts import ContractViolation


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/config"


class CP0ConfigTests(unittest.TestCase):
    def test_unified_config_loads_with_provenance(self):
        config, provenance = load_project_config(FIXTURES / "unified")
        self.assertEqual(provenance["source"], ".rncscanner.toml")
        self.assertFalse(provenance["migrated"])
        self.assertEqual(config["ci"]["accepted_result_codes"], [1, 2])
        self.assertEqual(config["policy"]["blocks"][0]["selector"], "vendor/**")
        self.assertTrue(config_digest(config).startswith("sha256:"))

    def test_legacy_config_migrates_explicitly(self):
        config, provenance = load_project_config(FIXTURES / "legacy")
        self.assertTrue(provenance["migrated"])
        self.assertEqual(provenance["source"], "security.config")
        self.assertEqual(len(config["policy"]["blocks"]), 2)
        self.assertEqual(config["policy"]["exemptions"], [])
        self.assertEqual(config["policy"]["effective_policies"][0]["origin"], "repository")
        self.assertEqual(config["scan"]["max_file_bytes"], 1048576)

    def test_dual_sources_fail_closed(self):
        with self.assertRaises(ContractViolation) as caught:
            load_project_config(FIXTURES / "dual")
        self.assertEqual(caught.exception.code, "CONFIG_DUAL_SOURCE")

    def test_unsafe_legacy_reporting_fails(self):
        with self.assertRaises(ContractViolation) as caught:
            load_project_config(FIXTURES / "invalid-unsafe")
        self.assertEqual(caught.exception.code, "LEGACY_UNSAFE_REPORTING")

    def test_unknown_legacy_fields_fail(self):
        with self.assertRaises(ContractViolation) as caught:
            load_project_config(FIXTURES / "invalid-unknown")
        self.assertEqual(caught.exception.code, "LEGACY_UNSUPPORTED")

    def test_mandatory_policy_must_be_global(self):
        config = default_config()
        config["policy"]["effective_policies"].append({
            "policy_id": "MANDATORY-1",
            "origin": "repository",
            "version": "1",
            "digest": "sha256:" + "a" * 64,
            "mandatory": True,
        })
        with self.assertRaises(ContractViolation) as caught:
            validate_config(config)
        self.assertEqual(caught.exception.code, "CONFIG_MANDATORY_ORIGIN")

    def test_legacy_unknown_secret_detection_field_fails(self):
        document = {
            "version": 1,
            "secret_detection": {
                "enabled": True,
                "ruleset": "synthetic-v1",
                "ruleset_digest": "sha256:" + "a" * 64,
                "provider_keys": ["x"],
            },
        }
        with self.assertRaises(ContractViolation) as caught:
            migrate_legacy(document)
        self.assertEqual(caught.exception.code, "LEGACY_UNSUPPORTED")

    def test_legacy_cannot_accept_incomplete_or_failed(self):
        document = {
            "version": 1,
            "secret_detection": {
                "enabled": True,
                "ruleset": "synthetic-v1",
                "ruleset_digest": "sha256:" + "a" * 64,
            },
            "ci": {"accepted_result_codes": [1, 2, 4]},
        }
        with self.assertRaises(ContractViolation) as caught:
            migrate_legacy(document)
        self.assertEqual(caught.exception.code, "LEGACY_CI")

    def test_default_limits_do_not_follow_symlinks(self):
        config = default_config()
        self.assertEqual(config["scan"], DEFAULT_LIMITS)
        self.assertFalse(config["scan"]["follow_symlinks"])


if __name__ == "__main__":
    unittest.main()
