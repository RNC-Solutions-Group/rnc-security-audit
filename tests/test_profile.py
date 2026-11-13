"""DEFAULT/CUSTOM profile separation tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.adapters import get_adapter
from harness.errors import HarnessError
from harness.profile import CUSTOM, DEFAULT, load_profile


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.adapter = get_adapter("gitleaks")

    def test_default_profile_uses_bundled_scanner_rules(self):
        profile = load_profile(self.adapter, DEFAULT, None)
        self.assertEqual(profile.name, "DEFAULT".lower())
        self.assertIsNone(profile.scanner_config)
        self.assertTrue(profile.is_default)
        self.assertEqual(profile.config_sha256, None)
        self.assertEqual(profile.applied_settings["scanner_config_argument"], None)
        self.assertTrue(profile.to_dict()["baseline_metrics_included"])

    def test_default_profile_rejects_external_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "custom.toml"
            path.write_text("title = 'custom'\n", encoding="utf-8")
            with self.assertRaises(HarnessError):
                load_profile(self.adapter, DEFAULT, path)

    def test_custom_profile_records_config_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "custom.toml"
            path.write_text("title = 'custom'\n", encoding="utf-8")
            profile = load_profile(self.adapter, CUSTOM, path)
            self.assertEqual(profile.name, CUSTOM)
            self.assertEqual(profile.scanner_config, path.resolve())
            self.assertEqual(len(profile.config_sha256), 64)
            self.assertEqual(profile.applied_settings["scanner_config_sha256"], profile.config_sha256)
            self.assertFalse(profile.to_dict()["baseline_metrics_included"])

    def test_custom_profile_requires_config(self):
        with self.assertRaises(HarnessError):
            load_profile(self.adapter, CUSTOM, None)

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(HarnessError):
            load_profile(self.adapter, "sneaky", None)


if __name__ == "__main__":
    unittest.main()
