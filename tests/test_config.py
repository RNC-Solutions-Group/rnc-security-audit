"""TOML harness configuration tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.config import ConfigError, load_config, raw_destination_is_safe


class ConfigTests(unittest.TestCase):
    def test_example_config_is_valid(self):
        config = load_config("harness.toml.example")
        self.assertEqual(config.scanner, "gitleaks")
        self.assertIsNone(config.artifact.build)
        self.assertTrue(str(config.artifact.manifest).endswith("run\\manifest.toml") or str(config.artifact.manifest).endswith("run/manifest.toml"))
        self.assertEqual(config.suites, ("levain", "leaky-repo"))
        self.assertEqual(config.reports.formats, ("markdown", "json"))
        self.assertFalse(config.reports.raw)

    def test_defaults_are_usable(self):
        config = load_config()
        self.assertIsNone(config.artifact.build)
        self.assertEqual(config.reports.output_dir.name, "experiments")
        self.assertTrue(config.reports.console)
        self.assertTrue(config.reports.sanitized)

    def test_artifact_manifest_and_build_are_configurable(self):
        text = Path("harness.toml.example").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harness.toml"
            path.write_text(
                text.replace(
                    "[artifact]\n",
                    '[artifact]\nbuild = "rnc-cp4a"\nmanifest = "run/manifest.toml"\n',
                ),
                encoding="utf-8",
            )
            config = load_config(path)
            self.assertEqual(config.artifact.build, "rnc-cp4a")
            self.assertEqual(config.artifact.manifest, path.parent / "run" / "manifest.toml")

    def test_non_default_timeout_takes_effect(self):
        text = Path("harness.toml.example").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harness.toml"
            path.write_text(text.replace("timeout = 1200", "timeout = 42"), encoding="utf-8")
            config = load_config(path)
            self.assertEqual(config.timeout, 42)

    def test_nested_report_sections_take_effect(self):
        config = load_config("harness.toml.example")
        self.assertTrue(config.reports.sanitized)
        self.assertFalse(config.reports.raw)
        self.assertTrue(config.reports.exceptions_enabled)
        self.assertEqual(config.reports.exception_mode, "exceptions-only")
        self.assertEqual(config.reports.output_dir.name, "experiments")
        self.assertEqual(config.reports.raw_output_dir.name, "unsanitized")

    def test_history_and_performance_configuration(self):
        config = load_config("harness.toml.example")
        self.assertEqual(config.benchmark_warmups, 1)
        self.assertEqual(config.benchmark_runs, 5)
        self.assertEqual(config.benchmark_environment, "DEV")
        self.assertEqual(config.stress_profile, "none")
        self.assertNotIn("git-history", config.suites)
        self.assertNotIn("synthetic-filesystem", config.suites)
        self.assertEqual(config.suites, ("levain", "leaky-repo"))
        self.assertFalse(hasattr(config, "leaky_modes"))

    def test_invalid_benchmark_environment_is_rejected(self):
        text = Path("harness.toml.example").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harness.toml"
            path.write_text(
                text.replace('environment = "DEV"', 'environment = "PRODUCTION"'),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(path)
            path.write_text(
                text.replace('stress_profile = "none"', 'stress_profile = "gpu"'),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_invalid_format_is_rejected(self):
        text = Path("harness.toml.example").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harness.toml"
            path.write_text(text.replace('["markdown", "json"]', '["xml"]'), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_invalid_platform_and_suite_are_rejected(self):
        text = Path("harness.toml.example").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "harness.toml"
            path.write_text(text.replace('["host"]', '["solaris"]'), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)
            path.write_text(
                text.replace(
                    '["levain", "leaky-repo"]', '["unknown"]'
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_raw_destination_safety(self):
        safe, reason = raw_destination_is_safe(Path("work/raw"))
        self.assertTrue(safe, reason)
        safe, reason = raw_destination_is_safe(Path("reports/cp1c"))
        self.assertFalse(safe, reason)
        with tempfile.TemporaryDirectory() as tmp:
            safe, reason = raw_destination_is_safe(Path(tmp))
            self.assertTrue(safe, reason)


if __name__ == "__main__":
    unittest.main()
