"""CLI-level tests for dataset preparation and the source-commit interface."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from harness.cli import build_parser, main
from harness.dataset import prepare
from tests.support import write_mini_repo


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.fixture = write_mini_repo(root / "fixture")
        cls.cache = root / "cache"
        prepare(cls.fixture.manifest, cls.cache)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _call(self, argv: list[str]):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_prepare_json(self):
        code, output, _ = self._call(
            [
                "prepare",
                "--manifest",
                str(self.fixture.manifest),
                "--cache-dir",
                str(self.cache),
                "--json",
            ]
        )
        self.assertEqual(code, 0)
        summary = json.loads(output)
        self.assertEqual(summary["positive"]["secrets"], 3)
        self.assertEqual(summary["revision"], self.fixture.revision)

    def test_removed_legacy_gitleaks_run_command(self):
        parser = build_parser()
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["run", "--gitleaks", "x"])

    def test_experiment_requires_exact_commit_before_work(self):
        code, _, stderr = self._call(["experiment", "--scanner", "gitleaks"])
        self.assertEqual(code, 2)
        self.assertIn("--commit", stderr)

    def test_unknown_config_is_a_harness_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, _, stderr = self._call(
                [
                    "experiment",
                    "--scanner",
                    "gitleaks",
                    "--commit",
                    "a" * 40,
                    "--config",
                    str(Path(tmp) / "missing.toml"),
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("configuration", stderr)


if __name__ == "__main__":
    unittest.main()
