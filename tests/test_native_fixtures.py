"""Native fixture lane helpers and one controlled end-to-end execution."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from harness import native_fixtures, status as statuses


class NativeFixtureHelperTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.fixtures = self.root / "fixtures"
        self.docker_dir = self.root / "docker"
        (self.fixtures / "testdata" / "repos" / "nogit").mkdir(parents=True)
        (self.fixtures / "testdata" / "repos" / "nogit" / "main.go").write_text(
            "aws = 1\n", encoding="utf-8"
        )
        (self.fixtures / "testdata" / "repos" / "nogit" / ".gitleaksignore").write_text(
            "../testdata/repos/nogit/api.go:aws:1\n", encoding="utf-8"
        )
        (self.docker_dir / "fixtures" / "baseline").mkdir(parents=True)
        (self.docker_dir / "fixtures" / "baseline" / "baseline.json").write_text(
            "[]\n", encoding="utf-8"
        )
        self.prepared = SimpleNamespace(
            root=self.fixtures,
            docker_dir=self.docker_dir,
            revision="a" * 40,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_docker_only_traces_are_not_native_assertions(self):
        case = {
            "assert_stderr_contains": [
                "scanning path path=/rnc/local/clean/clean.txt",
                "1 commits scanned.",
            ]
        }
        portable, docker_only = native_fixtures._stderr_traces(case)
        self.assertEqual(portable, ["1 commits scanned."])
        self.assertEqual(docker_only, ["scanning path path=/rnc/local/clean/clean.txt"])

    def test_canonical_paths_cover_upstream_local_and_relative(self):
        upstream = self.fixtures / "testdata" / "repos" / "nogit" / "main.go"
        local = self.docker_dir / "fixtures" / "clean" / "clean.txt"
        self.assertEqual(
            native_fixtures._canonical_path(str(upstream), self.prepared, None),
            "testdata/repos/nogit/main.go",
        )
        self.assertEqual(
            native_fixtures._canonical_path(str(local), self.prepared, None),
            "local/clean/clean.txt",
        )
        self.assertEqual(
            native_fixtures._canonical_path(
                "../testdata/repos/nogit/main.go", self.prepared, None
            ),
            "testdata/repos/nogit/main.go",
        )

    def test_relative_layout_preserves_pinned_ignore_and_baseline_paths(self):
        case = {
            "source": "testdata/repos/nogit",
            "gitleaks_ignore_path": "testdata/repos/nogit",
            "baseline_path": "fixtures/baseline/baseline.json",
        }
        work, source, ignore, baseline = native_fixtures._stage_relative_layout(
            case, self.prepared, self.root / "case"
        )
        self.assertTrue(work.is_dir())
        self.assertEqual(source, "../testdata/repos/nogit")
        self.assertEqual(ignore, "../testdata/repos/nogit")
        self.assertEqual(baseline, "../local/baseline/baseline.json")
        staged = self.root / "case" / "root"
        self.assertTrue((staged / "testdata/repos/nogit/.gitleaksignore").is_file())
        self.assertTrue((staged / "local/baseline/baseline.json").is_file())

    def test_not_applicable_is_not_a_pass(self):
        result = native_fixtures._not_applicable(
            {"id": "x", "name": "x", "fixture": "fixtures/x"}, "Windows"
        )
        self.assertEqual(result["status"], statuses.NOT_APPLICABLE)
        self.assertFalse(result["applicable"])


class NativeFixtureExecutionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.fixtures = self.root / "fixtures"
        self.docker_dir = self.root / "docker"
        (self.fixtures / "testdata" / "config").mkdir(parents=True)
        (self.fixtures / "testdata" / "config" / "simple.toml").write_text(
            "title = 'test'\n", encoding="utf-8"
        )
        (self.docker_dir / "fixtures" / "clean").mkdir(parents=True)
        (self.docker_dir / "fixtures" / "clean" / "clean.txt").write_text(
            "native-secret\n", encoding="utf-8"
        )
        self.secret_sha = hashlib.sha256(b"native-secret").hexdigest()
        cases = {
            "manifest_version": 2,
            "cases": [
                {
                    "id": "native-positive",
                    "name": "Native controlled positive",
                    "command": "dir",
                    "fixture": "fixtures/clean/clean.txt",
                    "source": "fixtures/clean/clean.txt",
                    "config": "testdata/config/simple.toml",
                    "options": [],
                    "expected_exit_code": 1,
                    "expected_findings": [
                        {
                            "rule_id": "test-rule",
                            "file": "local/clean/clean.txt",
                            "start_line": 1,
                            "secret_sha256": self.secret_sha,
                        }
                    ],
                }
            ],
        }
        (self.docker_dir / "cases.json").write_text(
            json.dumps(cases), encoding="utf-8"
        )
        self.prepared = SimpleNamespace(
            root=self.fixtures,
            docker_dir=self.docker_dir,
            revision="b" * 40,
        )
        self.stub = self._make_stub()

    def tearDown(self):
        self._tmp.cleanup()

    def _make_stub(self) -> Path:
        script = self.root / "stub.py"
        script.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "report = Path(args[args.index('--report-path') + 1])\n"
            "source = Path(args[-1]).resolve()\n"
            "report.write_text(json.dumps([{\n"
            "  'RuleID': 'test-rule',\n"
            "  'File': str(source),\n"
            "  'StartLine': 1,\n"
            "  'EndLine': 1,\n"
            "  'StartColumn': 1,\n"
            "  'EndColumn': 12,\n"
            "  'Secret': 'native-secret',\n"
            "  'Match': 'native-secret',\n"
            "  'Description': 'test',\n"
            "  'Entropy': 3.0,\n"
            "}]), encoding='utf-8')\n"
            "sys.exit(1)\n",
            encoding="utf-8",
        )
        if os.name == "nt":
            wrapper = self.root / "stub.cmd"
            wrapper.write_text(
                f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8"
            )
        else:
            wrapper = self.root / "stub.sh"
            wrapper.write_text(
                f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8"
            )
            wrapper.chmod(0o755)
        return wrapper

    def test_native_lane_runs_pinned_case_manifest(self):
        result = native_fixtures.run(
            self.prepared, self.stub, self.root / "work", timeout=30
        )
        self.assertEqual(result["status"], statuses.PASS)
        self.assertEqual(result["summary"]["scenario_passed"], 1)
        self.assertEqual(result["summary"]["assertion_failed"], 0)
        self.assertEqual(result["tests"][0]["findings"][0]["file"], "local/clean/clean.txt")


if __name__ == "__main__":
    unittest.main()
