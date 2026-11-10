"""Benchmark infrastructure tests. They do not assert language performance."""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.cp0.bench_runner import (
    _build_workload,
    _expected,
    _fnv,
    _rules,
    _write_rules,
    build_workloads,
)
from tools.cp0.benchmark import benchmark, write_corpus


class CP0BenchmarkTests(unittest.TestCase):
    def test_rule_table_is_shared_and_compiles(self):
        basic, expanded = _rules()
        self.assertEqual(len(basic), 8)
        self.assertEqual(len(expanded), 64)
        for line in expanded:
            _rule_id, capture, _family, pattern = line.split("\t", 3)
            self.assertIn(capture, {"0", "1"})
            re.compile(pattern)
        self.assertTrue(all("\\s" not in line for line in expanded))

    def test_rules_files_have_expected_limits(self):
        with tempfile.TemporaryDirectory() as temp:
            basic, expanded = _write_rules(Path(temp))
            self.assertIn("basic", basic.name)
            self.assertIn("expanded", expanded.name)
            self.assertEqual(len([line for line in basic.read_text().splitlines() if line and not line.startswith("#")]), 8)
            self.assertEqual(len([line for line in expanded.read_text().splitlines() if line and not line.startswith("#")]), 64)

    def test_fnv1a_known_vector(self):
        self.assertEqual(_fnv(["a"]), "af63dc4c8601ec8c")

    def test_workload_expected_count_and_checksum_are_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = _build_workload(root, "unit", size=64 * 1024, marker_count=5, ruleset="basic")
            second = _build_workload(root, "unit", size=64 * 1024, marker_count=5, ruleset="basic")
            self.assertEqual(first["expected_count"], 5)
            self.assertEqual(first["expected_checksum"], second["expected_checksum"])
            self.assertEqual(first["bytes"], 64 * 1024)
            self.assertEqual(first["files"], 1)
            data = (root / "unit" / "unit.bin").read_bytes()
            self.assertEqual(data.count(b"RNC_SYNTH_KEY_"), 5)
            self.assertEqual(_expected([]), (0, "cbf29ce484222325"))

    def test_workload_set_covers_required_dimensions(self):
        with tempfile.TemporaryDirectory() as temp:
            workloads = build_workloads(Path(temp))
            names = {workload["name"] for workload in workloads}
            self.assertEqual(
                names,
                {"large-low", "large-high", "small-many", "fp-heavy", "unicode", "large-ruleset", "worst-case", "multiline"},
            )
            for workload in workloads:
                self.assertGreater(workload["bytes"], 0)
                self.assertGreater(workload["manifest"].stat().st_size, 0)

    def test_literal_baseline_probe_remains_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bench.bin"
            digest = write_corpus(path, 64 * 1024, 16)
            self.assertEqual(path.stat().st_size, 64 * 1024)
            self.assertEqual(path.read_bytes().count(b"RNC_SYNTH_KEY_"), 16)
            self.assertEqual(len(digest), 64)
        with patch("tools.cp0.benchmark.shutil.which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "missing go toolchain"):
                benchmark(3)


if __name__ == "__main__":
    unittest.main()
