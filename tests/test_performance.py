"""Performance telemetry and aggregation tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from harness import execution, performance
from harness.adapters.base import PLATFORMS


class FakeAdapter:
    key = "fake"

    def __init__(self, fail_on: int | None = None):
        self.calls = 0
        self.fail_on = fail_on

    def invoke_native(
        self,
        executable,
        target,
        report_path,
        *,
        mode="dir",
        timeout_seconds=10,
        collect_telemetry=False,
        **kwargs,
    ):
        self.calls += 1
        if self.fail_on is not None and self.calls == self.fail_on:
            raise RuntimeError("controlled failure")
        Path(report_path).write_text("[]", encoding="utf-8")
        return execution.Invocation(
            binary_path="fake",
            binary_sha256="a" * 64,
            argv=("fake",),
            mode=mode,
            report_path=str(report_path),
            exit_code=0,
            timed_out=False,
            duration_seconds=0.1 * self.calls,
            timeout_seconds=timeout_seconds,
            stdout=b"",
            stderr=b"",
            report_bytes=b"[]",
            resource_metrics={
                "cpu_total_seconds": 0.05 * self.calls,
                "peak_memory_bytes": 1024,
                "cpu_utilization_percent": 50.0,
                "method": "fake",
                "sample_count": 1,
            },
        )

    def invocation_problem(self, invocation):
        return None


class PerformanceTests(unittest.TestCase):
    def test_benchmark_aggregates_warmup_and_measured_runs(self):
        artifact = SimpleNamespace(
            platform=PLATFORMS["windows-amd64"],
            artifact_path="fake.exe",
            artifact_sha256="b" * 64,
            image_id=None,
            image_tag=None,
            version="v1",
            metadata={},
        )
        adapter = FakeAdapter()
        document = performance.benchmark_product(
            adapter,
            artifact,
            Path("."),
            Path("work/cp1e/test-performance"),
            plan=performance.BenchmarkPlan(warmups=1, measured_runs=3),
            workload={"bytes": 1000},
        )
        self.assertEqual(len(document["runs"]), 4)
        self.assertEqual(document["summary"]["runtime_seconds"]["count"], 3)
        self.assertEqual(document["summary"]["peak_memory_bytes"]["max"], 1024)
        self.assertEqual(document["summary"]["throughput_bytes_per_second"], 3333.333)
        self.assertEqual(document["summary"]["telemetry_methods"], ["fake"])

    def test_missing_telemetry_is_not_zero(self):
        document = performance._stats([])
        self.assertIsNone(document["median"])

    def test_failure_is_recorded(self):
        artifact = SimpleNamespace(
            platform=PLATFORMS["windows-amd64"],
            artifact_path="fake.exe",
            artifact_sha256="b" * 64,
            image_id=None,
            image_tag=None,
            version="v1",
            metadata={},
        )
        document = performance.benchmark_product(
            FakeAdapter(fail_on=2),
            artifact,
            Path("."),
            Path("work/cp1e/test-performance-failure"),
            plan=performance.BenchmarkPlan(warmups=0, measured_runs=2),
            workload={"bytes": 10},
        )
        self.assertEqual(document["summary"]["failures"], 1)
        self.assertEqual(document["summary"]["stability"], "INCOMPLETE")

    def test_real_subprocess_telemetry(self):
        inv = execution.run_process(
            [sys.executable, "-c", "print('x')"],
            binary_path="python",
            binary_sha256="c" * 64,
            mode="dir",
            report_path=Path("work/cp1e/test-telemetry/report.json"),
            timeout_seconds=30,
            collect_telemetry=True,
        )
        self.assertEqual(inv.exit_code, 0)
        self.assertGreater(inv.duration_seconds, 0)
        self.assertIsNotNone(inv.resource_metrics.get("method"))
        self.assertGreaterEqual(inv.resource_metrics.get("sample_count", 0), 0)

    def test_scanner_config_is_passed_to_measured_runs(self):
        seen = []

        class ConfigAware(FakeAdapter):
            def invoke_native(self, *args, **kwargs):
                seen.append(kwargs.get("config"))
                return super().invoke_native(*args, **kwargs)

        artifact = SimpleNamespace(
            platform=PLATFORMS["windows-amd64"],
            artifact_path="fake.exe",
            artifact_sha256="b" * 64,
            image_id=None,
            image_tag=None,
            version="v1",
            metadata={},
        )
        performance.benchmark_product(
            ConfigAware(),
            artifact,
            Path("."),
            Path("work/cp1e/test-performance-config"),
            plan=performance.BenchmarkPlan(warmups=0, measured_runs=1),
            workload={"bytes": 10},
            scanner_config=Path("custom.toml"),
        )
        self.assertEqual(seen, [Path("custom.toml")])

    def test_environment_profiles_are_separate_from_detection(self):
        dev = performance.environment_for("DEV")
        controlled = performance.environment_for("CONTROLLED")
        release = performance.environment_for("RELEASE")
        self.assertEqual(dev.mode, "DEV")
        self.assertFalse(dev.publishable)
        self.assertEqual(controlled.mode, "CONTROLLED")
        self.assertGreater(dev.stability_threshold, controlled.stability_threshold)
        self.assertTrue(release.publishable)
        with self.assertRaises(ValueError):
            performance.environment_for("RELEASE", stress_profile="cpu")

    def test_benchmark_records_environment_coverage_and_order(self):
        artifact = SimpleNamespace(
            platform=PLATFORMS["windows-amd64"],
            artifact_path="fake.exe",
            artifact_sha256="b" * 64,
            image_id=None,
            image_tag=None,
            version="v1",
            metadata={},
        )
        document = performance.benchmark_product(
            FakeAdapter(),
            artifact,
            Path("."),
            Path("work/cp1e/test-performance-environment"),
            plan=performance.BenchmarkPlan(
                warmups=1,
                measured_runs=2,
                environment="CONTROLLED",
            ),
            workload={
                "bytes": 1000,
                "files": 10,
                "eligible_files": 10,
                "inspected_files": 8,
                "archive_files": 2,
                "archives_extracted": 2,
            },
            sequence_index=1,
            cache_state="warm_after_warmup",
        )
        self.assertEqual(document["benchmark_environment"]["mode"], "CONTROLLED")
        self.assertFalse(document["benchmark_environment"]["publishable"])
        self.assertEqual(document["summary"]["files_inspected"], 8)
        self.assertEqual(document["summary"]["file_coverage_percent"], 80.0)
        self.assertEqual(document["summary"]["archive_files"], 2)
        self.assertEqual(document["benchmark"]["sequence_index"], 1)
        self.assertEqual(document["benchmark"]["cache_state"], "warm_after_warmup")
        self.assertEqual(document["runs"][0]["cache_state"], "warmup")

    def test_performance_drift_is_explicit(self):
        previous = {
            "product": {"platform": "windows-amd64", "artifact_sha256": "a" * 64},
            "benchmark_environment": {"mode": "CONTROLLED"},
            "summary": {"runtime_seconds": {"median": 2.0}, "stability": "STABLE"},
        }
        current = {
            "product": {"platform": "windows-amd64", "artifact_sha256": "b" * 64},
            "benchmark_environment": {"mode": "CONTROLLED"},
            "summary": {"runtime_seconds": {"median": 2.4}, "stability": "STABLE"},
        }
        drift = performance.performance_drift(previous, current)
        self.assertEqual(drift["runtime_ratio"], 1.2)
        self.assertEqual(drift["runtime_change_percent"], 20.0)
        self.assertTrue(drift["artifact_changed"])
        self.assertFalse(drift["environment_changed"])


if __name__ == "__main__":
    unittest.main()
