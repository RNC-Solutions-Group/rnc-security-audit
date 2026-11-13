"""Scanner-independent performance benchmarking.

Performance observation is deliberately separate from detection scoring. The
module invokes scanner products through the adapter boundary and records only
normalized execution metadata; it never parses scanner findings.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass
from pathlib import Path

from . import __version__
from . import telemetry

PERFORMANCE_VERSION = "2"


@dataclass(frozen=True)
class BenchmarkEnvironment:
    """Declared measurement conditions, separate from scanner detection config."""

    mode: str = "DEV"
    description: str = "contended developer workstation; functional and preliminary timing"
    contention: str = "uncontrolled"
    documented_conditions: str = "not a controlled benchmark host"
    publishable: bool = False
    stability_threshold: float = 0.25
    stress_profile: str = "none"
    allowed_stress_profiles: tuple[str, ...] = ("none", "cpu", "memory", "io", "network")

    def validate(self) -> None:
        if self.mode not in ("DEV", "CONTROLLED", "RELEASE"):
            raise ValueError("benchmark environment must be DEV, CONTROLLED, or RELEASE")
        if self.stress_profile not in self.allowed_stress_profiles:
            raise ValueError(
                f"unknown stress profile {self.stress_profile!r}; "
                f"choose from {', '.join(self.allowed_stress_profiles)}"
            )
        if self.mode == "RELEASE" and self.stress_profile != "none":
            raise ValueError("RELEASE measurements must use the default stress profile")

    def to_dict(self) -> dict:
        return asdict(self)


ENVIRONMENTS = {
    "DEV": BenchmarkEnvironment(),
    "CONTROLLED": BenchmarkEnvironment(
        mode="CONTROLLED",
        description="reduced-contention host with documented conditions",
        contention="documented and reduced",
        documented_conditions="operator must record host CPU, RAM, disk, power mode and background load",
        publishable=False,
        stability_threshold=0.10,
    ),
    "RELEASE": BenchmarkEnvironment(
        mode="RELEASE",
        description="pinned scanner build, default configuration, controlled hardware",
        contention="controlled",
        documented_conditions="pinned artifacts and controlled hardware; publishable evidence only",
        publishable=True,
        stability_threshold=0.05,
    ),
}


def environment_for(mode: str = "DEV", *, stress_profile: str = "none") -> BenchmarkEnvironment:
    try:
        base = ENVIRONMENTS[mode.upper()]
    except KeyError as exc:
        raise ValueError("benchmark environment must be DEV, CONTROLLED, or RELEASE") from exc
    result = BenchmarkEnvironment(
        **{**asdict(base), "stress_profile": stress_profile}
    )
    result.validate()
    return result


@dataclass(frozen=True)
class BenchmarkPlan:
    warmups: int = 1
    measured_runs: int = 5
    timeout_seconds: float = 300.0
    mode: str = "dir"
    environment: str = "DEV"
    stress_profile: str = "none"

    def validate(self) -> None:
        if self.warmups < 0:
            raise ValueError("warmups must be non-negative")
        if self.measured_runs < 1:
            raise ValueError("measured_runs must be at least one")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        environment_for(self.environment, stress_profile=self.stress_profile)


@dataclass
class RunRecord:
    run_index: int
    phase: str
    duration_seconds: float
    cpu_total_seconds: float | None
    cpu_utilization_percent: float | None
    peak_memory_bytes: int | None
    exit_code: int | None
    timed_out: bool
    telemetry_method: str
    telemetry_unavailable_reason: str | None
    error: str | None = None
    sequence_index: int = 0
    cache_state: str = "uncontrolled"
    coverage_caveat: dict | None = None
    command: list[str] | None = None
    command_sha256: str | None = None


def _stats(values: list[float]) -> dict:
    if not values:
        return {
            "count": 0,
            "median": None,
            "minimum": None,
            "maximum": None,
            "stdev": None,
            "coefficient_of_variation": None,
        }
    mean = statistics.mean(values)
    stdev = statistics.pstdev(values) if len(values) > 1 else 0.0
    return {
        "count": len(values),
        "median": round(statistics.median(values), 6),
        "minimum": round(min(values), 6),
        "maximum": round(max(values), 6),
        "stdev": round(stdev, 6),
        "coefficient_of_variation": round(stdev / mean, 6) if mean else None,
    }


def _run_once(
    adapter,
    artifact,
    target: Path,
    out_dir: Path,
    plan: BenchmarkPlan,
    index: int,
    phase: str,
    scanner_config: Path | None = None,
    *,
    sequence_index: int = 0,
    cache_state: str = "uncontrolled",
    allow_partial: bool = False,
    suite: str | None = None,
    workload_key: str | None = None,
) -> RunRecord:
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        if artifact.platform.is_executable:
            invocation = adapter.invoke_native(
                artifact.artifact_path,
                target,
                out_dir / "report.json",
                config=scanner_config,
                mode=plan.mode,
                timeout_seconds=plan.timeout_seconds,
                collect_telemetry=True,
                artifact=artifact,
                invocation_type=phase,
                suite=suite,
                workload=workload_key,
            )
        else:
            invocation = adapter.invoke_container(
                artifact.image_tag,
                artifact.image_id,
                target,
                out_dir,
                config=scanner_config,
                mode=plan.mode,
                timeout_seconds=plan.timeout_seconds,
                collect_telemetry=True,
                artifact=artifact,
                invocation_type=phase,
                suite=suite,
                workload=workload_key,
            )
        problem = adapter.invocation_problem(invocation)
        partial = None
        if problem:
            partial_method = getattr(adapter, "partial_execution_evidence", None)
            if allow_partial and callable(partial_method):
                partial = partial_method(invocation)
            if not partial:
                raise RuntimeError(problem)
        metrics = invocation.resource_metrics or {}
        return RunRecord(
            run_index=index,
            phase=phase,
            duration_seconds=float(invocation.duration_seconds),
            cpu_total_seconds=metrics.get("cpu_total_seconds"),
            cpu_utilization_percent=metrics.get("cpu_utilization_percent"),
            peak_memory_bytes=metrics.get("peak_memory_bytes"),
            exit_code=invocation.exit_code,
            timed_out=invocation.timed_out,
            telemetry_method=str(metrics.get("method", "unavailable")),
            telemetry_unavailable_reason=metrics.get("unavailable_reason"),
            sequence_index=sequence_index,
            cache_state=cache_state,
            coverage_caveat=partial,
            command=list(invocation.argv),
        )
    except Exception as exc:
        return RunRecord(
            run_index=index,
            phase=phase,
            duration_seconds=0.0,
            cpu_total_seconds=None,
            cpu_utilization_percent=None,
            peak_memory_bytes=None,
            exit_code=None,
            timed_out=False,
            telemetry_method="unavailable",
            telemetry_unavailable_reason=None,
            error=str(exc),
            sequence_index=sequence_index,
            cache_state=cache_state,
        )


def benchmark_product(
    adapter,
    artifact,
    target: Path | str,
    work_dir: Path | str,
    *,
    plan: BenchmarkPlan | None = None,
    workload: dict | None = None,
    scanner_version: str | None = None,
    dataset: dict | None = None,
    scanner_config: Path | None = None,
    sequence_index: int = 0,
    cache_state: str = "uncontrolled",
    allow_partial: bool = False,
    suite: str | None = None,
    workload_key: str | None = None,
) -> dict:
    plan = plan or BenchmarkPlan()
    plan.validate()
    environment = environment_for(plan.environment, stress_profile=plan.stress_profile)
    target = Path(target)
    work_dir = Path(work_dir)
    workload = workload or {}
    suite = suite or workload.get("suite")
    workload_key = workload_key or workload.get("key") or workload.get("workload_key")
    records: list[RunRecord] = []
    for index in range(plan.warmups):
        records.append(
            _run_once(
                adapter,
                artifact,
                target,
                work_dir / "warmup" / str(index),
                plan,
                index,
                "warmup",
                scanner_config,
                sequence_index=sequence_index,
                cache_state="warmup" if index == 0 else "warm",
                allow_partial=allow_partial,
                suite=suite,
                workload_key=workload_key,
            )
        )
    for index in range(plan.measured_runs):
        records.append(
            _run_once(
                adapter,
                artifact,
                target,
                work_dir / "measured" / str(index),
                plan,
                index,
                "measured",
                scanner_config,
                sequence_index=sequence_index,
                cache_state=cache_state,
                allow_partial=allow_partial,
                suite=suite,
                workload_key=workload_key,
            )
        )
    measured = [record for record in records if record.phase == "measured" and not record.error]
    durations = [record.duration_seconds for record in measured if record.duration_seconds > 0]
    cpu_values = [
        record.cpu_total_seconds
        for record in measured
        if record.cpu_total_seconds is not None
    ]
    memory_values = [
        record.peak_memory_bytes
        for record in measured
        if record.peak_memory_bytes is not None
    ]
    failures = sum(record.error is not None for record in records)
    timeouts = sum(record.timed_out for record in records)
    duration_stats = _stats(durations)
    cv = duration_stats["coefficient_of_variation"]
    stability = (
        "STABLE"
        if len(durations) == plan.measured_runs
        and failures == 0
        and (cv or 0) <= environment.stability_threshold
        else "UNSTABLE"
        if len(durations) == plan.measured_runs
        else "INCOMPLETE"
    )
    throughput = None
    if workload.get("bytes") and duration_stats["median"]:
        throughput = round(workload["bytes"] / duration_stats["median"], 3)
    inspected_bytes = workload.get("inspected_bytes", workload.get("bytes"))
    inspected_throughput = None
    if inspected_bytes and duration_stats["median"]:
        inspected_throughput = round(inspected_bytes / duration_stats["median"], 3)
    eligible_files = workload.get("eligible_files", workload.get("files"))
    inspected_files = workload.get("inspected_files", eligible_files)
    file_coverage_percent = None
    if isinstance(eligible_files, int) and eligible_files:
        if isinstance(inspected_files, int):
            file_coverage_percent = round(100.0 * inspected_files / eligible_files, 2)
    files_per_second = None
    if isinstance(eligible_files, int) and duration_stats["median"]:
        files_per_second = round(eligible_files / duration_stats["median"], 3)
    return {
        "report_type": "rnc-scan-harness/performance",
        "performance_version": PERFORMANCE_VERSION,
        "harness_version": __version__,
        "scanner": {
            "key": getattr(adapter, "key", "unknown"),
            "version": scanner_version or artifact.version,
        },
        "product": {
            "platform": artifact.platform.key,
            "kind": "docker" if artifact.platform.is_docker else "executable",
            "execution_method": (
                "docker" if artifact.platform.is_docker else "native"
            ),
            "build_id": (artifact.metadata or {}).get("build_id"),
            "source_commit": (artifact.metadata or {}).get("source_commit"),
            "image_id": artifact.image_id,
            "image_tag": artifact.image_tag,
            "artifact_sha256": artifact.artifact_sha256,
            "architecture": artifact.platform.arch,
            "emulated": bool((artifact.metadata or {}).get("emulated", False)),
            "manifest_sha256": ((artifact.metadata or {}).get("manifest") or {}).get(
                "sha256"
            ),
        },
        "benchmark_environment": environment.to_dict(),
        "environment": telemetry.host_metadata(),
        "dataset": dataset or {},
        "workload": workload,
        "benchmark": {
            "version": PERFORMANCE_VERSION,
            "mode": plan.mode,
            "warmups": plan.warmups,
            "measured_runs": plan.measured_runs,
            "timeout_seconds": plan.timeout_seconds,
            "sequential": True,
            "sequence_index": sequence_index,
            "cache_state": cache_state,
            "scanner_order_controlled": cache_state != "uncontrolled",
            "stress_profile": plan.stress_profile,
            "environment_mode": environment.mode,
            "suite": suite,
            "workload_key": workload_key,
        },
        "runs": [record.__dict__ for record in records],
        "summary": {
            "runtime_seconds": duration_stats,
            "cpu_total_seconds": _stats(cpu_values),
            "cpu_utilization_percent": _stats(
                [
                    record.cpu_utilization_percent
                    for record in measured
                    if record.cpu_utilization_percent is not None
                ]
            ),
            "peak_memory_bytes": {
                "max": max(memory_values) if memory_values else None,
                "median": round(statistics.median(memory_values), 3)
                if memory_values
                else None,
                "available_samples": len(memory_values),
            },
            "throughput_bytes_per_second": throughput,
            "inspected_throughput_bytes_per_second": inspected_throughput,
            "files_per_second": files_per_second,
            "files_eligible": eligible_files,
            "files_inspected": inspected_files,
            "file_coverage_percent": file_coverage_percent,
            "archive_files": workload.get("archive_files"),
            "archives_extracted": workload.get("archives_extracted"),
            "resource_limit_events": workload.get("resource_limit_events"),
            "failures": failures,
            "timeouts": timeouts,
            "stability": stability,
            "stability_threshold_cv": environment.stability_threshold,
            "telemetry_methods": sorted(
                {record.telemetry_method for record in measured}
                or {"unavailable"}
            ),
            "coverage_caveat_count": sum(
                1 for record in measured if record.coverage_caveat
            ),
            "coverage_caveats": [
                record.coverage_caveat
                for record in measured
                if record.coverage_caveat
            ],
        },
    }


def performance_drift(previous: dict, current: dict) -> dict:
    """Compare two already-published performance documents.

    The function is intentionally reporting-only; it never interprets scanner
    findings or modifies either measurement.
    """
    def _median(document: dict):
        return ((document.get("summary") or {}).get("runtime_seconds") or {}).get("median")

    before = _median(previous)
    after = _median(current)
    ratio = round(after / before, 6) if before and after else None
    return {
        "previous_product": (previous.get("product") or {}).get("platform"),
        "current_product": (current.get("product") or {}).get("platform"),
        "previous_environment": (previous.get("benchmark_environment") or {}).get("mode"),
        "current_environment": (current.get("benchmark_environment") or {}).get("mode"),
        "previous_median_seconds": before,
        "current_median_seconds": after,
        "runtime_ratio": ratio,
        "runtime_change_percent": round(100.0 * (ratio - 1.0), 3) if ratio is not None else None,
        "previous_stability": (previous.get("summary") or {}).get("stability"),
        "current_stability": (current.get("summary") or {}).get("stability"),
        "artifact_changed": (previous.get("product") or {}).get("artifact_sha256")
        != (current.get("product") or {}).get("artifact_sha256"),
        "environment_changed": (previous.get("benchmark_environment") or {}).get("mode")
        != (current.get("benchmark_environment") or {}).get("mode"),
    }


def write_report(document: dict, json_path: Path | str, markdown_path: Path | str) -> None:
    json_path = Path(json_path)
    markdown_path = Path(markdown_path)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    markdown_path.write_text(render_markdown(document), encoding="utf-8", newline="\n")


def render_markdown(document: dict) -> str:
    product = document["product"]
    summary = document["summary"]
    runtime = summary["runtime_seconds"]
    environment = document.get("benchmark_environment") or {}
    lines = [
        "# Performance Benchmark",
        "",
        f"> Product: `{product['platform']}` ({product['execution_method']})",
        f"> Scanner: `{document['scanner']['key']}` {document['scanner']['version'] or ''}",
        f"> Benchmark version: `{document['benchmark']['version']}`",
        f"> Environment profile: **{environment.get('mode')}** "
        f"({environment.get('contention')}); publishable={environment.get('publishable')}",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Warm-ups | {document['benchmark']['warmups']} |",
        f"| Measured runs | {document['benchmark']['measured_runs']} |",
        f"| Median runtime | {runtime['median']} s |",
        f"| Min / max runtime | {runtime['minimum']} / {runtime['maximum']} s |",
        f"| Runtime stdev | {runtime['stdev']} s |",
        f"| Runtime CV | {runtime['coefficient_of_variation']} |",
        f"| CPU time median | {summary['cpu_total_seconds']['median']} s |",
        f"| Peak memory | {summary['peak_memory_bytes']['max']} bytes |",
        f"| Throughput | {summary['throughput_bytes_per_second']} bytes/s |",
        f"| Files eligible / inspected | {summary.get('files_eligible')} / {summary.get('files_inspected')} |",
        f"| Failures / timeouts | {summary['failures']} / {summary['timeouts']} |",
        f"| Stability | **{summary['stability']}** |",
        "",
        "CPU and peak-memory values are `null` when the execution environment cannot "
        "provide them. Short container runs may finish before `docker stats` samples. "
        "DEV measurements are contended and are not release evidence.",
        "",
    ]
    return "\n".join(lines)
