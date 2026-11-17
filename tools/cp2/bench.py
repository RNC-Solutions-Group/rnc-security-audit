"""CP2 real-engine benchmark: strategies, modes and policy/config overhead."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

from tools.cp1.bench import MIB, _summary_count, _time_wrapper, build_workloads

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules/rnc-synthetic-v1.json"
STRATEGIES = ("regex", "regexset", "prefilter", "auto")
TIME_RE = re.compile(r"user=([0-9.]+) sys=([0-9.]+) rss=(\d+)")


def _run(binary: Path, workload: dict, mode: str, strategy: str, time_wrapper: str | None, metrics_path: Path) -> dict:
    command = [
        str(binary), "scan",
        "--root", str(workload["path"]),
        "--rules", str(RULES),
        "--format", "summary",
        "--run-id", f"cp2-bench-{workload['name']}-{mode}-{strategy}",
        "--mode", mode,
        "--strategy", strategy,
        "--stream-chunk-bytes", "65536",
        "--max-file-bytes", str(64 * MIB),
        "--max-total-bytes", str(64 * MIB),
    ]
    wrapped = [time_wrapper, "-f", "user=%U sys=%S rss=%M", "-o", str(metrics_path)] + command if time_wrapper else command
    started = time.perf_counter_ns()
    result = subprocess.run(wrapped, capture_output=True, text=True, timeout=600)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if result.returncode not in (0, 10, 20):
        raise RuntimeError(f"{workload['name']}/{mode}/{strategy}: exit {result.returncode}: {result.stderr.strip()}")
    count = _summary_count(result.stdout)
    if count != workload["expected"]:
        raise RuntimeError(f"{workload['name']}/{strategy}: findings {count} != {workload['expected']}")
    if "RNC_SYNTH_KEY_" in result.stdout or "evidence_digest" in result.stdout or "finding_id" in result.stdout:
        raise RuntimeError("benchmark summary leaked sensitive evidence")
    backend = "unknown"
    for line in result.stdout.splitlines():
        if line.startswith("Backend:"):
            backend = line.split()[1]
    metrics = {"wall_ms": elapsed_ms, "peak_rss_kb": None, "cpu_percent": None, "backend": backend}
    if time_wrapper and metrics_path.is_file():
        match = TIME_RE.search(metrics_path.read_text(encoding="utf-8", errors="replace"))
        if match:
            user, system, rss = match.groups()
            metrics["peak_rss_kb"] = int(rss)
            cpu_seconds = float(user) + float(system)
            metrics["cpu_percent"] = 100.0 * cpu_seconds / (elapsed_ms / 1000.0)
        metrics_path.unlink(missing_ok=True)
    return metrics


def _stats(samples: list[float]) -> dict:
    ordered = sorted(samples)
    return {
        "samples_ms": [round(value, 3) for value in samples],
        "median_ms": round(statistics.median(samples), 3),
        "p95_ms": round(ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)], 3),
        "max_ms": round(max(samples), 3),
        "min_ms": round(min(samples), 3),
    }


def _plan(binary: Path, strategy: str) -> dict:
    completed = subprocess.run(
        [str(binary), "rules", "validate", "--rules", str(RULES), "--strategy", strategy],
        capture_output=True, text=True, timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"plan failed for {strategy}: {completed.stderr}")
    result = {"strategy": strategy}
    for line in completed.stdout.splitlines():
        if line.startswith("Effective strategy:"):
            result["effective"] = line.split(":", 1)[1].strip()
        elif line.startswith("Fallback:"):
            result["fallback"] = line.split(":", 1)[1].strip()
    return result


def measure(binary: Path, runs: int, *, build_seconds: float | None, binary_sha256: str | None) -> dict:
    if runs < 3:
        raise ValueError("at least three runs are required")
    if not binary.is_file():
        raise RuntimeError(f"binary not found: {binary}")
    time_wrapper = _time_wrapper()
    plans = [_plan(binary, strategy) for strategy in STRATEGIES]
    with tempfile.TemporaryDirectory(prefix="rnc-cp2-bench-") as temp:
        workloads = build_workloads(Path(temp))
        metrics_path = Path(temp) / "time.metrics"
        profiles = []
        for workload in workloads:
            for mode in ("whole", "stream"):
                for strategy in STRATEGIES:
                    samples = []
                    memory = []
                    cpu = []
                    backend = None
                    for _ in range(runs):
                        observed = _run(binary, workload, mode, strategy, time_wrapper, metrics_path)
                        samples.append(observed["wall_ms"])
                        backend = observed["backend"]
                        if observed["peak_rss_kb"] is not None:
                            memory.append(observed["peak_rss_kb"])
                        if observed["cpu_percent"] is not None:
                            cpu.append(observed["cpu_percent"])
                    stats = _stats(samples)
                    stats["throughput_mib_s"] = round(workload["bytes"] / MIB / (stats["median_ms"] / 1000.0), 2)
                    stats["files_per_second"] = round(workload["files"] / (stats["median_ms"] / 1000.0), 2)
                    stats["peak_rss_kb_median"] = round(statistics.median(memory)) if memory else None
                    stats["cpu_percent_median"] = round(statistics.median(cpu), 2) if cpu else None
                    profiles.append({
                        "workload": workload["name"],
                        "mode": mode,
                        "strategy": strategy,
                        "effective_backend": backend,
                        "bytes": workload["bytes"],
                        "files": workload["files"],
                        "expected_findings": workload["expected"],
                        "measurements": stats,
                        "correct": True,
                    })
    return {
        "contract": "cp2-multi-strategy-benchmark-v0.1",
        "runs": runs,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "ruleset": "rnc-synthetic-v1",
        "rules_file_sha256": hashlib.sha256(RULES.read_bytes()).hexdigest(),
        "build": {
            "seconds": build_seconds,
            "binary_bytes": binary.stat().st_size,
            "binary_sha256": binary_sha256 or hashlib.sha256(binary.read_bytes()).hexdigest(),
        },
        "plans": plans,
        "performance_available": time_wrapper is not None,
        "parallelism": {"implemented": False, "note": "CP2 remains single-threaded; strategy parallelism is deferred."},
        "profiles": profiles,
        "all_correct": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--build-seconds", type=float)
    parser.add_argument("--binary-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = measure(args.binary, args.runs, build_seconds=args.build_seconds, binary_sha256=args.binary_sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"CP2 benchmark wrote {args.output} ({len(report['profiles'])} profiles)")


if __name__ == "__main__":
    main()
