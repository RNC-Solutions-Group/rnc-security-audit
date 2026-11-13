"""CP1 production-engine benchmark: real Rust CLI, CP1 rules, synthetic inputs.

This measures the actual detector implementation, not the disposable CP0 probes.
It verifies finding counts before accepting timings and records build/binary
characteristics supplied by the CI build step.
"""

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


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules/rnc-synthetic-v1.json"
MIB = 1024 * 1024
FINDINGS_RE = re.compile(r"Findings: (\d+)")
TIME_RE = re.compile(r"user=([0-9.]+) sys=([0-9.]+) rss=(\d+)")


def _fill(pattern: bytes, size: int) -> bytearray:
    return bytearray((pattern * (size // len(pattern) + 1))[:size])


def _marker(family: str, index: int) -> bytes:
    return f"RNC_SYNTH_KEY_{family}_{index:07d}".encode("ascii")


def _write_marker(data: bytearray, offset: int, family: str, index: int) -> tuple[int, int]:
    marker = _marker(family, index)
    line = b"KEY=" + marker + b"\n"
    if offset + len(line) > len(data):
        raise ValueError("marker exceeds workload")
    if offset > 0:
        # Terminate any adjacent decoy token so the inserted marker is not
        # extended by alphanumeric filler on either side.
        data[offset - 1] = 10
    data[offset : offset + len(line)] = line
    start = offset + 4
    return start, start + len(marker)


def _make_large(root: Path, name: str, size: int, count: int, families: tuple[str, ...]) -> dict:
    directory = root / name
    directory.mkdir(parents=True)
    path = directory / "data.bin"
    data = _fill(b"benign-RNC-cp1-workload-0123456789-abcdefghijklmnopqrstuvwxyz\n", size)
    spacing = size // (count + 1)
    keys = []
    for index in range(count):
        offset = spacing * (index + 1)
        family = families[index % len(families)]
        start, end = _write_marker(data, offset, family, index)
        keys.append((start, end))
    path.write_bytes(data)
    return {"name": name, "path": directory, "bytes": size, "files": 1, "expected": len(keys)}


def _make_small(root: Path, name: str, files: int, file_size: int) -> dict:
    directory = root / name
    directory.mkdir(parents=True)
    for index in range(files):
        path = directory / f"nested/{index // 100:02d}/file-{index:05d}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        data = _fill(b"benign-small-file-filler-0123456789\n", file_size)
        _write_marker(data, 128, "GENERIC", index)
        path.write_bytes(data)
    return {"name": name, "path": directory, "bytes": files * file_size, "files": files, "expected": files}


def _make_fp_heavy(root: Path, name: str, size: int, count: int) -> dict:
    directory = root / name
    directory.mkdir(parents=True)
    path = directory / "data.bin"
    pattern = (
        b"RNC_SYNTH_KEY_AWS_12- RNC_SYNTH_KEY_GITHUB_lower "
        b"RNC_DECOY_KEY_STRIPE_1234 RNC_SYNTH_KEY_HTTPS_!!!\n"
    )
    data = _fill(pattern, size)
    spacing = size // (count + 1)
    keys = []
    for index in range(count):
        start, end = _write_marker(data, spacing * (index + 1), "AWS", index)
        keys.append((start, end))
    path.write_bytes(data)
    return {"name": name, "path": directory, "bytes": size, "files": 1, "expected": len(keys)}


def _make_unicode(root: Path, name: str, size: int, count: int) -> dict:
    directory = root / name
    directory.mkdir(parents=True)
    path = directory / "data.bin"
    pattern = "café—naïve—résumé—données—\n".encode("utf-8")
    data = _fill(pattern, size)
    spacing = size // (count + 1)
    keys = []
    for index in range(count):
        start, end = _write_marker(data, spacing * (index + 1), "GENERIC", index)
        keys.append((start, end))
    path.write_bytes(data)
    return {"name": name, "path": directory, "bytes": size, "files": 1, "expected": len(keys)}


def build_workloads(root: Path) -> list[dict]:
    families = ("AWS", "GITHUB", "STRIPE", "HTTPS", "GENERIC")
    return [
        _make_large(root, "large-low", 32 * MIB, 64, families),
        _make_large(root, "large-high", 32 * MIB, 4096, families),
        _make_small(root, "small-many", 2000, 4096),
        _make_fp_heavy(root, "fp-heavy", 8 * MIB, 16),
        _make_unicode(root, "unicode", 8 * MIB, 256),
    ]


def _time_wrapper() -> str | None:
    candidate = shutil.which("time")
    if not candidate or "System32" in candidate:
        return None
    result = subprocess.run(
        [candidate, "-f", "user=%U sys=%S rss=%M", "-o", os.devnull, "true"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return candidate if result.returncode == 0 else None


def _summary_count(stdout: str) -> int:
    match = FINDINGS_RE.search(stdout)
    if not match:
        raise RuntimeError(f"scanner summary lacks findings count: {stdout!r}")
    return int(match.group(1))


def _run(binary: Path, workload: dict, mode: str, rules: Path, time_wrapper: str | None, metrics_path: Path) -> dict:
    command = [
        str(binary), "scan",
        "--root", str(workload["path"]),
        "--rules", str(rules),
        "--format", "summary",
        "--run-id", f"cp1-bench-{workload['name']}",
        "--mode", mode,
        "--stream-chunk-bytes", "65536",
        "--max-file-bytes", str(64 * MIB),
        "--max-total-bytes", str(64 * MIB),
    ]
    wrapped = command
    if time_wrapper:
        wrapped = [time_wrapper, "-f", "user=%U sys=%S rss=%M", "-o", str(metrics_path)] + command
    started = time.perf_counter_ns()
    result = subprocess.run(wrapped, capture_output=True, text=True, timeout=300)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if result.returncode not in (0, 10, 20):
        raise RuntimeError(f"scan failed for {workload['name']}/{mode} (exit {result.returncode}): {result.stderr.strip()} stdout={result.stdout.strip()[:200]}")
    count = _summary_count(result.stdout)
    if count != workload["expected"]:
        raise RuntimeError(f"{workload['name']}: findings {count} != {workload['expected']}")
    if "RNC_SYNTH_KEY_" in result.stdout or "evidence_digest" in result.stdout or "finding_id" in result.stdout:
        raise RuntimeError("benchmark summary leaked sensitive evidence")
    metrics = {"wall_ms": elapsed_ms, "peak_rss_kb": None, "cpu_percent": None}
    if time_wrapper and metrics_path.is_file():
        match = TIME_RE.search(metrics_path.read_text(encoding="utf-8", errors="replace"))
        if match:
            user, system, rss = match.groups()
            metrics["peak_rss_kb"] = int(rss)
            cpu_seconds = float(user) + float(system)
            if cpu_seconds > 0:
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
        "throughput_mib_s": None,
    }


def measure(binary: Path, runs: int, *, build_seconds: float | None, binary_sha256: str | None) -> dict:
    if runs < 3:
        raise ValueError("at least three runs are required")
    if not binary.is_file():
        raise RuntimeError(f"binary not found: {binary}")
    rules = RULES
    compile_samples = []
    compile_started = time.perf_counter()
    for _ in range(runs):
        started = time.perf_counter_ns()
        completed = subprocess.run(
            [str(binary), "rules", "validate", "--rules", str(rules)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"rule validation failed: {completed.stderr}")
        compile_samples.append((time.perf_counter_ns() - started) / 1_000_000)
    compile_overhead = time.perf_counter() - compile_started
    time_wrapper = _time_wrapper()
    with tempfile.TemporaryDirectory(prefix="rnc-cp1-bench-") as temp:
        root = Path(temp)
        workloads = build_workloads(root)
        metrics_path = root / "time.metrics"
        profiles = []
        for workload in workloads:
            for mode in ("whole", "stream"):
                samples = []
                memory = []
                cpu = []
                for _ in range(runs):
                    observed = _run(binary, workload, mode, rules, time_wrapper, metrics_path)
                    samples.append(observed["wall_ms"])
                    if observed["peak_rss_kb"] is not None:
                        memory.append(observed["peak_rss_kb"])
                    if observed["cpu_percent"] is not None:
                        cpu.append(observed["cpu_percent"])
                stats = _stats(samples)
                stats["throughput_mib_s"] = round(
                    workload["bytes"] / MIB / (stats["median_ms"] / 1000.0), 2
                ) if stats["median_ms"] else None
                stats["peak_rss_kb_median"] = round(statistics.median(memory)) if memory else None
                stats["cpu_percent_median"] = round(statistics.median(cpu), 2) if cpu else None
                stats["correct"] = True
                profiles.append({
                    "workload": workload["name"],
                    "mode": mode,
                    "bytes": workload["bytes"],
                    "files": workload["files"],
                    "expected_findings": workload["expected"],
                    "measurements": stats,
                })
    return {
        "contract": "cp1-real-engine-benchmark-v0.1",
        "not_cp0_comparator": True,
        "runs": runs,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "ruleset": "rnc-synthetic-v1",
        "rules_file_sha256": hashlib.sha256(rules.read_bytes()).hexdigest(),
        "build": {
            "seconds": build_seconds,
            "binary_bytes": binary.stat().st_size,
            "binary_sha256": binary_sha256 or hashlib.sha256(binary.read_bytes()).hexdigest(),
        },
        "rule_compile": {
            "samples_ms": [round(value, 3) for value in compile_samples],
            "median_ms": round(statistics.median(compile_samples), 3),
            "batch_seconds": round(compile_overhead, 3),
        },
        "parallelism": {
            "implemented": False,
            "note": "CP1 scanner is single-threaded; concurrency is a CP4/CP5 measurement target.",
        },
        "memory_and_cpu_available": time_wrapper is not None,
        "profiles": profiles,
        "all_correct": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--build-seconds", type=float)
    parser.add_argument("--binary-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = measure(
        args.binary,
        args.runs,
        build_seconds=args.build_seconds,
        binary_sha256=args.binary_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"CP1 benchmark wrote {args.output} ({len(report['profiles'])} profiles)")


if __name__ == "__main__":
    main()
