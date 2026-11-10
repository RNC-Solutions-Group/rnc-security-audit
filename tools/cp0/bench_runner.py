"""Representative, equivalent Go/Rust scanner benchmark for CP0.

This is disposable benchmark infrastructure, not the production detection
engine. Both implementations read the same rule table, use equivalent safe
regexes, validate candidates identically, and emit the same deterministic
checksum. Correctness is checked before timings are accepted.
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
BENCH = ROOT / "tools/cp0/bench"
RULES = BENCH / "rules.tsv"
MIB = 1024 * 1024
FNV_OFFSET = 14695981039346656037
FNV_PRIME = 1099511628211
OUTPUT_RE = re.compile(r"^count=(\d+) checksum=([0-9a-f]{16}) rules=(\d+) mode=(\w+) threads=(\d+)$")
TIME_RE = re.compile(r"user=([0-9.]+) sys=([0-9.]+) rss=(\d+)")
SEED = 20261110


def _fill(pattern: bytes, size: int) -> bytearray:
    if not pattern:
        raise ValueError("filler pattern must not be empty")
    return bytearray((pattern * (size // len(pattern) + 1))[:size])


def _write_marker_line(
    data: bytearray,
    offset: int,
    style: str,
    family: str,
    index: int,
) -> tuple[int, int]:
    marker = f"RNC_SYNTH_KEY_{family}_{index:07d}".encode("ascii")
    if style == "plain":
        line = b"VALUE=" + marker + b"\n"
        start = offset + len(b"VALUE=")
    elif style == "quoted":
        line = b'VALUE="' + marker + b'"\n'
        start = offset + len(b'VALUE="')
    elif style == "url":
        prefix = b"url=https://synthetic.invalid/"
        line = prefix + marker + b"\n"
        start = offset + len(prefix)
    elif style == "multiline":
        begin = b"-----BEGIN RNC SYNTHETIC KEY-----\n"
        end = b"-----END RNC SYNTHETIC KEY-----\n"
        line = begin + marker + b"\n" + end
        start = offset + len(begin)
    else:
        raise ValueError(f"unknown marker style {style}")
    if offset + len(line) > len(data):
        raise ValueError("marker line exceeds workload size")
    data[offset : offset + len(line)] = line
    return start, start + len(marker)


def _rules() -> tuple[list[str], list[str]]:
    lines = RULES.read_text(encoding="utf-8").splitlines()
    data = [line for line in lines if line and not line.startswith("#")]
    return data[:8], data


def _write_rules(work: Path) -> tuple[Path, Path]:
    basic, expanded = _rules()
    basic_path = work / "rules-basic.tsv"
    expanded_path = work / "rules-expanded.tsv"
    header = "# rule_id\tcapture_group\tfamily\tregex\n"
    basic_path.write_text(header + "\n".join(basic) + "\n", encoding="utf-8", newline="\n")
    expanded_path.write_text(header + "\n".join(expanded) + "\n", encoding="utf-8", newline="\n")
    return basic_path, expanded_path


def _fnv(keys: list[str]) -> str:
    value = FNV_OFFSET
    for key in keys:
        for byte in key.encode("utf-8"):
            value ^= byte
            value = (value * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def _expected(keys: list[str]) -> tuple[int, str]:
    ordered = sorted(keys)
    return len(ordered), _fnv(ordered)


def _build_workload(
    root: Path,
    name: str,
    *,
    size: int,
    marker_count: int,
    ruleset: str,
    files: int = 1,
    file_size: int | None = None,
    style_cycle: tuple[str, ...] = ("plain", "quoted", "url", "multiline"),
    family_cycle: tuple[str, ...] = ("AWS", "GITHUB", "STRIPE", "HTTPS", "GENERIC", "QUOTED", "MULTILINE", "URL"),
    unicode_filler: bool = False,
    false_positive_filler: bool = False,
    worst_case: bool = False,
) -> dict:
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    keys: list[str] = []
    relative_files: list[str] = []
    total_bytes = 0
    seed_index = 0
    if files > 1:
        per_file = marker_count // files
        for file_index in range(files):
            relative = f"bucket-{file_index // 200:02d}/file-{file_index:05d}.txt"
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            actual_size = file_size or size
            filler = b"benign-small-file-filler-0123456789\n"
            data = _fill(filler, actual_size)
            marker_total = per_file + (1 if file_index < marker_count % files else 0)
            positions = [128 + ordinal * 8192 for ordinal in range(marker_total)]
            for ordinal, offset in enumerate(positions):
                if offset + 256 > len(data):
                    raise ValueError("small file workload marker placement exceeds file")
                family = family_cycle[(seed_index + ordinal) % len(family_cycle)]
                style = "plain" if family in {"AWS", "GITHUB", "STRIPE", "HTTPS", "GENERIC"} else "quoted"
                if family == "URL":
                    style = "url"
                elif family == "MULTILINE":
                    style = "multiline"
                start, end = _write_marker_line(data, offset, style, family, seed_index + ordinal)
                rule = f"synthetic-{family.lower()}"
                keys.append(f"{rule}\t{relative}\t{start}\t{end}\n")
            target.write_bytes(data)
            relative_files.append(relative)
            total_bytes += len(data)
            seed_index += marker_total
    else:
        if worst_case:
            pattern = b"RNC_SYNTH_KEY_AWS_! RNC_SYNTH_KEY_GITHUB_! RNC_DECOY_ITEM\n"
            data = _fill(pattern, size)
        elif false_positive_filler:
            pattern = (
                b"RNC_SYNTH_KEY_AWS_12- RNC_SYNTH_KEY_GITHUB_lower "
                b"RNC_DECOY_KEY_STRIPE_1234 RNC_SYNTH_KEY_HTTPS_!!!\n"
            )
            data = _fill(pattern, size)
        elif unicode_filler:
            pattern = "café—naïve—résumé—données—\n".encode("utf-8")
            data = _fill(pattern, size)
        else:
            data = _fill(b"benign-RNC-benchmark-fixture-0123456789-abcdef\n", size)
        if marker_count:
            spacing = max(512, size // (marker_count + 1))
            for ordinal in range(marker_count):
                offset = spacing * (ordinal + 1)
                if offset + 512 > len(data):
                    raise ValueError("large workload marker placement exceeds file")
                family = family_cycle[(seed_index + ordinal) % len(family_cycle)]
                if family in {"AWS", "GITHUB", "STRIPE", "HTTPS", "GENERIC"}:
                    style = "plain"
                elif family == "QUOTED":
                    style = "quoted"
                elif family == "URL":
                    style = "url"
                elif family == "MULTILINE":
                    style = "multiline"
                else:
                    style = style_cycle[(seed_index + ordinal) % len(style_cycle)]
                start, end = _write_marker_line(data, offset, style, family, seed_index + ordinal)
                keys.append(f"synthetic-{family.lower()}\t{name}.bin\t{start}\t{end}\n")
        relative = f"{name}.bin"
        target = directory / relative
        target.write_bytes(data)
        relative_files.append(relative)
        total_bytes = len(data)
    manifest = directory / "files.txt"
    manifest.write_text("\n".join(relative_files) + "\n", encoding="utf-8", newline="\n")
    expected_count, expected_checksum = _expected(keys)
    if expected_count != marker_count:
        raise ValueError(f"{name}: expected {marker_count} findings, generated {expected_count}")
    return {
        "name": name,
        "directory": directory,
        "manifest": manifest,
        "ruleset": ruleset,
        "bytes": total_bytes,
        "files": len(relative_files),
        "expected_count": expected_count,
        "expected_checksum": expected_checksum,
    }


def build_workloads(root: Path) -> list[dict]:
    workloads = []
    workloads.append(_build_workload(root, "large-low", size=32 * MIB, marker_count=64, ruleset="basic"))
    workloads.append(_build_workload(root, "large-high", size=32 * MIB, marker_count=8192, ruleset="basic"))
    workloads.append(_build_workload(root, "small-many", size=0, marker_count=2000, ruleset="basic", files=2000, file_size=4096))
    workloads.append(_build_workload(root, "fp-heavy", size=8 * MIB, marker_count=16, ruleset="basic", false_positive_filler=True))
    workloads.append(_build_workload(root, "unicode", size=8 * MIB, marker_count=512, ruleset="basic", unicode_filler=True))
    workloads.append(_build_workload(root, "large-ruleset", size=8 * MIB, marker_count=256, ruleset="expanded"))
    workloads.append(_build_workload(root, "worst-case", size=8 * MIB, marker_count=0, ruleset="basic", worst_case=True))
    workloads.append(_build_workload(root, "multiline", size=8 * MIB, marker_count=128, ruleset="basic"))
    return workloads


def _run(command: list[str], *, cwd: Path | None = None, timeout: int = 180, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, **(env or {})},
    )


def _tool(command: list[str], *, cwd: Path | None = None) -> str:
    result = _run(command, cwd=cwd, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(command)}: {result.stderr.strip()}")
    return result.stdout.strip()


def build_go(work: Path) -> dict:
    binary = work / "cp0-bench-go"
    if os.name == "nt":
        binary = binary.with_suffix(".exe")
    started = time.perf_counter()
    result = _run(
        ["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(binary), "."],
        cwd=BENCH,
        timeout=600,
        env={"CGO_ENABLED": "0"},
    )
    duration = time.perf_counter() - started
    if result.returncode != 0:
        raise RuntimeError(f"go build failed: {result.stderr}")
    return {
        "language": "go",
        "version": _tool(["go", "version"]),
        "command": "go build -trimpath -ldflags=-s -w -o <binary> .",
        "duration_seconds": round(duration, 3),
        "binary_bytes": binary.stat().st_size,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "runtime_dependencies": _tool(["go", "list", "-m", "all"], cwd=BENCH),
        "environment": _tool(["go", "env", "GOOS", "GOARCH", "CGO_ENABLED"], cwd=BENCH),
        "binary": binary,
    }


def build_rust(work: Path) -> dict:
    target_dir = work / "cargo-target"
    started = time.perf_counter()
    result = _run(
        ["cargo", "build", "--release", "--locked"],
        cwd=BENCH,
        timeout=900,
        env={"CARGO_TARGET_DIR": str(target_dir)},
    )
    duration = time.perf_counter() - started
    if result.returncode != 0:
        raise RuntimeError(f"cargo build failed: {result.stderr}")
    binary = target_dir / "release" / ("cp0-bench-scanner.exe" if os.name == "nt" else "cp0-bench-scanner")
    if not binary.is_file():
        raise RuntimeError("cargo build produced no expected binary")
    dependency_tree = _tool(["cargo", "tree", "--locked"], cwd=BENCH)
    dependency_tree = "\n".join(line.split(" (", 1)[0] for line in dependency_tree.splitlines())
    return {
        "language": "rust",
        "version": _tool(["rustc", "--version"]),
        "cargo_version": _tool(["cargo", "--version"]),
        "command": "cargo build --release --locked",
        "duration_seconds": round(duration, 3),
        "binary_bytes": binary.stat().st_size,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "runtime_dependencies": dependency_tree,
        "environment": platform.platform(),
        "binary": binary,
    }


def _time_wrapper() -> str | None:
    candidate = shutil.which("time")
    if candidate and "System32" not in candidate:
        test = _run([candidate, "-f", "user=%U sys=%S rss=%M", "-o", os.devnull, "true"], timeout=30)
        if test.returncode == 0:
            return candidate
    return None


def _run_scanner(
    binary: Path,
    workload: dict,
    *,
    mode: str,
    threads: int,
    rules_path: Path,
    time_wrapper: str | None,
    work: Path,
) -> dict:
    command = [
        str(binary),
        "--corpus", str(workload["directory"]),
        "--manifest", str(workload["manifest"]),
        "--rules", str(rules_path),
        "--mode", mode,
        "--threads", str(threads),
    ]
    metrics_path = work / "time.metrics"
    wrapped = list(command)
    if time_wrapper:
        wrapped = [time_wrapper, "-f", "user=%U sys=%S rss=%M", "-o", str(metrics_path)] + command
    started = time.perf_counter_ns()
    result = subprocess.run(wrapped, capture_output=True, text=True, timeout=180)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if result.returncode != 0:
        raise RuntimeError(f"scanner failed ({result.returncode}): {result.stderr.strip()[:500]}")
    match = OUTPUT_RE.match(result.stdout.strip())
    if not match:
        raise RuntimeError(f"scanner produced unexpected output: {result.stdout!r}")
    count, checksum, loaded_rules, observed_mode, observed_threads = match.groups()
    if int(count) != workload["expected_count"] or checksum != workload["expected_checksum"]:
        raise RuntimeError(
            f"incorrect result for {workload['name']}: count={count} checksum={checksum}, "
            f"expected {workload['expected_count']}/{workload['expected_checksum']}"
        )
    if observed_mode != mode or int(observed_threads) != threads:
        raise RuntimeError("scanner echoed incorrect mode/threads")
    metrics = {"wall_ms": elapsed_ms, "peak_rss_kb": None, "user_seconds": None, "system_seconds": None}
    if time_wrapper and metrics_path.is_file():
        parsed = TIME_RE.search(metrics_path.read_text(encoding="utf-8", errors="replace"))
        if parsed:
            metrics["user_seconds"] = float(parsed.group(1))
            metrics["system_seconds"] = float(parsed.group(2))
            metrics["peak_rss_kb"] = int(parsed.group(3))
        metrics_path.unlink(missing_ok=True)
    metrics["loaded_rules"] = int(loaded_rules)
    return metrics


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def _summary(samples: list[float]) -> dict:
    return {
        "samples_ms": [round(value, 3) for value in samples],
        "median_ms": round(statistics.median(samples), 3),
        "p95_ms": round(_percentile(samples, 0.95), 3),
        "max_ms": round(max(samples), 3),
        "min_ms": round(min(samples), 3),
        "mean_ms": round(statistics.mean(samples), 3),
    }


def measure(work: Path, runs: int) -> dict:
    if runs < 3:
        raise ValueError("at least three repetitions are required")
    for tool in ("go", "rustc", "cargo"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"missing {tool} toolchain; no benchmark was run")
    basic_rules, expanded_rules = _write_rules(work)
    workloads = build_workloads(work)
    builds = {"go": build_go(work), "rust": build_rust(work)}
    time_wrapper = _time_wrapper()
    profiles = []
    for workload in workloads:
        rules_path = basic_rules if workload["ruleset"] == "basic" else expanded_rules
        thread_options = [1, 4] if workload["name"] == "small-many" else [1]
        for mode in ("whole", "stream"):
            for threads in thread_options:
                samples: dict[str, list[float]] = {"go": [], "rust": []}
                memory: dict[str, list[int]] = {"go": [], "rust": []}
                cpu: dict[str, list[float]] = {"go": [], "rust": []}
                for language in ("go", "rust"):
                    _run_scanner(
                        builds[language]["binary"], workload, mode=mode, threads=threads,
                        rules_path=rules_path, time_wrapper=time_wrapper, work=work,
                    )
                for repetition in range(runs):
                    order = ("go", "rust") if repetition % 2 == 0 else ("rust", "go")
                    for language in order:
                        metrics = _run_scanner(
                            builds[language]["binary"], workload, mode=mode, threads=threads,
                            rules_path=rules_path, time_wrapper=time_wrapper, work=work,
                        )
                        samples[language].append(metrics["wall_ms"])
                        if metrics["peak_rss_kb"] is not None:
                            memory[language].append(metrics["peak_rss_kb"])
                        if metrics["user_seconds"] is not None and metrics["system_seconds"] is not None:
                            cpu_seconds = metrics["user_seconds"] + metrics["system_seconds"]
                            # GNU time reports hundredths of a second; a zero
                            # reading for a sub-100 ms run is not measurable.
                            if cpu_seconds > 0:
                                cpu[language].append(100.0 * cpu_seconds / (metrics["wall_ms"] / 1000.0))
                row = {
                    "workload": workload["name"],
                    "mode": mode,
                    "threads": threads,
                    "ruleset": workload["ruleset"],
                    "bytes": workload["bytes"],
                    "files": workload["files"],
                    "expected_count": workload["expected_count"],
                    "expected_checksum": workload["expected_checksum"],
                    "measurements": {},
                }
                for language in ("go", "rust"):
                    stats = _summary(samples[language])
                    stats["throughput_mib_s"] = round(workload["bytes"] / MIB / (stats["median_ms"] / 1000.0), 2) if stats["median_ms"] else None
                    stats["peak_rss_kb_median"] = round(statistics.median(memory[language])) if memory[language] else None
                    stats["cpu_percent_median"] = round(statistics.median(cpu[language]), 2) if cpu[language] else None
                    stats["correct"] = True
                    row["measurements"][language] = stats
                profiles.append(row)
    report = {
        "contract": "cp0-representative-scanner-benchmark-v0.1",
        "not_production_engine_comparison": True,
        "description": "Equivalent disposable Go/Rust scanners: 32 pinned safe regex rules, shared candidate validation, whole-file and 8 KiB-overlap streaming modes, deterministic finding checksum.",
        "runs_per_language": runs,
        "warmups_per_language": 1,
        "seed": SEED,
        "memory_and_cpu_available": time_wrapper is not None,
        "time_wrapper": Path(time_wrapper).name if time_wrapper else None,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "toolchains": {"go": builds["go"]["version"], "rust": builds["rust"]["version"], "cargo": builds["rust"]["cargo_version"]},
        "builds": {
            language: {key: value for key, value in builds[language].items() if key != "binary"}
            for language in ("go", "rust")
        },
        "profiles": profiles,
        "summary": {
            "profiles": len(profiles),
            "all_correct": True,
            "languages": ["go", "rust"],
            "interpretation": "Measured on one runner with equivalent rules and outputs. Build, dependency, memory and portability tradeoffs belong in the ADR; this file does not choose a language.",
        },
    }
    if not time_wrapper:
        report["limitations"] = ["Peak memory and CPU utilization unavailable because GNU time was not found."]
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="rnc-cp0-bench-") as temp:
        report = measure(Path(temp), args.runs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"CP0 representative benchmark wrote {args.output} ({len(report['profiles'])} profiles, {args.runs} runs/language)")


if __name__ == "__main__":
    main()
