"""CP3 provider-catalog benchmark: correctness-aware throughput and resources.

The benchmark accepts a timing only when the scanner's finding count matches the
independently constructed workload count. Wall time is always measured; CPU and
peak RSS are measured when a GNU `time` wrapper is available (the CI Linux lane).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

from tools.cp1.bench import MIB, _summary_count, _time_wrapper
from tools.cp3.fixtures import _values, deterministic

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules/rnc-providers-v1.json"
STRATEGIES = ("regex", "regexset", "prefilter", "auto")
TIME_RE = re.compile(r"user=([0-9.]+) sys=([0-9.]+) rss=(\d+)")


def _values_map() -> dict[str, bytes]:
    return _values("bench")


def _write(root: Path, name: str, data: bytes, expected: int) -> dict:
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "data.bin").write_bytes(data)
    return {
        "name": name,
        "path": directory,
        "bytes": len(data),
        "files": 1,
        "expected": expected,
    }


def _large(
    root: Path,
    name: str,
    size: int,
    token_block: bytes,
    count: int,
    expected_per_block: int = 1,
) -> dict:
    spacing = max(len(token_block) + 32, size // count)
    filler = b"benign-provider-benchmark-filler-0123456789\n"
    padding = filler * ((spacing - len(token_block)) // len(filler) + 1)
    block = (token_block + padding)[:spacing]
    data = block * count
    if len(data) < size:
        data += filler * ((size - len(data)) // len(filler) + 1)
        data = data[:size]
    return _write(root, name, data, count * expected_per_block)


def _small_many(root: Path, files: int, file_size: int, token: bytes) -> dict:
    directory = root / "small-many"
    directory.mkdir(parents=True)
    line = b"token=" + token + b"\n"
    filler = b"benign-small-file-filler-0123456789\n" * 8
    data = (filler + line)[:file_size]
    if token not in data:
        data = line + data[len(line) :]
    for index in range(files):
        path = directory / f"nested/{index // 100:02d}/file-{index:05d}.env"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return {"name": "small-many", "path": directory, "bytes": files * len(data), "files": files, "expected": files}


def _fp_heavy(root: Path, size: int, values: dict[str, bytes]) -> dict:
    block = b"".join(
        [
            values["DOCS_AWS"] + b"\n",
            values["DOCS_GCP"] + b"\n",
            b"ghp_short\n",
            b"glpat-short\n",
            b"xoxb-short\n",
            b"SG.short.short\n",
            b"npm_short\n",
            b"-----BEGIN PUBLIC KEY-----\ncm5jLXRlc3Q=\n-----END PUBLIC KEY-----\n",
            b"password = \"${DB_PASSWORD}\"\n",
            b"api_key = \"password\"\n",
            b"sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            b"authorization: Bearer eyJhbGciOiJIUzI1NiJ9.not-json.signature\n",
        ]
    )
    data = (block * (size // len(block) + 1))[:size]
    return _write(root, "fp-heavy", data, 0)


def _high_entropy(root: Path, size: int) -> dict:
    block = (
        deterministic("bench-entropy-a", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 160).encode()
        + b"\n"
        + deterministic("bench-entropy-b", "0123456789abcdef", 128).encode()
        + b"\n"
    )
    data = (block * (size // len(block) + 1))[:size]
    return _write(root, "high-entropy", data, 0)


def _pem_heavy(root: Path, values: dict[str, bytes], count: int) -> dict:
    block = values["PEM_RSA"] + b"\nbenign-between-keys\n" * 8
    data = block * count
    return _write(root, "long-pem", data, count)


def _multi_family(root: Path, values: dict[str, bytes], count: int) -> dict:
    block = b"".join(
        [
            b"AWS_ACCESS_KEY_ID=" + values["AWS_KEY"] + b"\n",
            b"aws_secret_access_key = " + values["AWS_SECRET"] + b"\n",
            b"GOOGLE=" + values["GCP_KEY"] + b"\n",
            b"GITHUB=" + values["GH_CLASSIC"] + b"\n",
            b"GITHUB_FINE=" + values["GH_FINE"] + b"\n",
            b"GITHUB_OAUTH=" + values["GH_OAUTH"] + b"\n",
            b"GITLAB=" + values["GITLAB"] + b"\n",
            b"STRIPE=" + values["STRIPE"] + b"\n",
            b"SLACK=" + values["SLACK"] + b"\n",
            b"SENDGRID=" + values["SENDGRID"] + b"\n",
            b"NPM=" + values["NPM"] + b"\n",
            values["PEM_RSA"] + b"\n",
            b"authorization: Bearer " + values["JWT"] + b"\n",
            b"DATABASE_URL=postgresql://" + values["DB_CRED"] + b"@db.example.invalid/app\n",
            b'password = "' + values["GENERIC"] + b'"\n',
            b'resource "aws_iam_access_key" "ci" {\n  secret = "' + values["AWS_SECRET"] + b'"\n}\n',
        ]
    )
    data = block * count
    return _write(root, "multi-family", data, count * 16)


def _structured(root: Path, values: dict[str, bytes], count: int) -> dict:
    block = (
        b"authorization: Bearer " + values["JWT"] + b"\n"
        b"DATABASE_URL=postgresql://" + values["DB_CRED"] + b"@db.example.invalid/app\n"
    )
    data = block * count
    return _write(root, "structured", data, count * 2)


def _same_line(root: Path, values: dict[str, bytes], count: int) -> dict:
    block = b"pair=" + values["GH_DUP_A"] + b" " + values["GH_DUP_B"] + b"\n"
    data = block * count
    return _write(root, "same-line", data, count * 2)


def _github_installation_token(seed: str) -> bytes:
    def segment(tag: str) -> str:
        return deterministic(
            f"{seed}-{tag}",
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789_-",
            170,
        )

    return (
        "ghs_24681357_"
        + segment("header")
        + "."
        + segment("payload")
        + "."
        + segment("signature")
    ).encode()


def build_workloads(root: Path) -> list[dict]:
    values = _values_map()
    installation = _github_installation_token("bench-installation")
    workloads = [
        _large(
            root,
            "large-low",
            8 * MIB,
            b"AWS_ACCESS_KEY_ID=" + values["AWS_KEY"] + b"\n",
            64,
        ),
        _large(
            root,
            "large-high",
            8 * MIB,
            b"key=" + values["GCP_KEY"] + b"\n",
            4096,
        ),
        _small_many(root, 500, 4096, values["GH_CLASSIC"]),
        _large(
            root,
            "credential-configs",
            4 * MIB,
            b"AWS_ACCESS_KEY_ID="
            + values["AWS_KEY"]
            + b"\nGITHUB="
            + values["GH_CLASSIC"]
            + b'\npassword = "'
            + values["GENERIC"]
            + b'"\n',
            512,
            3,
        ),
        _fp_heavy(root, 4 * MIB, values),
        _high_entropy(root, 4 * MIB),
        _multi_family(root, values, 64),
        _pem_heavy(root, values, 32),
        _large(
            root,
            "github-installation-long",
            4 * MIB,
            b"token=" + installation + b"\n",
            256,
        ),
        _structured(root, values, 128),
        _same_line(root, values, 256),
    ]
    return workloads


def _run(
    binary: Path,
    workload: dict,
    mode: str,
    strategy: str,
    time_wrapper: str | None,
    metrics_path: Path,
) -> dict:
    command = [
        str(binary),
        "scan",
        "--root",
        str(workload["path"]),
        "--rules",
        str(RULES),
        "--format",
        "summary",
        "--run-id",
        f"cp3-bench-{workload['name']}-{mode}-{strategy}",
        "--mode",
        mode,
        "--strategy",
        strategy,
        "--stream-chunk-bytes",
        "65536",
        "--max-file-bytes",
        str(64 * MIB),
        "--max-total-bytes",
        str(128 * MIB),
        "--max-findings",
        "20000",
    ]
    wrapped = (
        [time_wrapper, "-f", "user=%U sys=%S rss=%M", "-o", str(metrics_path)] + command
        if time_wrapper
        else command
    )
    started = time.perf_counter_ns()
    result = subprocess.run(wrapped, capture_output=True, text=True, timeout=600)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if result.returncode not in (0, 10, 20):
        raise RuntimeError(
            f"{workload['name']}/{mode}/{strategy}: exit {result.returncode}: {result.stderr[:300]}"
        )
    count = _summary_count(result.stdout)
    if count != workload["expected"]:
        raise RuntimeError(
            f"{workload['name']}/{mode}/{strategy}: findings {count} != {workload['expected']}"
        )
    if "evidence_digest" in result.stdout or "finding_id" in result.stdout:
        raise RuntimeError("benchmark summary leaked private evidence")
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
        "min_ms": round(min(samples), 3),
        "max_ms": round(max(samples), 3),
    }


def _plan(binary: Path, strategy: str) -> dict:
    completed = subprocess.run(
        [str(binary), "rules", "validate", "--rules", str(RULES), "--strategy", strategy],
        capture_output=True,
        text=True,
        timeout=60,
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


def measure(
    binary: Path,
    runs: int,
    *,
    build_seconds: float | None = None,
    binary_sha256: str | None = None,
    strategies: tuple[str, ...] = STRATEGIES,
) -> dict:
    if runs < 3:
        raise ValueError("at least three runs are required")
    if not binary.is_file():
        raise RuntimeError(f"binary not found: {binary}")
    time_wrapper = _time_wrapper()
    plans = [_plan(binary, strategy) for strategy in strategies]
    compile_samples = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        completed = subprocess.run(
            [str(binary), "rules", "validate", "--rules", str(RULES)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"rule validation failed: {completed.stderr}")
        compile_samples.append((time.perf_counter_ns() - started) / 1_000_000)
    with tempfile.TemporaryDirectory(prefix="rnc-cp3-bench-") as temp:
        root = Path(temp)
        workloads = build_workloads(root)
        metrics_path = root / "time.metrics"
        profiles = []
        for workload in workloads:
            for mode in ("whole", "stream"):
                for strategy in strategies:
                    samples = []
                    memory = []
                    cpu = []
                    backend = None
                    for _ in range(runs):
                        observed = _run(
                            binary, workload, mode, strategy, time_wrapper, metrics_path
                        )
                        samples.append(observed["wall_ms"])
                        backend = observed["backend"]
                        if observed["peak_rss_kb"] is not None:
                            memory.append(observed["peak_rss_kb"])
                        if observed["cpu_percent"] is not None:
                            cpu.append(observed["cpu_percent"])
                    stats = _stats(samples)
                    stats["throughput_mib_s"] = (
                        round(workload["bytes"] / MIB / (stats["median_ms"] / 1000.0), 2)
                        if stats["median_ms"]
                        else None
                    )
                    stats["files_per_second"] = (
                        round(workload["files"] / (stats["median_ms"] / 1000.0), 2)
                        if stats["median_ms"]
                        else None
                    )
                    stats["peak_rss_kb_median"] = (
                        round(statistics.median(memory)) if memory else None
                    )
                    stats["cpu_percent_median"] = (
                        round(statistics.median(cpu), 2) if cpu else None
                    )
                    profiles.append(
                        {
                            "workload": workload["name"],
                            "mode": mode,
                            "strategy": strategy,
                            "effective_backend": backend,
                            "bytes": workload["bytes"],
                            "files": workload["files"],
                            "expected_findings": workload["expected"],
                            "measurements": stats,
                            "correct": True,
                        }
                    )
    return {
        "contract": "cp3-provider-benchmark-v0.1",
        "runs": runs,
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
        },
        "ruleset": "rnc-providers-v1",
        "rules_file_sha256": hashlib.sha256(RULES.read_bytes()).hexdigest(),
        "build": {
            "seconds": build_seconds,
            "binary_bytes": binary.stat().st_size,
            "binary_sha256": binary_sha256 or hashlib.sha256(binary.read_bytes()).hexdigest(),
        },
        "plans": plans,
        "performance_available": time_wrapper is not None,
        "rule_compile_ms": _stats(compile_samples),
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
    parser.add_argument("--strategies", default=",".join(STRATEGIES))
    args = parser.parse_args()
    strategies = tuple(value.strip() for value in args.strategies.split(",") if value.strip())
    if not strategies or any(value not in STRATEGIES for value in strategies):
        raise SystemExit("invalid strategies")
    report = measure(
        args.binary,
        args.runs,
        build_seconds=args.build_seconds,
        binary_sha256=args.binary_sha256,
        strategies=strategies,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"CP3 benchmark wrote {args.output} ({len(report['profiles'])} profiles)")


if __name__ == "__main__":
    main()
