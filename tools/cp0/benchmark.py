"""Generate CP0 full synthetic performance corpus and benchmark Go/Rust probes.

No external source downloads and no production scanner evaluation. Missing
toolchains are an explicit failure; this program never invents measurements.

Usage: python -m tools.cp0.benchmark --output /path/to/benchmarks.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MARKER = b"RNC_SYNTH_KEY_BENCHMARK_ONLY_0000\n"
PROFILES = (
    (1 * 1024 * 1024, 0), (1 * 1024 * 1024, 16), (1 * 1024 * 1024, 256),
    (8 * 1024 * 1024, 0), (8 * 1024 * 1024, 128), (8 * 1024 * 1024, 2048),
    (32 * 1024 * 1024, 0), (32 * 1024 * 1024, 512), (32 * 1024 * 1024, 8192),
)


def run_checked(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=True, timeout=300)
    return result.stdout.strip()


def write_corpus(path: Path, byte_size: int, marker_count: int) -> str:
    """Make deterministic fixed-size data with known marker placements."""
    filler = b"benign-RNC-corpus-fixture-1234567890-abcdef\n"
    with path.open("wb") as out:
        out.write((filler * (byte_size // len(filler) + 1))[:byte_size])
    if marker_count:
        spacing = byte_size // (marker_count + 1)
        assert spacing >= len(MARKER)
        with path.open("r+b") as out:
            for index in range(marker_count):
                out.seek(spacing * (index + 1))
                out.write(MARKER)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def benchmark(runs: int) -> dict:
    if runs < 3:
        raise ValueError("at least three measurement repetitions are required")
    for binary in ("go", "rustc"):
        if shutil.which(binary) is None:
            raise RuntimeError(f"missing {binary} toolchain; no benchmarks were run")

    with tempfile.TemporaryDirectory(prefix="rnc-cp0-bench-") as temp:
        work = Path(temp)
        binaries = {"go": work / "go-probe", "rust": work / "rust-probe"}
        run_checked(["go", "build", "-trimpath", "-o", str(binaries["go"]), str(ROOT / "tools/cp0/probe.go")])
        run_checked(["rustc", "-O", str(ROOT / "tools/cp0/probe.rs"), "-o", str(binaries["rust"])])
        profiles = []
        for size, count in PROFILES:
            path = work / f"corpus-{size}-{count}.bin"
            digest = write_corpus(path, size, count)
            samples = {"go": [], "rust": []}
            # Warmup and correctness check are mandatory before timings.
            for lang, executable in binaries.items():
                assert int(run_checked([str(executable), str(path)])) == count, f"{lang} incorrect result"
            for repetition in range(runs):
                for lang in (("go", "rust") if repetition % 2 == 0 else ("rust", "go")):
                    start = time.perf_counter_ns()
                    found = int(run_checked([str(binaries[lang]), str(path)]))
                    elapsed = time.perf_counter_ns() - start
                    assert found == count, f"{lang} changed result"
                    samples[lang].append(elapsed / 1_000_000)
            profiles.append({
                "size_bytes": size, "expected_matches": count, "sha256": digest,
                "measurements_ms": samples,
                "median_ms": {k: statistics.median(v) for k, v in samples.items()},
                "runs_per_language": runs,
            })
        return {
            "contract": "cp0-probe-v0.1", "workload": "whole-file-read + naive exact marker search",
            "not_production_engine_comparison": True,
            "host": {"platform": platform.platform(), "machine": platform.machine(),
                     "python": platform.python_version(), "cpu_count": os.cpu_count()},
            "toolchains": {"go": run_checked(["go", "version"]), "rust": run_checked(["rustc", "--version"])},
            "profiles": profiles,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    report = benchmark(args.runs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"CP0 benchmark wrote {args.output} ({len(report['profiles'])} profiles)")


if __name__ == "__main__":
    main()
