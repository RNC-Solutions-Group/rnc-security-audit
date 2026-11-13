"""Deterministic scanner invocation and shared report error semantics.

The harness supplies the target directory, report path, and optional config
path. It records the exact argv, exit status, duration, and artifact hashes.
It does not interpret scanner stdout as findings unless the JSON report is
missing, and it never prints raw matched values.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import telemetry
from .errors import ExecutionError, ReportError
from .model import Finding
from .util import sha256_bytes, sha256_file

ACCEPTED_EXIT_CODES = (0, 1)


@dataclass(frozen=True)
class Invocation:
    binary_path: str
    binary_sha256: str
    argv: tuple[str, ...]
    mode: str
    report_path: str
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    timeout_seconds: float
    stdout: bytes
    stderr: bytes
    report_bytes: bytes | None
    error_code: str | None = None
    error_message: str = ""
    resource_metrics: dict = field(default_factory=dict)

    @property
    def report_sha256(self) -> str | None:
        return sha256_bytes(self.report_bytes) if self.report_bytes is not None else None

    @property
    def stdout_sha256(self) -> str:
        return sha256_bytes(self.stdout)

    @property
    def stderr_sha256(self) -> str:
        return sha256_bytes(self.stderr)


def resolve_binary(binary: Path | str) -> tuple[Path, str]:
    path = Path(binary).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ExecutionError(f"Gitleaks executable not found: {path}") from exc
    if not resolved.is_file():
        raise ExecutionError(f"Gitleaks executable is not a file: {resolved}")
    return resolved, sha256_file(resolved)


def build_command(
    binary: Path,
    target: Path,
    report_path: Path,
    *,
    mode: str = "dir",
    config: Path | None = None,
    extra_args: tuple[str, ...] = (),
) -> list[str]:
    if mode not in {"dir", "detect", "git"}:
        raise ExecutionError(f"unsupported scan mode: {mode}")
    if mode == "dir":
        argv = [str(binary), "dir", str(target)]
    elif mode == "git":
        argv = [str(binary), "git", str(target)]
    else:
        argv = [str(binary), "detect", "--source", str(target)]
    argv.extend(["--report-format", "json", "--report-path", str(report_path), "--no-banner"])
    if config is not None:
        argv.extend(["--config", str(config)])
    argv.extend(extra_args)
    return argv


def run_process(
    argv: list[str],
    *,
    binary_path: str,
    binary_sha256: str,
    mode: str,
    report_path: Path,
    timeout_seconds: float = 300.0,
    env: dict[str, str] | None = None,
    unset_env: tuple[str, ...] = (),
    cwd: Path | None = None,
    collect_telemetry: bool = False,
) -> Invocation:
    if collect_telemetry:
        return _run_sampled(
            argv,
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            mode=mode,
            report_path=report_path,
            timeout_seconds=timeout_seconds,
            env=env,
            unset_env=unset_env,
            cwd=cwd,
        )
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if report_path.exists():
        report_path.unlink()

    started = time.perf_counter()
    try:
        process = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout_seconds,
            env=_merged_environment(env, unset_env),
            cwd=str(cwd) if cwd is not None else None,
        )
        duration = time.perf_counter() - started
        invocation = Invocation(
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            argv=tuple(argv),
            mode=mode,
            report_path=str(report_path),
            exit_code=process.returncode,
            timed_out=False,
            duration_seconds=round(duration, 3),
            timeout_seconds=timeout_seconds,
            stdout=process.stdout,
            stderr=process.stderr,
            report_bytes=None,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.perf_counter() - started
        return Invocation(
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            argv=tuple(argv),
            mode=mode,
            report_path=str(report_path),
            exit_code=None,
            timed_out=True,
            duration_seconds=round(duration, 3),
            timeout_seconds=timeout_seconds,
            stdout=exc.stdout or b"",
            stderr=exc.stderr or b"",
            report_bytes=None,
            error_code="TIMEOUT",
            error_message=f"scanner exceeded {timeout_seconds:g}s timeout",
        )
    except OSError as exc:
        duration = time.perf_counter() - started
        return Invocation(
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            argv=tuple(argv),
            mode=mode,
            report_path=str(report_path),
            exit_code=None,
            timed_out=False,
            duration_seconds=round(duration, 3),
            timeout_seconds=timeout_seconds,
            stdout=b"",
            stderr=b"",
            report_bytes=None,
            error_code="INVOCATION_FAILED",
            error_message=f"could not start scanner: {exc}",
        )

    if report_path.is_file():
        invocation = Invocation(
            **{**invocation.__dict__, "report_bytes": report_path.read_bytes()}
        )
    return invocation


def _run_sampled(
    argv: list[str],
    *,
    binary_path: str,
    binary_sha256: str,
    mode: str,
    report_path: Path,
    timeout_seconds: float,
    env: dict[str, str] | None,
    unset_env: tuple[str, ...],
    cwd: Path | None,
) -> Invocation:
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if report_path.exists():
        report_path.unlink()
    started = time.perf_counter()
    try:
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_merged_environment(env, unset_env),
            cwd=str(cwd) if cwd is not None else None,
        )
    except OSError as exc:
        duration = time.perf_counter() - started
        return Invocation(
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            argv=tuple(argv),
            mode=mode,
            report_path=str(report_path),
            exit_code=None,
            timed_out=False,
            duration_seconds=round(duration, 3),
            timeout_seconds=timeout_seconds,
            stdout=b"",
            stderr=b"",
            report_bytes=None,
            error_code="INVOCATION_FAILED",
            error_message=f"could not start scanner: {exc}",
            resource_metrics={"method": "unavailable", "unavailable_reason": str(exc)},
        )
    sampler, thread = telemetry.start_process_sampler(process.pid, argv)
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        duration = time.perf_counter() - started
        timed_out = False
        exit_code = process.returncode
        error_code = None
        error_message = ""
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        duration = time.perf_counter() - started
        timed_out = True
        exit_code = None
        error_code = "TIMEOUT"
        error_message = f"scanner exceeded {timeout_seconds:g}s timeout"
    finally:
        sampler.stop()
        thread.join(timeout=2)
    resource = sampler.telemetry.as_dict()
    if resource.get("sample_count") == 0 and not resource.get("unavailable_reason"):
        resource["unavailable_reason"] = (
            "execution finished before a telemetry sample was available"
        )
    if duration > 0 and resource.get("cpu_total_seconds") is not None:
        resource["cpu_utilization_percent"] = round(
            100.0 * resource["cpu_total_seconds"] / duration, 3
        )
    invocation = Invocation(
        binary_path=binary_path,
        binary_sha256=binary_sha256,
        argv=tuple(argv),
        mode=mode,
        report_path=str(report_path),
        exit_code=exit_code,
        timed_out=timed_out,
        duration_seconds=round(duration, 3),
        timeout_seconds=timeout_seconds,
        stdout=stdout,
        stderr=stderr,
        report_bytes=None,
        error_code=error_code,
        error_message=error_message,
        resource_metrics=resource,
    )
    if report_path.is_file():
        invocation = Invocation(
            **{**invocation.__dict__, "report_bytes": report_path.read_bytes()}
        )
    return invocation


def execute(
    binary: Path | str,
    target: Path,
    report_path: Path,
    *,
    mode: str = "dir",
    config: Path | None = None,
    extra_args: tuple[str, ...] = (),
    timeout_seconds: float = 300.0,
    env: dict[str, str] | None = None,
) -> Invocation:
    resolved, digest = resolve_binary(binary)
    argv = build_command(
        resolved,
        Path(target),
        Path(report_path),
        mode=mode,
        config=Path(config) if config is not None else None,
        extra_args=extra_args,
    )
    return run_process(
        argv,
        binary_path=str(resolved),
        binary_sha256=digest,
        mode=mode,
        report_path=Path(report_path),
        timeout_seconds=timeout_seconds,
        env=env,
    )


def _merged_environment(
    env: dict[str, str] | None, unset_env: tuple[str, ...]
) -> dict[str, str]:
    merged = {**os.environ, **(env or {})}
    for key in unset_env:
        merged.pop(key, None)
    return merged


def parse_report(data: bytes) -> list[Finding]:
    """Parse a Gitleaks JSON report (array, wrapper object, or JSON lines)."""
    from .adapters.gitleaks_parse import parse_entries

    return [
        Finding(
            file=entry["basename"],
            line=entry["line"],
            rule_id=entry["rule_id"],
            secret=entry["secret"],
            match=entry["match"],
        )
        for entry in parse_entries(data)
    ]


def invocation_problem(invocation: Invocation) -> str | None:
    """Return a failure status code, or None when the invocation can be scored."""
    if invocation.error_code:
        return invocation.error_code
    if invocation.timed_out:
        return "TIMEOUT"
    if invocation.exit_code not in ACCEPTED_EXIT_CODES:
        return "INVOCATION_FAILED"
    if invocation.report_bytes is None:
        return "REPORT_MISSING"
    try:
        parse_report(invocation.report_bytes)
    except ReportError:
        return "REPORT_INVALID"
    return None


def report_findings(invocation: Invocation) -> list[Finding]:
    if invocation.report_bytes is None:
        raise ReportError("scanner report is missing")
    return parse_report(invocation.report_bytes)
