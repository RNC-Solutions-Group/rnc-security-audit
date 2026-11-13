"""Scanner-independent native and Docker build primitives.

Build commands, package paths, linker flags, Dockerfiles, and version tags are
provided by the scanner adapter. This module owns deterministic process
execution, artifact hashing, Docker image identity, and build provenance.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError
from .source import SourceCheckout
from .util import sha256_bytes, sha256_file


def _tool_path(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    home = Path.home() / ".cargo" / "bin"
    for candidate in (home / name, home / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return None


def cargo_program() -> str | None:
    return _tool_path("cargo")


def rustc_program() -> str | None:
    return _tool_path("rustc")


@dataclass(frozen=True)
class BuildResult:
    kind: str
    status: str
    command: tuple[str, ...]
    exit_code: int | None
    duration_seconds: float
    stdout_sha256: str
    stderr_sha256: str
    output_path: str | None
    output_sha256: str | None
    image_id: str | None
    image_tag: str | None
    error: str | None


def _run(
    argv: list[str],
    *,
    cwd: Path,
    timeout: float,
    env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess, float]:
    started = time.perf_counter()
    try:
        result = subprocess.run(
            argv,
            cwd=str(cwd),
            capture_output=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
        )
    except subprocess.TimeoutExpired as exc:
        raise HarnessError(
            f"build command timed out after {timeout:g}s: {' '.join(argv[:3])}"
        ) from exc
    except OSError as exc:
        raise HarnessError(f"could not run build command: {exc}") from exc
    return result, round(time.perf_counter() - started, 3)


def build_executable(
    source: SourceCheckout,
    output_path: Path | str,
    *,
    package: str = ".",
    goos: str | None = None,
    goarch: str | None = None,
    ldflags: tuple[str, ...] = (),
    timeout: float = 900.0,
) -> BuildResult:
    output_path = Path(output_path)
    output_path = (
        output_path if output_path.is_absolute() else Path.cwd() / output_path
    ).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if (source.path / package / "main.go").is_file() is False and package != ".":
        return BuildResult(
            "executable",
            "FAIL",
            (),
            None,
            0.0,
            "",
            "",
            None,
            None,
            None,
            None,
            f"source checkout has no Go main package at {package!r}",
        )
    command = [
        "go",
        "build",
        "-mod=readonly",
        "-trimpath",
        "-buildvcs=true",
        "-o",
        str(output_path),
    ]
    for item in ldflags:
        command.append(f"-ldflags={item}")
    command.append(package)
    env = {
        "GOTOOLCHAIN": "local",
        "CGO_ENABLED": "0",
        "GOPROXY": "off",
        "GOSUMDB": "off",
    }
    if goos:
        env["GOOS"] = goos
    if goarch:
        env["GOARCH"] = goarch
    try:
        result, duration = _run(
            command, cwd=source.path, timeout=timeout, env=env
        )
    except HarnessError as exc:
        return BuildResult(
            "executable", "BLOCKED", tuple(command), None, 0.0, "", "", None, None, None, None, str(exc)
        )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        return BuildResult(
            "executable",
            "FAIL",
            tuple(command),
            result.returncode,
            duration,
            sha256_bytes(result.stdout),
            sha256_bytes(result.stderr),
            None,
            None,
            None,
            None,
            f"go build failed: {detail[0][:240] if detail else 'no diagnostic'}",
        )
    return BuildResult(
        "executable",
        "PASS",
        tuple(command),
        result.returncode,
        duration,
        sha256_bytes(result.stdout),
        sha256_bytes(result.stderr),
        str(output_path),
        sha256_file(output_path),
        None,
        None,
        None,
    )


def build_cargo_executable(
    source: SourceCheckout,
    output_path: Path | str,
    *,
    binary_name: str = "rnc",
    timeout: float = 2400.0,
) -> BuildResult:
    """Build a Cargo release binary and copy it out of the disposable tree."""
    output_path = Path(output_path)
    output_path = (
        output_path if output_path.is_absolute() else Path.cwd() / output_path
    ).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not (source.path / "Cargo.toml").is_file():
        return BuildResult(
            "executable", "FAIL", (), None, 0.0, "", "", None, None, None, None,
            "source checkout has no Cargo.toml",
        )
    cargo = cargo_program()
    if cargo is None:
        return BuildResult(
            "executable", "BLOCKED", (), None, 0.0, "", "", None, None, None, None,
            "Cargo executable is unavailable",
        )
    target_dir = output_path.parent / "cargo-target"
    command = [
        cargo,
        "build",
        "--release",
        "--locked",
        "--bin",
        binary_name,
        "--target-dir",
        str(target_dir),
    ]
    env = {
        "CARGO_TERM_COLOR": "never",
        "CARGO_NET_OFFLINE": "true",
    }
    try:
        result, duration = _run(command, cwd=source.path, timeout=timeout, env=env)
    except HarnessError as exc:
        return BuildResult(
            "executable", "BLOCKED", tuple(command), None, 0.0, "", "", None, None, None, None, str(exc)
        )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        return BuildResult(
            "executable",
            "FAIL",
            tuple(command),
            result.returncode,
            duration,
            sha256_bytes(result.stdout),
            sha256_bytes(result.stderr),
            None,
            None,
            None,
            None,
            f"cargo build failed: {detail[0][:240] if detail else 'no diagnostic'}",
        )
    built = target_dir / "release" / (
        f"{binary_name}.exe" if os.name == "nt" else binary_name
    )
    if not built.is_file():
        return BuildResult(
            "executable",
            "FAIL",
            tuple(command),
            result.returncode,
            duration,
            sha256_bytes(result.stdout),
            sha256_bytes(result.stderr),
            None,
            None,
            None,
            None,
            f"cargo completed but produced no binary at {built}",
        )
    shutil.copy2(built, output_path)
    return BuildResult(
        "executable",
        "PASS",
        tuple(command),
        result.returncode,
        duration,
        sha256_bytes(result.stdout),
        sha256_bytes(result.stderr),
        str(output_path),
        sha256_file(output_path),
        None,
        None,
        None,
    )


def inspect_image(tag: str) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                tag,
                "--format",
                "{{.Id}}|{{.Os}}/{{.Architecture}}",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    if result.returncode != 0:
        return None, None
    image_id, _, architecture = result.stdout.strip().partition("|")
    return image_id or None, architecture or None


def build_docker_image(
    source: SourceCheckout,
    tag: str,
    *,
    platform: str,
    build_context: Path | str | None = None,
    dockerfile: str = "Dockerfile",
    build_args: tuple[str, ...] = (),
    labels: tuple[str, ...] = (),
    timeout: float = 1800.0,
) -> BuildResult:
    context = Path(build_context or source.path).resolve()
    dockerfile_path = (
        Path(dockerfile).resolve()
        if Path(dockerfile).is_absolute()
        else (context / dockerfile).resolve()
    )
    if not dockerfile_path.is_file():
        return BuildResult(
            "docker",
            "FAIL",
            (),
            None,
            0.0,
            "",
            "",
            None,
            None,
            None,
            tag,
            f"source checkout has no Dockerfile at {dockerfile_path}",
        )
    command = [
        "docker",
        "build",
        "--quiet",
        "--pull=false",
        "--network",
        "none",
        "--platform",
        platform,
        "-f",
        str(dockerfile_path),
    ]
    for label in labels:
        command.extend(["--label", label])
    for argument in build_args:
        command.extend(["--build-arg", argument])
    command.extend(["-t", tag, str(context)])
    try:
        result, duration = _run(command, cwd=context, timeout=timeout)
    except HarnessError as exc:
        return BuildResult(
            "docker", "BLOCKED", tuple(command), None, 0.0, "", "", None, None, None, tag, str(exc)
        )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        return BuildResult(
            "docker",
            "FAIL",
            tuple(command),
            result.returncode,
            duration,
            sha256_bytes(result.stdout),
            sha256_bytes(result.stderr),
            None,
            None,
            None,
            tag,
            f"docker build failed: {detail[0][:240] if detail else 'no diagnostic'}",
        )
    image_id, architecture = inspect_image(tag)
    if image_id is None:
        return BuildResult(
            "docker",
            "FAIL",
            tuple(command),
            result.returncode,
            duration,
            sha256_bytes(result.stdout),
            sha256_bytes(result.stderr),
            None,
            None,
            None,
            tag,
            "docker image inspect failed",
        )
    if architecture != platform:
        return BuildResult(
            "docker",
            "FAIL",
            tuple(command),
            result.returncode,
            duration,
            sha256_bytes(result.stdout),
            sha256_bytes(result.stderr),
            None,
            None,
            image_id,
            tag,
            f"built image architecture {architecture!r} does not match {platform!r}",
        )
    return BuildResult(
        "docker",
        "PASS",
        tuple(command),
        result.returncode,
        duration,
        sha256_bytes(result.stdout),
        sha256_bytes(result.stderr),
        None,
        None,
        image_id,
        tag,
        None,
    )


def toolchain_metadata() -> dict:
    tools: dict[str, str | None] = {}
    cargo = cargo_program()
    rustc = rustc_program()
    commands = (
        ("go", ["go", "version"]),
        ("docker", ["docker", "version", "--format", "{{.Server.Version}}"]),
        ("git", ["git", "--version"]),
        ("cargo", [cargo, "--version"] if cargo else []),
        ("rustc", [rustc, "--version"] if rustc else []),
    )
    for key, argv in commands:
        if not argv:
            tools[key] = None
            continue
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            tools[key] = result.stdout.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            tools[key] = None
    return tools
