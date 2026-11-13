"""Betterleaks scanner adapter.

Betterleaks is a separate production scanner. The adapter builds its native
binary and Docker image from the operator-supplied source commit; it never
downloads a release executable or a published scanner image.
"""

from __future__ import annotations

import hashlib
import platform as host_platform_module
import shutil
import subprocess
from pathlib import Path

from .. import status as statuses
from ..builds import BuildResult, build_docker_image, build_executable, toolchain_metadata
from ..contracts import NormalizedFinding
from ..execution import Invocation, run_process
from ..source import SourceCheckout, ensure_version_tag
from ..util import sha256_file
from .base import (
    PLATFORM_CATALOG,
    BuildArtifact,
    ScannerAdapter,
    TargetPlatform,
)
from .strict_json import load_findings_document

VERSION_NAMESPACE = "github.com/betterleaks/betterleaks/version"


def _filename(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("scanner finding has no usable file path")
    return value.replace("\\", "/")


def _line(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _host_arch() -> str:
    machine = host_platform_module.machine().lower()
    return "amd64" if machine in ("x86_64", "amd64") else machine


class BetterleaksAdapter(ScannerAdapter):
    key = "betterleaks"
    display_name = "Betterleaks"
    default_repository = "https://github.com/betterleaks/betterleaks"
    supported_suites = (
        "synthetic-filesystem",
        "git-history",
        "levain",
        "leaky-repo",
        "rnclab",
    )
    platforms = PLATFORM_CATALOG

    def _version_tag(self, source: SourceCheckout) -> str:
        return ensure_version_tag(source, f"v0.0.0-rnc.{source.commit[:12]}")

    def _build_native(
        self, source: SourceCheckout, target: TargetPlatform, output_dir: Path
    ) -> BuildArtifact:
        version_tag = self._version_tag(source)
        extension = ".exe" if target.os_name == "windows" else ""
        output_path = output_dir / f"betterleaks-{target.key}{extension}"
        result = build_executable(
            source,
            output_path,
            goos=target.goos,
            goarch=target.goarch,
            ldflags=(f"-X={VERSION_NAMESPACE}.Version={version_tag}",),
        )
        if result.status != statuses.PASS:
            return self._artifact(target, result, version=None, metadata={})
        version, version_status = self._native_version(output_path, target)
        return self._artifact(
            target,
            result,
            version=version,
            version_status=version_status,
            metadata={
                "goos": target.goos,
                "goarch": target.goarch,
                "execution_method": "native",
                "source_commit": source.commit,
                "source_repository": source.repository,
                "build_version_tag": version_tag,
                "license": "MIT",
                "toolchain": toolchain_metadata(),
            },
        )

    def _dockerfile(self, output_dir: Path) -> Path:
        """Write a source-build Dockerfile for the pinned checkout.

        The upstream v1.8.1 Dockerfile pins a Go 1.24 builder while go.mod
        requires Go 1.25, so it cannot build this commit. The adapter keeps the
        source build honest by using the same checkout with a matching toolchain
        image and a deterministic build command. No published scanner image is
        substituted.
        """
        path = output_dir / "Dockerfile.rnc-betterleaks"
        path.write_text(
            "FROM golang:1.25 AS build\n"
            "ARG VERSION=dev\n"
            "WORKDIR /src\n"
            "ENV GOTOOLCHAIN=auto\n"
            "COPY . .\n"
            "RUN CGO_ENABLED=0 go build -mod=readonly -trimpath "
            "-o /out/betterleaks "
            "-ldflags \"-X=github.com/betterleaks/betterleaks/version.Version=${VERSION}\" .\n"
            "\n"
            "FROM alpine:3.22\n"
            "RUN apk add --no-cache bash git openssh-client ca-certificates\n"
            "COPY --from=build /out/betterleaks /usr/bin/betterleaks\n"
            "RUN git config --global --add safe.directory '*'\n"
            "ENTRYPOINT [\"betterleaks\"]\n",
            encoding="utf-8",
            newline="\n",
        )
        return path

    def _build_docker(
        self, source: SourceCheckout, target: TargetPlatform, output_dir: Path
    ) -> BuildArtifact:
        version_tag = self._version_tag(source)
        safe_run = "".join(
            ch if ch.isalnum() or ch in "._-" else "-" for ch in self.run_id
        ).strip("-.").lower()
        tag = f"rnc-betterleaks-{safe_run}-{source.commit[:12]}-{target.key}"
        dockerfile = self._dockerfile(output_dir)
        result = build_docker_image(
            source,
            tag,
            platform=target.docker_platform or f"linux/{target.arch}",
            dockerfile=str(dockerfile),
            build_args=(f"VERSION={version_tag}",),
            labels=self.docker_label_args(),
        )
        architecture = None
        if result.status == statuses.PASS:
            architecture = subprocess.run(
                [
                    "docker",
                    "image",
                    "inspect",
                    tag,
                    "--format",
                    "{{.Os}}/{{.Architecture}}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.strip()
        expected = f"linux/{target.arch}"
        build_status = result.status
        error = result.error
        if result.status == statuses.PASS and architecture != expected:
            build_status = statuses.FAIL
            error = (
                f"image architecture {architecture!r} does not match expected "
                f"{expected!r}"
            )
        version = None
        version_status = statuses.NOT_APPLICABLE
        if build_status == statuses.PASS:
            version, version_status = self._docker_version(tag, target)
        return self._artifact(
            target,
            result,
            version=version,
            version_status=version_status,
            status=build_status,
            error=error,
            metadata={
                "image_os_architecture": architecture,
                "expected_os_architecture": expected,
                "architecture_verified": architecture == expected,
                "emulated": target.arch != _host_arch(),
                "host_architecture": _host_arch(),
                "execution_method": "docker",
                "source_commit": source.commit,
                "source_repository": source.repository,
                "build_version_tag": version_tag,
                "docker_build_strategy": "adapter-source-dockerfile",
                "dockerfile_sha256": sha256_file(dockerfile),
                "upstream_dockerfile_compatible": False,
                "license": "MIT",
                "toolchain": toolchain_metadata(),
            },
        )

    def _artifact(
        self,
        target: TargetPlatform,
        result: BuildResult,
        *,
        version: str | None,
        metadata: dict,
        version_status: str | None = None,
        status: str | None = None,
        error: str | None = None,
    ) -> BuildArtifact:
        return BuildArtifact(
            platform=target,
            status=status or result.status,
            command=result.command,
            exit_code=result.exit_code,
            duration_seconds=result.duration_seconds,
            artifact_path=result.output_path,
            artifact_sha256=result.output_sha256,
            image_id=result.image_id,
            image_tag=result.image_tag,
            version=version,
            version_status=version_status or (
                statuses.PASS if version else statuses.NOT_APPLICABLE
            ),
            stdout_sha256=result.stdout_sha256,
            stderr_sha256=result.stderr_sha256,
            error=error if error is not None else result.error,
            metadata=metadata,
        )

    def build(
        self,
        source: SourceCheckout,
        target: TargetPlatform,
        output_dir: Path | str,
    ) -> BuildArtifact:
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        if target.is_executable:
            return self._build_native(source, target, output_dir)
        return self._build_docker(source, target, output_dir)

    def _native_version(self, binary: Path, target: TargetPlatform) -> tuple[str | None, str]:
        if not self.can_execute(target):
            return None, statuses.NOT_RUN
        try:
            result = subprocess.run(
                [str(binary), "version"], capture_output=True, text=True, timeout=60
            )
        except (OSError, subprocess.TimeoutExpired):
            return None, statuses.NOT_RUN
        if result.returncode != 0:
            return None, statuses.FAIL
        for line in result.stdout.splitlines():
            if line.strip():
                return line.strip().split()[-1], statuses.PASS
        return None, statuses.FAIL

    def _docker_version(
        self, image: str, target: TargetPlatform
    ) -> tuple[str | None, str]:
        try:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--platform",
                    f"linux/{target.arch}",
                    "--entrypoint",
                    "betterleaks",
                    image,
                    "version",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None, statuses.NOT_RUN
        if result.returncode != 0:
            return None, statuses.FAIL
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return (lines[-1].split()[-1] if lines else None), statuses.PASS if lines else statuses.FAIL

    def supports_mode(self, mode: str) -> bool:
        return mode in {"dir", "git"}

    def _clean_cwd(self, report_path: Path) -> Path:
        cwd = report_path.parent / "scanner-cwd"
        if cwd.exists():
            shutil.rmtree(cwd)
        cwd.mkdir(parents=True, exist_ok=True)
        return cwd

    def invoke_native(
        self,
        executable: Path | str,
        target: Path | str,
        report_path: Path | str,
        *,
        config: Path | str | None = None,
        timeout_seconds: float = 300.0,
        extra_args: tuple[str, ...] = (),
        cwd: Path | None = None,
        mode: str = "dir",
        collect_telemetry: bool = False,
    ) -> Invocation:
        binary = Path(executable).resolve(strict=True)
        target = Path(target).resolve(strict=True)
        report_path = Path(report_path).resolve()
        if mode not in {"dir", "git"}:
            raise ValueError(f"unsupported Betterleaks scan mode: {mode}")
        argv = [
            str(binary),
            mode,
            str(target),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--no-banner",
            "--exit-code",
            "1",
            "--log-level",
            "error",
        ]
        if config is not None:
            argv.extend(["--config", str(Path(config).resolve())])
        argv.extend(extra_args)
        return run_process(
            argv,
            binary_path=str(binary),
            binary_sha256=sha256_file(binary),
            mode=mode,
            report_path=report_path,
            timeout_seconds=timeout_seconds,
            env=self.clean_environment(),
            unset_env=self.config_environment_keys(),
            cwd=cwd or self._clean_cwd(report_path),
            collect_telemetry=collect_telemetry,
        )

    def invoke_container(
        self,
        image_tag: str,
        image_id: str,
        target: Path | str,
        out_dir: Path | str,
        *,
        config: Path | str | None = None,
        timeout_seconds: float = 300.0,
        extra_args: tuple[str, ...] = (),
        mode: str = "dir",
        collect_telemetry: bool = False,
    ) -> Invocation:
        out_dir = Path(out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        report_host = out_dir / "report.json"
        arch = "arm64" if "arm64" in image_tag else "amd64"
        argv = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--platform",
            f"linux/{arch}",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid",
            "--mount",
            f"type=bind,source={Path(target).resolve()},target=/scan,readonly",
            "--mount",
            f"type=bind,source={out_dir},target=/out",
            "--workdir",
            "/out",
            "--entrypoint",
            "betterleaks",
        ]
        for label in self.docker_label_args():
            argv.extend(["--label", label])
        argv.extend(["--name", self.container_name("docker")])
        if config is not None:
            config = Path(config).resolve()
            argv.extend(
                ["--mount", f"type=bind,source={config},target=/config.toml,readonly"]
            )
        argv.extend(
            [
                image_tag,
                mode,
                "/scan",
                "--report-format",
                "json",
                "--report-path",
                "/out/report.json",
                "--no-banner",
                "--exit-code",
                "1",
                "--log-level",
                "error",
            ]
        )
        if config is not None:
            argv.extend(["--config", "/config.toml"])
        argv.extend(extra_args)
        return run_process(
            argv,
            binary_path=f"docker:{image_tag}",
            binary_sha256=image_id.removeprefix("sha256:"),
            mode=mode,
            report_path=report_host,
            timeout_seconds=timeout_seconds,
            env=self.clean_environment(),
            unset_env=self.config_environment_keys(),
            collect_telemetry=collect_telemetry,
        )

    def parse_findings(self, data: bytes) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        for index, entry in enumerate(load_findings_document(data)):
            if not isinstance(entry, dict):
                raise ValueError(f"scanner finding {index} is not an object")
            try:
                file_value = _filename(
                    entry.get("File")
                    or entry.get("file")
                    or entry.get("Path")
                    or entry.get("path")
                )
            except ValueError as exc:
                raise ValueError(f"scanner finding {index}: {exc}") from exc
            secret = (
                entry.get("Secret")
                or entry.get("secret")
                or entry.get("Match")
                or entry.get("match")
                or ""
            )
            match = entry.get("Match") or entry.get("match") or ""
            line = entry.get("StartLine") or entry.get("startLine") or entry.get("line")
            commit = entry.get("Commit") or entry.get("commit") or None
            rule = (
                entry.get("RuleID")
                or entry.get("ruleId")
                or entry.get("rule_id")
                or ""
            )
            secret_text = str(secret) if secret else None
            match_text = str(match) if match else None
            findings.append(
                NormalizedFinding(
                    file=str(file_value),
                    line=_line(line),
                    rule_id=str(rule),
                    commit=str(commit) if commit else None,
                    secret_sha256=(
                        hashlib.sha256(secret_text.encode()).hexdigest()
                        if secret_text
                        else None
                    ),
                    match_sha256=(
                        hashlib.sha256(match_text.encode()).hexdigest()
                        if match_text
                        else None
                    ),
                    secret_redacted=secret_text == "REDACTED",
                    metadata={
                        "fingerprint": entry.get("Fingerprint"),
                        "description": entry.get("Description"),
                    },
                    secret_text=secret_text,
                    match_text=match_text,
                )
            )
        return findings
