"""Gitleaks scanner adapter.

All Gitleaks-specific source-build, invocation, parsing, fixture, and product
behavior lives here. The harness supplies a disposable exact-commit checkout and
the adapter builds both the native executable and Docker images from it.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform as host_platform_module
import re
import shutil
import subprocess
from pathlib import Path

from .. import status as statuses
from ..builds import BuildResult, build_docker_image, build_executable, toolchain_metadata
from ..execution import Invocation, run_process
from ..source import SourceCheckout, ensure_version_tag
from ..util import sha256_file
from . import gitleaks_fixtures
from .base import (
    PLATFORM_CATALOG,
    BuildArtifact,
    NormalizedFinding,
    ScannerAdapter,
    TargetPlatform,
)
from .gitleaks_parse import parse_entries

VERSION_NAMESPACE = "github.com/zricethezav/gitleaks/v8/version"


def _version_from_text(text: str) -> str | None:
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", text).strip()
    if not cleaned:
        return None
    for line in cleaned.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.search(r"v?\d+\.\d+\.\d+[^\s]*", line)
        if match:
            return match.group(0)
    return None


def _host_arch() -> str:
    machine = host_platform_module.machine().lower()
    return "amd64" if machine in ("x86_64", "amd64") else machine


def _docker_architecture(image_tag: str) -> str | None:
    try:
        result = subprocess.run(
            [
                "docker",
                "image",
                "inspect",
                image_tag,
                "--format",
                "{{.Os}}/{{.Architecture}}",
            ],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", "replace").strip() or None


class GitleaksAdapter(ScannerAdapter):
    key = "gitleaks"
    display_name = "Gitleaks"
    default_repository = "https://github.com/RNC-Solutions-Group/gitleaks"
    supported_suites = (
        "gitleaks",
        "git-history",
        "levain",
        "leaky-repo",
        "rnclab",
        "synthetic-filesystem",
    )
    platforms = PLATFORM_CATALOG

    def _version_tag(self, source: SourceCheckout) -> str:
        return ensure_version_tag(source, f"v8.0.0-rnc.{source.commit[:12]}")

    def _build_native(
        self, source: SourceCheckout, target: TargetPlatform, output_dir: Path
    ) -> BuildArtifact:
        version_tag = self._version_tag(source)
        extension = ".exe" if target.os_name == "windows" else ""
        output_path = output_dir / f"gitleaks-{target.key}{extension}"
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
                "toolchain": toolchain_metadata(),
            },
        )

    def _vendor_dependencies(self, source: SourceCheckout) -> tuple[bool, str | None, str | None]:
        """Create an offline vendor tree from the local Go module cache."""
        vendor = source.path / "vendor"
        try:
            result = subprocess.run(
                ["go", "mod", "vendor"],
                cwd=source.path,
                capture_output=True,
                timeout=600,
                env={
                    **os.environ,
                    "GOPROXY": "off",
                    "GOTOOLCHAIN": "local",
                    "GOFLAGS": "",
                },
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, None, f"offline dependency vendoring failed: {exc}"
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
            return (
                False,
                None,
                "offline dependency vendoring failed: "
                + (detail[0][:300] if detail else "no diagnostic"),
            )
        digest = hashlib.sha256()
        count = 0
        for path in sorted(vendor.rglob("*")):
            if not path.is_file():
                continue
            digest.update(path.relative_to(vendor).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
            count += 1
        return True, digest.hexdigest(), f"{count} vendored files"

    def _dockerfile(self, output_dir: Path, version_tag: str) -> Path:
        path = output_dir / "Dockerfile.rnc-gitleaks"
        path.write_text(
            "FROM golang:1.27.4 AS build\n"
            "ARG VERSION=dev\n"
            "WORKDIR /src\n"
            "COPY . .\n"
            "ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor GOTOOLCHAIN=local\n"
            "RUN go build -trimpath -buildvcs=false -o /out/gitleaks "
            f"-ldflags \"-X={VERSION_NAMESPACE}.Version=${{VERSION}}\" .\n"
            "\n"
            "FROM golang:1.27.4\n"
            "COPY --from=build /out/gitleaks /usr/bin/gitleaks\n"
            "RUN git config --global --add safe.directory '*'\n"
            "ENTRYPOINT [\"gitleaks\"]\n",
            encoding="utf-8",
            newline="\n",
        )
        return path

    def _build_docker(
        self, source: SourceCheckout, target: TargetPlatform, output_dir: Path
    ) -> BuildArtifact:
        version_tag = self._version_tag(source)
        vendored, vendor_sha, vendor_note = self._vendor_dependencies(source)
        if not vendored:
            return BuildArtifact(
                platform=target,
                status=statuses.BLOCKED,
                command=(),
                exit_code=None,
                duration_seconds=0.0,
                artifact_path=None,
                artifact_sha256=None,
                image_id=None,
                image_tag=None,
                version=None,
                version_status=statuses.NOT_APPLICABLE,
                stdout_sha256="",
                stderr_sha256="",
                error=vendor_note,
                metadata={
                    "source_commit": source.commit,
                    "source_repository": source.repository,
                    "docker_build_strategy": "BLOCKED_MISSING_LOCAL_DEPENDENCY",
                },
            )
        safe_run = "".join(
            ch if ch.isalnum() or ch in "._-" else "-" for ch in self.run_id
        ).strip("-.").lower()
        tag = f"rnc-gitleaks-{safe_run}-{source.commit[:12]}-{target.key}"
        dockerfile = self._dockerfile(output_dir, version_tag)
        result = build_docker_image(
            source,
            tag,
            platform=target.docker_platform or f"linux/{target.arch}",
            dockerfile=str(dockerfile),
            build_args=(f"VERSION={version_tag}",),
            labels=self.docker_label_args(),
        )
        architecture = _docker_architecture(tag) if result.status == statuses.PASS else None
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
                "host_architecture": _host_arch(),
                "emulated": target.arch != _host_arch(),
                "execution_method": "docker",
                "source_commit": source.commit,
                "source_repository": source.repository,
                "build_version_tag": version_tag,
                "docker_build_strategy": "adapter-source-dockerfile-local-base",
                "dockerfile_sha256": sha256_file(dockerfile),
                "vendor_sha256": vendor_sha,
                "vendor_inventory": vendor_note,
                "docker_base_images": ["golang:1.27.4"],
                "network_disabled": True,
                "pull_disabled": True,
                "toolchain": toolchain_metadata(),
            },
        )

    def _artifact(
        self,
        target: TargetPlatform,
        result: BuildResult,
        *,
        version: str | None,
        version_status: str | None = None,
        metadata: dict,
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

    def _native_version(
        self, executable: Path, target: TargetPlatform
    ) -> tuple[str | None, str]:
        if not self.can_execute(target):
            return None, statuses.NOT_RUN
        try:
            result = subprocess.run(
                [str(executable), "version"],
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None, statuses.NOT_RUN
        if result.returncode != 0:
            return None, statuses.FAIL
        text = result.stdout.decode("utf-8", "replace") or result.stderr.decode(
            "utf-8", "replace"
        )
        version = _version_from_text(text)
        return version, statuses.PASS if version else statuses.FAIL

    def _docker_version(
        self, image_tag: str, target: TargetPlatform
    ) -> tuple[str | None, str]:
        if not self.can_execute(target):
            return None, statuses.NOT_RUN
        try:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--platform",
                    f"linux/{target.arch}",
                    "--network",
                    "none",
                    image_tag,
                    "version",
                ],
                capture_output=True,
                timeout=90,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None, statuses.NOT_RUN
        if result.returncode != 0:
            return None, statuses.FAIL
        version = _version_from_text(
            result.stdout.decode("utf-8", "replace")
            or result.stderr.decode("utf-8", "replace")
        )
        if version is None:
            try:
                labels_result = subprocess.run(
                    [
                        "docker",
                        "image",
                        "inspect",
                        image_tag,
                        "--format",
                        "{{json .Config.Labels}}",
                    ],
                    capture_output=True,
                    timeout=30,
                )
                labels = json.loads(labels_result.stdout.decode("utf-8", "replace") or "{}")
                if isinstance(labels, dict):
                    version = (
                        labels.get("org.opencontainers.image.version")
                        or labels.get("version")
                        or labels.get("org.opencontainers.image.revision")
                    )
            except (OSError, ValueError, subprocess.TimeoutExpired):
                version = None
        return version, statuses.PASS if version else statuses.FAIL

    def supports_mode(self, mode: str) -> bool:
        return mode in {"dir", "detect", "git"}

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
        if mode == "dir":
            argv = [str(binary), "dir", str(target)]
        elif mode == "git":
            argv = [str(binary), "git", str(target)]
        elif mode == "detect":
            argv = [str(binary), "detect", "--source", str(target)]
        else:
            raise ValueError(f"unsupported Gitleaks scan mode: {mode}")
        argv.extend(
            [
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--no-banner",
                "--exit-code",
                "1",
            ]
        )
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
        argv = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--platform",
            f"linux/{'arm64' if 'arm64' in image_tag else 'amd64'}",
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
        return [
            NormalizedFinding(
                file=entry["file"],
                line=entry["line"],
                rule_id=entry["rule_id"],
                commit=entry.get("commit"),
                secret_sha256=entry["secret_sha256"],
                match_sha256=entry["match_sha256"],
                secret_redacted=entry["secret_redacted"],
                metadata={"fingerprint": entry.get("fingerprint")}
                if entry.get("fingerprint")
                else {},
                secret_text=entry["secret"] or None,
                match_text=entry["match"] or None,
            )
            for entry in parse_entries(data)
        ]

    def run_fixture_suite_native(
        self, fixtures, executable: Path | str, work_dir: Path | str, timeout: int
    ) -> dict:
        return gitleaks_fixtures.run_native(fixtures, executable, work_dir, timeout)

    def run_fixture_suite_docker(
        self, fixtures, image_tag: str, image_id: str, work_dir: Path | str, timeout: int
    ) -> dict:
        return gitleaks_fixtures.run_docker(
            fixtures, image_tag, image_id, work_dir, timeout
        )
