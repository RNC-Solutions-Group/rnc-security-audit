"""Betterleaks scanner adapter.

Betterleaks is a separate production scanner. Executables and Docker images are
operator-provided local artifacts verified through the run manifest; this
adapter never downloads, builds, or substitutes a scanner release.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

from ..contracts import NormalizedFinding
from ..execution import Invocation, run_process
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
        artifact: BuildArtifact | None = None,
        invocation_type: str = "detection",
        suite: str | None = None,
        workload: str | None = None,
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
        invocation = run_process(
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
            invocation_type=invocation_type,
            suite=suite,
            workload=workload,
        )
        self.record_invocation(invocation, artifact)
        return invocation

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
        artifact: BuildArtifact | None = None,
        invocation_type: str = "detection",
        suite: str | None = None,
        workload: str | None = None,
    ) -> Invocation:
        out_dir = Path(out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        report_host = out_dir / "report.json"
        arch = artifact.platform.arch if artifact is not None else (
            "arm64" if "arm64" in image_tag else "amd64"
        )
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
        container = self.container_name("docker")
        argv.extend(["--name", container])
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
        try:
            invocation = run_process(
                argv,
                binary_path=f"docker:{image_tag}",
                binary_sha256=image_id.removeprefix("sha256:"),
                mode=mode,
                report_path=report_host,
                timeout_seconds=timeout_seconds,
                env=self.clean_environment(),
                unset_env=self.config_environment_keys(),
                collect_telemetry=collect_telemetry,
                invocation_type=invocation_type,
                suite=suite,
                workload=workload,
            )
        except BaseException:
            self._remove_container(container)
            raise
        self.record_invocation(invocation, artifact)
        if invocation.timed_out or invocation.error_code:
            self._remove_container(container)
        return invocation

    @staticmethod
    def _remove_container(name: str) -> None:
        """Remove only this invocation's named container; never touch images."""
        try:
            subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return

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
