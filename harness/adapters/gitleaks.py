"""Gitleaks scanner adapter.

All Gitleaks-specific invocation, parsing, fixture, and product behavior lives
here. Scanner executables and Docker images are operator-provided and verified
through the local artifact manifest; this adapter never builds or pulls them.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..execution import Invocation, run_process
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
        artifact: BuildArtifact | None = None,
        invocation_type: str = "detection",
        suite: str | None = None,
        workload: str | None = None,
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
        self,
        fixtures,
        artifact: BuildArtifact,
        work_dir: Path | str,
        timeout: int,
    ) -> dict:
        def record(invocation, case):
            self.record_invocation(invocation, artifact)

        return gitleaks_fixtures.run_native(
            fixtures,
            artifact.artifact_path,
            work_dir,
            timeout,
            on_invocation=record,
        )

    def run_fixture_suite_docker(
        self,
        fixtures,
        artifact: BuildArtifact,
        work_dir: Path | str,
        timeout: int,
    ) -> dict:
        lane = gitleaks_fixtures.run_docker(
            fixtures, artifact.image_tag, artifact.image_id, work_dir, timeout
        )
        for item in lane.get("invocations") or []:
            command = item.get("command")
            if not isinstance(command, list) or not command:
                continue
            invocation = Invocation(
                binary_path=f"docker:{artifact.image_tag}",
                binary_sha256=artifact.image_id.removeprefix("sha256:"),
                argv=tuple(command),
                mode="gitleaks-fixture",
                report_path="",
                exit_code=item.get("exit_code"),
                timed_out=bool(item.get("timed_out")),
                duration_seconds=float(item.get("duration_seconds") or 0.0),
                timeout_seconds=float(timeout),
                stdout=b"",
                stderr=b"",
                report_bytes=None,
                invocation_type="detection",
                suite="gitleaks",
                workload=f"gitleaks-fixtures:{item.get('id')}",
            )
            self.record_invocation(invocation, artifact)
        return lane
