"""Stable scanner-adapter contract and target-platform catalog.

The harness deliberately uses a small in-code registry rather than plugin
discovery. An adapter owns scanner identity, source build strategy, native and
Docker build details, invocation, configuration behavior, output parsing, and
capabilities. The harness owns workspace lifecycle, source acquisition,
benchmark selection, scoring, reporting, performance, and cleanup.
"""

from __future__ import annotations

import platform
import shutil
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..contracts import NormalizedFinding
from ..execution import Invocation, ACCEPTED_EXIT_CODES
from ..source import SourceCheckout


@dataclass(frozen=True, order=True)
class TargetPlatform:
    key: str
    os_name: str
    arch: str
    kind: str  # "executable" or "docker"

    @property
    def goos(self) -> str:
        return self.os_name

    @property
    def goarch(self) -> str:
        return self.arch

    @property
    def docker_platform(self) -> str | None:
        return f"linux/{self.arch}" if self.kind == "docker" else None

    @property
    def is_executable(self) -> bool:
        return self.kind == "executable"

    @property
    def is_docker(self) -> bool:
        return self.kind == "docker"

    def to_dict(self) -> dict:
        return asdict(self) | {
            "goos": self.goos,
            "goarch": self.goarch,
            "docker_platform": self.docker_platform,
        }


PLATFORM_CATALOG: tuple[TargetPlatform, ...] = (
    TargetPlatform("windows-amd64", "windows", "amd64", "executable"),
    TargetPlatform("docker-linux-amd64", "linux", "amd64", "docker"),
    TargetPlatform("docker-linux-arm64", "linux", "arm64", "docker"),
)
PLATFORMS = {item.key: item for item in PLATFORM_CATALOG}


def _host_os() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "darwin":
        return "darwin"
    return "linux"


def _host_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return machine


def host_platform() -> TargetPlatform | None:
    key = f"{_host_os()}-{_host_arch()}"
    if key in PLATFORMS:
        return PLATFORMS[key]
    docker_key = f"docker-linux-{_host_arch()}"
    if shutil.which("docker") and docker_key in PLATFORMS:
        return PLATFORMS[docker_key]
    return None


def platform_for(key: str) -> TargetPlatform:
    try:
        return PLATFORMS[key]
    except KeyError as exc:
        raise ValueError(
            f"unknown target platform {key!r}; choose from {', '.join(sorted(PLATFORMS))}"
        ) from exc


def expand_platform_selection(
    value: str | list[str] | tuple[str, ...] | None,
) -> tuple[TargetPlatform, ...]:
    """Expand host/all/executable/docker aliases into immutable platform records."""
    if value is None:
        host = host_platform()
        return (host,) if host else ()
    if isinstance(value, str):
        items = [item.strip() for item in value.split(",") if item.strip()]
    else:
        items = [str(item).strip() for item in value if str(item).strip()]
    expanded: list[TargetPlatform] = []
    for item in items:
        if item == "host":
            host = host_platform()
            if host is None:
                raise ValueError(
                    f"host platform {platform.system()}/{platform.machine()} is not catalogued"
                )
            selected = [host]
        elif item == "all":
            selected = list(PLATFORM_CATALOG)
        elif item in ("executable", "executables", "native"):
            selected = [entry for entry in PLATFORM_CATALOG if entry.is_executable]
        elif item == "docker":
            selected = [entry for entry in PLATFORM_CATALOG if entry.is_docker]
        else:
            selected = [platform_for(item)]
        for entry in selected:
            if entry not in expanded:
                expanded.append(entry)
    return tuple(expanded)


@dataclass(frozen=True)
class BuildArtifact:
    platform: TargetPlatform
    status: str
    command: tuple[str, ...]
    exit_code: int | None
    duration_seconds: float
    artifact_path: str | None
    artifact_sha256: str | None
    image_id: str | None
    image_tag: str | None
    version: str | None
    version_status: str
    stdout_sha256: str
    stderr_sha256: str
    error: str | None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "platform": self.platform.to_dict(),
        }


class ScannerAdapter(ABC):
    key: str
    display_name: str
    supported_suites: tuple[str, ...]
    platforms: tuple[TargetPlatform, ...]
    default_repository: str

    def __init__(self) -> None:
        self.run_id: str = f"adhoc-{uuid.uuid4().hex[:8]}"

    def bind_run(self, run_id: str) -> None:
        """Bind run-owned Docker labels and names without changing the contract."""
        self.run_id = run_id

    def docker_label_args(self) -> tuple[str, ...]:
        return (
            f"rnc-scan-harness.run={self.run_id}",
            f"rnc-scan-harness.adapter={self.key}",
        )

    def container_name(self, platform: str) -> str:
        safe = "".join(
            ch if ch.isalnum() or ch in "._-" else "-" for ch in self.run_id
        ).strip("-.")
        return f"rnc-{safe}-{platform}-{uuid.uuid4().hex[:8]}"

    @abstractmethod
    def build(
        self,
        source: SourceCheckout,
        target: TargetPlatform,
        output_dir: Path | str,
    ) -> BuildArtifact:
        raise NotImplementedError

    @abstractmethod
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
        raise NotImplementedError

    @abstractmethod
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
        raise NotImplementedError

    @abstractmethod
    def parse_findings(self, data: bytes) -> list[NormalizedFinding]:
        raise NotImplementedError

    def partial_execution_evidence(self, invocation: Invocation) -> dict | None:
        """Return an explicit, bounded coverage caveat for a completed scan.

        A scanner may report INCOMPLETE because it intentionally does not follow
        symlink aliases while still inspecting every regular source unit.  An
        adapter may expose that exact condition here so a lab lane can score the
        inspected units without claiming complete coverage.  The base contract
        never permits partial credit.
        """
        return None

    def execution_coverage(
        self,
        invocation: Invocation,
        target_dir: Path | str,
        expected_files: tuple[str, ...],
    ) -> dict | None:
        """Return scanner-native execution coverage evidence, when available.

        The base contract has no coverage channel; scanners that expose one can
        return a safe dictionary with ``applicable``, ``verified``, ``notes``, and
        ``details``. Levain uses this only as an additional control witness; the
        independent negative oracle still decides whether findings are false
        positives.
        """
        return None

    def default_configuration(self) -> dict:
        """Describe how the adapter protects the scanner's bundled defaults."""
        return {
            "mode": "bundled-default",
            "config_argument": None,
            "isolated_working_directory": True,
            "removed_environment": sorted(self.config_environment_keys()),
            "verifiable": True,
            "limitations": [
                "DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.",
                "The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.",
            ],
        }

    def config_environment_keys(self) -> tuple[str, ...]:
        return (
            "GITLEAKS_CONFIG",
            "GITLEAKS_CONFIG_TOML",
            "BETTERLEAKS_CONFIG",
            "BETTERLEAKS_CONFIG_TOML",
            "RNC_CONFIG",
            "RNC_SCANNER_CONFIG",
        )

    def write_control_config(
        self, path: Path | str, pattern: str = "RNC_[A-Z0-9]{16}"
    ) -> Path:
        """Write a controlled scanner-rule configuration for a synthetic suite.

        The default form is the Gitleaks-compatible TOML rule used by the two
        existing adapters. An adapter with a different rule format overrides this
        method; the synthetic suite does not know scanner-specific formats.
        """
        target = Path(path)
        if target.suffix != ".toml":
            target = target.with_suffix(".toml")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            'title = "rnc-harness-controlled"\n'
            "\n"
            "[[rules]]\n"
            'id = "rnc-harness-controlled-token"\n'
            'description = "controlled synthetic credential"\n'
            f"regex = '''{pattern}'''\n"
            "secretGroup = 0\n",
            encoding="utf-8",
            newline="\n",
        )
        return target

    def clean_environment(self) -> dict[str, str]:
        """Return caller environment with known scanner-config overrides removed.

        ``run_process`` merges this mapping over the process environment and then
        unsets the returned keys again, so a parent-shell config variable cannot
        silently select a non-default rule set.
        """
        import os

        keys = {name.upper() for name in self.config_environment_keys()}
        return {key: value for key, value in os.environ.items() if key.upper() not in keys}

    def invocation_problem(self, invocation: Invocation) -> str | None:
        if invocation.error_code:
            return invocation.error_code
        if invocation.timed_out:
            return "TIMEOUT"
        if invocation.exit_code not in ACCEPTED_EXIT_CODES:
            return "INVOCATION_FAILED"
        if invocation.report_bytes is None:
            return "REPORT_MISSING"
        try:
            self.parse_findings(invocation.report_bytes)
        except Exception:
            return "REPORT_INVALID"
        return None

    def validate_config(self, path: Path | str | None) -> tuple[Path | None, str | None]:
        if path is None:
            return None, None
        resolved = Path(path).expanduser().resolve(strict=True)
        if not resolved.is_file():
            raise ValueError(f"scanner configuration is not a file: {resolved}")
        from ..util import sha256_file

        return resolved, sha256_file(resolved)

    def supports_mode(self, mode: str) -> bool:
        return mode in {"dir", "detect"}

    def can_execute(self, target: TargetPlatform) -> bool:
        if target.is_docker:
            return shutil.which("docker") is not None
        host = host_platform()
        return host is not None and target == host

    def execution_reason(self, target: TargetPlatform) -> str:
        if self.can_execute(target):
            return "executable on this host"
        if target.is_docker:
            return "Docker CLI is unavailable"
        return f"{target.key} is not executable on the current host"

    # Optional scanner-specific fixture hooks. A scanner without them reports
    # the corresponding suite as NOT_APPLICABLE.
    def run_fixture_suite_native(
        self, fixtures, executable: Path | str, work_dir: Path | str, timeout: int
    ) -> dict:
        raise NotImplementedError(f"{self.key} has no native fixture suite")

    def run_fixture_suite_docker(
        self, fixtures, image_tag: str, image_id: str, work_dir: Path | str, timeout: int
    ) -> dict:
        raise NotImplementedError(f"{self.key} has no Docker fixture suite")
