"""Stable scanner-adapter contract and target-platform catalog.

The harness deliberately uses a small in-code registry rather than plugin
discovery. An adapter owns scanner identity, local-artifact resolution, native
and Docker invocation, configuration behavior, output parsing, capabilities,
and exact-invocation recording. The harness owns workspace lifecycle, artifact
manifest verification, benchmark selection, scoring, reporting, performance,
and cleanup.
"""

from __future__ import annotations

import platform
import shutil
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..artifacts import RegisteredBuild, VerifiedArtifact, verify_artifact
from .. import status as statuses
from ..contracts import NormalizedFinding
from ..execution import Invocation, ACCEPTED_EXIT_CODES
from ..provenance import (
    artifact_identity,
    command_digest,
    environment_record,
    invocation_sequence_label,
    lane_for_workload,
    load_profile_from_workload,
    normalize_command,
    normalize_replacements,
    redact_argv,
    render_command,
)
from ..safe_text import safe_message, safe_path
from ..util import sha256_file


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
        self.experiment_id: str = self.run_id
        self.workspace_root: Path | None = None
        self.argument_policy: object | None = None
        self.argument_origin: str = "cli"
        self.invocations: list[dict] = []
        self.auxiliary_commands: list[dict] = []
        self.last_invocation_id: str = ""
        # Optional experiment-owned scanner flags (for example RNC CP4C
        # ``--workers auto``).  Empty by default so adapter behavior is
        # unchanged unless an experiment explicitly opts in.
        self.default_extra_args: tuple[str, ...] = ()

    def bind_run(self, run_id: str) -> None:
        """Bind run-owned Docker labels and names without changing the contract."""
        self.run_id = run_id
        if not self.experiment_id or self.experiment_id.startswith("adhoc-"):
            self.experiment_id = run_id

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

    def resolve_artifact(
        self,
        build: RegisteredBuild,
        target: TargetPlatform,
        work_dir: Path | None = None,
    ) -> BuildArtifact:
        """Verify and describe one operator-provided artifact.

        No source acquisition, compilation, image build, or image pull occurs.
        A missing or mismatched artifact is a BLOCKED product, never a
        substitute build.
        """
        verified = verify_artifact(build, target)
        return self.artifact_from_verification(verified, target)

    def artifact_from_verification(
        self,
        verified: VerifiedArtifact,
        target: TargetPlatform,
        *,
        metadata: dict | None = None,
    ) -> BuildArtifact:
        build = verified.build
        metadata = {
            **verified.identity(target),
            **(verified.details or {}),
            **(metadata or {}),
            "build_command": "not required: operator-provided local artifact",
        }
        return BuildArtifact(
            platform=target,
            status=verified.status,
            command=(),
            exit_code=None,
            duration_seconds=0.0,
            artifact_path=(
                str(verified.executable_path)
                if target.is_executable and verified.executable_path is not None
                else None
            ),
            artifact_sha256=verified.executable_sha256,
            image_id=verified.image_id,
            image_tag=build.docker_image if target.is_docker else None,
            version=build.version,
            version_status=(
                statuses.PASS if build.version else statuses.NOT_APPLICABLE
            ),
            stdout_sha256="",
            stderr_sha256="",
            error=verified.error,
            metadata=metadata,
        )

    def accepted_exit_codes(self) -> tuple[int, ...]:
        """Exit codes that mean the scanner completed and produced a report."""
        return ACCEPTED_EXIT_CODES

    def record_invocation(
        self,
        invocation: Invocation,
        artifact: BuildArtifact | None = None,
        *,
        target_path: Path | str | None = None,
        config_path: Path | str | None = None,
        supplied_args: tuple[str, ...] = (),
        argument_origin: str | None = None,
        direct_execution: bool = True,
        execution_origin: str = "direct",
    ) -> dict:
        """Record the actual argument vector, context, and outcome.

        The command is not reconstructed from intended settings: ``argv`` is the
        vector passed to the process.  A normalized template is derived only for
        display and is explicitly labelled as such.
        """
        if not hasattr(self, "invocations"):
            self.invocations = []
        metadata = (artifact.metadata if artifact is not None else {}) or {}
        platform = getattr(artifact, "platform", None) if artifact is not None else None
        platform_key = platform.key if platform is not None else metadata.get("platform")
        identity = artifact_identity(artifact)
        if artifact is None:
            identity.update(
                {
                    "kind": metadata.get("execution_method") or "unknown",
                    "build_id": metadata.get("build_id"),
                    "source_commit": metadata.get("source_commit"),
                }
            )
        sequence = len(self.invocations) + 1
        experiment_id = self.experiment_id or self.run_id
        invocation_id = invocation_sequence_label(experiment_id, sequence)
        command = list(invocation.argv)
        redacted, redactions = redact_argv(command)
        if not invocation.process_started:
            status = statuses.BLOCKED
        elif invocation.timed_out:
            status = statuses.BLOCKED
        elif invocation.error_code:
            status = statuses.BLOCKED
        elif invocation.exit_code in self.accepted_exit_codes():
            status = statuses.PASS
        else:
            status = statuses.FAIL
        accepted_exits = list(self.accepted_exit_codes())
        exit_accepted = (
            invocation.exit_code in accepted_exits
            if invocation.exit_code is not None
            else None
        )
        policy = getattr(self, "argument_policy", None)
        policy_dict = policy.to_dict() if hasattr(policy, "to_dict") else None
        policy_arguments = policy_dict.get("arguments", []) if policy_dict else []
        if supplied_args:
            # Supplied arguments are appended last by every adapter.  Verify the
            # suffix rather than searching for values, which could be ambiguous.
            supplied = list(supplied_args)
            suffix = command[-len(supplied) :] if supplied else []
            suffix_matches = suffix == supplied
            argument_records = [
                dict(item)
                for item in policy_arguments
                if 0 <= int(item.get("index", -1)) < len(supplied)
            ]
            for item in argument_records:
                item["accepted"] = (
                    True
                    if status == statuses.PASS
                    else False
                    if not invocation.process_started
                    else None
                )
                item["acceptance_evidence"] = (
                    "process launched and completed with an accepted exit status; "
                    "semantic acceptance of an unknown flag is not independently observable"
                    if status == statuses.PASS
                    else "process launched but did not complete with an accepted status"
                    if invocation.process_started
                    else "process was not launched"
                )
                item["suffix_verified"] = suffix_matches
        else:
            argument_records = []
        config = Path(config_path) if config_path is not None else None
        config_digest = (
            sha256_file(config)
            if config is not None and config.is_file()
            else None
        )
        target = Path(target_path) if target_path is not None else None
        report_path = Path(invocation.report_path) if invocation.report_path else None
        replacements = normalize_replacements(
            repo_root=Path(__file__).resolve().parents[2],
            workspace_root=self.workspace_root,
            target_path=target,
            report_path=report_path,
            config_path=config,
            run_id=self.run_id,
        )
        lane = lane_for_workload(invocation.workload, invocation.suite)
        environment = environment_record(
            invocation.environment_cleared,
            invocation.environment_overrides,
        )
        if command and Path(command[0]).name.lower() == "docker":
            container_env: list[dict[str, str]] = []
            index = 0
            while index < len(command):
                if command[index] in ("--env", "-e") and index + 1 < len(command):
                    key, _, value = command[index + 1].partition("=")
                    container_env.append(
                        {
                            "key": key,
                            "value": value
                            if not any(
                                marker in key.upper()
                                for marker in ("TOKEN", "SECRET", "PASSWORD", "KEY", "AUTH")
                            )
                            else "<redacted>",
                            "origin": "adapter-generated",
                        }
                    )
                    index += 2
                    continue
                index += 1
            environment["container"] = container_env
        record = {
            "schema_version": 1,
            "invocation_id": invocation_id,
            "experiment_id": experiment_id,
            "sequence": sequence,
            "scanner": self.key,
            "scanner_name": self.display_name,
            "adapter": self.key,
            "build_id": metadata.get("build_id") or identity.get("build_id"),
            "version": metadata.get("version") or identity.get("version"),
            "platform": platform_key,
            "artifact_kind": identity.get("kind"),
            "artifact_identity": identity,
            "executable": safe_path(identity.get("executable")),
            "executable_sha256": identity.get("executable_sha256"),
            "docker_image": identity.get("docker_image"),
            "docker_image_id": identity.get("docker_image_id"),
            "source_commit": metadata.get("source_commit"),
            "source_identity": metadata.get("source_identity") or "manifest-metadata",
            "source_commit_verified": False,
            "manifest_sha256": (metadata.get("manifest") or {}).get("sha256"),
            "invocation_type": invocation.invocation_type,
            "phase": invocation.invocation_type,
            "suite": invocation.suite,
            "workload": invocation.workload,
            "workload_context": {
                "suite": invocation.suite,
                "lane": lane,
                "load_profile": load_profile_from_workload(invocation.workload),
                "target": safe_path(target) if target is not None else None,
                "mode": invocation.mode,
            },
            "mode": invocation.mode,
            "direct_execution": direct_execution,
            "execution_origin": execution_origin,
            "command": redacted,
            "arguments": redacted[1:],
            "supplied_arguments": argument_records,
            "argument_policy": policy_dict,
            "command_sha256": command_digest(command),
            "command_rendered": {
                "powershell": render_command(redacted, shell="powershell"),
                "posix": render_command(redacted, shell="posix"),
            },
            "command_template": normalize_command(redacted, replacements),
            "command_template_label": (
                "normalized display template derived from this invocation; "
                "not the literal executed command"
            ),
            "command_redacted": bool(redactions),
            "redacted_argument_indexes": redactions,
            "cwd": safe_path(invocation.cwd),
            "environment": environment,
            "configuration": {
                "profile": getattr(policy, "profile", None),
                "config_path": safe_path(config) if config is not None else None,
                "config_sha256": config_digest,
                "rules_file": metadata.get("rules_file"),
                "rules_sha256": metadata.get("rules_sha256"),
                "effective_flags_observable": False,
            },
            "exit_code": invocation.exit_code,
            "accepted_exit_codes": accepted_exits,
            "exit_accepted": exit_accepted,
            "process_started": invocation.process_started,
            "duration_seconds": invocation.duration_seconds,
            "timeout_seconds": invocation.timeout_seconds,
            "timed_out": invocation.timed_out,
            "error_code": invocation.error_code,
            "error_message": safe_message(invocation.error_message),
            "status": status,
            "timestamps": {
                "started_at": invocation.started_at or None,
                "finished_at": invocation.finished_at or None,
            },
            "evidence": {
                "report_path": safe_path(report_path) if report_path is not None else None,
                "report_sha256": invocation.report_sha256,
                "stdout_sha256": invocation.stdout_sha256,
                "stderr_sha256": invocation.stderr_sha256,
                "raw_evidence": (
                    "transient run workspace; retained only when --retain-work is set"
                ),
            },
            "report_sha256": invocation.report_sha256,
        }
        self.invocations.append(record)
        self.last_invocation_id = invocation_id
        return record

    def record_auxiliary(
        self,
        *,
        operation: str,
        argv: list[str] | tuple[str, ...],
        exit_code: int | None,
        duration_seconds: float | None = None,
        status: str = statuses.PASS,
        error: str | None = None,
    ) -> dict:
        """Record a harness auxiliary operation without calling it a scanner run."""
        command = [str(item) for item in argv]
        redacted, redactions = redact_argv(command)
        record = {
            "schema_version": 1,
            "operation": operation,
            "command": redacted,
            "command_sha256": command_digest(command),
            "command_rendered": render_command(redacted),
            "command_redacted": bool(redactions),
            "redacted_argument_indexes": redactions,
            "exit_code": exit_code,
            "duration_seconds": duration_seconds,
            "status": status,
            "error": safe_message(error),
        }
        self.auxiliary_commands.append(record)
        return record

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
        artifact: BuildArtifact | None = None,
        invocation_type: str = "detection",
        suite: str | None = None,
        workload: str | None = None,
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
        artifact: BuildArtifact | None = None,
        invocation_type: str = "detection",
        suite: str | None = None,
        workload: str | None = None,
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
        self,
        fixtures,
        artifact: BuildArtifact,
        work_dir: Path | str,
        timeout: int,
    ) -> dict:
        raise NotImplementedError(f"{self.key} has no native fixture suite")

    def run_fixture_suite_docker(
        self,
        fixtures,
        artifact: BuildArtifact,
        work_dir: Path | str,
        timeout: int,
    ) -> dict:
        raise NotImplementedError(f"{self.key} has no Docker fixture suite")
