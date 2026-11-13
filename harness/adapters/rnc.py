"""RNC Scanner adapter.

RNC Scanner is a Rust CLI with a byte-addressed private JSON report and a
versioned provider rule bundle. The adapter builds both the native executable and
Docker image from the requested source commit, uses the scanner's own bundled
provider rules for DEFAULT, and normalizes private findings through the shared
harness contract.

CP4 adds a read-only Git-history source mode. The adapter invokes it only when a
suite explicitly requests Git mode; ordinary filesystem scans are unchanged.
"""

from __future__ import annotations

import hashlib
import json
import platform as host_platform_module
import re
import subprocess
from pathlib import Path, PurePosixPath

from .. import status as statuses
from ..builds import (
    BuildResult,
    build_cargo_executable,
    build_docker_image,
    inspect_image,
    toolchain_metadata,
)
from ..contracts import NormalizedFinding
from ..errors import ReportError
from ..execution import Invocation, run_process
from ..source import SourceCheckout
from ..util import sha256_file
from .base import (
    PLATFORM_CATALOG,
    BuildArtifact,
    ScannerAdapter,
    TargetPlatform,
    host_platform,
)

PRIVATE_FORMAT = "rnc-cp2-output-v1"
RULES_PATH = "rules/rnc-providers-v1.json"
RNC_ACCEPTED_EXITS = (0, 10, 20, 30)
RNC_RESULT_CODES = {1: "CLEAN", 2: "POLICY_APPLIED", 3: "ACTIONABLE", 4: "INCOMPLETE", 5: "FAILED"}
WORKING_TREE_SOURCE_KIND = "working_tree_file"
GIT_SOURCE_KIND = "git_commit_blob"
STRUCTURED_EVIDENCE_VERSION = "1"
DATABASE_PASSWORD_KIND = "database-password"
ANSI_VALUES = frozenset({"NONE", "TRIMMED", "INTERNAL"})
ANSI_NORMALIZATION = "ansi-sgr-v1"
HISTORY_REF = "HEAD"
HISTORY_SCOPE = "selected-refs"
HISTORY_SOURCE_ID = "local-git-history"
WORKING_TREE_SOURCE_ID = "local-working-tree"

_UNIT_ID = re.compile(r"u-[0-9a-f]{64}")
_GIT_LOCATOR = re.compile(r"commit/([0-9a-f]{40})/(.+)")


def _host_arch() -> str:
    machine = host_platform_module.machine().lower()
    return "amd64" if machine in ("x86_64", "amd64") else machine


def _sha256_file(path: Path) -> str:
    return sha256_file(path)


def _normalize_digest(value: object, *, label: str = "evidence") -> str:
    if not isinstance(value, str):
        raise ReportError(f"RNC {label} digest is missing")
    text = value.removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ReportError(f"RNC {label} digest is not SHA-256")
    return text


def _normalize_locator(value: object, *, label: str = "execution unit") -> str:
    """Validate the scanner's canonical relative locator without repairing it."""
    if not isinstance(value, str) or not value:
        raise ReportError(f"RNC {label} has no locator")
    locator = value
    if "\\" in locator:
        raise ReportError(f"RNC {label} locator uses backslashes")
    if locator.startswith(("/", "~")):
        raise ReportError(f"RNC {label} locator is absolute")
    if re.match(r"^[A-Za-z]:", locator):
        raise ReportError(f"RNC {label} locator has a drive prefix")
    if locator.endswith("/"):
        raise ReportError(f"RNC {label} locator ends with a separator")
    parts = locator.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ReportError(f"RNC {label} locator has an empty or traversal segment")
    return locator


def _parse_unit_source(unit_id: str, source_kind: str, locator: str) -> dict:
    if source_kind == GIT_SOURCE_KIND:
        match = _GIT_LOCATOR.fullmatch(locator)
        if not match:
            raise ReportError(
                f"RNC history unit {unit_id!r} locator is not commit/<40-hex-oid>/<path>"
            )
        commit, path = match.group(1), match.group(2)
        if not path or pure_path_is_unsafe(path):
            raise ReportError(f"RNC history unit {unit_id!r} has an unsafe repository path")
        return {"file": path, "commit": commit, "source_kind": source_kind, "locator": locator}
    if source_kind == WORKING_TREE_SOURCE_KIND:
        if pure_path_is_unsafe(locator):
            raise ReportError(f"RNC filesystem unit {unit_id!r} has an unsafe path")
        return {"file": locator, "commit": None, "source_kind": source_kind, "locator": locator}
    raise ReportError(f"RNC unit {unit_id!r} has unsupported source_kind {source_kind!r}")


def pure_path_is_unsafe(path: str) -> bool:
    candidate = PurePosixPath(path)
    return (
        not path
        or candidate.is_absolute()
        or any(part in ("", ".", "..") for part in candidate.parts)
        or "\\" in path
    )


def _unit_sources(document: dict) -> tuple[dict[str, dict], str]:
    units: dict[str, dict] = {}
    source_kinds: set[str] = set()
    for index, unit in enumerate(document["execution"]["units"]):
        if not isinstance(unit, dict):
            raise ReportError(f"RNC execution unit {index} is not an object")
        unit_id = unit.get("unit_id")
        if not isinstance(unit_id, str) or not _UNIT_ID.fullmatch(unit_id):
            raise ReportError(f"RNC execution unit {index} has an invalid unit_id")
        if unit_id in units:
            raise ReportError(f"RNC execution unit {unit_id!r} is duplicated")
        locator = _normalize_locator(unit.get("locator"), label=f"unit {unit_id}")
        source_kind = unit.get("source_kind")
        if not isinstance(source_kind, str) or not source_kind:
            raise ReportError(f"RNC execution unit {unit_id!r} has no source_kind")
        source_kinds.add(source_kind)
        units[unit_id] = _parse_unit_source(unit_id, source_kind, locator)
        units[unit_id]["unit"] = unit
    if len(source_kinds) > 1:
        raise ReportError("RNC private report mixes source kinds in one scan")
    source_kind = next(iter(source_kinds), "")
    return units, source_kind


def _load_private(data: bytes) -> dict:
    if not data:
        raise ReportError("RNC private report is empty")
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportError("RNC private report is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ReportError("RNC private report is not an object")
    if document.get("format_version") != PRIVATE_FORMAT:
        raise ReportError(
            f"RNC private report format is {document.get('format_version')!r}, "
            f"expected {PRIVATE_FORMAT!r}"
        )
    if not isinstance(document.get("findings"), list):
        raise ReportError("RNC private report has no findings list")
    execution = document.get("execution")
    if not isinstance(execution, dict) or not isinstance(execution.get("units"), list):
        raise ReportError("RNC private report has no execution units")
    if execution.get("state") not in ("COMPLETED", "ERROR", "INTERRUPTED"):
        raise ReportError("RNC private report has an invalid execution state")
    result = document.get("result")
    if not isinstance(result, dict) or result.get("result_code") not in RNC_RESULT_CODES:
        raise ReportError("RNC private report has no valid result classification")
    structured = document.get("structured_evidence")
    if structured is not None:
        if not isinstance(structured, dict):
            raise ReportError("RNC structured_evidence is not an object")
        if structured.get("version") != STRUCTURED_EVIDENCE_VERSION:
            raise ReportError(
                f"RNC structured_evidence version is {structured.get('version')!r}, "
                f"expected {STRUCTURED_EVIDENCE_VERSION!r}"
            )
        if not isinstance(structured.get("components"), list):
            raise ReportError("RNC structured_evidence has no components list")
    history = document.get("history")
    units, source_kind = _unit_sources(document)
    source_adapter = execution.get("source_adapter")
    if not isinstance(source_adapter, dict):
        raise ReportError("RNC execution record has no source_adapter")
    if source_kind == GIT_SOURCE_KIND:
        if not isinstance(history, dict):
            raise ReportError("RNC history scan has no history metadata")
        if source_adapter.get("id") != HISTORY_SOURCE_ID:
            raise ReportError("RNC history report has the wrong execution source adapter")
    elif source_kind == WORKING_TREE_SOURCE_KIND:
        if source_adapter.get("id") != WORKING_TREE_SOURCE_ID:
            raise ReportError("RNC filesystem report has the wrong execution source adapter")
    elif units:
        raise ReportError("RNC private report has an unsupported source kind")
    for finding in document["findings"]:
        if not isinstance(finding, dict):
            raise ReportError("RNC finding is not an object")
    return document


def _structured_components(
    document: dict, units: dict[str, dict], finding_entries: list[dict]
) -> dict[str, dict]:
    structured = document.get("structured_evidence")
    if structured is None:
        return {}
    findings_by_id: dict[str, dict] = {}
    for index, entry in enumerate(finding_entries):
        finding_id = entry.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise ReportError(f"RNC finding {index} has no finding_id")
        if finding_id in findings_by_id:
            raise ReportError(f"RNC finding_id {finding_id!r} is duplicated")
        findings_by_id[finding_id] = entry
    components: dict[str, dict] = {}
    for index, component in enumerate(structured.get("components", [])):
        if not isinstance(component, dict):
            raise ReportError(f"RNC structured component {index} is not an object")
        finding_id = component.get("finding_id")
        unit_id = component.get("unit_id")
        kind = component.get("kind")
        if not isinstance(finding_id, str) or finding_id not in findings_by_id:
            raise ReportError(f"RNC structured component {index} has an unknown finding_id")
        if not isinstance(unit_id, str) or unit_id not in units:
            raise ReportError(f"RNC structured component {index} has an unknown unit_id")
        if kind != DATABASE_PASSWORD_KIND:
            raise ReportError(f"RNC structured component {index} has unsupported kind {kind!r}")
        parent = findings_by_id[finding_id]
        if parent.get("unit_id") != unit_id:
            raise ReportError(f"RNC structured component {index} is linked to the wrong unit")
        if parent.get("rule_id") != "database-connection-credential":
            raise ReportError(
                f"RNC structured component {index} is not attached to a database URI finding"
            )
        start, end = component.get("start_byte"), component.get("end_byte")
        parent_start, parent_end = parent.get("start_byte"), parent.get("end_byte")
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 0
            or end <= start
        ):
            raise ReportError(f"RNC structured component {index} has an invalid byte range")
        if (
            not isinstance(parent_start, int)
            or not isinstance(parent_end, int)
            or start < parent_start
            or end > parent_end
        ):
            raise ReportError(
                f"RNC structured component {index} is outside its parent finding's byte range"
            )
        line = component.get("line")
        line_end = component.get("line_end") or line
        parent_line = parent.get("line")
        parent_line_end = parent.get("line_end") or parent_line
        if (
            not isinstance(line, int)
            or isinstance(line, bool)
            or not isinstance(line_end, int)
            or isinstance(line_end, bool)
            or line < 1
            or line_end < line
            or not isinstance(parent_line, int)
            or line < parent_line
            or line_end > parent_line_end
        ):
            raise ReportError(
                f"RNC structured component {index} has inconsistent line attribution"
            )
        source_digest = _normalize_digest(
            component.get("source_sha256"), label="structured component source"
        )
        normalized_digest = _normalize_digest(
            component.get("normalized_sha256"), label="structured component normalized"
        )
        ansi = component.get("ansi")
        if ansi not in ANSI_VALUES:
            raise ReportError(f"RNC structured component {index} has an invalid ansi value")
        normalization = component.get("normalization")
        if normalization is not None and normalization != ANSI_NORMALIZATION:
            raise ReportError(
                f"RNC structured component {index} has unsupported normalization {normalization!r}"
            )
        if ansi == "NONE" and (normalization is not None or source_digest != normalized_digest):
            raise ReportError(
                f"RNC structured component {index} has inconsistent no-ANSI evidence"
            )
        if ansi != "NONE" and normalization != ANSI_NORMALIZATION:
            raise ReportError(
                f"RNC structured component {index} omits ansi-sgr-v1 normalization"
            )
        if finding_id in components:
            raise ReportError(
                f"RNC finding {finding_id!r} has multiple structured components; "
                "the database-password contract permits one component per finding"
            )
        components[finding_id] = {
            "kind": kind,
            "source_sha256": source_digest,
            "normalized_sha256": normalized_digest,
            "normalization": normalization,
            "ansi": ansi,
        }
    return components


class RNCAdapter(ScannerAdapter):
    key = "rnc"
    display_name = "RNC Scanner"
    default_repository = "https://github.com/RNC-Solutions-Group/rnc-security-audit"
    supported_suites = ("synthetic-filesystem", "levain", "leaky-repo", "rnclab")
    platforms = PLATFORM_CATALOG

    def __init__(self) -> None:
        super().__init__()
        self._rules_path: Path | None = None
        self._ruleset: dict | None = None
        self._active_ruleset: dict | None = None
        self._history_supported: bool | None = None

    def _detect_history_capability(self, source: SourceCheckout) -> bool:
        """Inspect the pinned CLI source rather than assuming every RNC commit has it."""
        cli = source.path / "crates/rnc-cli/src/main.rs"
        try:
            text = cli.read_text(encoding="utf-8")
        except OSError:
            return False
        return "--history" in text and "GitHistorySource" in text and "--ref" in text

    def _describe_rules(self, path: Path) -> dict:
        payload = Path(path)
        document = json.loads(payload.read_text(encoding="utf-8"))
        rules = document.get("rules")
        if not isinstance(rules, list) or not rules:
            raise ValueError(f"RNC rule bundle {payload.name!r} contains no rules")
        families = {
            str(rule.get("family"))
            for rule in rules
            if isinstance(rule, dict) and rule.get("family")
        }
        extractors = sorted(
            {
                str(rule.get("component_extractor"))
                for rule in rules
                if isinstance(rule, dict) and rule.get("component_extractor")
            }
        )
        return {
            "path": payload.as_posix(),
            "sha256": _sha256_file(payload),
            "ruleset_id": document.get("ruleset_id"),
            "ruleset_version": document.get("ruleset_version"),
            "schema_version": document.get("schema_version"),
            "rule_count": len(rules),
            "family_count": len(families),
            "component_extractors": extractors,
        }

    def _load_ruleset(self, source: SourceCheckout) -> dict:
        path = source.path / RULES_PATH
        if not path.is_file():
            raise FileNotFoundError(f"RNC source has no bundled rule bundle at {RULES_PATH}")
        described = self._describe_rules(path)
        described["path"] = RULES_PATH
        described["source"] = "bundled provider catalogue in the pinned source checkout"
        return described

    def default_configuration(self) -> dict:
        return {
            "mode": "bundled-provider-rules",
            "config_argument": "--rules",
            "rules_path": RULES_PATH,
            "rules_sha256": None,
            "rules_hash_recorded_after_build": True,
            "config_isolation": "empty repository configuration passed as --config to suppress target auto-discovery",
            "isolated_working_directory": True,
            "removed_environment": sorted(self.config_environment_keys()),
            "verifiable": True,
            "history_mode": {
                "argument": "--history",
                "ref_argument": "--ref",
                "ref": HISTORY_REF,
                "scope": HISTORY_SCOPE,
                "read_only": True,
                "runtime_dependency": "git executable in the native host or container image",
                "limitations": [
                    "History scope is the pinned HEAD's reachable history, selected with --ref HEAD.",
                    "Submodules, symlinks and other uninspected units are never treated as covered.",
                ],
            },
            "limitations": [
                "The rule bundle is read from the pinned source checkout and hashed after the source build.",
                "The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.",
                "Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed.",
            ],
        }

    def write_control_config(
        self, path: Path | str, pattern: str = "RNC_[A-Z0-9]{16}"
    ) -> Path:
        target = Path(path)
        if target.suffix != ".json":
            target = target.with_suffix(".json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(
                {
                    "schema_version": "0.1.0",
                    "ruleset_id": "rnc-harness-controlled-v1",
                    "ruleset_version": "1",
                    "rules": [
                        {
                            "rule_id": "rnc-harness-controlled-token",
                            "rule_version": "1",
                            "category": "synthetic-control",
                            "pattern": pattern,
                            "capture_group": 0,
                            "validators": ["ASCII_ONLY"],
                            "confidence": "high",
                            "max_match_bytes": 64,
                        }
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        return target

    def _dockerfile(self, output_dir: Path) -> Path:
        path = output_dir / "Dockerfile.rnc-scanner"
        path.write_text(
            "FROM rust:1.85-bookworm AS build\n"
            "WORKDIR /src\n"
            "COPY . .\n"
            "RUN cargo build --release --locked --bin rnc\n"
            "\n"
            "FROM debian:bookworm-slim\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git "
            "&& rm -rf /var/lib/apt/lists/*\n"
            "# The mounted repository is owned by the host user; Git history is read-only.\n"
            "RUN git config --system --add safe.directory '*'\n"
            "COPY --from=build /src/target/release/rnc /usr/local/bin/rnc\n"
            "ENTRYPOINT [\"rnc\"]\n",
            encoding="utf-8",
            newline="\n",
        )
        return path

    def _artifact(
        self,
        target: TargetPlatform,
        result: BuildResult,
        *,
        version: str | None,
        version_status: str,
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
            version_status=version_status,
            stdout_sha256=result.stdout_sha256,
            stderr_sha256=result.stderr_sha256,
            error=error if error is not None else result.error,
            metadata=metadata,
        )

    def _native_version(self, binary: Path) -> tuple[str | None, str]:
        try:
            result = subprocess.run(
                [str(binary), "--version"], capture_output=True, text=True, timeout=60
            )
        except (OSError, subprocess.TimeoutExpired):
            return None, statuses.NOT_RUN
        if result.returncode != 0:
            return None, statuses.FAIL
        match = re.search(r"\brnc\s+([^\s]+)", result.stdout)
        return (match.group(1), statuses.PASS) if match else (None, statuses.FAIL)

    def _native_ruleset_digest(self, binary: Path, rules: Path) -> str | None:
        try:
            result = subprocess.run(
                [
                    str(binary),
                    "rules",
                    "validate",
                    "--rules",
                    str(rules),
                    "--strategy",
                    "auto",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        match = re.search(r"^Digest:\s+(sha256:[0-9a-f]{64})$", result.stdout, re.MULTILINE)
        return match.group(1) if match else None

    def _docker_ruleset_digest(
        self, image: str, target: TargetPlatform, rules: Path
    ) -> str | None:
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
                    "--mount",
                    f"type=bind,source={rules},target=/rules.json,readonly",
                    "--entrypoint",
                    "rnc",
                    image,
                    "rules",
                    "validate",
                    "--rules",
                    "/rules.json",
                    "--strategy",
                    "auto",
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        match = re.search(r"^Digest:\s+(sha256:[0-9a-f]{64})$", result.stdout, re.MULTILINE)
        return match.group(1) if match else None

    def _docker_version(self, image: str, target: TargetPlatform) -> tuple[str | None, str]:
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
                    "--entrypoint",
                    "rnc",
                    image,
                    "--version",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None, statuses.NOT_RUN
        if result.returncode != 0:
            return None, statuses.FAIL
        match = re.search(r"\brnc\s+([^\s]+)", result.stdout)
        return (match.group(1), statuses.PASS) if match else (None, statuses.FAIL)

    def build(
        self,
        source: SourceCheckout,
        target: TargetPlatform,
        output_dir: Path | str,
    ) -> BuildArtifact:
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        self._ruleset = self._load_ruleset(source)
        self._rules_path = source.path / RULES_PATH
        self._history_supported = self._detect_history_capability(source)
        common_metadata = {
            "source_commit": source.commit,
            "source_repository": source.repository,
            "ruleset": self._ruleset,
            "history_capability": self._history_supported,
            "toolchain": toolchain_metadata(),
            "implementation": "rust",
        }
        if target.is_executable:
            if host_platform() != target:
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
                    error=f"{target.key} is not executable on this host",
                    metadata=common_metadata,
                )
            extension = ".exe" if target.os_name == "windows" else ""
            output_path = output_dir / f"rnc-{target.key}{extension}"
            result = build_cargo_executable(
                source,
                output_path,
                binary_name="rnc",
                timeout=2400.0,
            )
            version, version_status = (
                self._native_version(output_path)
                if result.status == statuses.PASS
                else (None, statuses.NOT_APPLICABLE)
            )
            if result.status == statuses.PASS:
                digest = self._native_ruleset_digest(output_path, self._rules_path)
                if digest:
                    self._ruleset["digest"] = digest
                    self._ruleset["digest_validation"] = "rnc rules validate --strategy auto"
                else:
                    self._ruleset["digest_validation"] = "FAIL"
            return self._artifact(
                target,
                result,
                version=version,
                version_status=version_status,
                metadata={
                    **common_metadata,
                    "goos": target.goos,
                    "goarch": target.goarch,
                    "execution_method": "native",
                    "build_tool": "cargo",
                },
            )

        safe_run = "".join(
            ch if ch.isalnum() or ch in "._-" else "-" for ch in self.run_id
        ).strip("-.").lower()
        tag = f"rnc-scanner-{safe_run}-{source.commit[:12]}-{target.key}"
        dockerfile = self._dockerfile(output_dir)
        result = build_docker_image(
            source,
            tag,
            platform=target.docker_platform or f"linux/{target.arch}",
            dockerfile=str(dockerfile),
            labels=self.docker_label_args(),
        )
        image_id, architecture = inspect_image(tag) if result.status == statuses.PASS else (None, None)
        expected = f"linux/{target.arch}"
        build_status = result.status
        error = result.error
        if result.status == statuses.PASS and architecture != expected:
            build_status = statuses.FAIL
            error = f"image architecture {architecture!r} does not match expected {expected!r}"
        version, version_status = (
            self._docker_version(tag, target)
            if build_status == statuses.PASS
            else (None, statuses.NOT_APPLICABLE)
        )
        if build_status == statuses.PASS:
            digest = self._docker_ruleset_digest(tag, target, self._rules_path)
            if digest:
                self._ruleset["digest"] = digest
                self._ruleset["digest_validation"] = "rnc rules validate --strategy auto"
            else:
                self._ruleset["digest_validation"] = "FAIL"
        return self._artifact(
            target,
            result,
            version=version,
            version_status=version_status,
            status=build_status,
            error=error,
            metadata={
                **common_metadata,
                "execution_method": "docker",
                "docker_build_strategy": "adapter-source-dockerfile",
                "dockerfile_sha256": _sha256_file(dockerfile),
                "image_os_architecture": architecture,
                "expected_os_architecture": expected,
                "architecture_verified": architecture == expected,
                "host_architecture": _host_arch(),
                "emulated": target.arch != _host_arch(),
            },
        )

    def supports_mode(self, mode: str) -> bool:
        if mode == "dir":
            return True
        if mode == "git":
            # Unknown before a build; the pinned CP4 source is verified during
            # build and an older source commit is reported unsupported.
            return self._history_supported is not False
        return False

    def _is_rule_bundle(self, path: Path) -> bool:
        if path.suffix.lower() != ".json":
            return False
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return isinstance(document, dict) and isinstance(document.get("rules"), list)

    def _isolation_config(self, report_path: Path) -> Path:
        path = report_path.parent / "rnc-isolation.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('schema_version = "0.2.0"\n', encoding="utf-8", newline="\n")
        return path

    def _rule_and_repo_config(
        self, config: Path | str | None, report_path: Path
    ) -> tuple[Path, Path]:
        if self._rules_path is None:
            raise ValueError("RNC adapter has no built source rule bundle")
        if config is None:
            rules = self._rules_path
            repo_config = self._isolation_config(report_path)
        else:
            candidate = Path(config).resolve()
            if self._is_rule_bundle(candidate):
                rules = candidate
                repo_config = self._isolation_config(report_path)
            else:
                rules = self._rules_path
                repo_config = candidate
        described = self._describe_rules(rules)
        if self._rules_path is not None and Path(rules).resolve() == self._rules_path.resolve():
            if self._ruleset and self._ruleset.get("digest"):
                described["digest"] = self._ruleset["digest"]
        self._active_ruleset = described
        return rules, repo_config

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
        if mode not in {"dir", "git"}:
            raise ValueError(f"RNC Scanner does not support mode {mode!r}")
        binary = Path(executable).resolve(strict=True)
        target = Path(target).resolve(strict=True)
        report_path = Path(report_path).resolve()
        try:
            report_path.relative_to(target)
        except ValueError:
            pass
        else:
            raise ValueError("RNC private report must be outside the scanned root")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        rules, repo_config = self._rule_and_repo_config(config, report_path)
        argv = [str(binary), "scan"]
        if mode == "git":
            if not self.supports_mode("git"):
                raise ValueError("this RNC Scanner source commit does not support --history")
            argv.extend(["--history", "--ref", HISTORY_REF])
        argv.extend(
            [
                "--root",
                str(target),
                "--rules",
                str(rules),
                "--config",
                str(repo_config),
                "--output",
                str(report_path),
                "--format",
                "private",
                "--run-id",
                str(self.run_id),
                *extra_args,
            ]
        )
        return run_process(
            argv,
            binary_path=str(binary),
            binary_sha256=sha256_file(binary),
            mode=mode,
            report_path=report_path,
            timeout_seconds=timeout_seconds,
            env=self.clean_environment(),
            unset_env=self.config_environment_keys(),
            cwd=cwd or report_path.parent,
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
        if mode not in {"dir", "git"}:
            raise ValueError(f"RNC Scanner does not support mode {mode!r}")
        out_dir = Path(out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        target = Path(target).resolve(strict=True)
        try:
            out_dir.relative_to(target)
        except ValueError:
            pass
        else:
            raise ValueError("RNC container output directory must be outside the scanned root")
        report_host = out_dir / "report.json"
        rules, repo_config = self._rule_and_repo_config(config, report_host)
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
            "--env",
            "HOME=/tmp",
            "--mount",
            f"type=bind,source={target},target=/scan,readonly",
            "--mount",
            f"type=bind,source={out_dir},target=/out",
            "--mount",
            f"type=bind,source={rules},target=/rules.json,readonly",
            "--mount",
            f"type=bind,source={repo_config},target=/config.toml,readonly",
            "--workdir",
            "/out",
            "--entrypoint",
            "rnc",
        ]
        for label in self.docker_label_args():
            argv.extend(["--label", label])
        argv.extend(["--name", self.container_name("docker")])
        argv.extend([image_tag, "scan"])
        if mode == "git":
            if not self.supports_mode("git"):
                raise ValueError("this RNC Scanner source commit does not support --history")
            argv.extend(["--history", "--ref", HISTORY_REF])
        argv.extend(
            [
                "--root",
                "/scan",
                "--rules",
                "/rules.json",
                "--config",
                "/config.toml",
                "--output",
                "/out/report.json",
                "--format",
                "private",
                "--run-id",
                str(self.run_id),
                *extra_args,
            ]
        )
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

    def _history_coverage(
        self,
        document: dict,
        invocation: Invocation,
        details: dict,
    ) -> dict:
        execution = document["execution"]
        result = document["result"]
        history = document.get("history") or {}
        counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
        notes: list[str] = details["notes"]
        failures: list[str] = []

        def require(ok: bool, message: str) -> None:
            if not ok:
                failures.append(message)

        require(result.get("result_code") in (1, 2, 3), "result code is not CLEAN/POLICY_APPLIED/ACTIONABLE")
        require(execution.get("state") == "COMPLETED", "execution state is not COMPLETED")
        require(result.get("coverage") == "COMPLETE", "coverage is not COMPLETE")
        require(result.get("evidence_valid") is True, "evidence_valid is not true")
        require(not execution.get("failure_codes"), "execution has failure codes")
        require(not execution.get("fatal_errors"), "execution has fatal errors")
        reason_codes = " ".join(str(item) for item in (result.get("reason_codes") or ()))
        require(
            not any(
                marker in reason_codes
                for marker in (
                    "TIMEOUT",
                    "MAX_FINDINGS",
                    "CANDIDATE",
                    "READ_ERROR",
                    "INTERRUPT",
                    "GIT_",
                    "REQUIRED_COVERAGE",
                )
            ),
            "result reason codes indicate incomplete or failed historical coverage",
        )
        ci = document.get("ci")
        require(
            isinstance(ci, dict) and ci.get("process_exit_code") == invocation.exit_code,
            "CI process exit does not match the observed process exit",
        )
        require(
            isinstance(ci, dict) and ci.get("result_code") == result.get("result_code"),
            "CI result code does not match the result record",
        )
        require(
            execution.get("source_adapter", {}).get("id") == HISTORY_SOURCE_ID,
            "execution source adapter is not local-git-history",
        )
        require(
            history.get("scope") == HISTORY_SCOPE,
            "history scope is not the selected HEAD scope",
        )
        require(
            history.get("refs") == [HISTORY_REF],
            "history refs are not exactly [HEAD]",
        )
        units = execution.get("units") or []
        require(
            history.get("units_seen") == len(units),
            "history units_seen does not match execution units",
        )
        require(
            isinstance(history.get("commits"), int) and history.get("commits") > 0,
            "history commit count is missing or zero",
        )
        unit_map: dict[str, str] = {}
        source_ids: set[str] = set()
        source_kinds = set()
        bad_locators: list[str] = []
        for unit in units:
            try:
                unit_id = unit["unit_id"]
                source_kind = unit["source_kind"]
                source_id = unit["source_id"]
                locator = _normalize_locator(unit["locator"])
                _parse_unit_source(unit_id, source_kind, locator)
                if not isinstance(source_id, str) or not source_id:
                    raise ReportError(f"history unit {unit_id} has no source_id")
                if unit.get("content_sha256") is not None:
                    _normalize_digest(unit.get("content_sha256"), label="history unit content")
                if not isinstance(unit.get("byte_length"), int) or unit.get("byte_length") < 0:
                    raise ReportError(f"history unit {unit_id} has no valid byte_length")
                if not isinstance(unit.get("line_count"), int) or unit.get("line_count") < 0:
                    raise ReportError(f"history unit {unit_id} has no valid line_count")
            except (KeyError, ReportError) as exc:
                bad_locators.append(str(exc))
                continue
            if unit_id in unit_map:
                bad_locators.append(f"duplicate unit {unit_id}")
            unit_map[unit_id] = locator
            source_ids.add(source_id)
            source_kinds.add(source_kind)
        require(not bad_locators, f"{len(bad_locators)} history units have invalid locators")
        require(source_kinds == {GIT_SOURCE_KIND}, "history contains a non-git source unit")
        require(len(source_ids) == 1, "history units do not share one source identity")
        require(
            counts.get("discovered") == len(units) == counts.get("inspected"),
            "discovered/inspected history counts do not reconcile to all units",
        )
        require(
            counts.get("required_discovered") == len(units)
            and counts.get("required_inspected") == len(units),
            "required history units do not equal all discovered units",
        )
        require(counts.get("uninspected") == 0, "history units remain uninspected")
        require(counts.get("required_uninspected") == 0, "required history units remain uninspected")
        require(counts.get("verified_blocked") == 0, "history units were verified blocked")
        require(counts.get("required_verified_blocked") == 0, "required history units were verified blocked")
        require(
            counts.get("required_discovered")
            == counts.get("required_inspected", 0)
            + counts.get("required_verified_blocked", 0)
            + counts.get("required_uninspected", 0),
            "required history unit counts do not reconcile",
        )

        active_ruleset = self._active_ruleset or self._ruleset
        if active_ruleset:
            require(
                result.get("ruleset_id") == active_ruleset.get("ruleset_id"),
                "result ruleset ID does not match the intended rule bundle",
            )
            require(
                execution.get("ruleset_id") == active_ruleset.get("ruleset_id"),
                "execution ruleset ID does not match the intended rule bundle",
            )
            require(
                result.get("ruleset_digest") == execution.get("ruleset_digest"),
                "result and execution ruleset digests disagree",
            )
            require(
                bool(result.get("ruleset_digest"))
                and str(result.get("ruleset_digest")).startswith("sha256:"),
                "ruleset digest is not a SHA-256 provenance value",
            )
            if active_ruleset.get("digest"):
                require(
                    result.get("ruleset_digest") == active_ruleset.get("digest"),
                    "scanner ruleset digest does not match the independently evaluated digest",
                )
        else:
            failures.append("adapter has no recorded intended ruleset")

        details.update(
            {
                "mode": "git",
                "history": {
                    "commits": history.get("commits"),
                    "changed_paths": history.get("changed_paths"),
                    "deleted_paths": history.get("deleted_paths"),
                    "units_seen": history.get("units_seen"),
                    "scope": history.get("scope"),
                    "refs": history.get("refs"),
                },
                "unit_count": len(units),
                "source_kinds": sorted(source_kinds),
                "source_ids": sorted(source_ids),
                "unit_locator_errors": bad_locators[:20],
                "counts": counts,
                "ruleset": {
                    "id": result.get("ruleset_id"),
                    "digest": result.get("ruleset_digest"),
                    "intended_id": (active_ruleset or {}).get("ruleset_id"),
                    "intended_digest": (active_ruleset or {}).get("digest"),
                },
            }
        )
        details["verified"] = not failures
        details["notes"] = (
            [
                f"RNC verified {len(units)} Git commit/path units INSPECTED; "
                f"{history.get('commits')} commits selected by --ref HEAD, unit counts reconcile, "
                "execution COMPLETED, and no required unit is blocked or uninspected."
            ]
            if not failures
            else failures
        )
        return details

    def execution_coverage(
        self,
        invocation: Invocation,
        target_dir: Path | str,
        expected_files: tuple[str, ...],
    ) -> dict:
        """Verify RNC's private execution/coverage records for complete inspection.

        A completed process or parseable JSON is not enough. Every generated
        source unit must be present, required, inspected, and content-addressed;
        the scanner's count invariants must reconcile; and the result must have
        finalized without operational failures under the intended ruleset.
        """
        details: dict = {
            "applicable": True,
            "verified": False,
            "expected_file_count": len(expected_files),
            "notes": [],
        }
        notes: list[str] = details["notes"]
        if invocation.report_bytes is None:
            notes.append("RNC private report is missing")
            return details
        try:
            document = _load_private(invocation.report_bytes)
        except ReportError as exc:
            notes.append(f"RNC private report is invalid: {exc}")
            return details
        units, source_kind = _unit_sources(document)
        details["mode"] = "git" if source_kind == GIT_SOURCE_KIND else "dir"
        details["source_kind"] = source_kind
        if source_kind == GIT_SOURCE_KIND:
            if expected_files:
                notes.append("filesystem expected-file coverage is not applicable to history")
                details["expected_file_count"] = 0
            return self._history_coverage(document, invocation, details)
        if source_kind != WORKING_TREE_SOURCE_KIND:
            notes.append("RNC execution has no supported filesystem source kind")
            return details
        execution = document["execution"]
        result = document["result"]
        counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
        details.update(
            {
                "result_code": result.get("result_code"),
                "result": result.get("result"),
                "coverage": result.get("coverage"),
                "execution_state": execution.get("state"),
                "evidence_valid": result.get("evidence_valid"),
                "failure_codes": execution.get("failure_codes"),
                "fatal_errors": execution.get("fatal_errors"),
                "reason_codes": result.get("reason_codes"),
                "counts": counts,
            }
        )
        failures: list[str] = []

        def require(ok: bool, message: str) -> None:
            if not ok:
                failures.append(message)

        require(result.get("result_code") in (1, 2, 3), "result code is not CLEAN/POLICY_APPLIED/ACTIONABLE")
        require(execution.get("state") == "COMPLETED", "execution state is not COMPLETED")
        require(result.get("coverage") == "COMPLETE", "coverage is not COMPLETE")
        require(result.get("evidence_valid") is True, "evidence_valid is not true")
        require(not execution.get("failure_codes"), "execution has failure codes")
        require(not execution.get("fatal_errors"), "execution has fatal errors")
        reason_codes = " ".join(str(item) for item in (result.get("reason_codes") or ()))
        require(
            not any(
                marker in reason_codes
                for marker in ("TIMEOUT", "MAX_FINDINGS", "CANDIDATE", "READ_ERROR", "INTERRUPT")
            ),
            "result reason codes indicate a timeout, limit, read error, or interruption",
        )
        ci = document.get("ci")
        require(
            isinstance(ci, dict) and ci.get("process_exit_code") == invocation.exit_code,
            "CI process exit does not match the observed process exit",
        )
        require(
            isinstance(ci, dict) and ci.get("result_code") == result.get("result_code"),
            "CI result code does not match the result record",
        )

        active_ruleset = self._active_ruleset or self._ruleset
        if active_ruleset:
            require(
                result.get("ruleset_id") == active_ruleset.get("ruleset_id"),
                "result ruleset ID does not match the intended rule bundle",
            )
            require(
                execution.get("ruleset_id") == active_ruleset.get("ruleset_id"),
                "execution ruleset ID does not match the intended rule bundle",
            )
            require(
                result.get("ruleset_digest") == execution.get("ruleset_digest"),
                "result and execution ruleset digests disagree",
            )
            require(
                bool(result.get("ruleset_digest"))
                and str(result.get("ruleset_digest")).startswith("sha256:"),
                "ruleset digest is not a SHA-256 provenance value",
            )
            evaluated = active_ruleset.get("digest")
            if evaluated:
                require(
                    result.get("ruleset_digest") == evaluated,
                    "scanner ruleset digest does not match the independently evaluated digest",
                )
            elif self._ruleset and active_ruleset.get("ruleset_id") == self._ruleset.get("ruleset_id"):
                failures.append("adapter has no independently evaluated ruleset digest")
        else:
            failures.append("adapter has no recorded intended ruleset")

        for key in (
            "discovered",
            "inspected",
            "required_discovered",
            "required_inspected",
            "required_verified_blocked",
            "required_uninspected",
            "uninspected",
            "verified_blocked",
        ):
            value = counts.get(key)
            require(isinstance(value, int) and not isinstance(value, bool) and value >= 0, f"count {key} is invalid")
        if all(isinstance(counts.get(key), int) for key in ("required_discovered", "required_inspected", "required_verified_blocked", "required_uninspected")):
            require(
                counts["required_discovered"]
                == counts["required_inspected"]
                + counts["required_verified_blocked"]
                + counts["required_uninspected"],
                "required unit counts do not reconcile",
            )
        require(counts.get("required_uninspected") == 0, "required units remain uninspected")
        require(counts.get("uninspected") == 0, "units remain uninspected")
        require(counts.get("required_verified_blocked") == 0, "required units were verified blocked")
        require(counts.get("verified_blocked") == 0, "units were verified blocked")

        expected = tuple(expected_files)
        expected_set = {Path(item).as_posix() for item in expected}
        unit_map: dict[str, dict] = {}
        duplicate_units: list[str] = []
        for unit in execution.get("units", []):
            locator = _normalize_locator(unit.get("locator"))
            if locator in unit_map:
                duplicate_units.append(locator)
            unit_map[locator] = unit
        require(not duplicate_units, "execution contains duplicate source units")
        missing = sorted(expected_set - set(unit_map))
        extra_required = sorted(
            locator
            for locator, unit in unit_map.items()
            if unit.get("required_scope") is True and locator not in expected_set
        )
        details["missing_files"] = missing
        details["unexpected_required_files"] = extra_required
        require(not missing, f"{len(missing)} expected source units are missing")
        require(not extra_required, f"{len(extra_required)} required source units were not generated by the harness")
        require(counts.get("required_discovered") == len(expected_set), "required discovered count does not match expected files")
        require(counts.get("discovered") == len(unit_map), "discovered count does not match execution units")
        require(
            counts.get("inspected") == sum(1 for unit in unit_map.values() if unit.get("disposition") == "INSPECTED"),
            "inspected count does not match INSPECTED dispositions",
        )
        require(
            counts.get("required_inspected") == len(expected_set),
            "required inspected count does not match expected files",
        )

        root = Path(target_dir).resolve()
        content_mismatches: list[str] = []
        byte_mismatches: list[str] = []
        not_inspected: list[str] = []
        for locator in sorted(expected_set):
            unit = unit_map.get(locator)
            if unit is None:
                continue
            if unit.get("disposition") != "INSPECTED" or unit.get("required_scope") is not True:
                not_inspected.append(locator)
                continue
            relative = Path(locator)
            if relative.is_absolute() or ".." in relative.parts:
                content_mismatches.append(locator)
                continue
            file_path = (root / relative).resolve()
            try:
                file_path.relative_to(root)
            except ValueError:
                content_mismatches.append(locator)
                continue
            if not file_path.is_file():
                content_mismatches.append(locator)
                continue
            digest = "sha256:" + hashlib.sha256(file_path.read_bytes()).hexdigest()
            if unit.get("content_sha256") != digest:
                content_mismatches.append(locator)
            if unit.get("byte_length") != file_path.stat().st_size:
                byte_mismatches.append(locator)
        details.update(
            {
                "not_inspected_files": not_inspected,
                "content_mismatch_files": content_mismatches,
                "byte_length_mismatch_files": byte_mismatches,
                "unit_count": len(unit_map),
                "ruleset": {
                    "id": result.get("ruleset_id"),
                    "digest": result.get("ruleset_digest"),
                    "intended_id": (active_ruleset or {}).get("ruleset_id"),
                    "intended_file_sha256": (active_ruleset or {}).get("sha256"),
                    "intended_digest": (active_ruleset or {}).get("digest"),
                },
            }
        )
        require(not not_inspected, f"{len(not_inspected)} expected units are not INSPECTED and required")
        require(not content_mismatches, f"{len(content_mismatches)} source-unit content digests do not match local files")
        require(not byte_mismatches, f"{len(byte_mismatches)} source-unit byte lengths do not match local files")
        details["verified"] = not failures
        if failures:
            details["notes"] = failures
        else:
            details["notes"] = [
                f"RNC verified {len(expected_set)} required source units INSPECTED; "
                "unit counts reconcile, content digests match, execution COMPLETED, "
                f"and the reported ruleset is {result.get('ruleset_id')}."
            ]
        return details

    def invocation_problem(self, invocation: Invocation) -> str | None:
        if invocation.error_code:
            return invocation.error_code
        if invocation.timed_out:
            return "TIMEOUT"
        if invocation.exit_code not in RNC_ACCEPTED_EXITS:
            return "INVOCATION_FAILED"
        if invocation.report_bytes is None:
            return "REPORT_MISSING"
        try:
            document = _load_private(invocation.report_bytes)
            # Full normalization catches malformed units, structured evidence
            # ownership, and source-identity errors before a suite sees findings.
            self.parse_findings(invocation.report_bytes)
        except (ReportError, ValueError):
            return "REPORT_INVALID"
        result_code = document["result"]["result_code"]
        if result_code == 4:
            return "INCOMPLETE"
        if result_code == 5:
            return "FAILED"
        if result_code == 3 and invocation.exit_code not in (0, 10):
            return "REPORT_INVALID"
        if result_code in (1, 2) and invocation.exit_code != 0:
            return "REPORT_INVALID"
        return None

    def partial_execution_evidence(self, invocation: Invocation) -> dict | None:
        """Accept only the lab's explicit SYMLINK_NOT_FOLLOWED caveat.

        RNC deliberately does not follow symlinks.  The certified lab includes
        11 symlink aliases whose targets are already represented by their real
        paths; the scanner still inspects every regular source unit.  The lab
        load workloads also include scanner-declared `TOTAL_BYTE_LIMIT`
        exclusions.  This method exposes those bounded conditions so the lab
        lane can score/measure inspected units while keeping every exclusion
        visible as an unsupported capability.  Any other incomplete condition
        is rejected.
        """
        if invocation.report_bytes is None:
            return None
        try:
            document = _load_private(invocation.report_bytes)
        except (ReportError, ValueError):
            return None
        result = document.get("result") or {}
        execution = document.get("execution") or {}
        if result.get("result_code") != 4 or execution.get("state") != "COMPLETED":
            return None
        if execution.get("evidence_valid") is not True:
            return None
        units = execution.get("units") or []
        uninspected = [
            unit for unit in units if unit.get("disposition") != "INSPECTED"
        ]
        if not uninspected:
            return None
        if any(unit.get("required_scope") is not True for unit in uninspected):
            return None
        allowed_reasons = {"SYMLINK_NOT_FOLLOWED", "TOTAL_BYTE_LIMIT"}
        if any(
            not set(unit.get("reason_codes") or []).issubset(allowed_reasons)
            or not set(unit.get("reason_codes") or [])
            for unit in uninspected
        ):
            return None
        if any(
            unit.get("disposition") != "UNINSPECTED" for unit in uninspected
        ):
            return None
        reasons = sorted(
            {
                reason
                for unit in uninspected
                for reason in (unit.get("reason_codes") or [])
            }
        )
        return {
            "accepted": True,
            "reason": ",".join(reasons),
            "unsupported_capability_count": len(uninspected),
            "inspected_units": len(units) - len(uninspected),
            "uninspected_units": [
                unit.get("locator") for unit in uninspected
            ],
            "policy": (
                "regular source units inspected; symlink aliases are not followed "
                "and scanner-declared byte-limit exclusions remain visible"
            ),
        }

    def parse_findings(self, data: bytes) -> list[NormalizedFinding]:
        document = _load_private(data)
        units, source_kind = _unit_sources(document)
        entries = document["findings"]
        components = _structured_components(document, units, entries)
        result = document.get("result") or {}
        execution = document.get("execution") or {}
        engine_version = result.get("engine_version")
        ruleset_id = result.get("ruleset_id")
        ruleset_digest = result.get("ruleset_digest")
        result_code = result.get("result_code")
        source_adapter = execution.get("source_adapter") or {}
        findings: list[NormalizedFinding] = []
        for index, entry in enumerate(entries):
            try:
                unit_id = entry["unit_id"]
                if unit_id not in units:
                    raise ReportError(f"RNC finding {index} references an unknown unit")
                unit = units[unit_id]
                finding_id = entry.get("finding_id")
                if not isinstance(finding_id, str) or not finding_id:
                    raise ReportError(f"RNC finding {index} has no finding_id")
                digest = _normalize_digest(entry.get("evidence_digest"))
                line = entry.get("line")
                line_end = entry.get("line_end")
                if not isinstance(line, int) or isinstance(line, bool) or line < 1:
                    raise ReportError(f"RNC finding {index} has an invalid line")
                if line_end is not None and (
                    not isinstance(line_end, int)
                    or isinstance(line_end, bool)
                    or line_end < line
                ):
                    raise ReportError(f"RNC finding {index} has an invalid line_end")
                start_byte, end_byte = entry.get("start_byte"), entry.get("end_byte")
                if (
                    not isinstance(start_byte, int)
                    or isinstance(start_byte, bool)
                    or not isinstance(end_byte, int)
                    or isinstance(end_byte, bool)
                    or start_byte < 0
                    or end_byte <= start_byte
                ):
                    raise ReportError(f"RNC finding {index} has an invalid byte range")
                rule_id = entry.get("rule_id")
                if not isinstance(rule_id, str) or not rule_id:
                    raise ReportError(f"RNC finding {index} has no rule_id")
                component = components.get(finding_id)
                if component:
                    # The password-specific normalized digest is the matching
                    # identity. The contextual userinfo digest remains available
                    # separately; no second finding is created.
                    match_digest = digest
                    secret_digest = component["normalized_sha256"]
                    structured_metadata = {
                        "present": True,
                        "kind": component["kind"],
                        "ansi": component["ansi"],
                        "normalization": component["normalization"],
                    }
                else:
                    match_digest = digest
                    secret_digest = digest
                    structured_metadata = {"present": False}
                metadata = {
                    "unit_id": unit_id,
                    "source_kind": unit["source_kind"],
                    "rule_version": entry.get("rule_version"),
                    "category": entry.get("category"),
                    "confidence": entry.get("confidence"),
                    "validation": entry.get("validation"),
                    "start_byte": start_byte,
                    "end_byte": end_byte,
                    "line_end": line_end,
                    "evidence_digest": digest,
                    "contextual_secret_sha256": digest,
                    "structured_evidence": structured_metadata,
                    "result_code": result_code,
                    "result": result.get("result"),
                    "coverage": result.get("coverage"),
                    "execution_state": execution.get("state"),
                    "execution_evidence_valid": execution.get("evidence_valid"),
                    "source_adapter": {
                        "id": source_adapter.get("id"),
                        "version": source_adapter.get("version"),
                    },
                    "ruleset_id": ruleset_id,
                    "ruleset_digest": ruleset_digest,
                    "engine_version": engine_version,
                }
                if source_kind == GIT_SOURCE_KIND:
                    metadata["history_scope"] = document.get("history", {}).get("scope")
                    metadata["history_commits"] = document.get("history", {}).get("commits")
                findings.append(
                    NormalizedFinding(
                        file=unit["file"],
                        line=line,
                        rule_id=rule_id,
                        commit=unit["commit"],
                        secret_sha256=secret_digest,
                        match_sha256=match_digest,
                        secret_redacted=True,
                        finding_id=finding_id,
                        target="rnc",
                        scanner="rnc",
                        scanner_version=engine_version,
                        metadata=metadata,
                    )
                )
            except (KeyError, TypeError, ValueError, ReportError) as exc:
                raise ReportError(f"RNC finding {index} is invalid: {exc}") from exc
        return findings
