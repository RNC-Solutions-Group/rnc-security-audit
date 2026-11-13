"""Operator-provided scanner artifact registry.

The harness no longer acquires scanner source or builds products.  The operator
places executables and/or retains Docker images locally, records their exact
identity in ``run/manifest.toml``, and the harness verifies that identity before
executing any benchmark.

This module owns only manifest parsing and local-artifact verification.  Scanner
adapters own scanner-specific interpretation (for example, RNC rulesets).
"""

from __future__ import annotations

import hashlib
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import status as statuses
from .errors import HarnessError
from .util import is_commit_sha, is_sha256, sha256_file

ROOT = Path(__file__).resolve().parents[1]
RUN_DIR = ROOT / "run"
DEFAULT_MANIFEST = RUN_DIR / "manifest.toml"
SCHEMA_VERSION = 1
_BUILD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


class ArtifactManifestError(HarnessError):
    """The local artifact manifest is missing, malformed, or inconsistent."""


@dataclass(frozen=True)
class RegisteredBuild:
    """One operator-registered scanner build from ``run/manifest.toml``."""

    id: str
    scanner: str
    source_commit: str
    version: str | None
    source_repository: str | None
    executable: str | None
    executable_sha256: str | None
    docker_image: str | None
    docker_image_id: str | None
    rules_file: str | None
    rules_sha256: str | None
    capabilities: tuple[str, ...]
    run_dir: Path
    manifest_path: Path
    manifest_sha256: str

    @property
    def executable_path(self) -> Path | None:
        return self.run_dir / self.executable if self.executable else None

    @property
    def rules_path(self) -> Path | None:
        return self.run_dir / self.rules_file if self.rules_file else None

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scanner": self.scanner,
            "source_commit": self.source_commit,
            "version": self.version,
            "source_repository": self.source_repository,
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "docker_image": self.docker_image,
            "docker_image_id": self.docker_image_id,
            "rules_file": self.rules_file,
            "rules_sha256": self.rules_sha256,
            "capabilities": list(self.capabilities),
            "manifest": {
                "path": _relative_manifest(self.manifest_path),
                "sha256": self.manifest_sha256,
                "schema_version": SCHEMA_VERSION,
            },
        }


@dataclass(frozen=True)
class ArtifactManifest:
    """A parsed, syntactically validated local artifact registry."""

    path: Path
    run_dir: Path
    sha256: str
    builds: tuple[RegisteredBuild, ...]

    def select(self, build_id: str | None) -> RegisteredBuild:
        if build_id is None:
            if len(self.builds) == 1:
                return self.builds[0]
            raise ArtifactManifestError(
                "--build is required when the local manifest registers "
                f"{len(self.builds)} builds; choose one of: "
                + ", ".join(item.id for item in self.builds)
            )
        for item in self.builds:
            if item.id == build_id:
                return item
        raise ArtifactManifestError(
            f"build {build_id!r} is not registered in {_relative_manifest(self.path)}; "
            "available: " + ", ".join(item.id for item in self.builds)
        )

    def to_dict(self) -> dict:
        return {
            "path": _relative_manifest(self.path),
            "sha256": self.sha256,
            "schema_version": SCHEMA_VERSION,
            "builds": [item.to_dict() for item in self.builds],
        }


@dataclass(frozen=True)
class VerifiedArtifact:
    """Result of verifying one registered build for one target platform."""

    build: RegisteredBuild
    status: str
    error: str | None
    executable_path: Path | None = None
    executable_sha256: str | None = None
    image_id: str | None = None
    image_architecture: str | None = None
    rules_path: Path | None = None
    rules_sha256: str | None = None
    details: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == statuses.PASS

    def identity(self, target) -> dict:
        """Return report-safe identity fields shared by every scanner."""
        metadata = {
            "artifact_origin": "operator-provided-local-artifact",
            "build_id": self.build.id,
            "scanner": self.build.scanner,
            "version": self.build.version,
            "source_commit": self.build.source_commit,
            "source_repository": self.build.source_repository,
            "source_identity": "manifest-metadata",
            "source_commit_verified": False,
            "source_verification_note": (
                "Source commit is operator-supplied metadata. No scanner source "
                "was cloned, checked out, or compiled by the harness."
            ),
            "capabilities": list(self.build.capabilities),
            "manifest": {
                "path": _relative_manifest(self.build.manifest_path),
                "sha256": self.build.manifest_sha256,
                "schema_version": SCHEMA_VERSION,
            },
            "execution_method": "docker" if target.is_docker else "native",
            "platform": target.key,
            "host_architecture": _host_arch(),
            "emulated": target.is_docker and target.arch != _host_arch(),
        }
        if self.executable_path is not None:
            metadata.update(
                {
                    "executable": self.build.executable,
                    "executable_sha256": self.executable_sha256,
                    "executable_sha256_expected": self.build.executable_sha256,
                    "executable_hash_verified": bool(
                        self.executable_sha256
                        and self.executable_sha256 == self.build.executable_sha256
                    ),
                }
            )
        if self.build.docker_image is not None:
            metadata.update(
                {
                    "docker_image": self.build.docker_image,
                    "docker_image_id": self.image_id,
                    "docker_image_id_expected": self.build.docker_image_id,
                    "docker_image_id_verified": bool(
                        self.image_id
                        and self.build.docker_image_id
                        and self.image_id == self.build.docker_image_id
                    ),
                    "image_os_architecture": self.image_architecture,
                    "architecture_verified": bool(
                        self.image_architecture == f"linux/{target.arch}"
                    ),
                    "pull_policy": "never",
                }
            )
        if self.build.rules_file is not None:
            metadata.update(
                {
                    "rules_file": self.build.rules_file,
                    "rules_sha256": self.rules_sha256,
                    "rules_sha256_expected": self.build.rules_sha256,
                    "rules_hash_verified": bool(
                        self.rules_sha256
                        and self.rules_sha256 == self.build.rules_sha256
                    ),
                }
            )
        return metadata


def _relative_manifest(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _host_arch() -> str:
    value = platform.machine().lower()
    return "amd64" if value in ("x86_64", "amd64") else value


def _string(
    table: dict,
    key: str,
    *,
    required: bool = False,
    where: str = "builds",
) -> str | None:
    value = table.get(key)
    if value is None:
        if required:
            raise ArtifactManifestError(f"{where}.{key} is required")
        return None
    if not isinstance(value, str) or not value.strip():
        raise ArtifactManifestError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def _relative_file(
    table: dict,
    key: str,
    *,
    run_dir: Path,
    where: str,
) -> str | None:
    value = _string(table, key, where=where)
    if value is None:
        return None
    candidate = Path(value)
    if candidate.is_absolute() or value.startswith(("/", "\\")):
        raise ArtifactManifestError(f"{where}.{key} must be relative to {run_dir}")
    resolved = (run_dir / candidate).resolve()
    try:
        resolved.relative_to(run_dir.resolve())
    except ValueError as exc:
        raise ArtifactManifestError(
            f"{where}.{key} escapes the local run directory: {value!r}"
        ) from exc
    return candidate.as_posix()


def _optional_sha256(table: dict, key: str, *, where: str) -> str | None:
    value = _string(table, key, where=where)
    if value is None:
        return None
    normalized = value.lower()
    if not is_sha256(normalized):
        raise ArtifactManifestError(
            f"{where}.{key} must be a lowercase 64-character SHA-256"
        )
    return normalized


def _parse_build(
    table: dict,
    *,
    run_dir: Path,
    manifest_path: Path,
    manifest_sha256: str,
    index: int,
) -> RegisteredBuild:
    where = f"builds[{index}]"
    if not isinstance(table, dict):
        raise ArtifactManifestError(f"{where} must be a TOML table")
    build_id = _string(table, "id", required=True, where=where)
    assert build_id is not None
    if not _BUILD_ID.fullmatch(build_id):
        raise ArtifactManifestError(
            f"{where}.id must match [A-Za-z0-9][A-Za-z0-9._-]*"
        )
    scanner = _string(table, "scanner", required=True, where=where)
    assert scanner is not None
    from .adapters import adapter_keys

    if scanner not in adapter_keys():
        raise ArtifactManifestError(
            f"{where}.scanner {scanner!r} is unknown; available: "
            + ", ".join(adapter_keys())
        )
    source_commit = _string(table, "source_commit", required=True, where=where)
    assert source_commit is not None
    source_commit = source_commit.lower()
    if not is_commit_sha(source_commit):
        raise ArtifactManifestError(
            f"{where}.source_commit must be a full 40-character hexadecimal SHA"
        )
    version = _string(table, "version", where=where)
    source_repository = _string(table, "source_repository", where=where)
    executable = _relative_file(table, "executable", run_dir=run_dir, where=where)
    executable_sha256 = _optional_sha256(table, "executable_sha256", where=where)
    docker_image = _string(table, "docker_image", where=where)
    docker_image_id = _string(table, "docker_image_id", where=where)
    if docker_image_id is not None:
        docker_image_id = docker_image_id.lower()
        if not _IMAGE_ID.fullmatch(docker_image_id):
            raise ArtifactManifestError(
                f"{where}.docker_image_id must be sha256:<64 lowercase hex>"
            )
    rules_file = _relative_file(table, "rules_file", run_dir=run_dir, where=where)
    rules_sha256 = _optional_sha256(table, "rules_sha256", where=where)

    if (executable is None) != (executable_sha256 is None):
        raise ArtifactManifestError(
            f"{where}.executable and {where}.executable_sha256 must be provided together"
        )
    if (docker_image is None) != (docker_image_id is None):
        raise ArtifactManifestError(
            f"{where}.docker_image and {where}.docker_image_id must be provided together"
        )
    if (rules_file is None) != (rules_sha256 is None):
        raise ArtifactManifestError(
            f"{where}.rules_file and {where}.rules_sha256 must be provided together"
        )
    if executable is None and docker_image is None:
        raise ArtifactManifestError(
            f"{where} must declare an executable, a Docker image, or both"
        )

    raw_capabilities = table.get("capabilities")
    if raw_capabilities is None:
        capabilities = (
            ("filesystem", "git-history")
            if scanner in ("gitleaks", "betterleaks")
            else ("filesystem",)
        )
    else:
        if (
            not isinstance(raw_capabilities, list)
            or not raw_capabilities
            or not all(
                isinstance(item, str) and item.strip() for item in raw_capabilities
            )
        ):
            raise ArtifactManifestError(
                f"{where}.capabilities must be a non-empty array of strings"
            )
        capabilities = tuple(dict.fromkeys(item.strip() for item in raw_capabilities))

    return RegisteredBuild(
        id=build_id,
        scanner=scanner,
        source_commit=source_commit,
        version=version,
        source_repository=source_repository,
        executable=executable,
        executable_sha256=executable_sha256,
        docker_image=docker_image,
        docker_image_id=docker_image_id,
        rules_file=rules_file,
        rules_sha256=rules_sha256,
        capabilities=capabilities,
        run_dir=run_dir,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
    )


def load_manifest(path: Path | str | None = None) -> ArtifactManifest:
    """Load and syntactically validate the local operator artifact manifest."""
    target = Path(path).expanduser() if path is not None else DEFAULT_MANIFEST
    if not target.is_file():
        raise ArtifactManifestError(
            f"local artifact manifest not found: {target}. Copy "
            "run-manifest.example.toml to run/manifest.toml, place the operator "
            "executables/rules under run/, and record their exact SHA-256 values."
        )
    try:
        payload = target.read_bytes()
        data = tomllib.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ArtifactManifestError(
            f"cannot read local artifact manifest {target}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ArtifactManifestError("local artifact manifest must be a TOML table")
    version = data.get("schema_version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise ArtifactManifestError(
            f"unsupported local artifact manifest schema_version {version!r}"
        )
    builds_table = data.get("builds")
    if not isinstance(builds_table, list) or not builds_table:
        raise ArtifactManifestError(
            "local artifact manifest must contain at least one [[builds]] entry"
        )
    digest = hashlib.sha256(payload).hexdigest()
    run_dir = target.resolve().parent
    builds = tuple(
        _parse_build(
            item,
            run_dir=run_dir,
            manifest_path=target.resolve(),
            manifest_sha256=digest,
            index=index,
        )
        for index, item in enumerate(builds_table)
    )
    seen: set[str] = set()
    for item in builds:
        if item.id in seen:
            raise ArtifactManifestError(f"duplicate build id {item.id!r}")
        seen.add(item.id)
    return ArtifactManifest(
        path=target.resolve(),
        run_dir=run_dir,
        sha256=digest,
        builds=builds,
    )


def _docker_inspect(tag: str) -> tuple[str | None, str | None, str | None]:
    if shutil.which("docker") is None:
        return None, None, "Docker CLI is unavailable"
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
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, None, f"Docker image inspection failed: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        return (
            None,
            None,
            f"Docker image {tag!r} is not present in the local image store "
            "(no pull was attempted)"
            + (f": {detail[0][:240]}" if detail else ""),
        )
    image_id, _, architecture = result.stdout.strip().partition("|")
    if not image_id:
        return None, None, f"Docker image inspection returned no image ID for {tag!r}"
    return image_id, architecture or None, None


def verify_artifact(
    build: RegisteredBuild,
    target,
) -> VerifiedArtifact:
    """Verify one registered build for one target without substituting anything."""
    if target.is_executable:
        if not build.executable or not build.executable_sha256:
            return VerifiedArtifact(
                build=build,
                status=statuses.BLOCKED,
                error=(
                    f"build {build.id!r} does not register an executable; "
                    f"cannot satisfy platform {target.key!r}"
                ),
                details={"artifact_kind": "executable"},
            )
        path = build.executable_path
        assert path is not None
        if not path.is_file():
            return VerifiedArtifact(
                build=build,
                status=statuses.BLOCKED,
                error=f"registered executable is missing: {build.executable}",
                executable_path=path,
                details={"artifact_kind": "executable"},
            )
        try:
            actual = sha256_file(path)
        except OSError as exc:
            return VerifiedArtifact(
                build=build,
                status=statuses.BLOCKED,
                error=f"cannot hash registered executable {build.executable}: {exc}",
                executable_path=path,
                details={"artifact_kind": "executable"},
            )
        if actual != build.executable_sha256:
            return VerifiedArtifact(
                build=build,
                status=statuses.BLOCKED,
                error=(
                    f"executable SHA-256 mismatch for {build.executable}: "
                    f"manifest={build.executable_sha256} actual={actual}"
                ),
                executable_path=path,
                executable_sha256=actual,
                details={
                    "artifact_kind": "executable",
                    "executable_sha256_expected": build.executable_sha256,
                    "executable_sha256_actual": actual,
                },
            )
        details = {
            "artifact_kind": "executable",
            "executable_sha256_expected": build.executable_sha256,
            "executable_sha256_actual": actual,
        }
        rules_path, rules_sha256, rules_error = _verify_rules(build)
        if rules_error:
            return VerifiedArtifact(
                build=build,
                status=statuses.BLOCKED,
                error=rules_error,
                executable_path=path,
                executable_sha256=actual,
                rules_path=rules_path,
                rules_sha256=rules_sha256,
                details=details,
            )
        details["rules_sha256_actual"] = rules_sha256
        return VerifiedArtifact(
            build=build,
            status=statuses.PASS,
            error=None,
            executable_path=path,
            executable_sha256=actual,
            rules_path=rules_path,
            rules_sha256=rules_sha256,
            details=details,
        )

    if not build.docker_image or not build.docker_image_id:
        return VerifiedArtifact(
            build=build,
            status=statuses.BLOCKED,
            error=(
                f"build {build.id!r} does not register a Docker image; "
                f"cannot satisfy platform {target.key!r}"
            ),
            details={"artifact_kind": "docker"},
        )
    image_id, architecture, error = _docker_inspect(build.docker_image)
    details = {
        "artifact_kind": "docker",
        "docker_image_id_expected": build.docker_image_id,
        "docker_image_id_actual": image_id,
        "image_os_architecture": architecture,
        "expected_os_architecture": f"linux/{target.arch}",
        "pull_policy": "never",
    }
    if error:
        return VerifiedArtifact(
            build=build,
            status=statuses.BLOCKED,
            error=error,
            image_id=image_id,
            image_architecture=architecture,
            details=details,
        )
    assert image_id is not None
    if image_id != build.docker_image_id:
        return VerifiedArtifact(
            build=build,
            status=statuses.BLOCKED,
            error=(
                f"Docker image ID mismatch for {build.docker_image}: "
                f"manifest={build.docker_image_id} actual={image_id}"
            ),
            image_id=image_id,
            image_architecture=architecture,
            details=details,
        )
    if architecture != f"linux/{target.arch}":
        return VerifiedArtifact(
            build=build,
            status=statuses.BLOCKED,
            error=(
                f"Docker image architecture {architecture!r} for "
                f"{build.docker_image} does not match required "
                f"{f'linux/{target.arch}'!r}"
            ),
            image_id=image_id,
            image_architecture=architecture,
            details=details,
        )
    rules_path, rules_sha256, rules_error = _verify_rules(build)
    if rules_error:
        return VerifiedArtifact(
            build=build,
            status=statuses.BLOCKED,
            error=rules_error,
            image_id=image_id,
            image_architecture=architecture,
            rules_path=rules_path,
            rules_sha256=rules_sha256,
            details=details,
        )
    details["rules_sha256_actual"] = rules_sha256
    return VerifiedArtifact(
        build=build,
        status=statuses.PASS,
        error=None,
        image_id=image_id,
        image_architecture=architecture,
        rules_path=rules_path,
        rules_sha256=rules_sha256,
        details=details,
    )


def _verify_rules(build: RegisteredBuild) -> tuple[Path | None, str | None, str | None]:
    if not build.rules_file or not build.rules_sha256:
        return None, None, None
    path = build.rules_path
    assert path is not None
    if not path.is_file():
        return path, None, f"registered rules/configuration file is missing: {build.rules_file}"
    try:
        actual = sha256_file(path)
    except OSError as exc:
        return path, None, f"cannot hash registered rules file {build.rules_file}: {exc}"
    if actual != build.rules_sha256:
        return (
            path,
            actual,
            f"rules/configuration SHA-256 mismatch for {build.rules_file}: "
            f"manifest={build.rules_sha256} actual={actual}",
        )
    return path, actual, None


def toolchain_metadata() -> dict:
    """Record host tool availability for provenance.

    No scanner is built by the harness; these values are informational and
    deliberately tolerate missing compilers and Docker.
    """

    commands = {
        "docker": ["docker", "version", "--format", "{{.Server.Version}}"],
        "git": ["git", "--version"],
        "python": [sys.executable, "--version"],
    }
    tools: dict[str, str | None] = {}
    for key, argv in commands.items():
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            tools[key] = result.stdout.strip() or result.stderr.strip() or None
        except (OSError, subprocess.TimeoutExpired):
            tools[key] = None
    return tools


__all__ = [
    "ArtifactManifest",
    "ArtifactManifestError",
    "DEFAULT_MANIFEST",
    "RegisteredBuild",
    "RUN_DIR",
    "SCHEMA_VERSION",
    "VerifiedArtifact",
    "load_manifest",
    "toolchain_metadata",
    "verify_artifact",
]
