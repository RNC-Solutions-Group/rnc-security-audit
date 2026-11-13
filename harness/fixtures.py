"""Pinned external Gitleaks fixture acquisition and integrity verification.

The fixture checkout is a pinned reference source tree, separate from the target
branch under evaluation. It is cached in a Git-ignored, revision-addressed
directory and verified against the legacy Docker inventory lock before use.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .docker.inventory_lock import build_inventory_lock, canonical_digest, verify_inventory_lock
from .errors import DatasetError
from .util import sha256_file, utc_stamp

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SPEC = ROOT / "datasets" / "gitleaks-fixtures.toml"
DEFAULT_CACHE = ROOT / "datasets" / "cache"
DOCKER_DIR = ROOT / "harness" / "docker"


@dataclass(frozen=True)
class FixtureSpec:
    name: str
    source_repository: str
    revision: str
    license: str
    license_url: str
    license_sha256: str
    manifest_path: Path
    manifest_sha256: str
    inventory_lock_path: Path
    inventory_lock_sha256: str
    inventory_digest: str
    manifest_digest: str
    expected: dict[str, int]


@dataclass(frozen=True)
class PreparedFixtures:
    spec: FixtureSpec
    root: Path
    manifest: dict
    lock: dict
    docker_dir: Path

    @property
    def revision(self) -> str:
        return self.spec.revision


def load_spec(path: Path | str = DEFAULT_SPEC) -> FixtureSpec:
    path = Path(path)
    if not path.is_file():
        raise DatasetError(f"fixture manifest not found: {path}")
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise DatasetError(f"cannot read fixture manifest {path}: {exc}") from exc
    dataset = document.get("dataset")
    expected = document.get("expected")
    if not isinstance(dataset, dict) or not isinstance(expected, dict):
        raise DatasetError("fixture manifest must contain dataset and expected tables")
    revision = dataset.get("source_revision")
    if not isinstance(revision, str) or len(revision) != 40:
        raise DatasetError("fixture source_revision must be a full 40-character SHA")
    return FixtureSpec(
        name=str(dataset.get("name")),
        source_repository=str(dataset.get("source_repository")),
        revision=revision,
        license=str(dataset.get("license")),
        license_url=str(dataset.get("license_url")),
        license_sha256=str(dataset.get("license_sha256")),
        manifest_path=ROOT / str(dataset.get("manifest_path")),
        manifest_sha256=str(dataset.get("manifest_sha256")),
        inventory_lock_path=ROOT / str(dataset.get("inventory_lock_path")),
        inventory_lock_sha256=str(dataset.get("inventory_lock_sha256")),
        inventory_digest=str(dataset.get("inventory_digest")),
        manifest_digest=str(dataset.get("manifest_digest")),
        expected={key: int(value) for key, value in expected.items()},
    )


def _git(args: list[str], cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DatasetError(f"git {' '.join(args[:2])} failed: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise DatasetError(
            f"git {' '.join(args[:2])} failed (exit {result.returncode}): "
            f"{detail[0][:300] if detail else 'no diagnostic'}"
        )
    return result


def _quarantine(root: Path) -> None:
    stamp = utc_stamp()
    for child in sorted(root.iterdir()):
        target = child.with_name(f"{child.name}.corrupt-{stamp}")
        counter = 1
        while target.exists():
            counter += 1
            target = child.with_name(f"{child.name}.corrupt-{stamp}-{counter}")
        last_error = None
        for attempt in range(6):
            try:
                child.rename(target)
                break
            except PermissionError as exc:
                last_error = exc
                time.sleep(0.2 * (attempt + 1))
        else:
            raise DatasetError(f"could not quarantine fixture cache entry {child}: {last_error}")
    return


def _ensure_source(spec: FixtureSpec, root: Path, *, offline: bool, refresh: bool) -> Path:
    source = root / "source"
    if refresh and root.exists():
        _quarantine(root)
    root.mkdir(parents=True, exist_ok=True)
    if source.exists() and not (source / ".git").is_dir():
        if offline:
            raise DatasetError(f"fixture cache is not a Git checkout: {source}")
        _quarantine(root)
        shutil.rmtree(source, ignore_errors=True)
    if not source.exists():
        if offline:
            raise DatasetError(f"fixture cache is not prepared at {source}; run prepare online once")
        _git(["clone", "--quiet", spec.source_repository, str(source)])
        if os.name == "nt":
            _git(["-C", str(source), "config", "core.autocrlf", "true"])
            _git(["-C", str(source), "config", "core.symlinks", "false"])
        else:
            _git(["-C", str(source), "config", "core.autocrlf", "false"])
            _git(["-C", str(source), "config", "core.symlinks", "true"])
        _git(["-C", str(source), "checkout", "--force", "--", "."])
        _git(["-C", str(source), "checkout", "--quiet", "--detach", spec.revision])
        _git(["-C", str(source), "checkout", "--force", "--", "."])
    else:
        head = _git(["-C", str(source), "rev-parse", "HEAD"]).stdout.decode().strip()
        if head != spec.revision:
            if offline:
                raise DatasetError(
                    f"fixture cache is at {head[:12]}, not pinned {spec.revision[:12]} (offline)"
                )
            _git(["-C", str(source), "fetch", "--quiet", "origin"])
            _git(["-C", str(source), "checkout", "--quiet", "--detach", spec.revision])
    head = _git(["-C", str(source), "rev-parse", "HEAD"]).stdout.decode().strip()
    if head != spec.revision:
        raise DatasetError(f"fixture cache HEAD is {head}, expected {spec.revision}")
    if _git(["-C", str(source), "status", "--porcelain"], timeout=60).stdout.strip():
        raise DatasetError("fixture checkout working tree is modified; refusing to use it")
    return source


def prepare(
    spec_path: Path | str = DEFAULT_SPEC,
    cache_dir: Path | str = DEFAULT_CACHE,
    *,
    offline: bool = False,
    refresh: bool = False,
) -> PreparedFixtures:
    spec = load_spec(spec_path)
    root = (Path(cache_dir) / "gitleaks-fixtures" / spec.revision).resolve()
    source = _ensure_source(spec, root, offline=offline, refresh=refresh)

    license_bytes = _git(["-C", str(source), "show", f"{spec.revision}:LICENSE"]).stdout
    if hashlib.sha256(license_bytes).hexdigest() != spec.license_sha256:
        raise DatasetError("pinned fixture LICENSE does not match the manifest hash")
    if not (source / "testdata").is_dir():
        raise DatasetError("pinned fixture checkout has no testdata/ tree")

    for path, expected_hash, label in (
        (spec.manifest_path, spec.manifest_sha256, "fixture manifest"),
        (spec.inventory_lock_path, spec.inventory_lock_sha256, "fixture inventory lock"),
    ):
        if not path.is_file() or sha256_file(path) != expected_hash:
            raise DatasetError(f"{label} is missing or does not match the pinned hash: {path}")
    manifest = json.loads(spec.manifest_path.read_text(encoding="utf-8"))
    lock = json.loads(spec.inventory_lock_path.read_text(encoding="utf-8"))
    if lock.get("fixture_source_revision") != spec.revision:
        raise DatasetError("fixture inventory lock revision does not match the manifest pin")
    if lock.get("inventory_digest") != spec.inventory_digest:
        raise DatasetError("fixture inventory lock digest does not match the manifest pin")

    expected_lock = build_inventory_lock(
        manifest,
        copy.deepcopy(lock.get("entries", [])),
        source,
        DOCKER_DIR,
        spec.revision,
        canonical_digest(manifest),
    )
    errors = verify_inventory_lock(lock, expected_lock)
    if errors:
        raise DatasetError("fixture inventory verification failed: " + "; ".join(errors[:6]))
    if expected_lock.get("inventory_digest") != spec.inventory_digest:
        raise DatasetError("computed fixture inventory digest differs from the pinned digest")
    if expected_lock.get("manifest_digest") != spec.manifest_digest:
        raise DatasetError("computed fixture manifest digest differs from the pinned digest")

    prepared = PreparedFixtures(
        spec=spec,
        root=source,
        manifest=manifest,
        lock=lock,
        docker_dir=DOCKER_DIR,
    )
    _check_expected(prepared)
    return prepared


def _check_expected(prepared: PreparedFixtures) -> None:
    actual = summary(prepared)
    checks = {
        "scenarios": actual["scenarios"],
        "docker_applicable_fixtures": actual["docker_applicable_fixtures"],
        "inventory_entries": actual["entries"],
        "physical_entries": actual["physical_entries"],
        "symlinks": actual["symlinks"],
    }
    for key, value in checks.items():
        expected = prepared.spec.expected.get(key)
        if expected is not None and value != expected:
            raise DatasetError(
                f"fixture inventory count mismatch for {key}: found {value}, pinned {expected}"
            )


def summary(prepared: PreparedFixtures) -> dict:
    entries = prepared.lock.get("entries", [])
    assertable = [entry for entry in entries if entry.get("classification") == "ASSERTABLE"]
    physical = [entry for entry in entries if entry.get("fixture_type") != "scenario-bundle"]
    return {
        "name": prepared.spec.name,
        "revision": prepared.revision,
        "root": str(prepared.root),
        "license": prepared.spec.license,
        "manifest_sha256": prepared.spec.manifest_sha256,
        "inventory_lock_sha256": prepared.spec.inventory_lock_sha256,
        "inventory_digest": prepared.spec.inventory_digest,
        "entries": len(entries),
        "scenarios": len(prepared.manifest.get("cases", [])),
        "docker_applicable_fixtures": len(
            [entry for entry in assertable if entry.get("fixture_type") != "scenario-bundle"]
        ),
        "physical_entries": len(physical),
        "symlinks": sum(1 for entry in physical if entry.get("git_mode") == "120000"),
    }
