"""Deterministic retained-report input selection for detection-gap analysis.

The analysis must never choose a report by filesystem modification time.  A
pinned input lock records the report path, SHA-256, registered build identity,
run ID, source-commit metadata, profile and scanner argument digest.  Explicit
report overrides remain available for investigation, but are labelled as
unpinned and still have their identity validated.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import HarnessError
from ..provenance import redact_argv
from ..util import atomic_write_text

INPUT_SCHEMA_VERSION = 1
DEFAULT_LOCK_RELATIVE = "reports/detection-gaps/analysis-inputs.json"
EXPECTED_BUILDS = {
    "cp4c": "rnc-cp4c",
    "v14": "gl-rnc-mod-v14",
    "v16": "gl-rnc-mod-v16",
    "gitleaks": "gitleaks-master",
    "betterleaks": "betterleaks-lts",
}
REPORT_GLOBS = {
    "cp4c": "run/reports/all-windows-baselines/rnc-cp4c/*.json",
    "v14": "run/reports/all-windows-baselines/gl-rnc-mod-v14/*.json",
    "v16": "run/reports/all-windows-baselines/gl-rnc-mod-v16/*full*.json",
    "gitleaks": "run/reports/all-windows-baselines/gitleaks-master/*.json",
    "betterleaks": "run/reports/all-windows-baselines/betterleaks-lts/*.json",
}


class InputSelectionError(HarnessError):
    """A report cannot be selected deterministically or fails identity checks."""


@dataclass(frozen=True)
class ReportSelection:
    key: str
    path: Path
    sha256: str
    source: str
    locked_sha256: str | None = None
    lock_path: str | None = None
    lock_sha256: str | None = None
    build_id: str | None = None
    source_commit: str | None = None
    run_id: str | None = None
    profile: str | None = None
    override: bool = False
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "path": _display(path=self.path),
            "sha256": self.sha256,
            "selection": self.source,
            "locked_sha256": self.locked_sha256,
            "lock_path": self.lock_path,
            "lock_sha256": self.lock_sha256,
            "build_id": self.build_id,
            "source_commit": self.source_commit,
            "run_id": self.run_id,
            "profile": self.profile,
            "override": self.override,
            "warnings": list(self.warnings),
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _display(*, path: Path) -> str:
    try:
        return path.resolve().relative_to(_repo_root()).as_posix()
    except (OSError, ValueError):
        return f"<external>/{path.name}"


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputSelectionError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise InputSelectionError(f"{label} {path} is not a JSON object")
    return document


def _report_identity(path: Path, key: str) -> dict[str, Any]:
    report = _load_json(path, "retained report")
    summary = report.get("summary") or {}
    build = report.get("registered_build") or {}
    profile = report.get("profile") or {}
    options = report.get("report_options") or {}
    raw_args = options.get("scanner_extra_args") or []
    redacted_args, _redactions = redact_argv(list(raw_args))
    build_id = str(build.get("id") or summary.get("build_id") or "")
    expected = EXPECTED_BUILDS.get(key)
    if expected and build_id != expected:
        raise InputSelectionError(
            f"{path} is build {build_id!r}, expected {expected!r} for scanner key {key!r}"
        )
    if report.get("report_type") != "rnc-scan-harness/experiment":
        raise InputSelectionError(
            f"{path} is not an rnc-scan-harness/experiment report"
        )
    return {
        "path": _display(path=path),
        "sha256": _sha256_file(path),
        "build_id": build_id,
        "scanner": build.get("scanner") or (report.get("scanner") or {}).get("key"),
        "source_commit": build.get("source_commit") or summary.get("source_commit"),
        "executable_sha256": build.get("executable_sha256"),
        "docker_image_id": build.get("docker_image_id"),
        "run_id": report.get("run_id"),
        "generated_at": report.get("generated_at"),
        "profile": profile.get("name"),
        "scanner_extra_args_sha256": options.get("scanner_extra_args_sha256"),
        "scanner_extra_args": redacted_args,
        "scanner_extra_args_redacted": bool(
            options.get("scanner_extra_args_redacted") or _redactions
        ),
    }


def _resolve_path(value: str, root: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def load_lock(path: Path | str | None = None, *, root: Path | None = None) -> tuple[Path, dict[str, Any], str]:
    root = root or _repo_root()
    target = Path(path).expanduser() if path is not None else root / DEFAULT_LOCK_RELATIVE
    if not target.is_file():
        raise InputSelectionError(
            f"analysis input lock not found: {target}. Detection-gap analysis no "
            "longer selects the newest report by modification time. Generate or "
            "provide a pinned lock, or pass explicit report paths."
        )
    document = _load_json(target, "analysis input lock")
    if document.get("schema_version") != INPUT_SCHEMA_VERSION:
        raise InputSelectionError(
            f"unsupported analysis input lock schema_version "
            f"{document.get('schema_version')!r}; expected {INPUT_SCHEMA_VERSION}"
        )
    if not isinstance(document.get("reports"), dict):
        raise InputSelectionError("analysis input lock has no reports object")
    return target.resolve(), document, _sha256_file(target)


def build_lock(
    report_paths: dict[str, Path | str],
    *,
    root: Path | None = None,
    harness_version: str | None = None,
    harness_source_commit: str | None = None,
    scoring_epoch: str = "current-scoring-20261115",
    dataset_paths: dict[str, Path | str] | None = None,
) -> dict[str, Any]:
    root = root or _repo_root()
    reports: dict[str, Any] = {}
    for key, value in report_paths.items():
        path = _resolve_path(str(value), root)
        if not path.is_file():
            raise InputSelectionError(f"report not found for {key}: {path}")
        identity = _report_identity(path, key)
        try:
            identity["path"] = path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            identity["path"] = str(path.resolve())
        reports[key] = identity
    dataset_identifiers: dict[str, Any] = {}
    paths = {
        "rnclab_lab": root / "datasets" / "cache" / "rnc-synth-lab" / "lab.toml",
        "rnclab_groups": root / "datasets" / "cache" / "rnc-synth-lab" / "groups.json",
        "rnclab_oracle": root / "datasets" / "cache" / "rnc-synth-lab" / "oracle" / "oracle.jsonl",
        "leaky_truth": root / "datasets" / "leaky-repo.rnc-truth.json",
        "leaky_history_oracle": root / "datasets" / "leaky-repo.history-oracle.json",
        "levain_manifest": root / "datasets" / "manifest.toml",
    }
    for name, value in (dataset_paths or {}).items():
        paths[name] = _resolve_path(str(value), root)
    for name, path in paths.items():
        if path.is_file():
            dataset_identifiers[name] = {
                "path": _display(path=path),
                "sha256": _sha256_file(path),
            }
    return {
        "schema_version": INPUT_SCHEMA_VERSION,
        "scoring_epoch": scoring_epoch,
        "harness_version": harness_version,
        "harness_source_commit": harness_source_commit,
        "datasets": dataset_identifiers,
        "reports": reports,
        "selection_policy": (
            "Exact path and SHA-256. No modification-time selection. Explicit "
            "overrides are labelled and identity-checked but are not treated as locked."
        ),
    }


def write_lock(path: Path | str, document: dict[str, Any]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(
        target,
        json.dumps(document, indent=2, sort_keys=True) + "\n",
    )
    return target


def select_report(
    key: str,
    *,
    explicit: str | Path | None = None,
    lock_path: Path | str | None = None,
    root: Path | None = None,
) -> ReportSelection:
    root = root or _repo_root()
    if explicit is not None:
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            path = root / path
        if not path.is_file():
            raise InputSelectionError(f"report not found: {path}")
        identity = _report_identity(path, key)
        return ReportSelection(
            key=key,
            path=path,
            sha256=identity["sha256"],
            source="explicit-override",
            build_id=identity.get("build_id"),
            source_commit=identity.get("source_commit"),
            run_id=identity.get("run_id"),
            profile=identity.get("profile"),
            override=True,
            warnings=("explicit override is not pinned by the analysis input lock",),
        )
    lock_target, lock_document, lock_sha = load_lock(lock_path, root=root)
    entry = (lock_document.get("reports") or {}).get(key)
    if not isinstance(entry, dict):
        raise InputSelectionError(
            f"analysis input lock {lock_target} has no entry for scanner key {key!r}"
        )
    path = _resolve_path(str(entry.get("path") or ""), root)
    if not path.is_file():
        raise InputSelectionError(f"locked report for {key} is missing: {path}")
    actual = _sha256_file(path)
    expected = str(entry.get("sha256") or "")
    if not expected or actual != expected:
        raise InputSelectionError(
            f"locked report SHA-256 mismatch for {key}: "
            f"lock={expected or '<missing>'} actual={actual} path={path}"
        )
    identity = _report_identity(path, key)
    expected_build = entry.get("build_id")
    if expected_build and identity.get("build_id") != expected_build:
        raise InputSelectionError(
            f"locked report {path} build id changed: "
            f"lock={expected_build!r} actual={identity.get('build_id')!r}"
        )
    if entry.get("source_commit") and identity.get("source_commit") != entry.get("source_commit"):
        raise InputSelectionError(
            f"locked report {path} source commit changed: "
            f"lock={entry.get('source_commit')!r} actual={identity.get('source_commit')!r}"
        )
    return ReportSelection(
        key=key,
        path=path,
        sha256=actual,
        source="pinned-lock",
        locked_sha256=expected,
        lock_path=_display(path=lock_target),
        lock_sha256=lock_sha,
        build_id=identity.get("build_id"),
        source_commit=identity.get("source_commit"),
        run_id=identity.get("run_id"),
        profile=identity.get("profile"),
    )


__all__ = [
    "DEFAULT_LOCK_RELATIVE",
    "EXPECTED_BUILDS",
    "INPUT_SCHEMA_VERSION",
    "InputSelectionError",
    "ReportSelection",
    "build_lock",
    "load_lock",
    "select_report",
    "write_lock",
]
