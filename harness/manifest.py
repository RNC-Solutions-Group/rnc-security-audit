"""Dataset manifest parsing and validation.

The manifest is TOML so Python 3.11+ can read it with the standard library.
It records provenance only; corpus bytes live in an ignored cache.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .errors import ManifestError
from .util import is_commit_sha, is_sha256, sha256_file

DEFAULT_MANIFEST = Path(__file__).resolve().parents[1] / "datasets" / "manifest.toml"


@dataclass(frozen=True)
class ExpectedCounts:
    negative_sections: int
    negative_lines: int
    negative_secrets: int
    negative_personal_data: int
    positive_sections: int
    positive_lines: int
    positive_secrets: int
    positive_hard_sections: int
    positive_hard_secrets: int
    positive_personal_data: int


@dataclass(frozen=True)
class DatasetSpec:
    key: str
    name: str
    source_repository: str
    author_reference: str
    license: str
    license_url: str
    license_sha256: str
    revision: str
    revision_tag: str
    revision_date: str
    enabled: bool
    status: str
    counting_unit: str
    license_notice: str
    expected: ExpectedCounts
    artifact_sha256: dict[str, str]
    derived_sha256: dict[str, str]


@dataclass(frozen=True)
class LeakyRepoSpec:
    key: str
    name: str
    source_repository: str
    author_reference: str
    license: str
    license_url: str
    license_sha256: str
    revision: str
    revision_tag: str
    revision_date: str
    enabled: bool
    status: str
    counting_unit: str
    license_notice: str
    inventory_path: Path
    inventory_sha256: str
    truth_manifest_path: Path
    truth_manifest_sha256: str
    truth_manifest_version: str
    expected_count: int
    expected_risk: int
    expected_informative: int
    expected_files: int
    history_scope_path: Path | None = None
    history_scope_sha256: str | None = None
    history_scope_version: str | None = None
    history_oracle_path: Path | None = None
    history_oracle_sha256: str | None = None
    history_oracle_version: str | None = None


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    datasets: dict[str, object]
    leaky_repo: LeakyRepoSpec | None
    path: Path


def _require(table: dict, key: str, kind: type, where: str):
    if key not in table:
        raise ManifestError(f"{where}: missing required field {key!r}")
    value = table[key]
    if not isinstance(value, kind):
        raise ManifestError(f"{where}: field {key!r} must be {kind.__name__}")
    return value


def _counts(table: dict, where: str) -> ExpectedCounts:
    fields = {name: _require(table, name, int, where) for name in ExpectedCounts.__dataclass_fields__}
    for name, value in fields.items():
        if value < 0:
            raise ManifestError(f"{where}: {name} must not be negative")
    return ExpectedCounts(**fields)


def _hash_table(table: object, where: str) -> dict[str, str]:
    if not isinstance(table, dict) or not table:
        raise ManifestError(f"{where} must be a non-empty table")
    result: dict[str, str] = {}
    for name, value in table.items():
        if not isinstance(name, str) or not name:
            raise ManifestError(f"{where}: artifact names must be non-empty strings")
        if not is_sha256(value):
            raise ManifestError(f"{where}: {name!r} must be a lowercase sha256")
        result[name] = value
    return result


def _dataset(key: str, table: object, where: str) -> DatasetSpec:
    if not isinstance(table, dict):
        raise ManifestError(f"{where} must be a table")
    revision = _require(table, "revision", str, where)
    if not is_commit_sha(revision):
        raise ManifestError(f"{where}: revision must be a full 40-character commit SHA")
    license_sha = _require(table, "license_sha256", str, where)
    if not is_sha256(license_sha):
        raise ManifestError(f"{where}: license_sha256 must be a lowercase sha256")
    expected = _counts(_require(table, "expected", dict, where), where + ".expected")
    artifacts = _hash_table(_require(table, "artifact_sha256", dict, where), where + ".artifact_sha256")
    derived = _hash_table(_require(table, "derived_sha256", dict, where), where + ".derived_sha256")
    if "LICENSE" not in artifacts:
        raise ManifestError(f"{where}: artifact_sha256 must include LICENSE")
    return DatasetSpec(
        key=key,
        name=_require(table, "name", str, where),
        source_repository=_require(table, "source_repository", str, where),
        author_reference=_require(table, "author_reference", str, where),
        license=_require(table, "license", str, where),
        license_url=_require(table, "license_url", str, where),
        license_sha256=license_sha,
        revision=revision,
        revision_tag=_require(table, "revision_tag", str, where),
        revision_date=_require(table, "revision_date", str, where),
        enabled=_require(table, "enabled", bool, where),
        status=_require(table, "status", str, where),
        counting_unit=_require(table, "counting_unit", str, where),
        license_notice=_require(table, "license_notice", str, where),
        expected=expected,
        artifact_sha256=artifacts,
        derived_sha256=derived,
    )


def _leaky_repo(table: object, where: str) -> LeakyRepoSpec:
    if not isinstance(table, dict):
        raise ManifestError(f"{where} must be a table")
    revision = _require(table, "revision", str, where)
    if not is_commit_sha(revision):
        raise ManifestError(f"{where}: revision must be a full 40-character commit SHA")
    license_sha = _require(table, "license_sha256", str, where)
    if not is_sha256(license_sha):
        raise ManifestError(f"{where}: license_sha256 must be a lowercase sha256")
    inventory_sha = _require(table, "inventory_sha256", str, where)
    if not is_sha256(inventory_sha):
        raise ManifestError(f"{where}: inventory_sha256 must be a lowercase sha256")
    inventory_value = _require(table, "inventory_path", str, where)
    inventory_path = (DEFAULT_MANIFEST.parents[1] / inventory_value).resolve()
    truth_value = _require(table, "truth_manifest_path", str, where)
    truth_path = (DEFAULT_MANIFEST.parents[1] / truth_value).resolve()
    truth_sha = _require(table, "truth_manifest_sha256", str, where)
    if not is_sha256(truth_sha):
        raise ManifestError(f"{where}: truth_manifest_sha256 must be a lowercase sha256")
    truth_version = _require(table, "truth_manifest_version", str, where)
    history_value = table.get("history_scope_path")
    history_path = (
        (DEFAULT_MANIFEST.parents[1] / history_value).resolve()
        if isinstance(history_value, str) and history_value
        else None
    )
    history_sha = table.get("history_scope_sha256")
    if history_sha is not None and not is_sha256(str(history_sha)):
        raise ManifestError(f"{where}: history_scope_sha256 must be a lowercase sha256")
    history_version = table.get("history_scope_version")
    oracle_value = table.get("history_oracle_path")
    oracle_path = (
        (DEFAULT_MANIFEST.parents[1] / oracle_value).resolve()
        if isinstance(oracle_value, str) and oracle_value
        else None
    )
    oracle_sha = table.get("history_oracle_sha256")
    if oracle_sha is not None and not is_sha256(str(oracle_sha)):
        raise ManifestError(f"{where}: history_oracle_sha256 must be a lowercase sha256")
    oracle_version = table.get("history_oracle_version")
    expected_count = _require(table, "expected_count", int, where)
    expected_risk = _require(table, "expected_risk", int, where)
    expected_informative = _require(table, "expected_informative", int, where)
    expected_files = _require(table, "expected_files", int, where)
    for name, value in (
        ("expected_count", expected_count),
        ("expected_risk", expected_risk),
        ("expected_informative", expected_informative),
        ("expected_files", expected_files),
    ):
        if value < 0:
            raise ManifestError(f"{where}: {name} must not be negative")
    if expected_risk + expected_informative != expected_count:
        raise ManifestError(f"{where}: risk + informative must equal expected_count")
    return LeakyRepoSpec(
        key="leaky_repo",
        name=_require(table, "name", str, where),
        source_repository=_require(table, "source_repository", str, where),
        author_reference=_require(table, "author_reference", str, where),
        license=_require(table, "license", str, where),
        license_url=_require(table, "license_url", str, where),
        license_sha256=license_sha,
        revision=revision,
        revision_tag=_require(table, "revision_tag", str, where),
        revision_date=_require(table, "revision_date", str, where),
        enabled=_require(table, "enabled", bool, where),
        status=_require(table, "status", str, where),
        counting_unit=_require(table, "counting_unit", str, where),
        license_notice=_require(table, "license_notice", str, where),
        inventory_path=inventory_path,
        inventory_sha256=inventory_sha,
        truth_manifest_path=truth_path,
        truth_manifest_sha256=truth_sha,
        truth_manifest_version=truth_version,
        history_scope_path=history_path,
        history_scope_sha256=str(history_sha) if history_sha else None,
        history_scope_version=str(history_version) if history_version else None,
        history_oracle_path=oracle_path,
        history_oracle_sha256=str(oracle_sha) if oracle_sha else None,
        history_oracle_version=str(oracle_version) if oracle_version else None,
        expected_count=expected_count,
        expected_risk=expected_risk,
        expected_informative=expected_informative,
        expected_files=expected_files,
    )


def load_manifest(path: Path | str | None = DEFAULT_MANIFEST) -> Manifest:
    path = Path(path) if path is not None else DEFAULT_MANIFEST
    if not path.is_file():
        raise ManifestError(f"dataset manifest not found: {path}")
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"cannot read dataset manifest {path}: {exc}") from exc

    version = _require(data, "schema_version", int, str(path))
    if version != 1:
        raise ManifestError(f"{path}: unsupported schema_version {version}")
    datasets_table = _require(data, "datasets", dict, str(path))
    if "levain" not in datasets_table:
        raise ManifestError(f"{path}: no levain dataset entry")
    datasets: dict[str, object] = {}
    datasets["levain"] = _dataset(
        "levain", datasets_table["levain"], f"{path}:datasets.levain"
    )
    leaky_repo = None
    if "leaky_repo" in datasets_table:
        leaky_repo = _leaky_repo(
            datasets_table["leaky_repo"], f"{path}:datasets.leaky_repo"
        )
        datasets["leaky_repo"] = leaky_repo
    levain = datasets["levain"]
    assert isinstance(levain, DatasetSpec)
    if not levain.enabled:
        raise ManifestError(f"{path}: levain dataset is disabled")
    if levain.status != "PINNED_AND_VERIFIED":
        raise ManifestError(f"{path}: levain status is {levain.status!r}, not PINNED_AND_VERIFIED")
    if levain.license != "MIT":
        raise ManifestError(f"{path}: expected MIT license, found {levain.license!r}")
    if leaky_repo is not None:
        if not leaky_repo.enabled:
            raise ManifestError(f"{path}: leaky_repo dataset is disabled")
        if leaky_repo.status != "PINNED_AND_VERIFIED":
            raise ManifestError(
                f"{path}: leaky_repo status is {leaky_repo.status!r}, not PINNED_AND_VERIFIED"
            )
        if leaky_repo.license != "MIT":
            raise ManifestError(
                f"{path}: expected MIT license for leaky_repo, found {leaky_repo.license!r}"
            )
        if not leaky_repo.inventory_path.is_file():
            raise ManifestError(
                f"{path}: leaky_repo inventory is missing: {leaky_repo.inventory_path}"
            )
        if not is_sha256(sha256_file(leaky_repo.inventory_path)) or sha256_file(
            leaky_repo.inventory_path
        ) != leaky_repo.inventory_sha256:
            raise ManifestError(f"{path}: leaky_repo inventory hash does not match the manifest")
        if not leaky_repo.truth_manifest_path.is_file():
            raise ManifestError(
                f"{path}: leaky_repo truth manifest is missing: {leaky_repo.truth_manifest_path}"
            )
        if sha256_file(leaky_repo.truth_manifest_path) != leaky_repo.truth_manifest_sha256:
            raise ManifestError(f"{path}: leaky_repo truth manifest hash does not match the manifest")
        if leaky_repo.history_scope_path is not None:
            if not leaky_repo.history_scope_path.is_file():
                raise ManifestError(
                    f"{path}: leaky_repo history scope is missing: {leaky_repo.history_scope_path}"
                )
            if sha256_file(leaky_repo.history_scope_path) != leaky_repo.history_scope_sha256:
                raise ManifestError(f"{path}: leaky_repo history scope hash does not match the manifest")
        if leaky_repo.history_oracle_path is not None:
            if not leaky_repo.history_oracle_path.is_file():
                raise ManifestError(
                    f"{path}: leaky_repo history oracle is missing: {leaky_repo.history_oracle_path}"
                )
            if sha256_file(leaky_repo.history_oracle_path) != leaky_repo.history_oracle_sha256:
                raise ManifestError(f"{path}: leaky_repo history oracle hash does not match the manifest")
    return Manifest(
        schema_version=version,
        datasets=datasets,
        leaky_repo=leaky_repo,
        path=path.resolve(),
    )


def load_levain(path: Path | str | None = DEFAULT_MANIFEST) -> tuple[Manifest, DatasetSpec]:
    manifest = load_manifest(path)
    spec = manifest.datasets["levain"]
    assert isinstance(spec, DatasetSpec)
    return manifest, spec


def load_leaky_repo(path: Path | str | None = DEFAULT_MANIFEST) -> tuple[Manifest, LeakyRepoSpec]:
    manifest = load_manifest(path)
    if manifest.leaky_repo is None:
        raise ManifestError(f"{manifest.path}: no leaky_repo dataset entry")
    return manifest, manifest.leaky_repo
