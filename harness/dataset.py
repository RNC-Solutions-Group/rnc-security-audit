"""Pinned dataset preparation, verification, caching, and corpus loading.

Network access is confined to `prepare` and never occurs while a benchmark is
running. Every artifact is checked against a canonical Git-blob SHA-256 so a
Windows CRLF checkout and a Linux LF checkout verify identically.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import DatasetError
from .manifest import DatasetSpec, Manifest, load_levain
from .model import ExpectedSecret, Section
from .util import (
    atomic_write_bytes,
    sha256_bytes,
    sha256_file,
    slugify,
    utc_stamp,
)

DEFAULT_CACHE = Path(__file__).resolve().parents[1] / "datasets" / "cache"
_GIT_TIMEOUT = 300


@dataclass(frozen=True)
class PreparedDataset:
    manifest: Manifest
    spec: DatasetSpec
    manifest_sha256: str
    root: Path
    source: Path
    derived: Path
    artifact_hashes: dict[str, str]
    derived_hashes: dict[str, str]

    def read_blob(self, relative: str) -> bytes:
        data = _git_bytes(
            self.source,
            ["cat-file", "blob", f"{self.spec.revision}:{relative}"],
            what=f"dataset artifact {relative}",
        )
        wanted = self.spec.artifact_sha256.get(relative)
        if wanted is not None and sha256_bytes(data) != wanted:
            raise DatasetError(f"dataset artifact {relative} no longer matches the pinned hash")
        return data

    def read_derived(self, name: str) -> bytes:
        path = self.derived / name
        if not path.is_file():
            raise DatasetError(f"derived dataset artifact is missing: {path}")
        data = path.read_bytes()
        wanted = self.spec.derived_sha256[name]
        got = sha256_bytes(data)
        if got != wanted:
            raise DatasetError(
                f"derived dataset artifact is corrupted: {name} sha256={got}, expected {wanted}"
            )
        return data


@dataclass(frozen=True)
class CorpusBundle:
    negative: tuple[Section, ...]
    positive: tuple[Section, ...]
    negative_counts: dict[str, int]
    positive_counts: dict[str, int]


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _run_git(args: list[str], what: str) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            timeout=_GIT_TIMEOUT,
            env=_git_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DatasetError(f"{what} failed: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        summary = detail[0][:300] if detail else "no diagnostic"
        raise DatasetError(f"{what} failed (exit {result.returncode}): {summary}")
    return result


def _git_bytes(source: Path, args: list[str], what: str) -> bytes:
    return _run_git(["git", "-C", str(source), *args], what).stdout


def _git_text(source: Path, args: list[str], what: str) -> str:
    return _run_git(["git", "-C", str(source), *args], what).stdout.decode("utf-8", "replace").strip()


def _quarantine(root: Path) -> Path:
    """Preserve a corrupt cache for inspection without deleting it.

    Windows can refuse to rename the revision directory itself while allowing
    its children to move, so quarantine the children individually and leave the
    (now empty) revision directory in place.
    """
    stamp = utc_stamp()
    for child in sorted(root.iterdir()):
        candidate = child.with_name(f"{child.name}.corrupt-{stamp}")
        counter = 1
        while candidate.exists():
            counter += 1
            candidate = child.with_name(f"{child.name}.corrupt-{stamp}-{counter}")
        last_error: OSError | None = None
        for attempt in range(6):
            try:
                child.rename(candidate)
                break
            except PermissionError as exc:  # antivirus/indexer can briefly hold a fresh clone
                last_error = exc
                time.sleep(0.2 * (attempt + 1))
        else:
            raise DatasetError(
                f"could not quarantine corrupt cache entry {child}: {last_error}; "
                "close any process using it and retry"
            )
    return root


def _checkout(source: Path, revision: str) -> None:
    _run_git(
        ["git", "-C", str(source), "-c", "core.autocrlf=false", "checkout", "--quiet", "--detach", revision],
        f"checkout of pinned revision {revision[:12]}",
    )


def _ensure_source(
    spec: DatasetSpec,
    root: Path,
    source: Path,
    *,
    offline: bool,
    refresh: bool,
) -> None:
    if refresh and root.exists():
        _quarantine(root)
    root.mkdir(parents=True, exist_ok=True)

    if source.exists() and not (source / ".git").is_dir():
        if offline:
            raise DatasetError(f"cached dataset is not a Git checkout: {source} (offline mode)")
        _quarantine(root)
        root.mkdir(parents=True, exist_ok=True)

    if not source.exists():
        if offline:
            raise DatasetError(
                f"dataset cache is not prepared at {source}; run `prepare` once online first"
            )
        _run_git(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.eol=lf",
                "clone",
                "--quiet",
                spec.source_repository,
                str(source),
            ],
            f"clone of {spec.source_repository}",
        )
        # A clone follows the publisher's default branch, which may have advanced
        # past the pinned commit. Always detach at the immutable revision.
        _checkout(source, spec.revision)
    else:
        head = _git_text(source, ["rev-parse", "HEAD"], "read cached dataset HEAD")
        has_commit = True
        try:
            _run_git(
                ["git", "-C", str(source), "cat-file", "-e", f"{spec.revision}^{{commit}}"],
                "check pinned dataset commit",
            )
        except DatasetError:
            has_commit = False
        if not has_commit or head != spec.revision:
            if offline:
                raise DatasetError(
                    f"cached dataset is at {head[:12]}, not pinned {spec.revision[:12]} (offline mode)"
                )
            if not has_commit:
                _run_git(
                    ["git", "-C", str(source), "fetch", "--quiet", "--tags", "origin"],
                    "fetch pinned dataset revision",
                )
            _checkout(source, spec.revision)

    head = _git_text(source, ["rev-parse", "HEAD"], "verify pinned dataset revision")
    if head != spec.revision:
        raise DatasetError(f"dataset HEAD is {head}, expected pinned {spec.revision}")
    if _git_text(source, ["status", "--porcelain"], "check cached dataset cleanliness"):
        if offline:
            raise DatasetError("cached dataset working tree is modified (offline mode)")
        _quarantine(root)
        root.mkdir(parents=True, exist_ok=True)
        _run_git(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-c",
                "core.eol=lf",
                "clone",
                "--quiet",
                spec.source_repository,
                str(source),
            ],
            f"re-clone of {spec.source_repository}",
        )
        _checkout(source, spec.revision)
        if _git_text(source, ["status", "--porcelain"], "re-check cached dataset cleanliness"):
            raise DatasetError("fresh dataset checkout is unexpectedly modified")


def _verify_artifacts(spec: DatasetSpec, source: Path) -> dict[str, str]:
    verified: dict[str, str] = {}
    for relative, wanted in sorted(spec.artifact_sha256.items()):
        data = _git_bytes(
            source,
            ["cat-file", "blob", f"{spec.revision}:{relative}"],
            f"read dataset artifact {relative}",
        )
        got = sha256_bytes(data)
        if got != wanted:
            raise DatasetError(
                f"dataset artifact verification failed for {relative}: sha256={got}, expected {wanted}"
            )
        verified[relative] = got

    license_bytes = _git_bytes(
        source,
        ["cat-file", "blob", f"{spec.revision}:LICENSE"],
        "read dataset license",
    )
    if sha256_bytes(license_bytes) != spec.license_sha256:
        raise DatasetError("dataset license hash does not match the pinned manifest")
    if b"MIT License" not in license_bytes or b"Permission is hereby granted" not in license_bytes:
        raise DatasetError("dataset LICENSE does not contain the expected MIT text")
    return verified


def _derive_artifacts(
    spec: DatasetSpec,
    source: Path,
    derived_dir: Path,
) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for relative in spec.artifact_sha256:
        if relative.endswith(".b64") and relative[:-4] in spec.derived_sha256:
            pairs[relative] = relative[:-4]
    if set(pairs.values()) != set(spec.derived_sha256):
        raise DatasetError("derived artifact mapping in the manifest is incomplete")

    derived_dir.mkdir(parents=True, exist_ok=True)
    verified: dict[str, str] = {}
    for relative, name in sorted(pairs.items()):
        source_bytes = _git_bytes(
            source,
            ["cat-file", "blob", f"{spec.revision}:{relative}"],
            f"read encoded dataset artifact {relative}",
        )
        try:
            decoded = base64.b64decode(source_bytes, validate=False)
        except ValueError as exc:
            raise DatasetError(f"cannot decode {relative}: {exc}") from exc
        wanted = spec.derived_sha256[name]
        got = sha256_bytes(decoded)
        if got != wanted:
            raise DatasetError(
                f"decoded dataset artifact verification failed for {name}: sha256={got}, expected {wanted}"
            )
        destination = derived_dir / name
        if not destination.is_file() or sha256_file(destination) != wanted:
            atomic_write_bytes(destination, decoded)
        if sha256_file(destination) != wanted:
            raise DatasetError(f"could not write a verified derived artifact: {destination}")
        verified[name] = got
    return verified


def prepare(
    manifest_path: Path | str | None = None,
    cache_dir: Path | str = DEFAULT_CACHE,
    *,
    offline: bool = False,
    refresh: bool = False,
) -> PreparedDataset:
    """Fetch (unless offline), verify, and cache the pinned Levain revision."""
    manifest, spec = load_levain(manifest_path) if manifest_path else load_levain()
    cache_dir = Path(cache_dir)
    root = cache_dir / spec.key / spec.revision
    source = root / "source"
    derived_dir = root / "derived"

    _ensure_source(spec, root, source, offline=offline, refresh=refresh)
    artifacts = _verify_artifacts(spec, source)
    derived = _derive_artifacts(spec, source, derived_dir)

    return PreparedDataset(
        manifest=manifest,
        spec=spec,
        manifest_sha256=sha256_bytes(manifest.path.read_bytes().replace(b"\r\n", b"\n")),
        root=root,
        source=source,
        derived=derived_dir,
        artifact_hashes=artifacts,
        derived_hashes=derived,
    )


def _load_json(data: bytes, label: str) -> dict:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatasetError(f"cannot parse {label}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("sections"), list):
        raise DatasetError(f"{label} does not contain a sections array")
    return document


def _build_sections(document: dict, corpus: str) -> tuple[Section, ...]:
    sections: list[Section] = []
    seen_names: set[str] = set()
    for index, raw in enumerate(document["sections"], 1):
        if not isinstance(raw, dict):
            raise DatasetError(f"{corpus} section {index} is not an object")
        name = raw.get("name")
        text = raw.get("text")
        lines = raw.get("lines")
        if not isinstance(name, str) or not name or not isinstance(text, str):
            raise DatasetError(f"{corpus} section {index} lacks a name or text")
        if not isinstance(lines, int) or lines < 0:
            raise DatasetError(f"{corpus} section {name!r} lacks a valid published line count")
        if name in seen_names:
            raise DatasetError(f"{corpus} section name is duplicated: {name!r}")
        seen_names.add(name)

        secrets: list[ExpectedSecret] = []
        for item in raw.get("secrets", []):
            if not isinstance(item, dict):
                raise DatasetError(f"{corpus} section {name!r} has a malformed secret")
            kind = item.get("kind")
            value = item.get("text")
            if not isinstance(kind, str) or not isinstance(value, str) or not value:
                raise DatasetError(f"{corpus} section {name!r} has an incomplete secret")
            secrets.append(ExpectedSecret(kind=kind, text=value))

        personal: list[str] = []
        for item in raw.get("personal_data", []):
            if not isinstance(item, dict) or not isinstance(item.get("text"), str):
                raise DatasetError(f"{corpus} section {name!r} has malformed personal_data")
            personal.append(item["text"])

        sections.append(
            Section(
                name=name,
                text=text,
                secrets=tuple(secrets),
                personal_data=tuple(personal),
                hard=bool(raw.get("hard", False)),
                filename=f"{index:03d}-{slugify(name)}.log",
                lines=lines,
            )
        )
    return tuple(sections)


def _actual_counts(sections: tuple[Section, ...]) -> dict[str, int]:
    return {
        "sections": len(sections),
        "lines": sum(section.lines for section in sections),
        "secrets": sum(len(section.secrets) for section in sections),
        "personal_data": sum(len(section.personal_data) for section in sections),
        "hard_sections": sum(1 for section in sections if section.hard),
        "hard_secrets": sum(len(section.secrets) for section in sections if section.hard),
    }


def _require_counts(corpus: str, actual: dict[str, int], expected: dict[str, int]) -> None:
    for key, wanted in expected.items():
        got = actual[key]
        if got != wanted:
            raise DatasetError(f"{corpus} corpus {key} mismatch: found {got}, manifest pins {wanted}")


def load_corpora(prepared: PreparedDataset) -> CorpusBundle:
    negative_doc = _load_json(prepared.read_blob("fp-corpus.json"), "fp-corpus.json")
    positive_doc = _load_json(prepared.read_derived("tp-corpus.json"), "tp-corpus.json")
    negative = _build_sections(negative_doc, "negative")
    positive = _build_sections(positive_doc, "positive")
    negative_counts = _actual_counts(negative)
    positive_counts = _actual_counts(positive)
    spec = prepared.spec

    if negative_counts["secrets"] != 0:
        raise DatasetError("negative corpus unexpectedly contains labeled secrets")
    if any(section.hard for section in negative):
        raise DatasetError("negative corpus unexpectedly marks hard sections")

    _require_counts(
        "negative",
        negative_counts,
        {
            "sections": spec.expected.negative_sections,
            "lines": spec.expected.negative_lines,
            "secrets": spec.expected.negative_secrets,
            "personal_data": spec.expected.negative_personal_data,
        },
    )
    _require_counts(
        "positive",
        positive_counts,
        {
            "sections": spec.expected.positive_sections,
            "lines": spec.expected.positive_lines,
            "secrets": spec.expected.positive_secrets,
            "personal_data": spec.expected.positive_personal_data,
            "hard_sections": spec.expected.positive_hard_sections,
            "hard_secrets": spec.expected.positive_hard_secrets,
        },
    )

    declared_negative = negative_doc.get("counts", {})
    declared_positive = positive_doc.get("counts", {})
    if declared_negative.get("formats") != negative_counts["sections"]:
        raise DatasetError("negative corpus counts.formats disagrees with its sections")
    if declared_negative.get("lines") != negative_counts["lines"]:
        raise DatasetError("negative corpus counts.lines disagrees with its sections")
    if declared_negative.get("personal_data") != negative_counts["personal_data"]:
        raise DatasetError("negative corpus counts.personal_data disagrees with its sections")
    if declared_positive.get("formats") != positive_counts["sections"]:
        raise DatasetError("positive corpus counts.formats disagrees with its sections")
    if declared_positive.get("secrets") != positive_counts["secrets"]:
        raise DatasetError("positive corpus counts.secrets disagrees with its sections")
    if declared_positive.get("core") != positive_counts["sections"] - positive_counts["hard_sections"]:
        raise DatasetError("positive corpus counts.core disagrees with its sections")
    if declared_positive.get("hard") != positive_counts["hard_sections"]:
        raise DatasetError("positive corpus counts.hard disagrees with its sections")

    return CorpusBundle(
        negative=negative,
        positive=positive,
        negative_counts=negative_counts,
        positive_counts=positive_counts,
    )


def short_dataset_report(prepared: PreparedDataset, corpora: CorpusBundle) -> dict:
    return {
        "name": prepared.spec.name,
        "source": prepared.spec.source_repository,
        "revision": prepared.spec.revision,
        "tag": prepared.spec.revision_tag,
        "license": prepared.spec.license,
        "manifest_sha256": prepared.manifest_sha256,
        "cache": str(prepared.root),
        "negative": corpora.negative_counts,
        "positive": corpora.positive_counts,
    }
