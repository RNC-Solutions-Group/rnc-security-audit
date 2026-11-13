"""Certified RNC Synthetic Secrets Lab v3 loading and scoring.

The lab is an external, frozen, local-only dataset.  This module treats its
manifest and oracle as source truth: it verifies the manifest self-hash, every
corpus file, the Git lane identity, and the exact source span for every oracle
item before a scanner result can be scored.  Raw credential values are read
only transiently from the corpus and are never written to a report.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable

from . import evidence
from .errors import HarnessError
from .util import sha256_bytes, sha256_file

LAB_VERSION = "rnc-synthetic-secrets-lab/1.2.0"
BUILD_ID = "v3"
EXPECTED_MANIFEST_SHA256 = (
    "691548588679f4a1e5e41ecd5d253d7137693337c1ddef2c6e8943bbb7cd7d0b"
)
EXPECTED_ORACLE_SHA256 = (
    "83dea16b343ff7a9340ff463513f4bdb454cea6faaf3234696a78fe8e6b85214"
)
EXPECTED_COUNTS = {
    "POSITIVE": 800,
    "NEGATIVE_ORDINARY": 400,
    "NEGATIVE_TRAP": 202,
    "INFORMATIVE": 200,
    "TOTAL": 1602,
}
EXPECTED_LANE_COUNTS = {
    "filesystem": {
        "POSITIVE": 640,
        "NEGATIVE_ORDINARY": 330,
        "NEGATIVE_TRAP": 162,
        "INFORMATIVE": 150,
    },
    "git": {
        "POSITIVE": 160,
        "NEGATIVE_ORDINARY": 70,
        "NEGATIVE_TRAP": 40,
        "INFORMATIVE": 50,
    },
}
EXPECTED_UNIQUE_POSITIVES = 496
EXPECTED_CORPUS_FILES = 360
EXPECTED_GIT_HEAD = "cba273f44ccb90cbe3cb60cf2750b1847960830a"
EXPECTED_GIT_COMMITS = 51

CLASSIFICATIONS = (
    "POSITIVE",
    "NEGATIVE_ORDINARY",
    "NEGATIVE_TRAP",
    "INFORMATIVE",
)
MATCH_TP = "TRUE_POSITIVE"
MATCH_FN = "FALSE_NEGATIVE"
MATCH_FP = "FALSE_POSITIVE"
MATCH_INFORMATIVE = "INFORMATIVE"
MATCH_DUPLICATE = "DUPLICATE"
MATCH_NEAR_MISS = "NEAR_MISS"
MATCH_AMBIGUOUS = "AMBIGUOUS"
MATCH_UNMATCHED = "UNMATCHED_PENDING_REVIEW"
MATCH_UNVERIFIED = "UNVERIFIED_EVIDENCE"
MATCH_UNSUPPORTED = "UNSUPPORTED_CAPABILITY"


class RncLabError(HarnessError):
    """The frozen lab is missing, malformed, or source-inconsistent."""


@dataclass(frozen=True)
class LabItem:
    item_id: str
    occurrence_id: str
    classification: str
    lane: str
    category: str
    subtype: str
    scenario: str
    container_kind: str
    source_path: str
    source_member: str | None
    source_commit: str | None
    source_blob: str | None
    source_table: str | None
    source_rowid: int | None
    source_column: str | None
    source_format: str | None
    line: int | None
    byte_start: int
    byte_end: int
    identity_id: str | None
    identity_sha256: str | None
    span_sha256: str
    normalization: str
    representation: str
    match_policy: str | None
    group_id: str | None
    public_identity_sha256: str | None
    raw: dict = field(repr=False)

    @property
    def is_positive(self) -> bool:
        return self.classification == "POSITIVE"

    @property
    def is_negative(self) -> bool:
        return self.classification.startswith("NEGATIVE_")

    @property
    def source_key(self) -> tuple:
        return (
            self.lane,
            self.source_path,
            self.source_member,
            self.source_commit,
            self.source_table,
            self.source_rowid,
            self.source_column,
            self.byte_start,
            self.byte_end,
        )


@dataclass(frozen=True)
class LabDataset:
    root: Path
    manifest: dict
    oracle_document: tuple[dict, ...]
    items: tuple[LabItem, ...]
    manifest_sha256: str
    oracle_sha256: str
    corpus_sha256: str
    source_validation: dict
    git_head: str
    git_commit_count: int

    @property
    def filesystem_root(self) -> Path:
        return self.root / self.manifest["corpus"]["filesystem_root"]

    @property
    def history_root(self) -> Path:
        return self.root / self.manifest["corpus"]["history_root"]

    def lane_items(self, lane: str) -> tuple[LabItem, ...]:
        return tuple(item for item in self.items if item.lane == lane)

    def positives(self, lane: str) -> tuple[LabItem, ...]:
        return tuple(
            item for item in self.items if item.lane == lane and item.is_positive
        )

    def counts(self, lane: str) -> dict:
        result = Counter(item.classification for item in self.lane_items(lane))
        result["TOTAL"] = sum(result.values())
        return dict(result)


def _canonical_json(document: dict) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def manifest_hash(document: dict) -> str:
    payload = {key: value for key, value in document.items() if key != "manifest_sha256"}
    return sha256_bytes(_canonical_json(payload))


def _safe_rel(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    if not value or path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise RncLabError(f"unsafe lab-relative path: {value!r}")
    return path.as_posix()


def _git(source: Path, *args: str, binary: bool = False) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *args],
            capture_output=True,
            timeout=180,
            env={
                **os.environ,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RncLabError(f"cannot run git for lab verification: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise RncLabError(
            f"git {' '.join(args)} failed: {detail[0][:240] if detail else 'no diagnostic'}"
        )
    return result.stdout if binary else result.stdout.decode("utf-8", "replace")


def _git_blobs(source: Path, specs: Iterable[tuple[str, str]]) -> dict[tuple[str, str], tuple[str, bytes]]:
    specs = sorted(set(specs))
    if not specs:
        return {}
    request = "".join(f"{commit}:{path}\n" for commit, path in specs).encode("utf-8")
    try:
        result = subprocess.run(
            ["git", "-C", str(source), "cat-file", "--batch"],
            input=request,
            capture_output=True,
            timeout=180,
            env={"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RncLabError(f"git cat-file --batch failed: {exc}") from exc
    if result.returncode != 0:
        raise RncLabError("git cat-file --batch failed for lab verification")
    data = result.stdout
    offset = 0
    output: dict[tuple[str, str], tuple[str, bytes]] = {}
    for commit, path in specs:
        newline = data.find(b"\n", offset)
        if newline < 0:
            raise RncLabError("truncated git cat-file --batch output")
        header = data[offset:newline].decode("utf-8", "replace")
        offset = newline + 1
        parts = header.split()
        if len(parts) == 2 and parts[1] == "missing":
            output[(commit, path)] = ("", b"")
            continue
        if len(parts) != 3 or not parts[2].isdigit():
            raise RncLabError(f"unexpected git cat-file header: {header[:120]}")
        size = int(parts[2])
        content = data[offset : offset + size]
        offset += size + 1
        output[(commit, path)] = (parts[0], content)
    return output


def _extract_archive_member(path: Path, member: str) -> bytes:
    """Extract a direct or nested archive member without writing a temp tree."""
    segments = [segment for segment in member.split("!/") if segment]
    if not segments:
        raise RncLabError(f"archive source has no member: {path}")
    data = path.read_bytes()
    for segment in segments:
        data = _extract_one(data, segment)
    return data


def _extract_one(data: bytes, member: str) -> bytes:
    from io import BytesIO

    bio = BytesIO(data)
    if zipfile.is_zipfile(bio):
        bio.seek(0)
        with zipfile.ZipFile(bio) as archive:
            try:
                return archive.read(member)
            except KeyError as exc:
                raise RncLabError(f"archive member is absent: {member}") from exc
    bio.seek(0)
    try:
        with tarfile.open(fileobj=bio, mode="r:*") as archive:
            try:
                selected = archive.getmember(member)
            except KeyError as exc:
                raise RncLabError(f"tar member is absent: {member}") from exc
            handle = archive.extractfile(selected)
            if handle is None:
                raise RncLabError(f"tar member is not a regular file: {member}")
            return handle.read()
    except tarfile.TarError:
        pass
    # Single-stream compressed members are used by the lab's .gz/.bz2/.xz
    # entries.  They do not carry an internal path.
    for opener in (gzip.decompress, bz2.decompress, lzma.decompress):
        try:
            return opener(data)
        except (OSError, EOFError, ValueError):
            continue
    raise RncLabError(f"unsupported archive member: {member}")


def _bson_documents(data: bytes) -> list[dict[str, object]]:
    documents: list[dict[str, object]] = []
    offset = 0
    while offset + 5 <= len(data):
        length = int.from_bytes(data[offset : offset + 4], "little")
        if length < 5 or offset + length > len(data):
            raise RncLabError("invalid BSON document length")
        document: dict[str, object] = {}
        pos = offset + 4
        end = offset + length - 1
        while pos < end:
            element_type = data[pos]
            pos += 1
            terminator = data.find(b"\x00", pos)
            if terminator < 0:
                raise RncLabError("invalid BSON field name")
            name = data[pos:terminator].decode("utf-8", "replace")
            pos = terminator + 1
            if element_type == 0x02:
                size = int.from_bytes(data[pos : pos + 4], "little")
                pos += 4
                document[name] = data[pos : pos + size - 1]
                pos += size
            elif element_type == 0x03:
                size = int.from_bytes(data[pos : pos + 4], "little")
                nested, pos = _bson_one(data, pos)
                document[name] = nested
                if size < 5:
                    raise RncLabError("invalid nested BSON")
            elif element_type == 0x04:
                nested, pos = _bson_one(data, pos)
                document[name] = nested
            elif element_type == 0x05:
                size = int.from_bytes(data[pos : pos + 4], "little")
                pos += 4
                document[name] = data[pos : pos + size]
                pos += size
            elif element_type == 0x07:
                document[name] = data[pos : pos + 12]
                pos += 12
            elif element_type in (0x08,):
                document[name] = bool(data[pos])
                pos += 1
            elif element_type in (0x01, 0x09, 0x11, 0x12):
                size = {0x01: 8, 0x09: 8, 0x11: 8, 0x12: 8}[element_type]
                document[name] = data[pos : pos + size]
                pos += size
            elif element_type == 0x0A:
                document[name] = None
            elif element_type == 0x10:
                document[name] = int.from_bytes(data[pos : pos + 4], "little", signed=True)
                pos += 4
            elif element_type == 0x13:
                pos += 16
            else:
                raise RncLabError(f"unsupported BSON element type 0x{element_type:02x}")
        documents.append(document)
        offset += length
    return documents


def _bson_one(data: bytes, offset: int) -> tuple[dict[str, object], int]:
    length = int.from_bytes(data[offset : offset + 4], "little")
    if length < 5 or offset + length > len(data):
        raise RncLabError("invalid nested BSON document")
    nested = _bson_documents(data[offset : offset + length])
    return (nested[0] if nested else {}), offset + length


def _database_cell(path: Path, table: str, rowid: int, column: str, fmt: str) -> bytes:
    if fmt == "sqlite":
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            query = f'SELECT "{column}" FROM "{table}" WHERE rowid = ?'
            row = connection.execute(query, (rowid,)).fetchone()
            if row is None:
                raise RncLabError(f"SQLite cell is absent: {table}.{column} row {rowid}")
            value = row[0]
            if isinstance(value, bytes):
                return value
            if value is None:
                return b""
            return str(value).encode("utf-8")
        finally:
            connection.close()
    if fmt == "bson":
        documents = _bson_documents(path.read_bytes())
        if rowid < 1 or rowid > len(documents):
            raise RncLabError(f"BSON row is absent: {table} row {rowid}")
        value = documents[rowid - 1].get(column)
        if value is None:
            raise RncLabError(f"BSON cell is absent: {table}.{column} row {rowid}")
        if isinstance(value, bytes):
            return value
        return str(value).encode("utf-8")
    raise RncLabError(f"unsupported database format: {fmt}")


def _item_bytes(item: LabItem, dataset: LabDataset, git_cache: dict) -> bytes:
    if item.lane == "git":
        key = (item.source_commit or "", item.source_path)
        if key not in git_cache:
            raise RncLabError(f"Git blob was not loaded: {item.source_path}")
        return git_cache[key][1]
    path = dataset.filesystem_root / item.source_path
    if item.container_kind == "archive":
        if not item.source_member:
            raise RncLabError(f"archive item has no member: {item.item_id}")
        return _extract_archive_member(path, item.source_member)
    if item.container_kind == "database":
        if not all((item.source_table, item.source_rowid, item.source_column, item.source_format)):
            raise RncLabError(f"database item has incomplete source: {item.item_id}")
        if item.source_format == "bson":
            # BSON oracle offsets address the document stream, not an extracted
            # cell.  SQLite offsets address the selected cell value.
            return path.read_bytes()
        return _database_cell(
            path,
            item.source_table,
            int(item.source_rowid),
            item.source_column,
            item.source_format,
        )
    return path.read_bytes()


def _parse_item(document: dict) -> LabItem:
    try:
        source = document["source"]
        location = document["location"]
        value = document["value"]
        container = document.get("container") or {}
        expected = document.get("expected") or {}
        return LabItem(
            item_id=str(document["item_id"]),
            occurrence_id=str(document["occurrence_id"]),
            classification=str(document["classification"]),
            lane=str(document["lane"]),
            category=str(document.get("category") or ""),
            subtype=str(document.get("subtype") or ""),
            scenario=str(document.get("scenario") or ""),
            container_kind=str(container.get("kind") or "file"),
            source_path=_safe_rel(str(source["path"])),
            source_member=(
                str(source["member"]) if source.get("member") is not None else None
            ),
            source_commit=(
                str(source["commit"]) if source.get("commit") is not None else None
            ),
            source_blob=(
                str(source["blob"]) if source.get("blob") is not None else None
            ),
            source_table=(
                str(source["table"]) if source.get("table") is not None else None
            ),
            source_rowid=(
                int(source["rowid"]) if source.get("rowid") is not None else None
            ),
            source_column=(
                str(source["column"]) if source.get("column") is not None else None
            ),
            source_format=(
                str(source["format"]) if source.get("format") is not None else None
            ),
            line=(int(location["line"]) if location.get("line") is not None else None),
            byte_start=int(location["byte_start"]),
            byte_end=int(location["byte_end"]),
            identity_id=(
                str(value["identity_id"]) if value.get("identity_id") is not None else None
            ),
            identity_sha256=(
                str(value["identity_sha256"])
                if value.get("identity_sha256") is not None
                else None
            ),
            span_sha256=str(value["span_sha256"]),
            normalization=str(value.get("normalization") or "identity_direct"),
            representation=str(value.get("representation") or ""),
            match_policy=(
                str(value["match_policy"]) if value.get("match_policy") is not None else None
            ),
            group_id=(
                str(expected["group_id"]) if expected.get("group_id") is not None else None
            ),
            public_identity_sha256=(
                str(value["public_identity_sha256"])
                if value.get("public_identity_sha256") is not None
                else None
            ),
            raw=document,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RncLabError(f"invalid oracle item: {exc}") from exc


def load(cache_dir: Path | str = "datasets/cache/rnc-synth-lab") -> LabDataset:
    root = Path(cache_dir).expanduser().resolve()
    if not root.is_dir():
        raise RncLabError(f"certified RNC Lab cache is missing: {root}")
    manifest_path = root / "config" / "manifest.json"
    oracle_path = root / "oracle" / "oracle.jsonl"
    if not manifest_path.is_file() or not oracle_path.is_file():
        raise RncLabError("certified RNC Lab manifest or oracle is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RncLabError(f"cannot read lab manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RncLabError("lab manifest is not an object")
    if manifest.get("lab_version") != LAB_VERSION or manifest.get("build_id") != BUILD_ID:
        raise RncLabError(
            f"lab identity is {manifest.get('lab_version')!r}/{manifest.get('build_id')!r}, "
            f"expected {LAB_VERSION}/{BUILD_ID}"
        )
    actual_manifest_hash = manifest_hash(manifest)
    if actual_manifest_hash != EXPECTED_MANIFEST_SHA256:
        raise RncLabError(
            f"lab manifest SHA-256 is {actual_manifest_hash}, expected "
            f"{EXPECTED_MANIFEST_SHA256}"
        )
    if manifest.get("manifest_sha256") != EXPECTED_MANIFEST_SHA256:
        raise RncLabError("lab manifest self-hash does not match the certified pin")
    oracle_bytes = oracle_path.read_bytes()
    oracle_hash = sha256_bytes(oracle_bytes)
    if oracle_hash != EXPECTED_ORACLE_SHA256:
        raise RncLabError(
            f"lab oracle SHA-256 is {oracle_hash}, expected {EXPECTED_ORACLE_SHA256}"
        )
    oracle_document: list[dict] = []
    for line_number, line in enumerate(oracle_bytes.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError as exc:
            raise RncLabError(f"lab oracle line {line_number} is not JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise RncLabError(f"lab oracle line {line_number} is not an object")
        oracle_document.append(value)
    items = tuple(_parse_item(value) for value in oracle_document)
    counts = Counter(item.classification for item in items)
    if len(items) != EXPECTED_COUNTS["TOTAL"]:
        raise RncLabError(f"lab oracle has {len(items)} items, expected 1602")
    for name, expected in EXPECTED_COUNTS.items():
        if name == "TOTAL":
            continue
        if counts.get(name) != expected:
            raise RncLabError(
                f"lab oracle {name} count is {counts.get(name)}, expected {expected}"
            )
    if len({item.item_id for item in items}) != len(items):
        raise RncLabError("lab oracle item IDs are not unique")
    if len({item.occurrence_id for item in items}) != len(items):
        raise RncLabError("lab oracle occurrence IDs are not unique")
    for lane, expected in EXPECTED_LANE_COUNTS.items():
        actual = Counter(item.classification for item in items if item.lane == lane)
        for classification, count in expected.items():
            if actual.get(classification) != count:
                raise RncLabError(
                    f"lab {lane} {classification} count is {actual.get(classification)}, "
                    f"expected {count}"
                )
    unique_groups = {
        item.group_id for item in items if item.is_positive and item.group_id is not None
    }
    if len(unique_groups) != EXPECTED_UNIQUE_POSITIVES:
        raise RncLabError(
            f"lab has {len(unique_groups)} unique positive groups, expected "
            f"{EXPECTED_UNIQUE_POSITIVES}"
        )

    corpus = manifest.get("corpus") or {}
    files = corpus.get("files")
    if not isinstance(files, list) or len(files) != EXPECTED_CORPUS_FILES:
        raise RncLabError("lab manifest corpus file inventory is incomplete")
    actual_hashes: list[str] = []
    listed_paths: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise RncLabError("lab corpus file entry is not an object")
        rel = _safe_rel(str(entry.get("path")))
        if rel in listed_paths:
            raise RncLabError(f"lab corpus file is duplicated: {rel}")
        listed_paths.add(rel)
        path = root / corpus.get("filesystem_root", "corpus/filesystem") / rel
        if not path.is_file():
            raise RncLabError(f"lab corpus file is missing: {rel}")
        actual = sha256_file(path)
        if actual != entry.get("sha256"):
            raise RncLabError(f"lab corpus file hash differs: {rel}")
        if path.stat().st_size != entry.get("bytes"):
            raise RncLabError(f"lab corpus file size differs: {rel}")
        actual_hashes.append(f"{rel}:{actual}")
    content_hash = sha256_bytes("\n".join(actual_hashes).encode("utf-8"))
    if content_hash != corpus.get("content_sha256"):
        raise RncLabError("lab corpus content hash differs from the manifest")
    filesystem_root = root / corpus.get("filesystem_root", "corpus/filesystem")
    discovered = {
        path.relative_to(filesystem_root).as_posix()
        for path in filesystem_root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if discovered != listed_paths:
        missing = sorted(discovered - listed_paths)[:4]
        extra = sorted(listed_paths - discovered)[:4]
        raise RncLabError(
            f"lab corpus file inventory differs from disk (unlisted={missing}, "
            f"missing={extra})"
        )

    history_root = root / corpus.get("history_root", "corpus/history")
    try:
        head = _git(history_root, "rev-parse", "HEAD").strip()
        commit_count = int(_git(history_root, "rev-list", "--count", "HEAD").strip())
        remotes = _git(history_root, "remote").strip()
        dirty = _git(history_root, "status", "--porcelain").strip()
    except (RncLabError, ValueError) as exc:
        raise RncLabError(f"lab Git history is unavailable: {exc}") from exc
    if head != EXPECTED_GIT_HEAD:
        raise RncLabError(f"lab Git HEAD is {head}, expected {EXPECTED_GIT_HEAD}")
    if commit_count != EXPECTED_GIT_COMMITS:
        raise RncLabError(
            f"lab Git history has {commit_count} commits, expected {EXPECTED_GIT_COMMITS}"
        )
    if remotes:
        raise RncLabError("lab Git history has a remote")
    if dirty:
        raise RncLabError("lab Git history working tree is not clean")

    dataset = LabDataset(
        root=root,
        manifest=manifest,
        oracle_document=tuple(oracle_document),
        items=items,
        manifest_sha256=actual_manifest_hash,
        oracle_sha256=oracle_hash,
        corpus_sha256=content_hash,
        source_validation={},
        git_head=head,
        git_commit_count=commit_count,
    )
    git_items = [item for item in items if item.lane == "git"]
    git_specs = {
        (item.source_commit or "", item.source_path) for item in git_items
    }
    git_cache = _git_blobs(history_root, git_specs)
    span_errors: list[str] = []
    checked = 0
    for item in items:
        try:
            data = _item_bytes(item, dataset, git_cache)
        except (OSError, RncLabError, sqlite3.Error) as exc:
            span_errors.append(f"{item.item_id} source unavailable: {exc}")
            continue
        if item.lane == "git":
            blob_sha, blob = git_cache.get((item.source_commit or "", item.source_path), ("", b""))
            if item.source_blob and blob_sha != item.source_blob:
                span_errors.append(f"{item.item_id} Git blob object differs from the oracle")
                continue
            if blob != data:
                span_errors.append(f"{item.item_id} Git source content changed")
                continue
        if item.byte_start < 0 or item.byte_end <= item.byte_start or item.byte_end > len(data):
            span_errors.append(f"{item.item_id} span is outside its source unit")
            continue
        span = data[item.byte_start : item.byte_end]
        if sha256_bytes(span) != item.span_sha256:
            span_errors.append(f"{item.item_id} span digest differs from the oracle")
            continue
        checked += 1
    if span_errors:
        raise RncLabError(
            "lab source validation failed: " + "; ".join(span_errors[:12])
        )
    source_validation = {
        "status": "PASS",
        "checked_items": checked,
        "checked_spans": checked,
        "manifest_sha256": actual_manifest_hash,
        "oracle_sha256": oracle_hash,
        "corpus_sha256": content_hash,
        "corpus_files": len(files),
        "git_head": head,
        "git_commit_count": commit_count,
        "git_remotes": [],
    }
    return LabDataset(
        root=root,
        manifest=manifest,
        oracle_document=tuple(oracle_document),
        items=items,
        manifest_sha256=actual_manifest_hash,
        oracle_sha256=oracle_hash,
        corpus_sha256=content_hash,
        source_validation=source_validation,
        git_head=head,
        git_commit_count=commit_count,
    )


def verify_frozen(dataset: LabDataset) -> dict:
    """Re-verify the immutable lab after a run without trusting the first load."""
    manifest_path = dataset.root / "config" / "manifest.json"
    oracle_path = dataset.root / "oracle" / "oracle.jsonl"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_actual = manifest_hash(manifest)
    oracle_actual = sha256_file(oracle_path)
    files = manifest.get("corpus", {}).get("files") or []
    hashes: list[str] = []
    for entry in files:
        path = dataset.filesystem_root / _safe_rel(str(entry["path"]))
        if not path.is_file() or sha256_file(path) != entry["sha256"]:
            raise RncLabError(f"lab corpus changed during the run: {entry.get('path')}")
        hashes.append(f"{entry['path']}:{entry['sha256']}")
    content_hash = sha256_bytes("\n".join(hashes).encode("utf-8"))
    head = _git(dataset.history_root, "rev-parse", "HEAD").strip()
    verified = {
        "status": "PASS",
        "manifest_sha256": manifest_actual,
        "oracle_sha256": oracle_actual,
        "corpus_sha256": content_hash,
        "git_head": head,
        "manifest_unchanged": manifest_actual == dataset.manifest_sha256,
        "oracle_unchanged": oracle_actual == dataset.oracle_sha256,
        "corpus_unchanged": content_hash == dataset.corpus_sha256,
        "git_head_unchanged": head == dataset.git_head,
    }
    if not all(
        verified[key]
        for key in (
            "manifest_unchanged",
            "oracle_unchanged",
            "corpus_unchanged",
            "git_head_unchanged",
        )
    ):
        verified["status"] = "FAIL"
        raise RncLabError("frozen lab integrity changed during the run")
    return verified


# ---------------------------------------------------------------------------
# Finding evidence and occurrence attribution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LabFinding:
    index: int
    file: str
    line: int | None
    rule_id: str
    commit: str | None
    secret_sha256: str | None
    match_sha256: str | None
    byte_start: int | None = None
    byte_end: int | None = None
    container_member: str | None = None
    source_span_sha256: str | None = None
    secret_text: str = field(default="", repr=False)
    match_text: str = field(default="", repr=False)
    metadata: dict = field(default_factory=dict, repr=False)

    @property
    def safe(self) -> dict:
        return {
            "index": self.index,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "commit": self.commit,
            "secret_sha256": self.secret_sha256,
            "match_sha256": self.match_sha256,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "container_member": self.container_member,
            "source_span_sha256": self.source_span_sha256,
        }


@dataclass
class FindingOutcome:
    finding: LabFinding
    classification: str
    item_id: str | None = None
    reason: str = ""
    group_id: str | None = None
    private_key_evidence: bool | None = None
    evidence_kind: str | None = None
    stage: str | None = None
    reason_code: str | None = None
    candidate_ids: tuple[str, ...] = ()


def _normalize_path(value: str, root: Path) -> str:
    raw = value.replace("\\", "/").strip()
    if not raw:
        return ""
    try:
        path = Path(raw)
        if path.is_absolute():
            return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        pass
    if raw.startswith("./"):
        raw = raw[2:]
    # Docker adapters mount the scan root at /scan and some scanners report that
    # container path in JSON.  Treat it as the lane root before path matching.
    if raw.startswith("/scan/"):
        raw = raw[len("/scan/") :]
    # Gitleaks and Betterleaks report either lane-relative paths or an absolute
    # path under the scan target.  Strip the lane root exactly, not just its
    # parent directory, so archive and dotted paths stay intact.
    for marker in (
        f"/corpus/{root.name}/",
        f"corpus/{root.name}/",
        f"/{root.name}/",
    ):
        if marker in raw:
            return raw.split(marker, 1)[1]
    return raw


def _canonical_member(value: str | None) -> str | None:
    if not value:
        return None
    value = value.replace("!/", "!").replace("::", "!").strip("/")
    return value or None


def _archive_member(path: str) -> tuple[str, str | None]:
    for marker in ("!", "::"):
        if marker in path:
            archive, member = path.split(marker, 1)
            return archive, _canonical_member(member)
    return path, None


def _path_matches(item: LabItem, finding_file: str, root: Path) -> bool:
    """Match path and, for archives, the reported member identity.

    An enclosing archive path alone is not proof that the correct member was
    detected.  RNC's adapter may report only the archive path; in that case the
    finding remains eligible only when the oracle item itself has no member
    identity.  Reports that include a member must match it exactly.
    """
    if not finding_file:
        return False
    finding_archive, finding_member = _archive_member(finding_file)
    item_member = _canonical_member(item.source_member)
    if item.container_kind == "archive":
        if finding_archive != item.source_path:
            return False
        if item_member:
            if finding_member is not None:
                return finding_member == item_member
            # A gzip stream has exactly one member; the enclosing path is the
            # only available identity.  Multi-member archives require an exact
            # member report.
            formats = {
                str(item.source_format or "").lower(),
                str(((item.raw.get("container") or {}).get("format") or "")).lower(),
            }
            return item.source_path.lower().endswith(".gz") or bool(
                formats & {"gz", "gzip"}
            )
        return finding_member is None
    if finding_file == item.source_path:
        return True
    if item.lane == "filesystem":
        left = (root / item.source_path).resolve()
        right = (root / finding_file).resolve()
        if left == right:
            return True
    return False
def _text_candidates(text: str) -> set[str]:
    if not text:
        return set()
    candidates: set[str] = set()
    stripped = text.strip()
    for value in (text, stripped, stripped.strip("\"'")):
        if value:
            candidates.add(value)
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        candidates.add(line)
        for match in re.finditer(r"[\"']([^\"']{4,})[\"']", line):
            candidates.add(match.group(1))
        for match in re.finditer(r"[A-Za-z0-9_+/=.~-]{6,}", line):
            candidates.add(match.group(0))
        for prefix in ("Password=", "password=", "passwd=", "pwd="):
            if prefix in line:
                value = line.split(prefix, 1)[1].strip().strip("\"',;")
                candidates.add(value)
        if ":" in line:
            value = line.split(":", 1)[1].strip().strip("\"',;")
            candidates.add(value)
        if "=" in line:
            value = line.split("=", 1)[1].strip().strip("\"',;")
            candidates.add(value)
    # Bounded decode probing.  The digest comparison remains exact, so a
    # decoded fragment can only match a lab identity, never a line prefix.
    for value in list(candidates):
        if len(value) < 8 or len(value) % 4:
            continue
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            continue
        try:
            text_value = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        candidates.add(text_value)
        for match in re.finditer(r"[A-Za-z0-9_+/=.~-]{6,}", text_value):
            candidates.add(match.group(0))
        if ":" in text_value:
            candidates.add(text_value.split(":", 1)[1])
    return candidates


def _candidate_hashes(finding: LabFinding) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for digest in (finding.secret_sha256, finding.match_sha256, finding.source_span_sha256):
        if digest:
            hashes[digest] = "reported"
    for text in (finding.secret_text, finding.match_text):
        if not text:
            continue
        for candidate in _text_candidates(text):
            digest = sha256_bytes(candidate.encode("utf-8"))
            hashes.setdefault(digest, "candidate")
    return hashes


def _private_text_complete(finding: LabFinding) -> bool:
    text = (finding.secret_text or "") + "\n" + (finding.match_text or "")
    if "PuTTY-User-Key-File-" in text:
        return True
    return bool(
        re.search(
            r"-----BEGIN (?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----[\s\S]*?"
            r"-----END (?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----",
            text,
        )
    )


def _source_span_bytes(
    dataset: LabDataset,
    item: LabItem,
    cache: dict[str, bytes | None],
) -> bytes | None:
    if item.item_id in cache:
        return cache[item.item_id]
    value: bytes | None = None
    try:
        if item.lane == "filesystem" and item.container_kind == "file":
            data = (dataset.filesystem_root / item.source_path).read_bytes()
            value = data[item.byte_start : item.byte_end]
        elif item.lane == "git" and item.source_blob:
            data = _git(dataset.history_root, "cat-file", "blob", item.source_blob, binary=True)
            value = data[item.byte_start : item.byte_end]
    except (OSError, RncLabError):
        value = None
    cache[item.item_id] = value
    return value


def _item_aliases(
    dataset: LabDataset,
    item: LabItem,
    span_cache: dict[str, bytes | None],
) -> tuple[evidence.EvidenceAlias, ...]:
    aliases: list[evidence.EvidenceAlias] = []
    seen: set[str] = set()
    for digest, kind, detail in (
        (item.identity_sha256, evidence.IDENTITY_DIGEST, "oracle identity digest"),
        (item.span_sha256, evidence.SOURCE_SPAN_EXACT, "exact oracle source span"),
        (item.public_identity_sha256, evidence.PUBLIC_KEY_ONLY, "public-key identity only"),
    ):
        if digest and digest not in seen:
            seen.add(digest)
            aliases.append(evidence.EvidenceAlias(kind=kind, digest=digest, detail=detail))
    if item.match_policy == "private_key_material_required":
        span = _source_span_bytes(dataset, item, span_cache)
        if span:
            for alias in evidence.private_span_aliases(span, item.representation):
                if alias.digest not in seen:
                    seen.add(alias.digest)
                    aliases.append(alias)
    return tuple(aliases)


def _line_matches(item: LabItem, finding: LabFinding) -> bool:
    if item.line is None:
        return True
    if finding.line is None:
        return False
    if finding.line == item.line:
        return True
    # A Kubernetes secret YAML scanner may locate the enclosing data block
    # rather than the base64 value line.  This is an explicit structured-source
    # location policy, valid only when the value digest already matched.
    if (
        str(item.representation).startswith("kubernetes_")
        and str(finding.rule_id) in ("kubernetes-secret-yaml", "pem-private-key-base64")
        and finding.line < item.line
    ):
        return True
    return False


def _byte_matches(item: LabItem, finding: LabFinding) -> bool:
    if item.container_kind not in ("file", "git"):
        return True
    if finding.byte_start is None or finding.byte_end is None:
        return True
    if (finding.byte_start, finding.byte_end) == (item.byte_start, item.byte_end):
        return True
    # A scanner may report the credential component (for example the userinfo
    # inside a database URL) rather than the oracle's enclosing representation.
    # An exact value identity plus a contained byte range is a valid source
    # location; an extended or overlapping range is not.
    return item.byte_start <= finding.byte_start and finding.byte_end <= item.byte_end


def _location_reason(item: LabItem, finding: LabFinding) -> str | None:
    if item.line is not None:
        if finding.line is None:
            return evidence.LOCATION_UNVERIFIED
        if not _line_matches(item, finding):
            return evidence.LOCATION_LINE_MISMATCH
    if not _byte_matches(item, finding):
        return evidence.LOCATION_OFFSET_MISMATCH
    return None


def _material_status(
    dataset: LabDataset,
    item: LabItem,
    finding: LabFinding,
    alias: evidence.EvidenceAlias,
    hashes: dict[str, str],
    span_cache: dict[str, bytes | None],
) -> tuple[bool, str | None]:
    if item.match_policy != "private_key_material_required":
        return True, None
    if item.public_identity_sha256 and item.public_identity_sha256 in hashes:
        return False, evidence.PUBLIC_KEY_ONLY
    if _private_text_complete(finding):
        return True, None
    if item.identity_sha256 and item.identity_sha256 in hashes:
        return True, None
    if alias.kind in (evidence.SOURCE_SPAN_EXACT, evidence.SOURCE_SPAN_NORMALIZED):
        span = _source_span_bytes(dataset, item, span_cache)
        if span and evidence.private_key_material(span, item.representation):
            return True, None
    return False, evidence.PRIVATE_MATERIAL_UNPROVEN


def _line_distance(item: LabItem, finding: LabFinding) -> int:
    if item.line is None or finding.line is None:
        return 1_000_000
    return abs(item.line - finding.line)


def _near_miss_relation(
    dataset: LabDataset,
    lane: str,
    finding: LabFinding,
    lane_items: list[LabItem],
    alias_index: dict[str, list[tuple[LabItem, evidence.EvidenceAlias]]],
    *,
    source_root: Path,
    commit_ancestors: dict[str, frozenset[str]] | None,
    span_cache: dict[str, bytes | None],
    used: set[str],
) -> tuple[LabItem, str, str] | None:
    hashes = _candidate_hashes(finding)
    if not hashes:
        return None
    candidates: list[tuple[int, int, str, LabItem, str, str]] = []

    def _commit_ok(item: LabItem) -> bool:
        if lane != "git":
            return True
        if not finding.commit:
            return False
        return item.source_commit in (commit_ancestors or {}).get(finding.commit, frozenset())

    # Exact/normalized value at the right path but the wrong line/offset.
    for digest in hashes:
        for item, alias in alias_index.get(digest, []):
            if not item.is_positive or item.item_id in used or not _commit_ok(item):
                continue
            if alias.kind == evidence.PUBLIC_KEY_ONLY:
                continue
            if not _path_matches(item, finding.file, source_root):
                continue
            reason = _location_reason(item, finding)
            if reason:
                candidates.append((0, _line_distance(item, finding), item.item_id, item, reason, "source value matched but location did not"))

    # Exact value at a different source occurrence.
    for digest in hashes:
        for item, alias in alias_index.get(digest, []):
            if not item.is_positive or item.item_id in used or not _commit_ok(item):
                continue
            if alias.kind == evidence.PUBLIC_KEY_ONLY:
                continue
            if _path_matches(item, finding.file, source_root):
                continue
            candidates.append((1, 1_000_000, item.item_id, item, evidence.SOURCE_OCCURRENCE_MISMATCH, "exact credential value belongs to a different source occurrence"))

    # Same source path and line: prove a value-level near miss from source bytes.
    for item in lane_items:
        if not item.is_positive or item.item_id in used or not _commit_ok(item):
            continue
        if not _path_matches(item, finding.file, source_root):
            continue
        if item.line is not None and finding.line != item.line:
            continue
        span = _source_span_bytes(dataset, item, span_cache)
        if not span:
            continue
        relation, detail = evidence.value_relation(
            span,
            finding_digest=finding.secret_sha256 or finding.match_sha256,
            finding_text=finding.secret_text or finding.match_text or None,
        )
        if item.match_policy == "private_key_material_required":
            text = finding.secret_text or finding.match_text or ""
            if "PRIVATE KEY-----" in text and not _private_text_complete(finding):
                relation, detail = evidence.PARTIAL_MATERIAL, "incomplete private-key block"
        if relation in (
            evidence.VALUE_TRUNCATED,
            evidence.VALUE_EXTENDED,
            evidence.VALUE_MISMATCH,
            evidence.PARTIAL_MATERIAL,
        ):
            if item.match_policy == "private_key_material_required" and relation == evidence.VALUE_TRUNCATED:
                relation, detail = evidence.PARTIAL_MATERIAL, "incomplete private-key material"
            candidates.append((2, _line_distance(item, finding), item.item_id, item, relation, detail))

    if not candidates:
        return None
    candidates.sort(key=lambda value: (value[0], value[1], value[2]))
    _rank, _distance, _item_id, item, reason, detail = candidates[0]
    return item, reason, detail
def _commit_ancestors(history_root: Path) -> dict[str, frozenset[str]]:
    text = _git(history_root, "rev-list", "--parents", "--all")
    parents: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if parts:
            parents[parts[0]] = parts[1:]
    cache: dict[str, frozenset[str]] = {}

    def visit(commit: str, stack: frozenset[str] = frozenset()) -> frozenset[str]:
        if commit in cache:
            return cache[commit]
        if commit in stack:
            raise RncLabError("lab Git history contains a cycle")
        result = {commit}
        for parent in parents.get(commit, []):
            result.update(visit(parent, stack | {commit}))
        cache[commit] = frozenset(result)
        return cache[commit]

    for commit in parents:
        visit(commit)
    return cache


def _attribute(
    dataset: LabDataset,
    lane: str,
    raw_findings: list,
    *,
    source_root: Path,
    commit_ancestors: dict[str, frozenset[str]] | None = None,
) -> dict:
    findings = [
        LabFinding(
            index=index,
            file=_normalize_path(value.file, source_root),
            line=value.line,
            rule_id=value.rule_id,
            commit=value.commit,
            secret_sha256=value.secret_sha256,
            match_sha256=value.match_sha256,
            byte_start=value.byte_start,
            byte_end=value.byte_end,
            container_member=value.container_member,
            source_span_sha256=value.source_span_sha256,
            secret_text=value.secret_text or "",
            match_text=value.match_text or "",
            metadata=dict(value.metadata or {}),
        )
        for index, value in enumerate(raw_findings)
    ]
    lane_items = [item for item in dataset.items if item.lane == lane]
    span_cache: dict[str, bytes | None] = {}
    alias_index: dict[str, list[tuple[LabItem, evidence.EvidenceAlias]]] = defaultdict(list)
    for item in lane_items:
        for alias in _item_aliases(dataset, item, span_cache):
            alias_index[alias.digest].append((item, alias))

    priority = {
        evidence.IDENTITY_DIGEST: 5,
        evidence.SOURCE_SPAN_EXACT: 4,
        evidence.SOURCE_SPAN_NORMALIZED: 3,
        evidence.DECODED_IDENTITY: 2,
    }
    # A finding may have candidates at several items.  Build all edges first so
    # attribution does not depend on input order or premature short-circuiting.
    edges: list[dict] = []
    failures: dict[int, list[tuple[LabItem | None, str, str, str]]] = defaultdict(list)
    candidates_by_finding: dict[int, list[dict]] = defaultdict(list)
    for finding in findings:
        hashes = _candidate_hashes(finding)
        if not hashes:
            failures[finding.index].append((None, evidence.EVIDENCE_MISSING, evidence.STAGE_VALUE, "scanner supplied no value evidence"))
            continue
        seen_items: set[str] = set()
        for digest in sorted(hashes):
            for item, alias in alias_index.get(digest, []):
                if item.item_id in seen_items:
                    continue
                if alias.kind == evidence.PUBLIC_KEY_ONLY:
                    failures[finding.index].append((item, evidence.PUBLIC_KEY_ONLY, evidence.STAGE_MATERIAL, "only public-key identity was reported"))
                    continue
                if not _path_matches(item, finding.file, source_root):
                    continue
                if lane == "git":
                    if not finding.commit or item.source_commit not in (
                        commit_ancestors or {}
                    ).get(finding.commit, frozenset()):
                        continue
                location_reason = _location_reason(item, finding)
                if location_reason:
                    failures[finding.index].append((item, location_reason, evidence.STAGE_LOCATION, "source value and path matched but location did not"))
                    continue
                material_ok, material_reason = _material_status(
                    dataset, item, finding, alias, hashes, span_cache
                )
                if not material_ok:
                    failures[finding.index].append((item, material_reason or evidence.PRIVATE_MATERIAL_UNPROVEN, evidence.STAGE_MATERIAL, "private-key material could not be verified"))
                    continue
                seen_items.add(item.item_id)
                candidate_priority = priority.get(alias.kind, 1)
                candidate = {
                    "finding_index": finding.index,
                    "finding_key": evidence.stable_finding_key(
                        file=finding.file,
                        line=finding.line,
                        commit=finding.commit,
                        rule_id=finding.rule_id,
                        secret_sha256=finding.secret_sha256,
                        match_sha256=finding.match_sha256,
                        byte_start=finding.byte_start,
                        byte_end=finding.byte_end,
                    ),
                    "item": item,
                    "alias": alias,
                    "priority": candidate_priority,
                    "line_distance": _line_distance(item, finding),
                    "byte_distance": (
                        abs((finding.byte_start or 0) - item.byte_start)
                        if finding.byte_start is not None
                        else 1_000_000
                    ),
                }
                edges.append(candidate)
                candidates_by_finding[finding.index].append(candidate)
        if not candidates_by_finding.get(finding.index):
            # Same known positive path/line but a non-matching value is
            # unverified evidence, not a near miss (proximity alone is not a
            # relationship).
            for item in lane_items:
                if not item.is_positive:
                    continue
                if not _path_matches(item, finding.file, source_root):
                    continue
                if lane == "git":
                    if not finding.commit or item.source_commit not in (
                        commit_ancestors or {}
                    ).get(finding.commit, frozenset()):
                        continue
                if _line_matches(item, finding):
                    failures[finding.index].append(
                        (
                            item,
                            evidence.EVIDENCE_CONFLICT,
                            evidence.STAGE_VALUE,
                            "known positive location but value evidence did not match",
                        )
                    )
                    break

    # Equal-strength candidates that cannot be resolved by location are
    # ambiguous, not a reason to pick one by oracle order.
    ambiguous: set[int] = set()
    for index, candidates in candidates_by_finding.items():
        top = min((c["priority"], c["line_distance"], c["byte_distance"]) for c in candidates)
        top_items = {
            c["item"].item_id
            for c in candidates
            if (c["priority"], c["line_distance"], c["byte_distance"]) == top
        }
        if len(top_items) > 1:
            ambiguous.add(index)

    edges.sort(
        key=lambda c: (
            -c["priority"],
            c["line_distance"],
            c["byte_distance"],
            c["item"].item_id,
            c["finding_key"],
        )
    )
    assigned_finding: dict[int, dict] = {}
    assigned_item: dict[str, int] = {}
    for edge in edges:
        if edge["finding_index"] in ambiguous or edge["finding_index"] in assigned_finding:
            continue
        item = edge["item"]
        if item.item_id in assigned_item:
            continue
        assigned_finding[edge["finding_index"]] = edge
        assigned_item[item.item_id] = edge["finding_index"]

    outcomes: list[FindingOutcome] = []
    used = set(assigned_item)
    for finding in findings:
        edge = assigned_finding.get(finding.index)
        if finding.index in ambiguous:
            candidates = candidates_by_finding[finding.index]
            outcomes.append(
                FindingOutcome(
                    finding,
                    MATCH_AMBIGUOUS,
                    candidates[0]["item"].item_id if candidates else None,
                    "multiple equal-strength oracle candidates could not be resolved safely",
                    candidates[0]["item"].group_id if candidates else None,
                    evidence_kind=candidates[0]["alias"].kind if candidates else None,
                    stage=evidence.STAGE_ATTRIBUTION,
                    reason_code=evidence.CANDIDATE_AMBIGUOUS,
                    candidate_ids=tuple(sorted({c["item"].item_id for c in candidates})),
                )
            )
            continue
        if edge:
            item = edge["item"]
            alias = edge["alias"]
            if item.is_positive:
                classification = MATCH_TP
            elif item.is_negative:
                classification = MATCH_FP
            else:
                classification = MATCH_INFORMATIVE
            outcomes.append(
                FindingOutcome(
                    finding,
                    classification,
                    item.item_id,
                    f"verified {alias.kind} and source location",
                    item.group_id,
                    private_key_evidence=True if item.match_policy == "private_key_material_required" else None,
                    evidence_kind=alias.kind,
                    stage=evidence.STAGE_ATTRIBUTION,
                    reason_code=None,
                    candidate_ids=tuple(sorted({c["item"].item_id for c in candidates_by_finding[finding.index]})),
                )
            )
            continue

        candidates = candidates_by_finding.get(finding.index, [])
        if candidates:
            # The item was already credited by a stronger/earlier deterministic
            # edge; this is a duplicate alert, not additional coverage.
            best = sorted(
                candidates,
                key=lambda c: (-c["priority"], c["line_distance"], c["byte_distance"], c["item"].item_id),
            )[0]
            item = best["item"]
            outcomes.append(
                FindingOutcome(
                    finding,
                    MATCH_DUPLICATE,
                    item.item_id,
                    "additional alert for an already-credited source occurrence",
                    item.group_id,
                    evidence_kind=best["alias"].kind,
                    stage=evidence.STAGE_ATTRIBUTION,
                    reason_code=None,
                    candidate_ids=tuple(sorted({c["item"].item_id for c in candidates})),
                )
            )
            continue

        near = _near_miss_relation(
            dataset,
            lane,
            finding,
            lane_items,
            alias_index,
            source_root=source_root,
            commit_ancestors=commit_ancestors,
            span_cache=span_cache,
            used=used,
        )
        if near is not None:
            item, reason_code, detail = near
            outcomes.append(
                FindingOutcome(
                    finding,
                    MATCH_NEAR_MISS,
                    item.item_id,
                    detail,
                    item.group_id,
                    stage=evidence.STAGE_ATTRIBUTION,
                    reason_code=reason_code,
                    candidate_ids=(item.item_id,),
                )
            )
            continue

        item_failures = failures.get(finding.index, [])
        if item_failures:
            item, reason_code, stage, detail = sorted(
                item_failures,
                key=lambda value: (
                    0 if value[0] is not None else 1,
                    value[1],
                    value[0].item_id if value[0] is not None else "",
                ),
            )[0]
            outcomes.append(
                FindingOutcome(
                    finding,
                    MATCH_UNVERIFIED,
                    item.item_id if item is not None else None,
                    detail,
                    item.group_id if item is not None else None,
                    stage=stage,
                    reason_code=reason_code,
                )
            )
            continue

        outcomes.append(
            FindingOutcome(
                finding,
                MATCH_UNMATCHED,
                None,
                "no confirmed relationship to an oracle item",
                stage=evidence.STAGE_CANDIDATE_DISCOVERY,
                reason_code=evidence.ORACLE_COVERAGE_UNKNOWN,
            )
        )

    outcomes.sort(
        key=lambda outcome: (
            evidence.stable_finding_key(
                file=outcome.finding.file,
                line=outcome.finding.line,
                commit=outcome.finding.commit,
                rule_id=outcome.finding.rule_id,
                secret_sha256=outcome.finding.secret_sha256,
                match_sha256=outcome.finding.match_sha256,
                byte_start=outcome.finding.byte_start,
                byte_end=outcome.finding.byte_end,
            ),
            outcome.finding.index,
        )
    )

    by_item = {item.item_id: item for item in lane_items}
    positives = [item for item in lane_items if item.is_positive]
    matched_positive = [item for item in positives if item.item_id in used]
    missed_positive = [item for item in positives if item.item_id not in used]
    negative_outcomes = [o for o in outcomes if o.classification == MATCH_FP]
    informative_outcomes = [o for o in outcomes if o.classification == MATCH_INFORMATIVE]
    duplicate_outcomes = [o for o in outcomes if o.classification == MATCH_DUPLICATE]
    near_miss_outcomes = [o for o in outcomes if o.classification == MATCH_NEAR_MISS]
    unmatched_outcomes = [o for o in outcomes if o.classification == MATCH_UNMATCHED]
    unverified_outcomes = [o for o in outcomes if o.classification == MATCH_UNVERIFIED]
    ambiguous_outcomes = [o for o in outcomes if o.classification == MATCH_AMBIGUOUS]
    tp_ids = {item.item_id for item in matched_positive}
    tp_groups = {item.group_id for item in matched_positive if item.group_id}
    expected_groups = {item.group_id for item in positives if item.group_id}
    category_rows = []
    for category in sorted({item.category for item in positives}):
        selected = [item for item in positives if item.category == category]
        hit = [item for item in selected if item.item_id in tp_ids]
        category_rows.append(
            {
                "category": category,
                "expected_occurrences": len(selected),
                "matched_occurrences": len(hit),
                "occurrence_recall_percent": round(
                    100.0 * len(hit) / len(selected), 2
                )
                if selected
                else None,
                "expected_groups": len({item.group_id for item in selected if item.group_id}),
                "matched_groups": len(
                    {item.group_id for item in hit if item.group_id}
                ),
            }
        )
    representation_rows = []
    for representation in sorted({item.representation for item in positives}):
        selected = [item for item in positives if item.representation == representation]
        hit = [item for item in selected if item.item_id in tp_ids]
        representation_rows.append(
            {
                "representation": representation,
                "expected_occurrences": len(selected),
                "matched_occurrences": len(hit),
                "occurrence_recall_percent": round(
                    100.0 * len(hit) / len(selected), 2
                )
                if selected
                else None,
            }
        )
    container_misses = Counter(item.container_kind for item in missed_positive)
    metrics = {
        "observed_findings": len(findings),
        "expected_positives": len(positives),
        "true_positive_occurrences": len(matched_positive),
        "false_negative_occurrences": len(missed_positive),
        "occurrence_recall_percent": round(
            100.0 * len(matched_positive) / len(positives), 2
        )
        if positives
        else None,
        "expected_unique_groups": len(expected_groups),
        "unique_groups_matched": len(tp_groups),
        "unique_recall_percent": round(
            100.0 * len(tp_groups) / len(expected_groups), 2
        )
        if expected_groups
        else None,
        "duplicate_count": len(duplicate_outcomes),
        "informative_match_count": len(informative_outcomes),
        "informative_unique_item_count": len(
            {outcome.item_id for outcome in informative_outcomes}
        ),
        "verified_false_positive_alert_count": len(negative_outcomes),
        "unique_verified_nonsecret_exposures": len(
            {outcome.item_id for outcome in negative_outcomes}
        ),
        "near_miss_count": len(near_miss_outcomes),
        "near_miss_target_count": len({o.item_id for o in near_miss_outcomes if o.item_id}),
        "near_miss_reason_counts": dict(Counter(o.reason_code for o in near_miss_outcomes if o.reason_code)),
        "near_miss_targets": [item.item_id for item in positives if item.item_id in {o.item_id for o in near_miss_outcomes}],
        "unmatched_pending_review_count": len(unmatched_outcomes),
        "unverified_evidence_count": len(unverified_outcomes),
        "ambiguous_count": len(ambiguous_outcomes),
        "unsupported_capability_count": 0,
        "accounted_finding_count": len(outcomes),
        "target_accounting_reconciled": len(matched_positive) + len(missed_positive) == len(positives),
        "finding_accounting_reconciled": len(outcomes) == len(findings),
        "accounted_percent": round(100.0 * len(outcomes) / len(findings), 2)
        if findings
        else 100.0,
        "precision_percent": None,
        "f1_percent": None,
        "precision_certification_status": "BLOCKED_INCOMPLETE_NEGATIVE_ORACLE",
        "negative_oracle": True,
        "unmatched_positive_container_counts": dict(container_misses),
    }
    if metrics["accounted_finding_count"] != metrics["observed_findings"]:
        raise RncLabError(
            f"{lane} finding accountability does not reconcile: "
            f"{metrics['accounted_finding_count']} != {metrics['observed_findings']}"
        )
    exceptions = []
    for outcome in outcomes:
        if outcome.classification in (
            MATCH_NEAR_MISS,
            MATCH_UNMATCHED,
            MATCH_UNVERIFIED,
            MATCH_FP,
            MATCH_AMBIGUOUS,
        ):
            exceptions.append(
                {
                    "classification": outcome.classification,
                    "path": outcome.finding.file,
                    "line": outcome.finding.line,
                    "rule_id": outcome.finding.rule_id,
                    "expected_id": outcome.item_id,
                    "reason": outcome.reason,
                    "reason_code": outcome.reason_code,
                    "stage": outcome.stage,
                    "evidence_kind": outcome.evidence_kind,
                    "candidate_ids": list(outcome.candidate_ids),
                }
            )
    exceptions.extend(
        {
            "classification": "MISSED_EXPECTATION",
            "path": item.source_path,
            "line": item.line,
            "expected_id": item.item_id,
            "reason": f"{item.category}/{item.subtype} in {item.container_kind}",
        }
        for item in missed_positive[:200]
    )
    return {
        "metrics": metrics,
        "categories": category_rows,
        "representations": representation_rows,
        "exception_count": len(exceptions),
        "exceptions": exceptions[:250],
        "exceptions_truncated": len(exceptions) > 250,
        "accounted": len(outcomes),
        "findings": [
            {
                **outcome.finding.safe,
                "classification": outcome.classification,
                "expected_id": outcome.item_id,
                "reason_code": outcome.reason_code,
                "stage": outcome.stage,
                "evidence_kind": outcome.evidence_kind,
                "candidate_ids": list(outcome.candidate_ids),
            }
            for outcome in outcomes
        ],
        "matched_positive_ids": [item.item_id for item in matched_positive],
        "missed_positive_ids": [item.item_id for item in missed_positive],
    }


def score_findings(
    dataset: LabDataset,
    lane: str,
    normalized_findings: list,
) -> dict:
    root = dataset.filesystem_root if lane == "filesystem" else dataset.history_root
    ancestors = _commit_ancestors(root) if lane == "git" else None
    result = _attribute(
        dataset,
        lane,
        normalized_findings,
        source_root=root,
        commit_ancestors=ancestors,
    )
    result["lane"] = lane
    result["counts"] = dataset.counts(lane)
    result["source_root"] = str(root)
    if lane == "git":
        result["git_commit_count"] = len(ancestors or {})
    return result


# ---------------------------------------------------------------------------
# Local load-workload generation
# ---------------------------------------------------------------------------


def _copy_lab_subset(dataset: LabDataset, destination: Path) -> Path:
    """Copy only what the lab stress generator needs into a disposable root."""
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    shutil.copy2(dataset.root / "lab.toml", destination / "lab.toml")
    shutil.copytree(
        dataset.root / "generator",
        destination / "generator",
        symlinks=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    shutil.copytree(
        dataset.root / "corpus" / "filesystem",
        destination / "corpus" / "filesystem",
        symlinks=True,
    )
    return destination


def generate_stress(
    dataset: LabDataset,
    work_dir: Path | str,
    profile: str,
    *,
    timeout: int = 900,
) -> dict:
    """Generate a run-owned legacy-Nx workload from a disposable lab copy."""
    if profile not in ("legacy-5x", "legacy-10x"):
        raise RncLabError(f"unsupported lab load profile: {profile}")
    work_dir = Path(work_dir).resolve()
    lab_copy = work_dir / "lab"
    _copy_lab_subset(dataset, lab_copy)
    out_root = lab_copy / "stress-runs"
    command = [
        os.fspath(Path(os.sys.executable)),
        str(lab_copy / "generator" / "stress.py"),
        "--profile",
        profile,
        "--out",
        str(out_root),
    ]
    try:
        result = subprocess.run(
            command,
            cwd=str(lab_copy),
            capture_output=True,
            timeout=timeout,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        shutil.rmtree(lab_copy, ignore_errors=True)
        raise RncLabError(f"lab stress generation failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        shutil.rmtree(lab_copy, ignore_errors=True)
        raise RncLabError(
            f"lab stress generation failed: {detail[0][:300] if detail else 'no diagnostic'}"
        )
    target = out_root / "factor-5" if profile == "legacy-5x" else out_root / "factor-10"
    manifest_path = target / "manifest.json"
    if not manifest_path.is_file():
        shutil.rmtree(lab_copy, ignore_errors=True)
        raise RncLabError("lab stress generator produced no manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = sum(1 for path in target.rglob("*") if path.is_file())
    byte_count = sum(path.stat().st_size for path in target.rglob("*") if path.is_file())
    # The generator writes manifest.json after finalising its file/byte counts.
    expected_files = int(manifest.get("files") or 0) + 1
    expected_bytes = int(manifest.get("bytes") or 0) + manifest_path.stat().st_size
    if files != expected_files or byte_count != expected_bytes:
        shutil.rmtree(lab_copy, ignore_errors=True)
        raise RncLabError(
            "generated lab stress inventory does not match its manifest "
            f"(files {files}/{expected_files}, bytes {byte_count}/{expected_bytes})"
        )
    return {
        "profile": profile,
        "multiplier": 5 if profile == "legacy-5x" else 10,
        "target": str(target),
        "lab_copy": str(lab_copy),
        "manifest": manifest,
        "files": files,
        "bytes": byte_count,
        "command": command,
    }


def cleanup_stress(generated: dict) -> None:
    lab_copy = Path(generated.get("lab_copy") or "")
    if lab_copy.exists():
        shutil.rmtree(lab_copy, ignore_errors=True)
