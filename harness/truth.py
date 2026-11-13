"""Truth-manifest loading and structural validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .contracts import CLASSIFICATIONS, SCHEMA_VERSION, TruthItem, TruthManifest


class TruthError(ValueError):
    pass


def _item(raw: dict) -> TruthItem:
    if not isinstance(raw, dict):
        raise TruthError("truth item must be an object")
    required = ("finding_id", "dataset_id", "dataset_version", "path")
    for key in required:
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise TruthError(f"truth item is missing {key!r}")
    classification = raw.get("classification", "EXPECTED_DETECTION")
    if classification not in CLASSIFICATIONS:
        raise TruthError(f"unknown truth classification {classification!r}")
    line_start = raw.get("line_start")
    line_end = raw.get("line_end")
    for name, value in (("line_start", line_start), ("line_end", line_end)):
        if value is not None and (not isinstance(value, int) or value < 1):
            raise TruthError(f"truth item {raw['finding_id']}: invalid {name}")
    if line_start is not None and line_end is not None and line_end < line_start:
        raise TruthError(f"truth item {raw['finding_id']}: line_end precedes line_start")
    return TruthItem(
        finding_id=raw["finding_id"],
        dataset_id=raw["dataset_id"],
        dataset_version=raw["dataset_version"],
        path=raw["path"].replace("\\", "/"),
        classification=classification,
        category=str(raw.get("category", "")),
        risk_bearing=raw.get("risk_bearing"),
        line_start=line_start,
        line_end=line_end,
        location=raw.get("location"),
        commit=raw.get("commit"),
        fingerprint_sha256=raw.get("fingerprint_sha256"),
        source_reference=raw.get("source_reference"),
        matching_policy=str(raw.get("matching_policy", "line_range")),
        category_conflict=bool(raw.get("category_conflict", False)),
        notes=str(raw.get("notes", "")),
        expected_text=raw.get("expected_text"),
        expected_rule_id=raw.get("expected_rule_id"),
        metadata=raw.get("metadata") or {},
    )


def from_dict(document: dict) -> TruthManifest:
    if not isinstance(document, dict):
        raise TruthError("truth manifest must be an object")
    version = document.get("schema_version")
    if version != SCHEMA_VERSION:
        raise TruthError(f"unsupported truth schema_version {version!r}")
    items_raw = document.get("items")
    if not isinstance(items_raw, list) or not items_raw:
        raise TruthError("truth manifest must contain a non-empty items array")
    items = tuple(_item(raw) for raw in items_raw)
    ids = [item.finding_id for item in items]
    duplicates = sorted({value for value in ids if ids.count(value) > 1})
    if duplicates:
        raise TruthError(f"duplicate truth finding IDs: {', '.join(duplicates[:5])}")
    dataset_ids = {item.dataset_id for item in items}
    dataset_versions = {item.dataset_version for item in items}
    if len(dataset_ids) != 1 or len(dataset_versions) != 1:
        raise TruthError("truth manifest mixes dataset IDs or versions")
    return TruthManifest(
        manifest_id=str(document.get("manifest_id", "")),
        manifest_version=str(document.get("manifest_version", "")),
        dataset_id=next(iter(dataset_ids)),
        dataset_version=next(iter(dataset_versions)),
        items=items,
        schema_version=version,
        scoring_policy=document.get("scoring_policy") or {},
        category_reconciliation=document.get("category_reconciliation") or {},
        counts=document.get("counts") or {},
        integrity=document.get("integrity") or {},
        metadata=document.get("metadata") or {},
    )


def load(path: Path | str) -> TruthManifest:
    path = Path(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise TruthError(f"cannot read truth manifest {path}: {exc}") from exc
    manifest = from_dict(document)
    manifest.integrity.setdefault("status", "PASS")
    manifest.integrity.setdefault("file_sha256", hashlib.sha256(path.read_bytes()).hexdigest())
    return manifest


def safe_manifest_summary(manifest: TruthManifest) -> dict:
    return {
        "manifest_id": manifest.manifest_id,
        "manifest_version": manifest.manifest_version,
        "schema_version": manifest.schema_version,
        "dataset_id": manifest.dataset_id,
        "dataset_version": manifest.dataset_version,
        "items": len(manifest.items),
        "counts": manifest.counts,
        "scoring_policy": manifest.scoring_policy,
        "category_reconciliation": manifest.category_reconciliation,
        "integrity": manifest.integrity,
    }
