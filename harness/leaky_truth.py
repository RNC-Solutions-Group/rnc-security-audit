"""Validation of the RNC Leaky Repo finding-level truth manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import truth
from .contracts import EXPECTED_DETECTION, TruthManifest


def _line_fingerprint(root: Path, relative: str, start: int, end: int) -> str:
    lines = (root / relative).read_text(encoding="utf-8", errors="replace").splitlines()
    text = "\n".join(lines[start - 1 : end])
    return hashlib.sha256(
        f"{relative}:{start}:{end}:{text}".encode("utf-8")
    ).hexdigest()


def validate(manifest: TruthManifest, dataset_root: Path | str) -> TruthManifest:
    root = Path(dataset_root)
    errors: list[str] = []
    if len(manifest.items) != 175:
        errors.append(f"item count is {len(manifest.items)}, expected 175")
    rows: dict[str, int] = {}
    for item in manifest.items:
        rows[item.path] = rows.get(item.path, 0) + 1
        path = root / item.path
        if not path.is_file():
            errors.append(f"missing source file: {item.path}")
            continue
        if item.line_start is None:
            errors.append(f"item has no source line: {item.finding_id}")
            continue
        end = item.line_end if item.line_end is not None else item.line_start
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if end > len(lines):
            errors.append(f"line range out of bounds: {item.finding_id}")
            continue
        fingerprint = _line_fingerprint(root, item.path, item.line_start, end)
        if item.fingerprint_sha256 != fingerprint:
            errors.append(f"line fingerprint mismatch: {item.finding_id}")
        if item.classification != EXPECTED_DETECTION:
            errors.append(f"unexpected truth classification: {item.finding_id}")
    if len(rows) != 44:
        errors.append(f"file count is {len(rows)}, expected 44")
    inventory_path = Path("datasets/leaky-repo.inventory.json")
    inventory_rows = []
    if inventory_path.is_file():
        try:
            inventory_rows = json.loads(inventory_path.read_text(encoding="utf-8")).get(
                "rows", []
            )
        except (OSError, ValueError):
            inventory_rows = []
    if not inventory_rows:
        errors.append("pinned Leaky Repo inventory is missing or unreadable")
    rnc_by_path: dict[str, list] = {}
    for item in manifest.items:
        rnc_by_path.setdefault(item.path, []).append(item)
    per_file = []
    for row in inventory_rows:
        items = rnc_by_path.get(row["path"], [])
        risk_count = sum(item.category == "risk" for item in items)
        info_count = sum(item.category == "informative" for item in items)
        total_ok = len(items) == row.get("total")
        if not total_ok:
            errors.append(
                f"per-file total mismatch for {row['path']}: {len(items)} != {row.get('total')}"
            )
        conflict = risk_count != row.get("risk") or info_count != row.get("informative")
        annotated = any(item.category_conflict for item in items)
        if conflict and not annotated:
            errors.append(
                f"unannotated category conflict for {row['path']}: "
                f"{risk_count}/{info_count} vs {row.get('risk')}/{row.get('informative')}"
            )
        per_file.append(
            {
                "path": row["path"],
                "expected_total": row.get("total"),
                "items": len(items),
                "upstream_risk": row.get("risk"),
                "upstream_informative": row.get("informative"),
                "rnc_risk": risk_count,
                "rnc_informative": info_count,
                "status": "CONFLICT" if conflict else "MATCH",
                "annotated": annotated,
            }
        )
    missing_rows = sorted(set(rnc_by_path) - {row["path"] for row in inventory_rows})
    if missing_rows:
        errors.append(f"truth files absent from inventory: {missing_rows[:5]}")
    risk = sum(item.category == "risk" for item in manifest.items)
    informative = sum(item.category == "informative" for item in manifest.items)
    if risk + informative != 175:
        errors.append("category totals do not cover all items")
    status = "PASS" if not errors else "FAIL"
    reason = None if not errors else "; ".join(errors[:8])
    manifest.integrity.update(
        {
            "status": status,
            "reason": reason,
            "verified_root": str(root.resolve()),
            "verified_file_count": len(rows),
            "verified_item_count": len(manifest.items),
            "verified_risk": risk,
            "verified_informative": informative,
            "per_file": per_file,
            "category_reconciliation": {
                "status": "CONFLICT" if risk != 96 or informative != 79 else "PASS",
                "upstream_risk": 96,
                "upstream_informative": 79,
                "rnc_risk": risk,
                "rnc_informative": informative,
                "conflicted_files": manifest.category_reconciliation.get(
                    "conflict_rows", []
                ),
            },
        }
    )
    return manifest


def reconciliation_report(manifest: TruthManifest, inventory: dict) -> dict:
    rows_by_path = {row["path"]: row for row in inventory.get("rows", [])}
    rnc_by_path: dict[str, dict] = {}
    for item in manifest.items:
        bucket = rnc_by_path.setdefault(
            item.path, {"risk": 0, "informative": 0, "items": 0, "conflicts": 0}
        )
        bucket[item.category] = bucket.get(item.category, 0) + 1
        bucket["items"] += 1
        if item.category_conflict:
            bucket["conflicts"] += 1
    files = []
    for path, bucket in sorted(rnc_by_path.items()):
        upstream = rows_by_path.get(path, {})
        status = (
            "MATCH"
            if bucket.get("risk") == upstream.get("risk")
            and bucket.get("informative") == upstream.get("informative")
            else "CONFLICT"
        )
        files.append(
            {
                "path": path,
                "upstream_risk": upstream.get("risk"),
                "upstream_informative": upstream.get("informative"),
                "rnc_risk": bucket.get("risk"),
                "rnc_informative": bucket.get("informative"),
                "expected_total": upstream.get("total"),
                "rnc_items": bucket["items"],
                "status": status,
                "conflict_items": bucket["conflicts"],
            }
        )
    return {
        "dataset_id": manifest.dataset_id,
        "dataset_version": manifest.dataset_version,
        "manifest_version": manifest.manifest_version,
        "integrity": manifest.integrity,
        "upstream": {
            "files": len(rows_by_path),
            "risk": sum(row.get("risk", 0) for row in rows_by_path.values()),
            "informative": sum(row.get("informative", 0) for row in rows_by_path.values()),
            "total": sum(row.get("total", 0) for row in rows_by_path.values()),
        },
        "rnc": {
            "files": len(rnc_by_path),
            "risk": sum(item.category == "risk" for item in manifest.items),
            "informative": sum(item.category == "informative" for item in manifest.items),
            "items": len(manifest.items),
            "conflict_items": sum(item.category_conflict for item in manifest.items),
        },
        "files": files,
        "conflicts": [item for item in files if item["status"] == "CONFLICT"],
    }


def load_validated(
    manifest_path: Path | str, dataset_root: Path | str
) -> TruthManifest:
    return validate(truth.load(manifest_path), dataset_root)
