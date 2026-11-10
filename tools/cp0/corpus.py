"""Independent synthetic truth loading and byte-level expansion.

The manifest declares the ground truth. This module locates declared harmless
markers in the fixture bytes and materializes expected byte ranges without
consulting any scanner output.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from tools.cp0.contracts import ContractViolation, canonical_json, sha256_bytes


ROOT = Path(__file__).resolve().parents[2]
V0 = ROOT / "tests/fixtures/synthetic-v0"
V1 = ROOT / "tests/fixtures/synthetic-v1"
MARKER_RE = re.compile(rb"RNC_SYNTH_KEY_[A-Z0-9_]+")
MARKER_PREFIX = b"RNC_SYNTH_KEY_"
SCOPE_VALUES = {"INSPECTED", "VERIFIED_BLOCKED", "UNINSPECTED"}


def load_manifest(path: Path) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ContractViolation("MANIFEST_UNREADABLE", f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("targets"), list):
        raise ContractViolation("MANIFEST_SHAPE", "manifest must contain a targets array")
    return document


def _occurrences(data: bytes, marker: str) -> list[tuple[int, int]]:
    needle = marker.encode("ascii")
    found: list[tuple[int, int]] = []
    offset = 0
    while True:
        index = data.find(needle, offset)
        if index < 0:
            return found
        found.append((index, index + len(needle)))
        offset = index + max(1, len(needle))


def _normalize_target(raw: dict, version: str) -> dict:
    target = dict(raw)
    target.setdefault("scope", "INSPECTED")
    target.setdefault("required", True)
    target.setdefault("labels", [])
    target.setdefault("rule_version", "synthetic-v0.1" if version.startswith("synthetic-v0") else "synthetic-v1")
    if target["scope"] not in SCOPE_VALUES:
        raise ContractViolation("MANIFEST_SCOPE", f"unknown scope for {target.get('id')}")
    if not isinstance(target.get("expected", []), list):
        raise ContractViolation("MANIFEST_EXPECTED", f"expected must be a list for {target.get('id')}")
    return target


def validate_manifest(path: Path, *, require_floor: bool = False) -> dict:
    manifest = load_manifest(path)
    root = path.parent.resolve()
    version = str(manifest.get("version", ""))
    if not version:
        raise ContractViolation("MANIFEST_VERSION", "manifest version is required")
    targets = [_normalize_target(raw, version) for raw in manifest["targets"]]
    ids: set[str] = set()
    paths: set[str] = set()
    marker_counts: dict[tuple[str, str], int] = {}
    expected_count = 0
    known_marker_count = 0
    contents: dict[str, bytes] = {}
    expected_findings: list[dict] = []
    for target in targets:
        target_id = target.get("id")
        relative = target.get("path")
        if not isinstance(target_id, str) or not target_id or target_id in ids:
            raise ContractViolation("MANIFEST_TARGET_ID", f"invalid/duplicate target ID {target_id!r}")
        if not isinstance(relative, str) or not relative or relative in paths:
            raise ContractViolation("MANIFEST_TARGET_PATH", f"invalid/duplicate path for {target_id}")
        ids.add(target_id)
        paths.add(relative)
        fixture = (root / relative).resolve()
        if not fixture.is_relative_to(root):
            raise ContractViolation("MANIFEST_PATH_ESCAPE", f"target {target_id} escapes the corpus root")
        if not fixture.is_file():
            raise ContractViolation("MANIFEST_TARGET_MISSING", f"target {target_id} does not exist at {relative}")
        data = fixture.read_bytes()
        contents[target_id] = data
        if "sha256" in target:
            actual_hash = hashlib.sha256(data).hexdigest()
            if actual_hash != target["sha256"]:
                raise ContractViolation("MANIFEST_HASH", f"target {target_id} hash mismatch")
        target_markers: dict[str, int] = {}
        for expected in target["expected"]:
            marker = expected.get("marker")
            count = expected.get("count")
            rule_id = expected.get("rule_id")
            if not isinstance(marker, str) or not MARKER_RE.fullmatch(marker.encode("ascii")):
                raise ContractViolation("MANIFEST_MARKER", f"invalid marker declaration in {target_id}")
            if not isinstance(rule_id, str) or not rule_id:
                raise ContractViolation("MANIFEST_RULE", f"missing rule ID in {target_id}")
            if not isinstance(count, int) or count < 1:
                raise ContractViolation("MANIFEST_COUNT", f"invalid count in {target_id}")
            occurrences = _occurrences(data, marker)
            if len(occurrences) != count:
                raise ContractViolation(
                    "MANIFEST_COUNT_MISMATCH",
                    f"{target_id}: marker {marker} occurs {len(occurrences)} times but {count} was declared",
                )
            previous = marker_counts.get((target_id, marker))
            if previous is not None and previous != count:
                raise ContractViolation("MANIFEST_MARKER_DUPLICATE", f"marker {marker} has conflicting counts")
            marker_counts[(target_id, marker)] = count
            target_markers[marker] = count
            if target["scope"] != "INSPECTED":
                continue
            if "start_byte" in expected or "end_byte" in expected:
                start = expected.get("start_byte")
                end = expected.get("end_byte")
                if not isinstance(start, int) or not isinstance(end, int) or (start, end) not in occurrences:
                    raise ContractViolation("MANIFEST_OFFSET", f"declared offset for {marker} does not match its bytes")
                occurrences = [(start, end)]
            for start, end in occurrences:
                expected_findings.append({
                    "target_id": target_id,
                    "path": relative,
                    "rule_id": rule_id,
                    "rule_version": expected.get("rule_version") or target["rule_version"],
                    "start_byte": start,
                    "end_byte": end,
                    "evidence_digest": sha256_bytes(data[start:end]),
                    "disposition": expected.get("disposition", "ACTIONABLE"),
                    "expected_id": "e-" + hashlib.sha256(
                        f"{target_id}\0{rule_id}\0{start}\0{end}".encode("utf-8")
                    ).hexdigest(),
                })
                expected_count += 1
        observed_markers = len(MARKER_RE.findall(data))
        declared_markers = sum(target_markers.values())
        if observed_markers != declared_markers:
            raise ContractViolation(
                "MANIFEST_MARKER_COVERAGE",
                f"{target_id}: observed {observed_markers} marker occurrences but declared {declared_markers}",
            )
        known_marker_count += declared_markers
    if require_floor and (len(targets) < 20 or expected_count < 20):
        raise ContractViolation("MANIFEST_FLOOR", "expanded authored corpus is below its minimum size")
    expected_findings.sort(key=lambda item: (item["target_id"], item["start_byte"], item["rule_id"]))
    summary = {
        "version": version,
        "manifest_sha256": manifest_digest(manifest),
        "targets": len(targets),
        "inspected_targets": sum(target["scope"] == "INSPECTED" for target in targets),
        "verified_blocked_targets": sum(target["scope"] == "VERIFIED_BLOCKED" for target in targets),
        "uninspected_targets": sum(target["scope"] == "UNINSPECTED" for target in targets),
        "required_targets": sum(bool(target["required"]) for target in targets),
        "optional_targets": sum(not bool(target["required"]) for target in targets),
        "known_markers": known_marker_count,
        "expected_findings": len(expected_findings),
        "expected_actionable": sum(item["disposition"] == "ACTIONABLE" for item in expected_findings),
        "expected_exempted": sum(item["disposition"] == "EXEMPTED" for item in expected_findings),
    }
    return {
        "manifest": manifest,
        "targets": targets,
        "contents": contents,
        "expected_findings": expected_findings,
        "summary": summary,
    }


def load_v0() -> dict:
    return validate_manifest(V0 / "manifest.json")


def load_v1() -> dict:
    return validate_manifest(V1 / "manifest.json", require_floor=True)


def target_findings(target: Mapping[str, Any], data: bytes, default_rule_version: str) -> list[dict]:
    """Materialize every declared marker in one target, including blocked scope.

    The result is ground truth, not scanner output. Callers decide whether a
    target's scope makes those findings eligible for scoring.
    """
    result: list[dict] = []
    for expected in target.get("expected", []):
        marker = expected["marker"]
        for start, end in _occurrences(data, marker):
            result.append({
                "target_id": target["id"],
                "path": target["path"],
                "rule_id": expected["rule_id"],
                "rule_version": expected.get("rule_version") or default_rule_version,
                "start_byte": start,
                "end_byte": end,
                "evidence_digest": sha256_bytes(data[start:end]),
                "disposition": expected.get("disposition", "ACTIONABLE"),
                "marker": marker,
            })
    result.sort(key=lambda item: (item["start_byte"], item["end_byte"], item["rule_id"]))
    return result


def target_unit_id(target: Mapping[str, Any], manifest_version: str) -> str:
    from tools.cp0.contracts import make_unit_id

    source_id = "synthetic-corpus"
    if manifest_version:
        source_id += ":" + manifest_version
    return make_unit_id(source_id, target["path"])


def manifest_digest(document: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()
