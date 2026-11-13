"""Pinned Leaky Repo dataset acquisition and count-based benchmark scoring.

Leaky Repo is used as a filesystem benchmark, not as a credential-level answer
key. Its published counts are risk/informative count units; the harness reports
count coverage, files covered, and excess findings without converting them to
strict TP/FP labels.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import DatasetError
from .manifest import DEFAULT_MANIFEST, LeakyRepoSpec, Manifest, load_manifest
from .util import atomic_write_text, sha256_bytes, sha256_file, utc_stamp

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CACHE = ROOT / "datasets" / "cache"
_GIT_TIMEOUT = 300


@dataclass(frozen=True)
class PreparedLeakyRepo:
    manifest: Manifest
    spec: LeakyRepoSpec
    root: Path
    source: Path
    inventory: dict
    inventory_sha256: str

    @property
    def revision(self) -> str:
        return self.spec.revision

    @property
    def rows(self) -> list[dict]:
        return list(self.inventory.get("rows", []))


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
        raise DatasetError(
            f"{what} failed (exit {result.returncode}): "
            f"{detail[0][:300] if detail else 'no diagnostic'}"
        )
    return result


def _git_text(source: Path, args: list[str], what: str) -> str:
    return _run_git(["git", "-C", str(source), *args], what).stdout.decode(
        "utf-8", "replace"
    ).strip()


def _git_blob(source: Path, revision: str, relative: str, what: str) -> bytes:
    return _run_git(
        ["git", "-C", str(source), "cat-file", "blob", f"{revision}:{relative}"],
        what,
    ).stdout


def _quarantine(root: Path) -> None:
    stamp = utc_stamp()
    for child in sorted(root.iterdir()):
        target = child.with_name(f"{child.name}.corrupt-{stamp}")
        counter = 1
        while target.exists():
            counter += 1
            target = child.with_name(f"{child.name}.corrupt-{stamp}-{counter}")
        last_error: OSError | None = None
        for attempt in range(6):
            try:
                child.rename(target)
                break
            except PermissionError as exc:
                last_error = exc
                time.sleep(0.2 * (attempt + 1))
        else:
            raise DatasetError(
                f"could not quarantine Leaky Repo cache entry {child}: {last_error}"
            )


def _ensure_source(
    spec: LeakyRepoSpec,
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
            raise DatasetError(f"Leaky Repo cache is not a Git checkout: {source}")
        _quarantine(root)
        root.mkdir(parents=True, exist_ok=True)
    if not source.exists():
        if offline:
            raise DatasetError(
                f"Leaky Repo cache is not prepared at {source}; run prepare once online"
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
        _run_git(
            [
                "git",
                "-C",
                str(source),
                "checkout",
                "--quiet",
                "--detach",
                spec.revision,
            ],
            f"checkout of Leaky Repo {spec.revision[:12]}",
        )
    else:
        head = _git_text(source, ["rev-parse", "HEAD"], "read Leaky Repo HEAD")
        if head != spec.revision:
            if offline:
                raise DatasetError(
                    f"Leaky Repo cache is at {head[:12]}, not pinned {spec.revision[:12]}"
                )
            _run_git(
                ["git", "-C", str(source), "fetch", "--quiet", "origin"],
                "fetch Leaky Repo",
            )
            _run_git(
                [
                    "git",
                    "-C",
                    str(source),
                    "checkout",
                    "--quiet",
                    "--detach",
                    spec.revision,
                ],
                "checkout pinned Leaky Repo revision",
            )
    head = _git_text(source, ["rev-parse", "HEAD"], "verify Leaky Repo HEAD")
    if head != spec.revision:
        raise DatasetError(f"Leaky Repo HEAD is {head}, expected {spec.revision}")
    if _git_text(source, ["status", "--porcelain"], "check Leaky Repo cleanliness"):
        raise DatasetError("Leaky Repo checkout working tree is modified; refusing to use it")


def _canonical_inventory_digest(inventory: dict) -> str:
    canonical = json.dumps(
        {
            "rows": inventory.get("rows", []),
            "files": inventory.get("files", []),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _verify_inventory(
    spec: LeakyRepoSpec,
    source: Path,
    inventory: dict,
) -> None:
    if inventory.get("source_revision") != spec.revision:
        raise DatasetError("Leaky Repo inventory revision does not match the manifest pin")
    if inventory.get("inventory_digest") != _canonical_inventory_digest(inventory):
        raise DatasetError("Leaky Repo inventory digest is invalid")
    rows = inventory.get("rows")
    files = inventory.get("files")
    if not isinstance(rows, list) or not isinstance(files, list):
        raise DatasetError("Leaky Repo inventory must contain rows and files arrays")
    if len(rows) != spec.expected_files:
        raise DatasetError(
            f"Leaky Repo row count is {len(rows)}, expected {spec.expected_files}"
        )
    totals = {
        "risk": sum(int(row.get("risk", 0)) for row in rows),
        "informative": sum(int(row.get("informative", 0)) for row in rows),
        "total": sum(int(row.get("total", 0)) for row in rows),
    }
    if totals != {
        "risk": spec.expected_risk,
        "informative": spec.expected_informative,
        "total": spec.expected_count,
    }:
        raise DatasetError(
            f"Leaky Repo count totals {totals} do not match the manifest pin"
        )
    by_path = {str(row.get("path")): row for row in rows}
    if len(by_path) != len(rows):
        raise DatasetError("Leaky Repo inventory contains duplicate row paths")
    for row in rows:
        path = str(row.get("path"))
        if row.get("total") != int(row.get("risk", 0)) + int(row.get("informative", 0)):
            raise DatasetError(f"Leaky Repo count row is inconsistent: {path}")
        blob = _git_blob(source, spec.revision, path, f"read Leaky Repo file {path}")
        expected_hash = next(
            (item.get("git_blob_sha256") for item in files if item.get("path") == path),
            None,
        )
        if not expected_hash:
            raise DatasetError(f"Leaky Repo inventory has no file record for {path}")
        if sha256_bytes(blob) != expected_hash:
            raise DatasetError(f"Leaky Repo file hash mismatch: {path}")
        expected_size = next(
            (int(item.get("size", -1)) for item in files if item.get("path") == path),
            -1,
        )
        if expected_size != len(blob):
            raise DatasetError(f"Leaky Repo file size mismatch: {path}")
    for item in files:
        if item.get("path") not in by_path:
            raise DatasetError(f"Leaky Repo file record is not a scoring row: {item.get('path')}")


def prepare(
    manifest_path: Path | str | None = None,
    cache_dir: Path | str = DEFAULT_CACHE,
    *,
    offline: bool = False,
    refresh: bool = False,
) -> PreparedLeakyRepo:
    manifest = load_manifest(manifest_path or DEFAULT_MANIFEST)
    spec = manifest.leaky_repo
    if spec is None:
        raise DatasetError("no leaky_repo dataset entry in the manifest")
    if not spec.enabled or spec.status != "PINNED_AND_VERIFIED":
        raise DatasetError("Leaky Repo dataset is not enabled and pinned")
    if not spec.inventory_path.is_file() or sha256_file(spec.inventory_path) != spec.inventory_sha256:
        raise DatasetError("Leaky Repo inventory is missing or does not match the pinned hash")
    if (
        not spec.truth_manifest_path.is_file()
        or sha256_file(spec.truth_manifest_path) != spec.truth_manifest_sha256
    ):
        raise DatasetError("Leaky Repo truth manifest is missing or does not match the pinned hash")
    if spec.history_oracle_path is not None:
        if not spec.history_oracle_path.is_file() or sha256_file(
            spec.history_oracle_path
        ) != spec.history_oracle_sha256:
            raise DatasetError(
                "Leaky Repo history oracle is missing or does not match the pinned hash"
            )
    inventory = json.loads(spec.inventory_path.read_text(encoding="utf-8"))
    root = (Path(cache_dir) / "leaky-repo" / spec.revision).resolve()
    source = root / "source"
    _ensure_source(spec, root, source, offline=offline, refresh=refresh)

    license_blob = _git_blob(source, spec.revision, "LICENSE", "read Leaky Repo license")
    if sha256_bytes(license_blob) != spec.license_sha256:
        raise DatasetError("Leaky Repo LICENSE does not match the manifest hash")
    if b"MIT License" not in license_blob or b"Permission is hereby granted" not in license_blob:
        raise DatasetError("Leaky Repo LICENSE does not contain the expected MIT text")
    csv_blob = _git_blob(
        source,
        spec.revision,
        ".leaky-meta/secrets.csv",
        "read Leaky Repo scoring metadata",
    )
    if sha256_bytes(csv_blob) != inventory.get("scoring_csv_sha256"):
        raise DatasetError("Leaky Repo scoring CSV does not match the inventory hash")
    _verify_inventory(spec, source, inventory)
    return PreparedLeakyRepo(
        manifest=manifest,
        spec=spec,
        root=root,
        source=source,
        inventory=inventory,
        inventory_sha256=spec.inventory_sha256,
    )


def copy_scan_tree(prepared: PreparedLeakyRepo, destination: Path | str) -> Path:
    """Copy the worktree without .git so the benchmark scans files, not objects."""
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        prepared.source,
        destination,
        ignore=shutil.ignore_patterns(".git"),
    )
    return destination


def _relative_file(value: str, scan_root: Path) -> str | None:
    normalized = str(value).replace("\\", "/")
    if normalized.startswith("/scan/"):
        return normalized[len("/scan/") :]
    root = str(scan_root.resolve()).replace("\\", "/").rstrip("/")
    if normalized == root:
        return ""
    if normalized.startswith(root + "/"):
        return normalized[len(root) + 1 :]
    if normalized.startswith("./"):
        normalized = normalized[2:]
    # A relative report path is already relative to the scan root.
    if not normalized.startswith("/") and not (
        len(normalized) > 2 and normalized[1] == ":"
    ):
        return normalized
    return None


def score(findings, prepared: PreparedLeakyRepo, scan_root: Path | str) -> dict:
    scan_root = Path(scan_root)
    rows = {str(row["path"]): row for row in prepared.rows}
    observed: dict[str, int] = {path: 0 for path in rows}
    unlisted: list[dict] = []
    for finding in findings:
        relative = _relative_file(finding.file, scan_root)
        if relative is None:
            unlisted.append({"file": "<outside-scan-root>", "rule_id": finding.rule_id})
            continue
        if relative in rows:
            observed[relative] += 1
        else:
            unlisted.append({"file": relative, "rule_id": finding.rule_id})

    per_file = []
    for path, row in rows.items():
        count = observed[path]
        expected = int(row["total"])
        per_file.append(
            {
                "path": path,
                "expected_count": expected,
                "risk_count": int(row["risk"]),
                "informative_count": int(row["informative"]),
                "observed_findings": count,
                "covered_count": min(count, expected),
                "excess_findings": max(0, count - expected),
            }
        )
    expected_total = sum(item["expected_count"] for item in per_file)
    covered = sum(item["covered_count"] for item in per_file)
    files_covered = sum(1 for item in per_file if item["observed_findings"] > 0)
    total_observed = sum(item["observed_findings"] for item in per_file) + len(unlisted)
    return {
        "methodology": "count-based filesystem benchmark; not credential-level TP/FP",
        "counting_unit": prepared.spec.counting_unit,
        "expected_count": expected_total,
        "expected_risk_count": sum(item["risk_count"] for item in per_file),
        "expected_informative_count": sum(item["informative_count"] for item in per_file),
        "expected_files": len(per_file),
        "observed_findings": total_observed,
        "covered_count": covered,
        "count_coverage_percent": round(100.0 * covered / expected_total, 2)
        if expected_total
        else 0.0,
        "files_covered": files_covered,
        "files_covered_percent": round(100.0 * files_covered / len(per_file), 2)
        if per_file
        else 0.0,
        "excess_findings": sum(item["excess_findings"] for item in per_file),
        "unlisted_findings": len(unlisted),
        "unlisted": unlisted[:50],
        "per_file": per_file,
        "notes": [
            "Count coverage is min(observed, expected) summed over the 44 labeled file rows.",
            "Excess findings are observations above a row's published count and are not false positives.",
            "No credential-level TP, FP, precision, or recall is claimed for this benchmark.",
        ],
    }


def write_inventory_snapshot(prepared: PreparedLeakyRepo, path: Path) -> None:
    atomic_write_text(path, json.dumps(prepared.inventory, indent=2, sort_keys=True) + "\n")
