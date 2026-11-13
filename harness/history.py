"""Git-history discovery for benchmark scope and truth limitations.

This module discovers what can be established from a pinned repository's
history. It never invents secret-level historical truth: if no independently
verified history manifest exists, the result is explicitly ``BLOCKED``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

SCOPE_VERSION = "1"


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def discover(repo: Path | str) -> dict:
    repo = Path(repo)
    head = _git(repo, "rev-parse", "HEAD").strip()
    commits = int(_git(repo, "rev-list", "--count", "HEAD").strip())
    root = _git(repo, "rev-list", "--max-parents=0", "HEAD").strip().splitlines()
    first = root[0] if root else None
    current_files = [
        line
        for line in _git(repo, "ls-tree", "-r", "--name-only", "HEAD").splitlines()
        if line
    ]
    blob_groups: dict[str, list[str]] = {}
    for line in _git(repo, "ls-tree", "-r", "HEAD").splitlines():
        if "\t" not in line:
            continue
        metadata, path = line.split("\t", 1)
        blob = metadata.split()[2]
        blob_groups.setdefault(blob, []).append(path.replace("\\", "/"))
    duplicate_blobs = {
        blob: paths for blob, paths in blob_groups.items() if len(paths) > 1
    }
    additions = modifications = deletions = 0
    renames: list[dict] = []
    changed_paths: set[str] = set()
    log = _git(
        repo,
        "log",
        "--find-renames",
        "--name-status",
        "--format=__commit__%H",
        "HEAD",
    )
    commit = None
    for line in log.splitlines():
        if line.startswith("__commit__"):
            commit = line.removeprefix("__commit__")
            continue
        if not line.strip() or "\t" not in line:
            continue
        fields = line.split("\t")
        status = fields[0]
        if status.startswith("R") and len(fields) >= 3:
            renames.append(
                {
                    "commit": commit,
                    "from": fields[1].replace("\\", "/"),
                    "to": fields[2].replace("\\", "/"),
                }
            )
            changed_paths.update(fields[1:])
        elif len(fields) >= 2:
            path = fields[1].replace("\\", "/")
            changed_paths.add(path)
            if status.startswith("A"):
                additions += 1
            elif status.startswith("M"):
                modifications += 1
            elif status.startswith("D"):
                deletions += 1
    current_set = set(current_files)
    historical_only = sorted(changed_paths - current_set)
    current_only = sorted(current_set - changed_paths)
    objects = [
        line.split(" ", 1)
        for line in _git(repo, "rev-list", "--objects", "--all").splitlines()
        if " " in line
    ]
    blob_ids = {oid for oid, _ in objects}
    return {
        "scope_version": SCOPE_VERSION,
        "dataset_id": "leaky-repo",
        "dataset_version": head,
        "head": head,
        "first_commit": first,
        "commit_count": commits,
        "current_file_count": len(current_files),
        "changed_path_count": len(changed_paths),
        "historical_only_path_count": len(historical_only),
        "current_only_path_count": len(current_only),
        "additions": additions,
        "modifications": modifications,
        "deletions": deletions,
        "renames": renames,
        "duplicate_blob_group_count": len(duplicate_blobs),
        "duplicate_blob_groups": [
            {"blob": blob, "paths": paths}
            for blob, paths in sorted(duplicate_blobs.items())[:20]
        ],
        "historical_only_paths": historical_only[:100],
        "current_only_paths": current_only[:100],
        "object_count": len(blob_ids),
        "history_truth_status": "BLOCKED",
        "reason": (
            "The pinned repository has no independently verified per-commit secret "
            "manifest. Git-history observations cannot be converted into recall or "
            "precision without inventing historical expectations."
        ),
        "current_truth_manifest": "datasets/leaky-repo.rnc-truth.json",
        "current_truth_scope": "pinned working tree only",
        "filesystem_denominator_reusable": False,
        "verified_historical_findings": 0,
        "unverified_history_observations": "reported separately by the Leaky Repo history mode",
    }
