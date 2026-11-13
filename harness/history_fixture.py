"""Controlled synthetic Git history used to validate history scoring.

The corpus is deterministic: fixed author/committer identities and dates, so its
commit IDs are stable for a given Git implementation. It is deliberately small
and contains no real credentials.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .contracts import TruthItem, TruthManifest

DATASET_ID = "rnc-synthetic-history"
DATASET_VERSION = "1"
SECRETS = {
    "alpha": "RNC_AAAABBBBCCCCDDDD",
    "beta": "RNC_EEEEFFFFGGGGHHHH",
    "gamma": "RNC_IIIIJJJJKKKKLLLL",
}


@dataclass(frozen=True)
class HistoryCorpus:
    root: Path
    commits: dict[str, str]
    manifest: TruthManifest
    files: dict[str, list[str]]

    @property
    def scope(self) -> dict:
        return {
            "dataset_id": DATASET_ID,
            "dataset_version": DATASET_VERSION,
            "root": str(self.root),
            "commits": dict(self.commits),
            "commit_order": list(self.commits),
            "unique_secret_count": len({item.metadata["unique_secret_id"] for item in self.manifest.items}),
            "occurrence_count": len(self.manifest.items),
        }


def _git(root: Path, *args: str, env: dict | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, **(env or {})},
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _commit(root: Path, message: str, index: int) -> str:
    stamp = f"2024-01-0{index}T12:00:00+0000"
    env = {
        "GIT_AUTHOR_NAME": "RNC Harness",
        "GIT_AUTHOR_EMAIL": "harness@example.invalid",
        "GIT_COMMITTER_NAME": "RNC Harness",
        "GIT_COMMITTER_EMAIL": "harness@example.invalid",
        "GIT_AUTHOR_DATE": stamp,
        "GIT_COMMITTER_DATE": stamp,
    }
    _git(root, "add", "-A", env=env)
    _git(root, "commit", "-m", message, env=env)
    return _git(root, "rev-parse", "HEAD")


def build(dest: Path | str) -> HistoryCorpus:
    root = Path(dest)
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.name", "RNC Harness")
    _git(root, "config", "user.email", "harness@example.invalid")

    files: dict[str, list[str]] = {}
    commits: dict[str, str] = {}

    app = root / "config" / "app.env"
    app.parent.mkdir(parents=True)
    app.write_text(f"API_KEY={SECRETS['alpha']}\nSAFE_SETTING=example\n", encoding="utf-8")
    files["c1_app"] = ["config/app.env"]
    commits["c1"] = _commit(root, "add alpha key", 1)

    duplicate = root / "config" / "duplicate.env"
    duplicate.write_text(f"API_KEY={SECRETS['alpha']}\n", encoding="utf-8")
    files["c2_duplicate"] = ["config/duplicate.env"]
    commits["c2"] = _commit(root, "repeat alpha in another file", 2)

    app.write_text(f"API_KEY={SECRETS['beta']}\nSAFE_SETTING=example\n", encoding="utf-8")
    duplicate.unlink()
    deploy = root / "deploy" / "prod.env"
    deploy.parent.mkdir()
    deploy.write_text(f"DB_PASSWORD={SECRETS['beta']}\n", encoding="utf-8")
    files["c3_app"] = ["config/app.env"]
    files["c3_deploy"] = ["deploy/prod.env"]
    commits["c3"] = _commit(root, "replace alpha with beta and repeat beta", 3)

    legacy = root / "removed" / "legacy.env"
    legacy.parent.mkdir()
    legacy.write_text(f"TOKEN={SECRETS['gamma']}\n", encoding="utf-8")
    files["c4_legacy"] = ["removed/legacy.env"]
    commits["c4"] = _commit(root, "add gamma token", 4)

    legacy.unlink()
    files["c5_removal"] = ["removed/legacy.env"]
    commits["c5"] = _commit(root, "remove gamma token", 5)

    items = (
        _item("occ-alpha-c1", "alpha", commits["c1"], "config/app.env", 1, "current_absent_after_c2", "c1"),
        _item("occ-alpha-c2", "alpha", commits["c2"], "config/duplicate.env", 1, "historical_only", "c2"),
        _item("occ-beta-c3a", "beta", commits["c3"], "config/app.env", 1, "current", "c3"),
        _item("occ-beta-c3b", "beta", commits["c3"], "deploy/prod.env", 1, "current", "c3"),
        _item("occ-gamma-c4", "gamma", commits["c4"], "removed/legacy.env", 1, "historical_only", "c4"),
    )
    manifest = TruthManifest(
        manifest_id="rnc-synthetic-history-truth",
        manifest_version="1",
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        items=items,
        scoring_policy={"id": "git-history-occurrence-v1", "version": "1"},
        integrity={"status": "PASS", "reason": "controlled synthetic corpus"},
        metadata={
            "scope": "five deterministic commits",
            "unique_expected_secrets": 3,
            "expected_occurrences": 5,
            "unique_secret_ids": ["alpha", "beta", "gamma"],
        },
    )
    return HistoryCorpus(root=root, commits=commits, manifest=manifest, files=files)


def _item(
    finding_id: str,
    unique_id: str,
    commit: str,
    path: str,
    line: int,
    occurrence: str,
    commit_label: str,
) -> TruthItem:
    from .util import sha256_bytes

    return TruthItem(
        finding_id=f"{DATASET_ID}:{finding_id}",
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        path=path,
        category="risk",
        risk_bearing=True,
        line_start=line,
        line_end=line,
        commit=commit,
        location=f"{path}:{line}@{commit_label}",
        source_reference=f"synthetic manifest {commit_label}:{path}:{line}",
        matching_policy="line_range",
        fingerprint_sha256=sha256_bytes(f"{unique_id}:{commit}:{path}:{line}".encode()),
        metadata={
            "unique_secret_id": unique_id,
            "occurrence_kind": occurrence,
            "value_fingerprints": [sha256_bytes(SECRETS[unique_id].encode())],
            "verification_status": "VERIFIED",
        },
    )


def write_config(path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        'title = "rnc-synthetic-history"\n'
        "\n"
        "[[rules]]\n"
        'id = "rnc-synthetic-history-token"\n'
        'description = "controlled synthetic history credential"\n'
        "regex = '''RNC_[A-Z0-9]{16}'''\n"
        "secretGroup = 0\n",
        encoding="utf-8",
    )
    return path
