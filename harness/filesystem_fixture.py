"""Deterministic filesystem control corpus for end-to-end adapter/scorer tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .contracts import TruthItem, TruthManifest

DATASET_ID = "rnc-synthetic-filesystem"
DATASET_VERSION = "1"
SECRETS = {
    "alpha": "RNC_AAAABBBBCCCCDDDD",
    "beta": "RNC_EEEEFFFFGGGGHHHH",
    "gamma": "RNC_IIIIJJJJKKKKLLLL",
    "delta": "RNC_MMMMNNNNOOOOPPPP",
}


@dataclass(frozen=True)
class FilesystemCorpus:
    root: Path
    manifest: TruthManifest


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build(dest: Path | str) -> FilesystemCorpus:
    root = Path(dest)
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.env").write_text(
        f"API_KEY={SECRETS['alpha']}\nSAFE_SETTING=example\n", encoding="utf-8"
    )
    (root / "nested").mkdir()
    (root / "nested" / "db.json").write_text(
        '{\n  "password": "' + SECRETS["beta"] + '"\n}\n', encoding="utf-8"
    )
    (root / "multi.env").write_text(
        f"FIRST={SECRETS['gamma']}\nSECOND={SECRETS['delta']}\n", encoding="utf-8"
    )
    (root / "docs").mkdir()
    (root / "docs" / "safe.txt").write_text(
        "No credentials in this controlled negative file.\n", encoding="utf-8"
    )
    (root / "docs" / "safe.env").write_text(
        "LOG_LEVEL=debug\nSAFE_SETTING=example\n", encoding="utf-8"
    )
    items = (
        _item("app-alpha", "alpha", "app.env", 1),
        _item("db-beta", "beta", "nested/db.json", 2),
        _item("multi-gamma", "gamma", "multi.env", 1),
        _item("multi-delta", "delta", "multi.env", 2),
    )
    manifest = TruthManifest(
        manifest_id="rnc-synthetic-filesystem-truth",
        manifest_version="1",
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        items=items,
        scoring_policy={"id": "filesystem-controlled-v1", "version": "1"},
        integrity={"status": "PASS", "reason": "controlled synthetic corpus"},
        metadata={
            "negative_oracle": True,
            "negative_files": ["docs/safe.txt", "docs/safe.env"],
            "expected_count": 4,
            "note": "Custom scanner config restricts detection to the RNC token format.",
        },
    )
    return FilesystemCorpus(root=root, manifest=manifest)


def _item(finding_id: str, unique_id: str, path: str, line: int) -> TruthItem:
    return TruthItem(
        finding_id=f"{DATASET_ID}:{finding_id}",
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        path=path,
        category="risk",
        risk_bearing=True,
        line_start=line,
        line_end=line,
        location=f"{path}:{line}",
        source_reference=f"synthetic manifest {path}:{line}",
        matching_policy="line_range",
        fingerprint_sha256=hashlib.sha256(f"{unique_id}:{path}:{line}".encode()).hexdigest(),
        metadata={
            "unique_secret_id": unique_id,
            "verification_status": "VERIFIED",
            "value_fingerprints": [_sha(SECRETS[unique_id])],
            "requires_value": True,
        },
    )


def write_config(path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        'title = "rnc-synthetic-filesystem"\n'
        "\n"
        "[[rules]]\n"
        'id = "rnc-synthetic-filesystem-token"\n'
        'description = "controlled synthetic filesystem credential"\n'
        "regex = '''RNC_[A-Z0-9]{16}'''\n"
        "secretGroup = 0\n",
        encoding="utf-8",
    )
    return path
