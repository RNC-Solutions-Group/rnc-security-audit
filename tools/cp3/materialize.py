"""Materialize review-safe provider fixtures from the committed hex bundle.

Raw provider-shaped fixture bytes are intentionally not committed: GitHub secret
scanning would treat harmless structural lookalikes as credentials. The bundle
contains only hex-encoded bytes; tests decode it into a temporary source root.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUNDLE = ROOT / "tests/fixtures/providers/bundle.json"


def load_bundle() -> dict:
    document = json.loads(BUNDLE.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1 or not isinstance(document.get("tiers"), dict):
        raise ValueError("unsupported provider fixture bundle")
    return document


def write_bundle(tiers: dict[str, Path], destination: Path = BUNDLE) -> dict:
    tier_values = {}
    for tier, root in tiers.items():
        files = {}
        for path in sorted(root.rglob("*")):
            if path.is_file():
                files[path.relative_to(root).as_posix()] = path.read_bytes().hex()
        tier_values[tier] = files
    document = {
        "schema_version": 1,
        "description": (
            "Hex-encoded deterministic provider fixtures. Materialize with "
            "tools.cp3.materialize.materialize; never scan this bundle directly."
        ),
        "tiers": tier_values,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return document


def materialize(tier: str, destination: Path) -> Path:
    document = load_bundle()
    files = document["tiers"].get(tier)
    if not isinstance(files, dict) or not files:
        raise ValueError(f"unknown provider fixture tier {tier!r}")
    root = Path(destination) / tier
    for relative, encoded in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bytes.fromhex(encoded))
    return root


def bundle_files() -> list[tuple[str, str, bytes]]:
    result = []
    for tier, files in sorted(load_bundle()["tiers"].items()):
        for relative, encoded in sorted(files.items()):
            result.append((tier, relative, bytes.fromhex(encoded)))
    return result
