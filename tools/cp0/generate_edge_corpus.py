"""Generate deterministic edge-case synthetic inputs that are impractical to commit.

The generator owns the answer key from the bytes it writes. It never invokes a
scanner and never creates a real credential. Large and oversize files are
created under the caller-provided output directory only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


MARKER = b"RNC_SYNTH_KEY_"
FILLER = b"benign-edge-fixture-0123456789-abcdefghijklmnopqrstuvwxyz\n"


def _filler(size: int) -> bytearray:
    return bytearray((FILLER * (size // len(FILLER) + 1))[:size])


def _place(data: bytearray, offset: int, marker: bytes) -> None:
    if offset < 0 or offset + len(marker) > len(data):
        raise ValueError("marker placement outside the generated file")
    data[offset : offset + len(marker)] = marker


def _target(target_id: str, relative: str, data: bytes, expected: list[dict], *, scope: str = "INSPECTED", required: bool = True, reason: str | None = None) -> dict:
    target = {
        "id": target_id,
        "path": relative,
        "scope": scope,
        "required": required,
        "labels": ["generated-edge"],
        "sha256": hashlib.sha256(data).hexdigest(),
        "byte_length": len(data),
        "expected": expected,
    }
    if reason:
        target["reason_codes"] = [reason]
    return target


def build(destination: Path) -> dict:
    destination.mkdir(parents=True, exist_ok=True)
    targets: list[dict] = []

    large = _filler(2 * 1024 * 1024)
    large_markers = [
        (0, b"RNC_SYNTH_KEY_EDGE_LARGE_ALPHA"),
        (1024 * 1024, b"RNC_SYNTH_KEY_EDGE_LARGE_BRAVO"),
        (len(large) - 32, b"RNC_SYNTH_KEY_EDGE_LARGE_CHARLIE"),
    ]
    for offset, marker in large_markers:
        _place(large, offset, marker)
    large_path = destination / "large-2m.bin"
    large_path.write_bytes(large)
    targets.append(_target(
        "large-2m",
        "large-2m.bin",
        bytes(large),
        [
            {"marker": marker.decode("ascii"), "rule_id": "synthetic-edge-large", "rule_version": "synthetic-v1", "count": 1, "disposition": "ACTIONABLE", "start_byte": offset, "end_byte": offset + len(marker)}
            for offset, marker in large_markers
        ],
    ))

    # Exceeds the CP1 reference 8 MiB default. The marker is beyond the limit so
    # a correct adapter records an uninspected required unit, not a clean file.
    oversize = _filler(9 * 1024 * 1024)
    oversize_marker = b"RNC_SYNTH_KEY_EDGE_OVERSIZE_DELTA"
    oversize_offset = 8 * 1024 * 1024 + 128
    _place(oversize, oversize_offset, oversize_marker)
    oversize_path = destination / "oversize-9m.bin"
    oversize_path.write_bytes(oversize)
    targets.append(_target(
        "oversize-9m",
        "oversize-9m.bin",
        bytes(oversize),
        [
            {"marker": oversize_marker.decode("ascii"), "rule_id": "synthetic-edge-large", "rule_version": "synthetic-v1", "count": 1, "disposition": "ACTIONABLE", "start_byte": oversize_offset, "end_byte": oversize_offset + len(oversize_marker)}
        ],
        scope="UNINSPECTED",
        reason="FILE_SIZE_LIMIT",
    ))

    manifest = {
        "version": "synthetic-edge-v1.0",
        "description": "Deterministic large/oversize edge corpus. All values are nonfunctional synthetic markers.",
        "marker_prefix": "RNC_SYNTH_KEY_",
        "targets": targets,
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = build(args.output)
    print(json.dumps({
        "targets": len(manifest["targets"]),
        "bytes": sum(target["byte_length"] for target in manifest["targets"]),
        "manifest": str(args.output / "manifest.json"),
    }, indent=2))


if __name__ == "__main__":
    main()
