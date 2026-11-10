"""Manifest-driven synthetic adapter stub for an independent evaluation harness.

This deliberately reads the answer key and therefore CANNOT evaluate the
accuracy of a production scanner. It tests only the harness's normalization and
scoring contract. Never include this stub in a scanner release.
"""

from __future__ import annotations

import argparse
import hashlib
import json

from tools.cp0.validate import FIXTURES, load_json


def events(mode: str) -> list[dict]:
    manifest = load_json(FIXTURES / "manifest.json")
    result = []
    for target in manifest["targets"]:
        if target.get("scope") == "VERIFIED_BLOCKED":
            continue
        data = (FIXTURES / target["path"]).read_bytes()
        for expected in target["expected"]:
            needle = expected["marker"].encode("ascii")
            offset = 0
            while True:
                index = data.find(needle, offset)
                if index < 0:
                    break
                result.append({
                    "target_id": target["id"],
                    "rule_id": expected["rule_id"],
                    "start_byte": index,
                    "end_byte": index + len(needle),
                    "evidence_digest": "sha256:" + hashlib.sha256(needle).hexdigest(),
                })
                offset = index + len(needle)

    if mode == "miss-one":
        result = result[1:]
    elif mode == "false-positive":
        result.append({"target_id": "clean", "rule_id": "synthetic-decoy",
                       "start_byte": 0, "end_byte": 1,
                       "evidence_digest": "sha256:" + "0" * 64})
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("perfect", "miss-one", "false-positive"), default="perfect")
    args = parser.parse_args()
    print(json.dumps({"adapter": "synthetic-cp0-stub", "mode": args.mode,
                      "findings": events(args.mode)}, indent=2))


if __name__ == "__main__":
    main()
