"""Validate CP0 authored fixtures, JSON schemas and decision tables.

Usage: python -m tools.cp0.validate
Requires jsonschema >=4.23. No scanner is invoked and no external corpus is
downloaded; this is a specification check, not a scanner accuracy claim.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from tools.cp0.contract_oracle import RESULT_NAMES, ci_decision, classify


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "docs/contracts/schemas"
FIXTURES = ROOT / "tests/fixtures/synthetic-v0"
MARKER = re.compile(rb"RNC_SYNTH_KEY_[A-Z0-9_]+")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def schema_registry() -> tuple[dict[str, dict], Registry]:
    schemas = {p.name: load_json(p) for p in SCHEMAS.glob("*.schema.json")}
    registry = Registry().with_resources([
        (schema["$id"], Resource.from_contents(schema))
        for schema in schemas.values()
    ])
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    return schemas, registry


def validate_corpus() -> dict:
    manifest = load_json(FIXTURES / "manifest.json")
    assert manifest["marker_prefix"] == "RNC_SYNTH_KEY_"
    ids, paths, expected_all = set(), set(), 0
    digest = hashlib.sha256()

    for target in manifest["targets"]:
        assert target["id"] not in ids, "duplicate target id"
        assert target["path"] not in paths, "duplicate target path"
        ids.add(target["id"])
        paths.add(target["path"])
        path = (FIXTURES / target["path"]).resolve()
        assert path.is_relative_to(FIXTURES.resolve()) and path.is_file(), "escaped/missing fixture"
        data = path.read_bytes()
        digest.update(target["path"].encode() + b"\x00" + data)
        actual = [m.group().decode("ascii") for m in MARKER.finditer(data)]
        declared = []
        for finding in target["expected"]:
            assert finding["rule_id"].startswith("synthetic-")
            assert finding["marker"].startswith(manifest["marker_prefix"])
            assert finding["count"] > 0
            declared.extend([finding["marker"]] * finding["count"])
        assert sorted(actual) == sorted(declared), f"truth mismatch in {target['id']}"
        expected_all += len(declared)

    assert len(ids) >= 9 and expected_all >= 14, "corpus reduced below CP0 floor"
    return {"targets": len(ids), "declared_markers": expected_all, "sha256": digest.hexdigest()}


def validate_outcomes(schemas: dict[str, dict], registry: Registry) -> dict:
    cases = load_json(FIXTURES / "outcome-cases.json")["cases"]
    ids = set()
    for case in cases:
        assert case["id"] not in ids
        ids.add(case["id"])
        result = classify(case)
        assert result == case["expected_code"], f"classification mismatch: {case['id']}"
        counts = {
            "discovered": case["inspected"] + case["blocked"] + case["uninspected"],
            "inspected": case["inspected"],
            "verified_blocked": case["blocked"],
            "uninspected": case["uninspected"],
            "detected": case["actionable"] + case["exempted"],
            "actionable": case["actionable"],
            "exempted": case["exempted"],
        }
        output = {
            "schema_version": "0.1.0", "run_id": case["id"],
            "result_code": result, "result": RESULT_NAMES[result],
            "counts": counts, "reason_codes": [],
        }
        Draft202012Validator(schemas["result.schema.json"], registry=registry).validate(output)
        for accepted in ({1}, {1, 2}, {1, 2, 3}):
            decision = {"run_id": case["id"], **ci_decision(result, accepted)}
            Draft202012Validator(schemas["ci-decision.schema.json"], registry=registry).validate(decision)
            assert decision["result_code"] == case["expected_code"]
    assert len(ids) >= 12
    return {"cases": len(ids), "acceptance_combinations": len(ids) * 3}


def main() -> None:
    schemas, registry = schema_registry()
    corpus = validate_corpus()
    outcomes = validate_outcomes(schemas, registry)
    print(json.dumps({
        "status": "CP0_CONTRACTS_VALIDATED",
        "schema_count": len(schemas),
        "corpus": corpus,
        "outcomes": outcomes,
        "scanner_accuracy_evaluated": False,
        "engine_language_selected": False,
    }, indent=2))


if __name__ == "__main__":
    main()
