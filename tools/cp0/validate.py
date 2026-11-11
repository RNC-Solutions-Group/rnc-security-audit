"""Validate CP0 schemas, authored corpora, outcome tables and config fixtures.

Usage: python -m tools.cp0.validate [--json]
Requires jsonschema >=4.23. No scanner is invoked and no external corpus is
downloaded; this is a specification check, not a scanner accuracy claim.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.cp0.contracts import (
    RESULT_NAMES,
    SCHEMA_VERSION,
    classify,
    coverage_for,
    reason_codes_for,
    record_digest,
    schema_check,
    schema_registry,
)
from tools.cp0.config_migration import load_project_config
from tools.cp0.corpus import load_v0, load_v1, validate_manifest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures/synthetic-v0"
V1_FIXTURES = ROOT / "tests/fixtures/synthetic-v1"
OUTCOMES = FIXTURES / "outcome-cases.json"
OUTCOMES_V1 = V1_FIXTURES / "outcome-cases.json"
DUMMY_DIGEST = "sha256:" + "0" * 64


def _counts(case: dict) -> dict:
    inspected = case["inspected"]
    blocked = case["blocked"]
    uninspected = case["uninspected"]
    required_inspected = case.get("required_inspected", inspected)
    required_blocked = case.get("required_blocked", blocked)
    required_uninspected = case.get("required_uninspected", uninspected)
    if required_inspected > inspected or required_blocked > blocked or required_uninspected > uninspected:
        raise ValueError(f"{case['id']}: required counts exceed total counts")
    return {
        "discovered": inspected + blocked + uninspected,
        "inspected": inspected,
        "verified_blocked": blocked,
        "uninspected": uninspected,
        "required_discovered": required_inspected + required_blocked + required_uninspected,
        "required_inspected": required_inspected,
        "required_verified_blocked": required_blocked,
        "required_uninspected": required_uninspected,
        "detected": case["actionable"] + case["exempted"],
        "actionable": case["actionable"],
        "exempted": case["exempted"],
    }


def validate_outcomes(path: Path, schemas: dict, registry) -> dict:
    cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
    ids = set()
    for case in cases:
        if case["id"] in ids:
            raise ValueError(f"duplicate outcome case id {case['id']}")
        ids.add(case["id"])
        counts = _counts(case)
        execution = {
            "state": case["state"],
            "evidence_valid": bool(case["evidence_valid"]),
            "fatal_errors": ["synthetic fatal"] if case["fatal"] else [],
            "failure_codes": ["EXECUTION_FAILURE"] if case["fatal"] else [],
        }
        policy = {
            "policy_valid": bool(case.get("policy_valid", True)),
            "errors": list(case.get("policy_errors", [])),
        }
        code = classify(execution, policy, counts)
        if code != case["expected_code"]:
            raise ValueError(f"{case['id']}: expected {case['expected_code']}, classified {code}")
        result = {
            "schema_version": SCHEMA_VERSION,
            "run_id": case["id"],
            "result_code": code,
            "result": RESULT_NAMES[code],
            "coverage": coverage_for(code, counts),
            "evidence_valid": bool(case["evidence_valid"]),
            "engine_version": "cp0-reference",
            "ruleset_id": "synthetic",
            "ruleset_digest": DUMMY_DIGEST,
            "source_adapter": {"id": "synthetic", "version": "0.2.0"},
            "counts": counts,
            "reason_codes": reason_codes_for(execution, policy, counts, code),
            "records": {
                "execution_digest": DUMMY_DIGEST,
                "findings_digest": DUMMY_DIGEST,
                "policy_digest": DUMMY_DIGEST,
            },
        }
        schema_check(result, "result.schema.json", schemas, registry)
        for accepted in ({1}, {1, 2}, {1, 2, 3}):
            from tools.cp0.contracts import ci_decision

            decision = ci_decision(code, accepted, run_id=case["id"], result_digest=record_digest(result))
            schema_check(decision, "ci-decision.schema.json", schemas, registry)
            if code in (4, 5) and decision["accepted"]:
                raise ValueError(f"{case['id']}: incomplete/failed result was accepted")
    if len(ids) < 12:
        raise ValueError("outcome matrix regressed below the CP0 baseline")
    return {"source": str(path.resolve().relative_to(ROOT)), "cases": len(ids), "acceptance_combinations": len(ids) * 3}


def validate_corpus() -> dict:
    v0 = load_v0()
    v1 = load_v1()
    if v0["summary"]["targets"] != 9 or v0["summary"]["known_markers"] != 14:
        raise ValueError("synthetic-v0 baseline changed")
    if v1["summary"]["targets"] < 20 or v1["summary"]["expected_findings"] < 20:
        raise ValueError("synthetic-v1 expanded corpus regressed")
    return {
        "v0": v0["summary"],
        "v1": v1["summary"],
        "total_targets": v0["summary"]["targets"] + v1["summary"]["targets"],
    }


def validate_config_fixtures() -> dict:
    config_root = ROOT / "tests/fixtures/config"
    unified, unified_provenance = load_project_config(config_root / "unified")
    legacy, legacy_provenance = load_project_config(config_root / "legacy")
    if unified_provenance["migrated"] or not legacy_provenance["migrated"]:
        raise ValueError("config provenance is misclassified")
    if len(legacy["policy"]["blocks"]) != 2 or legacy["policy"]["exemptions"]:
        raise ValueError("legacy exclusion migration changed")
    dual_failed = False
    try:
        load_project_config(config_root / "dual")
    except Exception:
        dual_failed = True
    if not dual_failed:
        raise ValueError("dual configuration sources were not rejected")
    return {
        "unified_source": unified_provenance["source"],
        "legacy_source": legacy_provenance["source"],
        "legacy_blocks": len(legacy["policy"]["blocks"]),
        "dual_source_rejected": True,
        "accepted_result_codes": unified["ci"]["accepted_result_codes"],
    }


def validate_edge_corpus(path: Path) -> dict:
    loaded = validate_manifest(path / "manifest.json")
    if loaded["summary"]["uninspected_targets"] != 1:
        raise ValueError("edge corpus did not declare the oversize uninspected unit")
    if loaded["summary"]["expected_findings"] < 3:
        raise ValueError("edge corpus lost its large-file truth")
    return loaded["summary"]


def validate_all() -> dict:
    schemas, registry = schema_registry()
    corpus = validate_corpus()
    outcomes_v0 = validate_outcomes(OUTCOMES, schemas, registry)
    outcomes_v1 = validate_outcomes(OUTCOMES_V1, schemas, registry)
    return {
        "status": "CP0_CONTRACTS_VALIDATED",
        "schema_count": len(schemas),
        "schemas": sorted(schemas),
        "corpus": corpus,
        "outcomes": [outcomes_v0, outcomes_v1],
        "config": validate_config_fixtures(),
        "scanner_accuracy_evaluated": False,
        "engine_language_selected": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="emit stable machine-readable JSON")
    parser.add_argument("--edge", type=Path, help="also validate an already-generated edge corpus directory")
    args = parser.parse_args()
    document = validate_all()
    if args.edge:
        document["edge_corpus"] = validate_edge_corpus(args.edge)
    if args.json:
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        print(json.dumps(document, indent=2))
        print("\nCP0 contract validation passed. No scanner accuracy is claimed.", flush=True)


if __name__ == "__main__":
    main()
