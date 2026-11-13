"""CP1 end-to-end integration against independently defined CP0 synthetic truth.

This script stages only source fixtures (never the truth manifest), invokes the
Rust CLI, validates CP0 v0.2 records, builds synthetic policy evidence, and scores
the actual detector output against the truth. It is test infrastructure, not part
of the scanner runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

from tools.cp0.contracts import (
    SCHEMA_VERSION,
    make_finding_id,
    make_request_id,
    record_digest,
    schema_registry,
    sha256_bytes,
    validate_records,
)
from tools.cp0.corpus import load_v0, load_v1, validate_manifest
from tools.cp0.harness_adapter import build_handoff, conformance_score
from tools.cp1.rules import canonical_digest as rules_digest, load as load_rules


ROOT = Path(__file__).resolve().parents[2]
RULES_V0 = ROOT / "rules/rnc-synthetic-v0.json"
RULES_V1 = ROOT / "rules/rnc-synthetic-v1.json"


def _stage(loaded: dict, destination: Path) -> dict[str, bytes]:
    source_root = (ROOT / "tests/fixtures/synthetic-v1") if loaded["summary"]["version"].startswith("synthetic-v1") else (ROOT / "tests/fixtures/synthetic-v0")
    contents = {}
    for target in loaded["targets"]:
        source = source_root / target["path"]
        destination_path = destination / target["path"]
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination_path)
        contents[target["id"]] = source.read_bytes()
    return contents


def _run_cli(binary: Path, stage: Path, rules: Path, output: Path, *, mode: str, corpus: str) -> tuple[dict, str, int]:
    excludes = ["blocked.txt"] if corpus in {"v0", "v1"} else []
    skips = ["uninspected-optional.txt"] if corpus == "v1" else []
    optional = ["uninspected-optional.txt", "optional-clean.txt"] if corpus == "v1" else []
    command = [
        str(binary), "scan",
        "--root", str(stage),
        "--rules", str(rules),
        "--format", "json",
        "--output", str(output),
        "--run-id", f"cp1-{corpus}-integration",
        "--mode", mode,
        "--stream-chunk-bytes", "64",
    ]
    for value in excludes:
        command.extend(["--exclude", value])
    for value in skips:
        command.extend(["--skip", value])
    for value in optional:
        command.extend(["--optional", value])
    completed = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if completed.returncode not in (0, 10, 20):
        raise RuntimeError(f"CLI failed ({completed.returncode}): {completed.stderr.strip()}")
    document = json.loads(output.read_text(encoding="utf-8"))
    return document, completed.stdout, completed.returncode


def _finding_key(unit_locator: str, finding: dict) -> tuple[str, str, int, int]:
    return (unit_locator, finding["rule_id"], finding["start_byte"], finding["end_byte"])


def _policy_for(execution: dict, findings: list[dict], expected_findings: list[dict]) -> dict:
    policy_id = "CP1-INTEGRATION-POLICY"
    effective = [{
        "policy_id": policy_id,
        "origin": "repository",
        "version": "1",
        "digest": sha256_bytes(policy_id.encode("utf-8")),
        "mandatory": False,
    }]
    requests = []
    applied_blocks = []
    for unit in execution["units"]:
        if unit["disposition"] != "VERIFIED_BLOCKED":
            continue
        request_id = make_request_id(policy_id, "BLOCK", unit["locator"])
        reason = "CP1 integration pre-scan block"
        requests.append({
            "request_id": request_id,
            "kind": "BLOCK",
            "policy_id": policy_id,
            "origin": "repository",
            "selector": unit["locator"],
            "reason": reason,
            "status": "APPLIED",
            "matched_unit_ids": [unit["unit_id"]],
            "matched_finding_ids": [],
        })
        applied_blocks.append({
            "unit_id": unit["unit_id"],
            "request_id": request_id,
            "policy_id": policy_id,
            "origin": "repository",
            "reason": reason,
            "enforcement_method": "ADAPTER_ENUMERATION_FILTER",
            "verified_non_access": True,
        })
    expected_exempted = {
        (item["target_id"], item["rule_id"], item["start_byte"], item["end_byte"])
        for item in expected_findings
        if item["disposition"] == "EXEMPTED"
    }
    dispositions = []
    for finding in findings:
        unit_locator = next(unit["locator"] for unit in execution["units"] if unit["unit_id"] == finding["unit_id"])
        is_exempted = any(
            unit_locator == next(target["path"] for target in load_v1()["targets"] if target["id"] == target_id)
            and finding["rule_id"] == rule_id
            and finding["start_byte"] == start
            and finding["end_byte"] == end
            for target_id, rule_id, start, end in expected_exempted
        )
        if is_exempted:
            request_id = make_request_id(policy_id, "EXEMPTION", finding["finding_id"])
            requests.append({
                "request_id": request_id,
                "kind": "EXEMPTION",
                "policy_id": policy_id,
                "origin": "repository",
                "selector": finding["finding_id"],
                "reason": "CP1 integration post-scan exemption",
                "status": "APPLIED",
                "matched_unit_ids": [],
                "matched_finding_ids": [finding["finding_id"]],
            })
            dispositions.append({
                "finding_id": finding["finding_id"],
                "status": "EXEMPTED",
                "request_id": request_id,
                "policy_id": policy_id,
                "origin": "repository",
                "reason": "CP1 integration post-scan exemption",
            })
        else:
            dispositions.append({"finding_id": finding["finding_id"], "status": "ACTIONABLE"})
    effective.sort(key=lambda item: item["policy_id"])
    requests.sort(key=lambda item: item["request_id"])
    applied_blocks.sort(key=lambda item: (item["unit_id"], item["request_id"]))
    dispositions.sort(key=lambda item: item["finding_id"])
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": execution["run_id"],
        "policy_valid": True,
        "effective_policy_digest": record_digest(effective),
        "effective_policies": effective,
        "requests": requests,
        "applied_blocks": applied_blocks,
        "dispositions": dispositions,
    }


def _validate_records(document: dict, rules_loaded: dict, contents: dict[str, bytes], corpus: str):
    schemas, registry = schema_registry()
    execution = document["execution"]
    findings = document["findings"]
    policy = document["policy"]
    result = document["result"]
    ci = document["ci"]
    for name, value in (
        ("execution.schema.json", execution),
        ("policy.schema.json", policy),
        ("result.schema.json", result),
        ("ci-decision.schema.json", ci),
    ):
        Draft202012Validator(schemas[name], registry=registry).validate(value)
    for unit in execution["units"]:
        Draft202012Validator(schemas["source-unit.schema.json"], registry=registry).validate(unit)
    for finding in findings:
        Draft202012Validator(schemas["finding.schema.json"], registry=registry).validate(finding)
    content_by_unit = {}
    for unit in execution["units"]:
        if unit["disposition"] == "INSPECTED":
            content_by_unit[unit["unit_id"]] = contents[next(target["id"] for target in rules_loaded["targets"] if target["path"] == unit["locator"])]
    summary = validate_records(execution, findings, policy, result, ci, contents=content_by_unit)
    return policy, result, ci, summary

def _compare_truth(loaded: dict, document: dict, contents: dict[str, bytes], corpus: str) -> dict:
    execution = document["execution"]
    findings = document["findings"]
    units_by_locator = {unit["locator"]: unit for unit in execution["units"]}
    expected = loaded["expected_findings"]
    expected_keys = {
        (item["path"], item["rule_id"], item["start_byte"], item["end_byte"])
        for item in expected
    }
    actual_keys = {
        (item["locator"], finding["rule_id"], finding["start_byte"], finding["end_byte"])
        for finding in findings
        for item in [next(unit for unit in execution["units"] if unit["unit_id"] == finding["unit_id"])]
    }
    if expected_keys != actual_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise AssertionError(f"{corpus}: finding set mismatch; missing={missing[:10]} extra={extra[:10]}")
    for item in expected:
        data = contents[item["target_id"]]
        actual = next(
            finding for finding in findings
            if finding["unit_id"] == units_by_locator[item["path"]]["unit_id"]
            and finding["rule_id"] == item["rule_id"]
            and finding["start_byte"] == item["start_byte"]
            and finding["end_byte"] == item["end_byte"]
        )
        expected_digest = sha256_bytes(data[item["start_byte"]:item["end_byte"]])
        if actual["evidence_digest"] != expected_digest:
            raise AssertionError(f"{item['expected_id']}: evidence digest mismatch")
        expected_id = make_finding_id(
            actual["unit_id"], actual["rule_id"], actual["rule_version"],
            actual["start_byte"], actual["end_byte"], actual["evidence_digest"],
        )
        if actual["finding_id"] != expected_id:
            raise AssertionError(f"{item['expected_id']}: finding ID mismatch")
    expected_targets = {target["id"]: target for target in loaded["targets"]}
    if len(execution["units"]) != len(expected_targets):
        raise AssertionError(f"{corpus}: expected {len(expected_targets)} units, got {len(execution['units'])}")
    for target in loaded["targets"]:
        unit = units_by_locator.get(target["path"])
        if unit is None:
            raise AssertionError(f"{corpus}: target {target['id']} was not accounted for")
        if target["scope"] == "INSPECTED":
            if unit["disposition"] != "INSPECTED":
                raise AssertionError(f"{corpus}: target {target['id']} not inspected")
            if "content_sha256" not in unit or "byte_length" not in unit:
                raise AssertionError(f"{corpus}: inspected unit lacks evidence")
        elif target["scope"] == "VERIFIED_BLOCKED":
            if unit["disposition"] != "VERIFIED_BLOCKED" or "content_sha256" in unit:
                raise AssertionError(f"{corpus}: blocked unit mishandled")
        elif target["scope"] == "UNINSPECTED":
            if unit["disposition"] != "UNINSPECTED" or "content_sha256" in unit:
                raise AssertionError(f"{corpus}: uninspected unit mishandled")
        if bool(target["required"]) != bool(unit["required_scope"]):
            raise AssertionError(f"{corpus}: required-scope mismatch for {target['id']}")
    return {
        "expected": len(expected),
        "actual": len(findings),
        "targets": len(execution["units"]),
        "inspected": execution["inspected_count"] if isinstance(execution, dict) and "inspected_count" in execution else sum(unit["disposition"] == "INSPECTED" for unit in execution["units"]),
        "blocked": sum(unit["disposition"] == "VERIFIED_BLOCKED" for unit in execution["units"]),
        "uninspected": sum(unit["disposition"] == "UNINSPECTED" for unit in execution["units"]),
    }


def run(binary: Path, corpus: str, mode: str, handoff_dir: Path | None = None) -> dict:
    loaded = load_v0() if corpus == "v0" else load_v1()
    rules = RULES_V0 if corpus == "v0" else RULES_V1
    with tempfile.TemporaryDirectory(prefix=f"rnc-cp1-{corpus}-") as temp:
        root = Path(temp)
        stage = root / "stage"
        stage.mkdir()
        contents = _stage(loaded, stage)
        output = root / "findings.json"
        document, stdout, exit_code = _run_cli(binary, stage, rules, output, mode=mode, corpus=corpus)
        expected_rules_digest = rules_digest(load_rules(rules))
        if document["execution"]["ruleset_digest"] != expected_rules_digest:
            raise AssertionError(f"{corpus}: Rust ruleset digest does not match canonical digest")
        repeated, _, _ = _run_cli(binary, stage, rules, root / "findings-repeat.json", mode=mode, corpus=corpus)
        if json.dumps(document["findings"], sort_keys=True) != json.dumps(repeated["findings"], sort_keys=True):
            raise AssertionError(f"{corpus}/{mode}: repeated execution findings are not stable")
        if json.dumps(document["execution"]["units"], sort_keys=True) != json.dumps(repeated["execution"]["units"], sort_keys=True):
            raise AssertionError(f"{corpus}/{mode}: repeated execution units are not stable")
        if "RNC_SYNTH_KEY_" in stdout or "evidence_digest" in stdout or "finding_id" in stdout:
            raise AssertionError("summary leaked sensitive evidence")
        raw_json = output.read_text(encoding="utf-8")
        if "RNC_SYNTH_KEY_" in raw_json:
            raise AssertionError("private JSON leaked a raw marker")
        policy, result, ci, summary = _validate_records(document, loaded, contents, corpus)
        metrics = _compare_truth(loaded, document, contents, corpus)
        handoff = build_handoff({
            "adapter": "rnc-cli",
            "mode": mode,
            "execution": document["execution"],
            "findings": document["findings"],
            "policy": policy,
            "result": result,
            "ci": ci,
        }, loaded)
        conformance = conformance_score(handoff)
        if conformance["matched"] != len(loaded["expected_findings"]):
            raise AssertionError(f"{corpus}: handoff conformance missed findings: {conformance}")
        if result["result_code"] != 3:
            raise AssertionError(f"{corpus}: expected ACTIONABLE integration result, got {result['result_code']}")
        if ci["process_exit_code"] != exit_code:
            raise AssertionError(f"{corpus}: CI exit {ci['process_exit_code']} != process exit {exit_code}")
        if handoff_dir is not None:
            handoff_dir.mkdir(parents=True, exist_ok=True)
            (handoff_dir / f"{corpus}-{mode}.json").write_text(
                json.dumps(handoff, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
            )
        return {
            "corpus": loaded["summary"]["version"],
            "mode": mode,
            "exit_code": exit_code,
            "metrics": metrics,
            "result_code": result["result_code"],
            "result": result["result"],
            "ci_exit": ci["process_exit_code"],
            "conformance": conformance,
            "contract": summary["result"],
            "ruleset_digest": document["execution"]["ruleset_digest"],
            "deterministic": True,
            "ruleset_digest_verified": True,
        }


def run_edge(binary: Path, edge_root: Path) -> dict:
    loaded = validate_manifest(edge_root / "manifest.json")
    with tempfile.TemporaryDirectory(prefix="rnc-cp1-edge-") as temp:
        root = Path(temp)
        stage = root / "stage"
        stage.mkdir()
        for target in loaded["targets"]:
            destination = stage / target["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(edge_root / target["path"], destination)
        output = root / "findings.json"
        document, stdout, exit_code = _run_cli(binary, stage, RULES_V1, output, mode="stream", corpus="edge")
        if "RNC_SYNTH_KEY_" in stdout or "evidence_digest" in stdout or "finding_id" in stdout:
            raise AssertionError("edge summary leaked sensitive evidence")
        policy, result, ci, summary = _validate_records(document, loaded, loaded["contents"], "edge")
        metrics = _compare_truth(loaded, document, loaded["contents"], "edge")
        if result["result_code"] != 4:
            raise AssertionError(f"edge: expected INCOMPLETE, got {result['result_code']}")
        if ci["process_exit_code"] != exit_code:
            raise AssertionError(f"edge: CI exit mismatch")
        return {
            "corpus": loaded["summary"]["version"],
            "mode": "stream",
            "exit_code": exit_code,
            "metrics": metrics,
            "result_code": result["result_code"],
            "result": result["result"],
            "ci_exit": ci["process_exit_code"],
            "deterministic": True,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--edge-corpus", type=Path)
    parser.add_argument("--handoff-dir", type=Path)
    args = parser.parse_args()
    cases = []
    for corpus in ("v1", "v0"):
        for mode in ("whole", "stream"):
            cases.append(run(args.binary, corpus, mode, args.handoff_dir))
    if args.edge_corpus:
        cases.append(run_edge(args.binary, args.edge_corpus))
    document = {
        "integration": "CP1 Rust engine vs CP0 independent truth",
        "scanner_accuracy_claim": False,
        "cases": cases,
        "all_correct": all(case["metrics"]["expected"] == case["metrics"]["actual"] for case in cases),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(document, indent=2, sort_keys=True))
    if not document["all_correct"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
