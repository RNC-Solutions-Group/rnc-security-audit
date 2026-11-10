"""Manifest-driven synthetic adapter stub for independent harness calibration.

This deliberately reads the answer key and therefore CANNOT evaluate a
production scanner. It tests the harness's normalization, reconciliation and
scoring contract. Never include this stub in a scanner release.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.cp0.contracts import (
    DEFAULT_ACCEPTED,
    SCHEMA_VERSION,
    canonical_json,
    ci_decision,
    line_count,
    line_for_offset,
    make_finding_id,
    make_request_id,
    record_digest,
    sha256_bytes,
    sorted_findings,
)
from tools.cp0.corpus import load_v0, load_v1, target_findings, target_unit_id
from tools.cp0.reconcile import build_result


MODES = (
    "perfect",
    "all-exempt",
    "miss-one",
    "false-positive",
    "duplicate-new-id",
    "wrong-location",
    "missing-target",
    "blocked-leak",
    "uninspected-required",
    "unverified-block",
    "duplicate-id",
    "bad-evidence",
    "error",
    "interrupted",
    "request-unmatched",
    "invalid-policy",
)
BLOCK_POLICY = "POLICY-BLOCK-SYNTHETIC"
EXEMPT_POLICY = "POLICY-EXEMPT-SYNTHETIC"


def _policy_entry(policy_id: str) -> dict:
    return {
        "policy_id": policy_id,
        "origin": "repository",
        "version": "1",
        "digest": sha256_bytes(policy_id.encode("utf-8")),
        "mandatory": False,
    }


def _unit(run_id: str, target: dict, manifest_version: str, data: bytes) -> dict:
    base = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "unit_id": target_unit_id(target, manifest_version),
        "source_id": f"synthetic-corpus:{manifest_version}",
        "source_kind": "working_tree_file",
        "locator": target["path"],
        "required_scope": bool(target["required"]),
    }
    if target["scope"] == "INSPECTED":
        base.update({
            "disposition": "INSPECTED",
            "reason_codes": [],
            "byte_length": len(data),
            "line_count": line_count(data),
            "content_sha256": sha256_bytes(data),
        })
    else:
        base.update({
            "disposition": target["scope"],
            "reason_codes": list(target.get("reason_codes") or (
                ["POLICY_BLOCKED"] if target["scope"] == "VERIFIED_BLOCKED" else ["TARGET_UNAVAILABLE"]
            )),
        })
    return base


def _finding(run_id: str, unit_id: str, item: dict, data: bytes) -> dict:
    finding = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "finding_id": make_finding_id(
            unit_id,
            item["rule_id"],
            item["rule_version"],
            item["start_byte"],
            item["end_byte"],
            item["evidence_digest"],
        ),
        "unit_id": unit_id,
        "rule_id": item["rule_id"],
        "rule_version": item["rule_version"],
        "category": "synthetic-credential",
        "start_byte": item["start_byte"],
        "end_byte": item["end_byte"],
        "line": line_for_offset(data, item["start_byte"]),
        "confidence": "high",
        "validation": ["FORMAT_MATCH", "SYNTHETIC_MARKER"],
        "evidence_digest": item["evidence_digest"],
    }
    return finding


def _build_policy(units: list[dict], findings: list[dict], target_by_unit: dict[str, dict], *, valid: bool = True) -> dict:
    requests: list[dict] = []
    applied_blocks: list[dict] = []
    dispositions: list[dict] = []
    blocked = [unit for unit in units if unit["disposition"] == "VERIFIED_BLOCKED"]
    for unit in blocked:
        target = target_by_unit[unit["unit_id"]]
        request_id = make_request_id(BLOCK_POLICY, "BLOCK", target["path"])
        requests.append({
            "request_id": request_id,
            "kind": "BLOCK",
            "policy_id": BLOCK_POLICY,
            "origin": "repository",
            "selector": target["path"],
            "reason": "Synthetic pre-scan block fixture",
            "status": "APPLIED",
            "matched_unit_ids": [unit["unit_id"]],
            "matched_finding_ids": [],
        })
        applied_blocks.append({
            "unit_id": unit["unit_id"],
            "request_id": request_id,
            "policy_id": BLOCK_POLICY,
            "origin": "repository",
            "reason": "Synthetic pre-scan block fixture",
            "enforcement_method": "ADAPTER_ENUMERATION_FILTER",
            "verified_non_access": True,
        })
    for finding in findings:
        disposition = next(
            (item for item in target_by_unit[finding["unit_id"]]["_findings"] if item["finding_id"] == finding["finding_id"]),
            None,
        )
        status = disposition.get("disposition", "ACTIONABLE") if disposition else "ACTIONABLE"
        if status == "EXEMPTED":
            request_id = make_request_id(EXEMPT_POLICY, "EXEMPTION", finding["finding_id"])
            requests.append({
                "request_id": request_id,
                "kind": "EXEMPTION",
                "policy_id": EXEMPT_POLICY,
                "origin": "repository",
                "selector": finding["finding_id"],
                "reason": "Synthetic post-scan exemption fixture",
                "status": "APPLIED",
                "matched_unit_ids": [],
                "matched_finding_ids": [finding["finding_id"]],
            })
            dispositions.append({
                "finding_id": finding["finding_id"],
                "status": "EXEMPTED",
                "request_id": request_id,
                "policy_id": EXEMPT_POLICY,
                "origin": "repository",
                "reason": "Synthetic post-scan exemption fixture",
            })
        else:
            dispositions.append({"finding_id": finding["finding_id"], "status": "ACTIONABLE"})
    policy = {
        "schema_version": SCHEMA_VERSION,
        "run_id": units[0]["run_id"] if units else "cp0-stub-empty",
        "policy_valid": valid,
        "effective_policy_digest": record_digest([_policy_entry(BLOCK_POLICY), _policy_entry(EXEMPT_POLICY)]),
        "effective_policies": [_policy_entry(BLOCK_POLICY), _policy_entry(EXEMPT_POLICY)],
        "requests": requests,
        "applied_blocks": applied_blocks,
        "dispositions": dispositions,
    }
    if not valid:
        policy["errors"] = ["SYNTHETIC_POLICY_INVALID"]
    return policy


def build(*, corpus: str = "v1", mode: str = "perfect", accepted: set[int] | None = None) -> dict:
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode}")
    accepted = DEFAULT_ACCEPTED if accepted is None else accepted
    loaded = load_v0() if corpus == "v0" else load_v1()
    manifest_version = loaded["summary"]["version"]
    run_id = f"cp0-stub-{corpus}-{mode}"
    units: list[dict] = []
    target_by_unit: dict[str, dict] = {}
    findings: list[dict] = []
    first_required_inspected: str | None = None
    blocked_target: dict | None = None
    for target in loaded["targets"]:
        data = loaded["contents"][target["id"]]
        unit = _unit(run_id, target, manifest_version, data)
        unit_id = unit["unit_id"]
        if target["scope"] == "INSPECTED" and target["required"] and target["expected"] and first_required_inspected is None:
            first_required_inspected = target["id"]
        if target["scope"] == "VERIFIED_BLOCKED":
            blocked_target = target
        target_record = dict(target)
        target_record["_findings"] = []
        for item in target_findings(target, data, target.get("rule_version", "synthetic-v1")):
            finding = _finding(run_id, unit_id, item, data)
            target_record["_findings"].append({**finding, "disposition": item["disposition"]})
        target_by_unit[unit_id] = target_record
        units.append(unit)
        if target["scope"] == "INSPECTED":
            findings.extend({key: value for key, value in row.items() if key != "disposition"} for row in target_record["_findings"])

    def drop_target(target_id: str) -> None:
        nonlocal units, findings
        unit = next(item for item in units if item["locator"] == next(t["path"] for t in loaded["targets"] if t["id"] == target_id))
        units = [item for item in units if item["unit_id"] != unit["unit_id"]]
        findings = [item for item in findings if item["unit_id"] != unit["unit_id"]]
        target_by_unit.pop(unit["unit_id"], None)

    if mode == "missing-target" and first_required_inspected:
        drop_target(first_required_inspected)
    if mode == "uninspected-required" and first_required_inspected:
        unit = next(item for item in units if item["locator"] == next(t["path"] for t in loaded["targets"] if t["id"] == first_required_inspected))
        for key in ("byte_length", "line_count", "content_sha256"):
            unit.pop(key, None)
        unit["disposition"] = "UNINSPECTED"
        unit["reason_codes"] = ["RUNTIME_ERROR"]
        findings = [item for item in findings if item["unit_id"] != unit["unit_id"]]
    if mode == "blocked-leak" and blocked_target is not None:
        unit = next(item for item in units if item["locator"] == blocked_target["path"])
        data = loaded["contents"][blocked_target["id"]]
        unit.pop("reason_codes", None)
        unit.update({
            "disposition": "INSPECTED",
            "reason_codes": [],
            "byte_length": len(data),
            "line_count": line_count(data),
            "content_sha256": sha256_bytes(data),
        })
        leaked = [
            _finding(run_id, unit["unit_id"], item, data)
            for item in target_findings(blocked_target, data, "synthetic-v1")
        ]
        target_by_unit[unit["unit_id"]]["_findings"] = [{**row, "disposition": "ACTIONABLE"} for row in leaked]
        findings.extend(leaked)
    if mode == "miss-one" and findings:
        removed = findings.pop(0)
        target_by_unit[removed["unit_id"]]["_findings"] = [
            row for row in target_by_unit[removed["unit_id"]]["_findings"] if row["finding_id"] != removed["finding_id"]
        ]
    if mode == "false-positive":
        clean = next(target for target in loaded["targets"] if target["id"] == "clean")
        unit = next(item for item in units if item["locator"] == clean["path"])
        data = loaded["contents"][clean["id"]]
        start, end = 0, min(10, len(data))
        digest = sha256_bytes(data[start:end])
        finding = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "finding_id": make_finding_id(unit["unit_id"], "synthetic-decoy", "synthetic-v1", start, end, digest),
            "unit_id": unit["unit_id"],
            "rule_id": "synthetic-decoy",
            "rule_version": "synthetic-v1",
            "category": "synthetic-decoy",
            "start_byte": start,
            "end_byte": end,
            "line": 1,
            "confidence": "low",
            "validation": ["SYNTHETIC_FALSE_POSITIVE"],
            "evidence_digest": digest,
        }
        findings.append(finding)
        target_by_unit[unit["unit_id"]]["_findings"].append({**finding, "disposition": "ACTIONABLE"})
    if mode == "duplicate-new-id" and findings:
        first = dict(findings[0])
        first["rule_version"] = first["rule_version"] + "-duplicate"
        first["finding_id"] = make_finding_id(
            first["unit_id"], first["rule_id"], first["rule_version"],
            first["start_byte"], first["end_byte"], first["evidence_digest"],
        )
        findings.append(first)
        target_by_unit[first["unit_id"]]["_findings"].append({**first, "disposition": "ACTIONABLE"})
    if mode == "wrong-location" and findings:
        first = findings[0]
        first["start_byte"] += 1
        first["end_byte"] += 1
        data = loaded["contents"][next(t["id"] for t in loaded["targets"] if t["path"] == target_by_unit[first["unit_id"]]["path"])]
        first["evidence_digest"] = sha256_bytes(data[first["start_byte"]:first["end_byte"]])
        first["line"] = line_for_offset(data, first["start_byte"])
        first["finding_id"] = make_finding_id(
            first["unit_id"], first["rule_id"], first["rule_version"],
            first["start_byte"], first["end_byte"], first["evidence_digest"],
        )
    if mode == "bad-evidence" and findings:
        findings[0]["evidence_digest"] = sha256_bytes(b"not-the-matched-bytes")
    if mode == "duplicate-id" and findings:
        findings.append(dict(findings[0]))
    if mode == "all-exempt":
        for row in target_by_unit.values():
            for finding in row["_findings"]:
                finding["disposition"] = "EXEMPTED"
    if mode == "unverified-block" and any(unit["disposition"] == "VERIFIED_BLOCKED" for unit in units):
        pass

    state = "ERROR" if mode == "error" else "INTERRUPTED" if mode == "interrupted" else "COMPLETED"
    fatal_errors = ["Synthetic operational failure"] if state != "COMPLETED" else []
    execution = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "state": state,
        "evidence_valid": state == "COMPLETED",
        "engine_version": "cp0-stub-0.2.0",
        "ruleset_id": manifest_version,
        "ruleset_digest": sha256_bytes(manifest_version.encode("utf-8")),
        "source_adapter": {"id": "synthetic-cp0-stub", "version": "0.2.0"},
        "units": sorted(units, key=lambda unit: unit["unit_id"]),
        "fatal_errors": fatal_errors,
        "failure_codes": ["EXECUTION_FAILED"] if state != "COMPLETED" else [],
    }
    policy = _build_policy(
        execution["units"],
        findings,
        target_by_unit,
        valid=mode != "invalid-policy",
    )
    if mode == "request-unmatched":
        policy["requests"].append({
            "request_id": make_request_id("POLICY-NO-MATCH", "BLOCK", "vendor/**"),
            "kind": "BLOCK",
            "policy_id": BLOCK_POLICY,
            "origin": "repository",
            "selector": "vendor/**",
            "reason": "Synthetic requested-but-unmatched block",
            "status": "NOT_MATCHED",
            "matched_unit_ids": [],
            "matched_finding_ids": [],
        })
    if mode == "unverified-block" and policy["applied_blocks"]:
        policy["applied_blocks"][0]["verified_non_access"] = False
    policy["effective_policies"] = sorted(policy["effective_policies"], key=lambda entry: entry["policy_id"])
    policy["requests"] = sorted(policy["requests"], key=lambda entry: entry["request_id"])
    policy["applied_blocks"] = sorted(policy["applied_blocks"], key=lambda entry: (entry["unit_id"], entry["request_id"]))
    policy["dispositions"] = sorted(policy["dispositions"], key=lambda entry: entry["finding_id"])
    policy["effective_policy_digest"] = record_digest(policy["effective_policies"])
    findings = sorted_findings(findings)
    result = build_result(execution, findings, policy)
    decision = ci_decision(
        result["result_code"], accepted,
        run_id=run_id,
        result_digest=record_digest(result),
    )
    return {
        "bundle_schema_version": SCHEMA_VERSION,
        "adapter": "synthetic-cp0-stub",
        "mode": mode,
        "corpus": corpus,
        "run_id": run_id,
        "accepted_result_codes": sorted(accepted),
        "execution": execution,
        "findings": findings,
        "policy": policy,
        "result": result,
        "ci": decision,
        "warning": "This stub reads the answer key and cannot grade a production scanner.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", choices=("v0", "v1"), default="v1")
    parser.add_argument("--mode", choices=MODES, default="perfect")
    parser.add_argument("--accepted", default="1,2")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    accepted = {int(value) for value in args.accepted.split(",") if value}
    document = build(corpus=args.corpus, mode=args.mode, accepted=accepted)
    text = canonical_json(document) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {args.output}")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
