"""Concrete CP0 -> external harness handoff.

The external scanner-agnostic harness uses line-addressed normalized findings and
versioned truth manifests (schema version 1 at the inspected revision). This
module exports CP0 records into that shape, keeps policy/result provenance in a
sidecar, and checks that the handoff preserves accountable findings. It does not
claim that the external harness or any external corpus was executed.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from tools.cp0.contracts import (
    ContractViolation,
    assert_public_safe,
    canonical_json,
    line_for_offset,
    record_digest,
)
from tools.cp0.corpus import load_v0, load_v1, target_unit_id


HANDOFF_VERSION = "rnc-harness-handoff-v1"
EXTERNAL_SCHEMA_VERSION = 1


def _relative_path(value: str) -> str:
    path = value.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if path.startswith("/") or re.match(r"^[A-Za-z]:/", path) or ".." in path.split("/"):
        raise ContractViolation("HANDOFF_PATH", f"unsafe handoff path {value!r}")
    return path


def _scope_item(target: dict, version: str) -> dict:
    classification = "BLOCKED" if target["scope"] == "VERIFIED_BLOCKED" else "SKIPPED"
    return {
        "finding_id": f"scope-{target['id']}",
        "dataset_id": f"rnc-{version}",
        "dataset_version": version,
        "path": _relative_path(target["path"]),
        "classification": classification,
        "category": "scope",
        "risk_bearing": False,
        "line_start": 1,
        "line_end": 1,
        "location": "scope",
        "fingerprint_sha256": hashlib.sha256(target["id"].encode("utf-8")).hexdigest(),
        "source_reference": f"scope:{target['id']}",
        "matching_policy": "file",
        "category_conflict": False,
        "notes": "CP0 scope item; not a detection expectation.",
        "metadata": {"scope": target["scope"], "required": bool(target["required"])},
    }


def export_truth(loaded: dict) -> dict:
    version = loaded["summary"]["version"]
    dataset_id = f"rnc-{version}"
    items = []
    contents = loaded["contents"]
    for item in loaded["expected_findings"]:
        data = contents[item["target_id"]]
        line = line_for_offset(data, item["start_byte"])
        end_line = line_for_offset(data, max(item["start_byte"], item["end_byte"] - 1))
        items.append({
            "finding_id": item["expected_id"],
            "dataset_id": dataset_id,
            "dataset_version": version,
            "path": _relative_path(item["path"]),
            "classification": "EXPECTED_DETECTION",
            "category": "synthetic-credential",
            "risk_bearing": True,
            "line_start": line,
            "line_end": end_line,
            "location": "line",
            "fingerprint_sha256": item["evidence_digest"].removeprefix("sha256:"),
            "source_reference": f"synthetic:{item['target_id']}:{item['rule_id']}:{item['start_byte']}",
            "matching_policy": "line_range",
            "expected_rule_id": item["rule_id"],
            "category_conflict": False,
            "notes": "Synthetic expected finding; harmless marker.",
            "metadata": {
                "target_id": item["target_id"],
                "rule_id": item["rule_id"],
                "rule_version": item["rule_version"],
                "start_byte": item["start_byte"],
                "end_byte": item["end_byte"],
                "disposition": item["disposition"],
            },
        })
    for target in loaded["targets"]:
        if target["scope"] != "INSPECTED":
            items.append(_scope_item(target, version))
    items.sort(key=lambda item: (item["path"], item["line_start"], item["finding_id"]))
    document = {
        "schema_version": EXTERNAL_SCHEMA_VERSION,
        "manifest_id": f"cp0-{version}",
        "manifest_version": version,
        "dataset_id": dataset_id,
        "dataset_version": version,
        "items": items,
        "scoring_policy": {
            "id": "rnc-line-range-v1",
            "version": "1",
            "negative_oracle": True,
            "line_tolerance": 0,
            "one_to_one": True,
        },
        "counts": {
            "items": len(items),
            "expected_detection": sum(item["classification"] == "EXPECTED_DETECTION" for item in items),
            "blocked": sum(item["classification"] == "BLOCKED" for item in items),
            "skipped": sum(item["classification"] == "SKIPPED" for item in items),
        },
        "integrity": {"status": "PASS"},
    }
    document["integrity"]["sha256"] = record_digest(document)
    return document


def export_findings(bundle: dict, loaded: dict) -> list[dict]:
    version = loaded["summary"]["version"]
    target_by_unit = {
        target_unit_id(target, version): target for target in loaded["targets"]
    }
    unit_by_id = {unit["unit_id"]: unit for unit in bundle["execution"]["units"]}
    result = []
    for finding in bundle["findings"]:
        unit = unit_by_id.get(finding["unit_id"])
        if unit is None:
            raise ContractViolation("HANDOFF_UNIT_UNKNOWN", "finding has no execution unit")
        if unit["disposition"] != "INSPECTED":
            raise ContractViolation("HANDOFF_SCOPE_LEAK", "finding is attached to a non-inspected unit")
        target = target_by_unit.get(unit["unit_id"])
        if target is None:
            raise ContractViolation("HANDOFF_TARGET_UNKNOWN", "unit does not map to a manifest target")
        result.append({
            "finding_id": finding["finding_id"],
            "file": _relative_path(unit["locator"]),
            "line": finding["line"],
            "rule_id": finding["rule_id"],
            "secret_sha256": finding["evidence_digest"].removeprefix("sha256:"),
            "match_sha256": finding["evidence_digest"].removeprefix("sha256:"),
            "secret_redacted": True,
            "target": f"target:{target['id']}",
            "scanner": "rnc",
            "scanner_version": bundle["execution"]["engine_version"],
            "metadata": {
                "unit_id": finding["unit_id"],
                "target_id": target["id"],
                "rule_version": finding["rule_version"],
                "start_byte": finding["start_byte"],
                "end_byte": finding["end_byte"],
                "evidence_digest": finding["evidence_digest"],
            },
        })
    result.sort(key=lambda item: (item["file"], item["line"], item["rule_id"], item["finding_id"]))
    return result


def build_handoff(bundle: dict, loaded: dict) -> dict:
    truth = export_truth(loaded)
    findings = export_findings(bundle, loaded)
    policy = bundle["policy"]
    result = bundle["result"]
    document = {
        "handoff_version": HANDOFF_VERSION,
        "external_contract": {
            "repository": "RNC-Solutions-Group/gitleaks",
            "branch": "test/scan-harness",
            "revision": "86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f",
            "scoring_schema_version": EXTERNAL_SCHEMA_VERSION,
        },
        "scanner": {
            "key": "rnc",
            "version": bundle["execution"]["engine_version"],
            "ruleset_id": bundle["execution"]["ruleset_id"],
            "ruleset_digest": bundle["execution"]["ruleset_digest"],
        },
        "dataset": {
            "id": truth["dataset_id"],
            "version": truth["dataset_version"],
            "manifest_sha256": loaded["summary"]["manifest_sha256"],
        },
        "truth": truth,
        "findings": findings,
        "provenance": {
            "execution_digest": record_digest(bundle["execution"]),
            "policy_digest": record_digest(policy),
            "result_digest": record_digest(result),
            "ci_decision_digest": record_digest(bundle["ci"]),
            "result_code": result["result_code"],
            "coverage": result["coverage"],
            "policy": {
                "policy_valid": policy["policy_valid"],
                "effective_policy_ids": [entry["policy_id"] for entry in policy["effective_policies"]],
                "applied_blocks": len(policy["applied_blocks"]),
                "exempted": result["counts"]["exempted"],
                "actionable": result["counts"]["actionable"],
                "requested_unapplied": sum(request["status"] != "APPLIED" for request in policy["requests"]),
            },
        },
        "score_lanes": {
            "corpus_native": "owned by the external corpus/harness; not computed here",
            "rnc_normalized": "line-addressed findings plus byte-offset metadata",
        },
        "execution_semantics": {
            "scanner_execution": bundle["execution"]["state"],
            "result_classification": result["result"],
            "ci_accepted": bundle["ci"]["accepted"],
            "ci_process_exit_code": bundle["ci"]["process_exit_code"],
        },
        "not_executed": [
            "No external harness run is claimed by this document.",
            "No Levain, Leaky Repo or Prowlbench execution is claimed.",
        ],
    }
    assert_handoff_safe(document)
    return document


def _check_relative(value: str, label: str) -> None:
    path = _relative_path(value)
    if path != value:
        raise ContractViolation("HANDOFF_PATH", f"{label} is not normalized")


def assert_handoff_safe(document: dict) -> None:
    if document.get("handoff_version") != HANDOFF_VERSION:
        raise ContractViolation("HANDOFF_VERSION", "unexpected handoff version")
    truth = document["truth"]
    findings = document["findings"]
    if truth.get("schema_version") != EXTERNAL_SCHEMA_VERSION:
        raise ContractViolation("HANDOFF_SCHEMA", "external truth schema version must be 1")
    if not isinstance(truth.get("items"), list) or not truth["items"]:
        raise ContractViolation("HANDOFF_TRUTH", "truth manifest has no items")
    truth_keys = set()
    for item in truth["items"]:
        _check_relative(item["path"], "truth path")
        if item["finding_id"] in truth_keys:
            raise ContractViolation("HANDOFF_TRUTH", "duplicate truth item ID")
        truth_keys.add(item["finding_id"])
        if item["classification"] not in {"EXPECTED_DETECTION", "BLOCKED", "SKIPPED", "NOT_APPLICABLE"}:
            raise ContractViolation("HANDOFF_TRUTH", f"unsupported truth classification {item['classification']}")
        if item["classification"] == "EXPECTED_DETECTION" and not item.get("expected_rule_id"):
            raise ContractViolation("HANDOFF_TRUTH", "expected item lacks expected_rule_id")
        if "RNC_SYNTH_KEY_" in item["path"]:
            raise ContractViolation("HANDOFF_SECRET_SHAPED", "truth path contains a marker")
    expected_count = sum(item["classification"] == "EXPECTED_DETECTION" for item in truth["items"])
    blocked_count = sum(item["classification"] == "BLOCKED" for item in truth["items"])
    skipped_count = sum(item["classification"] == "SKIPPED" for item in truth["items"])
    expected_counts = {
        "items": len(truth["items"]),
        "expected_detection": expected_count,
        "blocked": blocked_count,
        "skipped": skipped_count,
    }
    if truth.get("counts") != expected_counts:
        raise ContractViolation("HANDOFF_TRUTH_COUNTS", "truth counts do not reconcile to items")
    if len(findings) > expected_count:
        # Extra findings are legitimate false positives; this is a shape check,
        # not a precision gate. The scorer accounts for them separately.
        pass
    finding_ids = {item["finding_id"] for item in findings}
    if len(finding_ids) != len(findings):
        raise ContractViolation("HANDOFF_DUPLICATE", "duplicate normalized finding ID")
    for finding in findings:
        _check_relative(finding["file"], "finding path")
        for key in ("finding_id", "file", "rule_id", "scanner", "scanner_version"):
            if not finding.get(key):
                raise ContractViolation("HANDOFF_FINDING", f"missing {key}")
        if not isinstance(finding.get("line"), int) or finding["line"] < 1:
            raise ContractViolation("HANDOFF_FINDING", "finding line must be a positive integer")
        assert_public_safe({
            "finding_id": finding["finding_id"],
            "rule_id": finding["rule_id"],
            "scanner": finding["scanner"],
            "secret_sha256": finding["secret_sha256"],
            "match_sha256": finding["match_sha256"],
        })
    provenance = document["provenance"]
    for key in ("execution_digest", "policy_digest", "result_digest", "ci_decision_digest"):
        if not provenance[key].startswith("sha256:"):
            raise ContractViolation("HANDOFF_PROVENANCE", f"missing {key}")
    if document["execution_semantics"]["result_classification"] not in {
        "CLEAN", "POLICY_APPLIED", "ACTIONABLE", "INCOMPLETE", "FAILED"
    }:
        raise ContractViolation("HANDOFF_RESULT", "unsupported result name")


def conformance_score(document: dict) -> dict:
    """Line-addressed handoff conformance, not an external harness execution."""
    assert_handoff_safe(document)
    expected = [item for item in document["truth"]["items"] if item["classification"] == "EXPECTED_DETECTION"]
    expected_by_key: dict[tuple[str, str, int], list[dict]] = {}
    for item in expected:
        key = (item["path"], item["expected_rule_id"], item["line_start"])
        expected_by_key.setdefault(key, []).append(item)
    claimed: set[str] = set()
    matched = 0
    unexpected = 0
    duplicates = 0
    for finding in document["findings"]:
        key = (finding["file"], finding["rule_id"], finding["line"])
        candidates = [item for item in expected_by_key.get(key, []) if item["finding_id"] not in claimed]
        if not candidates:
            if any(item for item in expected_by_key.get(key, []) if item["finding_id"] in claimed):
                duplicates += 1
            else:
                unexpected += 1
            continue
        item = candidates[0]
        claimed.add(item["finding_id"])
        matched += 1
    missed = len(expected) - len(claimed)
    total_reported = len(document["findings"])
    return {
        "expected": len(expected),
        "matched": matched,
        "missed": missed,
        "unexpected": unexpected,
        "duplicates": duplicates,
        "reported": total_reported,
        "recall_percent": round(100.0 * matched / len(expected), 2) if expected else None,
        "precision_percent": round(100.0 * matched / total_reported, 2) if total_reported else None,
        "handoff_conformance_only": True,
        "external_harness_executed": False,
    }


def write_handoff(path: Path, bundle: dict, loaded: dict) -> dict:
    document = build_handoff(bundle, loaded)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(document) + "\n", encoding="utf-8", newline="\n")
    return document


def main() -> None:
    import argparse

    from tools.cp0.synthetic_stub import build

    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", choices=("v0", "v1"), default="v1")
    parser.add_argument("--mode", default="perfect")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    loaded = load_v0() if args.corpus == "v0" else load_v1()
    document = write_handoff(args.output, build(corpus=args.corpus, mode=args.mode), loaded)
    print(json.dumps(conformance_score(document), indent=2))


if __name__ == "__main__":
    main()
