"""RNC findings -> independent harness handoff for provider fixtures.

The external harness at the pinned revision is line-addressed. This adapter
preserves byte offsets in metadata and the independently authored truth, so the
compatibility limitation is explicit rather than hidden.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

HANDOFF_VERSION = "rnc-cp3-handoff-v1"
EXTERNAL_SCHEMA_VERSION = 1
HARNESS_REPOSITORY = "RNC-Solutions-Group/gitleaks"
HARNESS_BRANCH = "test/scan-harness"
HARNESS_REVISION = "86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f"


class AdapterError(ValueError):
    pass


def _relative_path(value: str) -> str:
    normalized = str(value).replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if not normalized or normalized.startswith("/") or (
        len(normalized) > 2 and normalized[1] == ":"
    ):
        raise AdapterError(f"unsafe locator {value!r}")
    return normalized


def _rule_index(rules_document: dict) -> dict[str, dict]:
    mapping = {}
    for rule in rules_document.get("rules", []):
        rule_id = rule.get("rule_id")
        if rule_id:
            mapping[rule_id] = rule
    return mapping


def export_truth(truth_document: dict) -> dict:
    items = []
    for item in truth_document.get("items", []):
        metadata = item.get("metadata") or {}
        items.append(
            {
                "finding_id": item["finding_id"],
                "dataset_id": item["dataset_id"],
                "dataset_version": item["dataset_version"],
                "path": _relative_path(item["path"]),
                "classification": item["classification"],
                "category": metadata.get("provider_family") or item.get("category", ""),
                "risk_bearing": item.get("risk_bearing", True),
                "line_start": item["line_start"],
                "line_end": item["line_end"],
                "location": "line",
                "fingerprint_sha256": item["secret_sha256"],
                "source_reference": (
                    f"provider:{metadata.get('provider_family', 'unknown')}:"
                    f"{item['start_byte']}"
                ),
                "matching_policy": "line_range",
                "expected_rule_id": item.get("expected_rule_id"),
                "category_conflict": False,
                "notes": "Independent provider-format truth; byte offset preserved in metadata.",
                "metadata": {
                    "start_byte": item["start_byte"],
                    "end_byte": item["end_byte"],
                    "provider_family": metadata.get("provider_family"),
                    "credential_type": metadata.get("credential_type"),
                    "detector_confidence": metadata.get("detector_confidence"),
                },
            }
        )
    items.sort(key=lambda item: (item["path"], item.get("line_start") or 0, item["finding_id"]))
    document = {
        "schema_version": EXTERNAL_SCHEMA_VERSION,
        "manifest_id": f"cp3-{truth_document['manifest_id']}",
        "manifest_version": truth_document["manifest_version"],
        "dataset_id": truth_document["dataset_id"],
        "dataset_version": truth_document["dataset_version"],
        "items": items,
        "scoring_policy": {
            "id": "rnc-provider-line-range-v1",
            "version": "1",
            "negative_oracle": True,
            "line_tolerance": 0,
            "one_to_one": True,
        },
        "counts": {
            "items": len(items),
            "expected_detection": sum(
                item["classification"] == "EXPECTED_DETECTION" for item in items
            ),
        },
        "integrity": {"status": "PASS"},
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    document["integrity"]["sha256"] = hashlib.sha256(canonical).hexdigest()
    return document


def export_findings(private_document: dict, rules_document: dict) -> list[dict]:
    units = {unit["unit_id"]: unit for unit in private_document["execution"]["units"]}
    rules = _rule_index(rules_document)
    output = []
    for finding in private_document["findings"]:
        unit = units.get(finding["unit_id"])
        if unit is None:
            raise AdapterError("finding has no execution unit")
        if unit["disposition"] != "INSPECTED":
            raise AdapterError("finding is attached to a non-inspected unit")
        rule = rules.get(finding["rule_id"], {})
        digest = finding["evidence_digest"]
        if not digest.startswith("sha256:"):
            raise AdapterError("finding evidence digest is not SHA-256")
        output.append(
            {
                "finding_id": finding["finding_id"],
                "file": _relative_path(unit["locator"]),
                "line": finding["line"],
                "rule_id": finding["rule_id"],
                "secret_sha256": digest.removeprefix("sha256:"),
                "match_sha256": digest.removeprefix("sha256:"),
                "secret_redacted": True,
                "target": f"file:{_relative_path(unit['locator'])}",
                "scanner": "rnc",
                "scanner_version": private_document["execution"]["engine_version"],
                "metadata": {
                    "unit_id": finding["unit_id"],
                    "rule_version": finding["rule_version"],
                    "start_byte": finding["start_byte"],
                    "end_byte": finding["end_byte"],
                    "provider_family": rule.get("family"),
                    "credential_type": rule.get("credential_type"),
                    "confidence": finding["confidence"],
                    "validation": finding["validation"],
                },
            }
        )
    output.sort(key=lambda item: (item["file"], item["line"], item["rule_id"], item["finding_id"]))
    return output


def build_handoff(private_document: dict, truth_document: dict, rules_document: dict) -> dict:
    findings = export_findings(private_document, rules_document)
    truth = export_truth(truth_document)
    return {
        "handoff_version": HANDOFF_VERSION,
        "external_contract": {
            "repository": HARNESS_REPOSITORY,
            "branch": HARNESS_BRANCH,
            "revision": HARNESS_REVISION,
            "scoring_schema_version": EXTERNAL_SCHEMA_VERSION,
            "byte_addressable": False,
            "same_line_limitation": (
                "The pinned harness matches by file and line. Distinct occurrences on one line "
                "are preserved as separate RNC findings and distinguished by the local "
                "byte-range scorer, but the external line scorer can report them as ambiguous."
            ),
        },
        "scanner": {
            "key": "rnc",
            "version": private_document["execution"]["engine_version"],
            "ruleset_id": private_document["execution"]["ruleset_id"],
            "ruleset_digest": private_document["execution"]["ruleset_digest"],
            "backend": private_document.get("execution_plan", {}).get("effective"),
            "backend_requested": private_document.get("execution_plan", {}).get("requested"),
        },
        "dataset": {
            "id": truth["dataset_id"],
            "version": truth["dataset_version"],
            "manifest_id": truth["manifest_id"],
        },
        "truth": truth,
        "findings": findings,
        "provenance": {
            "result_code": private_document["result"]["result_code"],
            "coverage": private_document["result"]["coverage"],
            "execution_state": private_document["execution"]["state"],
            "required_uninspected": sum(
                1
                for unit in private_document["execution"]["units"]
                if unit["disposition"] == "UNINSPECTED" and unit["required_scope"]
            ),
        },
        "scoring_lanes": {
            "byte_addressed": "local tools/cp3/score.py (authoritative for this corpus)",
            "line_addressed_external": "compatibility only; same-line occurrences may be ambiguous",
        },
    }
