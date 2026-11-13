"""Independent canonical rule-bundle digest and validation helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _rule_value(rule: dict, schema_version: str) -> dict:
    value = {
        "rule_id": rule["rule_id"],
        "rule_version": rule["rule_version"],
        "category": rule["category"],
        "pattern": rule["pattern"],
        "capture_group": rule["capture_group"],
        "validators": rule["validators"],
        "confidence": rule["confidence"],
        "max_match_bytes": rule["max_match_bytes"],
    }
    if schema_version == "0.2.0":
        for key in (
            "value_capture_groups",
            "provider",
            "family",
            "credential_type",
            "context",
            "component_extractor",
            "identifier_capture_group",
            "max_candidate_bytes",
            "fixture_set",
            "provenance",
        ):
            if key in rule:
                value[key] = rule[key]
    return value


def canonical_digest(document: dict) -> str:
    schema_version = document["schema_version"]
    rules = sorted(document["rules"], key=lambda rule: rule["rule_id"])
    normalized = {
        "schema_version": schema_version,
        "ruleset_id": document["ruleset_id"],
        "ruleset_version": document["ruleset_version"],
        "rules": [_rule_value(rule, schema_version) for rule in rules],
    }
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
