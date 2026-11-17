"""Reference unified-configuration loader and explicit legacy migration.

CP0 only. This is not the CP2 policy engine. It proves that one versioned
configuration model exists, that origin is assigned by the loader, and that a
legacy ``security.config`` cannot be silently dual-loaded with the new file.
"""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path
from typing import Any

from tools.cp0.contracts import (
    ContractViolation,
    SCHEMA_VERSION,
    record_digest,
    schema_check,
    schema_registry,
)


UNIFIED_NAME = ".rncscanner.toml"
LEGACY_NAME = "security.config"
DEFAULT_LIMITS = {
    "max_file_bytes": 8 * 1024 * 1024,
    "max_total_bytes": 64 * 1024 * 1024,
    "timeout_ms": 300_000,
    "max_findings": 10_000,
    "follow_symlinks": False,
}
RULE_VERSION = "legacy-security-config-v1"


def default_config() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "ruleset": {
            "id": "rnc-synthetic-v1",
            "version": "1",
            "digest": "sha256:" + hashlib.sha256(b"rnc-synthetic-v1").hexdigest(),
        },
        "scan": dict(DEFAULT_LIMITS),
        "policy": {"effective_policies": [], "blocks": [], "exemptions": []},
        "reporting": {"sanitized_only": True, "redaction_fail_closed": True},
        "ci": {"accepted_result_codes": [1, 2]},
    }


def _schema() -> tuple[dict, Any]:
    schemas, registry = schema_registry()
    return schemas, registry


def validate_config(config: dict) -> dict:
    schemas, registry = _schema()
    schema_check(config, "config.schema.json", schemas, registry, code="CONFIG_SCHEMA_INVALID")
    scan = config["scan"]
    if scan["max_total_bytes"] < scan["max_file_bytes"]:
        raise ContractViolation("CONFIG_LIMIT_ORDER", "max_total_bytes must be >= max_file_bytes")
    policies: dict[str, dict] = {}
    for entry in config["policy"]["effective_policies"]:
        policy_id = entry["policy_id"]
        if policy_id in policies:
            raise ContractViolation("CONFIG_POLICY_DUPLICATE", f"duplicate policy ID {policy_id}")
        if entry["mandatory"] and entry["origin"] != "global":
            raise ContractViolation("CONFIG_MANDATORY_ORIGIN", f"mandatory policy {policy_id} is not global")
        policies[policy_id] = entry
    for kind in ("blocks", "exemptions"):
        for entry in config["policy"][kind]:
            effective = policies.get(entry["policy_id"])
            if effective is None:
                raise ContractViolation("CONFIG_POLICY_UNKNOWN", f"{kind} entry uses unknown policy {entry['policy_id']}")
            if effective["origin"] != entry["origin"]:
                raise ContractViolation("CONFIG_POLICY_ORIGIN", f"{kind} entry origin disagrees with effective policy")
    accepted = config["ci"]["accepted_result_codes"]
    if accepted != sorted(accepted):
        raise ContractViolation("CONFIG_CI_ORDER", "accepted_result_codes must be sorted")
    return config


def _positive(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ContractViolation("LEGACY_FIELD_INVALID", f"{name} must be a positive integer")
    return value


def migrate_legacy(document: dict, *, legacy_digest: str | None = None) -> dict:
    """Map the narrowly reviewed legacy subset; reject everything else."""
    if not isinstance(document, dict):
        raise ContractViolation("LEGACY_SHAPE", "legacy configuration must be a TOML table")
    if document.get("version") != 1:
        raise ContractViolation("LEGACY_VERSION", "only legacy security.config version 1 is supported")
    allowed = {"version", "secret_detection", "exclusions", "limits", "reporting", "ci"}
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise ContractViolation("LEGACY_UNSUPPORTED", "unsupported legacy fields: " + ", ".join(unknown))

    detection = document.get("secret_detection") or {}
    if not isinstance(detection, dict):
        raise ContractViolation("LEGACY_SHAPE", "secret_detection must be a table")
    if detection.get("enabled") is not True:
        raise ContractViolation("LEGACY_SCANNER_DISABLED", "legacy scanner must be enabled to migrate a scan policy")
    ruleset_id = detection.get("ruleset")
    ruleset_digest = detection.get("ruleset_digest")
    if not isinstance(ruleset_id, str) or not ruleset_id:
        raise ContractViolation("LEGACY_RULESET", "secret_detection.ruleset is required")
    if not isinstance(ruleset_digest, str) or not ruleset_digest.startswith("sha256:"):
        raise ContractViolation("LEGACY_RULESET", "secret_detection.ruleset_digest must be a sha256 digest")
    unknown_detection = sorted(set(detection) - {"enabled", "ruleset", "ruleset_digest"})
    if unknown_detection:
        raise ContractViolation("LEGACY_UNSUPPORTED", "unsupported secret_detection fields: " + ", ".join(unknown_detection))

    reporting = document.get("reporting") or {}
    if not isinstance(reporting, dict):
        raise ContractViolation("LEGACY_SHAPE", "reporting must be a table")
    if reporting.get("sanitized", True) is not True:
        raise ContractViolation("LEGACY_UNSAFE_REPORTING", "legacy unsanitized reporting cannot be migrated")
    unknown_reporting = sorted(set(reporting) - {"sanitized"})
    if unknown_reporting:
        raise ContractViolation("LEGACY_UNSUPPORTED", "unsupported reporting fields: " + ", ".join(unknown_reporting))

    limits = document.get("limits") or {}
    if not isinstance(limits, dict):
        raise ContractViolation("LEGACY_SHAPE", "limits must be a table")
    unknown_limits = sorted(set(limits) - {"max_file_bytes", "max_total_bytes", "timeout_ms", "max_findings"})
    if unknown_limits:
        raise ContractViolation("LEGACY_UNSUPPORTED", "unsupported limit fields: " + ", ".join(unknown_limits))
    scan = dict(DEFAULT_LIMITS)
    for key in ("max_file_bytes", "max_total_bytes", "timeout_ms", "max_findings"):
        if key in limits:
            scan[key] = _positive(limits[key], key)

    exclusions = document.get("exclusions") or {}
    if not isinstance(exclusions, dict):
        raise ContractViolation("LEGACY_SHAPE", "exclusions must be a table")
    paths = exclusions.get("paths", [])
    if not isinstance(paths, list) or any(not isinstance(item, str) or not item for item in paths):
        raise ContractViolation("LEGACY_EXCLUSIONS", "exclusions.paths must be a list of non-empty strings")
    unknown_exclusions = sorted(set(exclusions) - {"paths"})
    if unknown_exclusions:
        raise ContractViolation("LEGACY_UNSUPPORTED", "unsupported exclusion fields: " + ", ".join(unknown_exclusions))

    policy_id = "LEGACY-SECURITY-CONFIG"
    blocks = [
        {
            "policy_id": policy_id,
            "origin": "repository",
            "selector": path,
            "reason": "Migrated from legacy security.config exclusions",
        }
        for path in paths
    ]
    effective = []
    if blocks:
        effective.append({
            "policy_id": policy_id,
            "origin": "repository",
            "version": RULE_VERSION,
            "digest": legacy_digest or record_digest(document),
            "mandatory": False,
        })

    ci = document.get("ci") or {}
    if not isinstance(ci, dict):
        raise ContractViolation("LEGACY_SHAPE", "ci must be a table")
    accepted = ci.get("accepted_result_codes", [1, 2])
    if not isinstance(accepted, list) or not accepted:
        raise ContractViolation("LEGACY_CI", "ci.accepted_result_codes must be a non-empty list")
    if any(not isinstance(item, int) or item not in (1, 2, 3) for item in accepted):
        raise ContractViolation("LEGACY_CI", "legacy CI may accept only completed result codes 1-3")
    if accepted != sorted(set(accepted)):
        raise ContractViolation("LEGACY_CI", "legacy CI result codes must be sorted and unique")
    unknown_ci = sorted(set(ci) - {"accepted_result_codes"})
    if unknown_ci:
        raise ContractViolation("LEGACY_UNSUPPORTED", "unsupported ci fields: " + ", ".join(unknown_ci))

    config = {
        "schema_version": SCHEMA_VERSION,
        "ruleset": {"id": ruleset_id, "version": RULE_VERSION, "digest": ruleset_digest},
        "scan": scan,
        "policy": {"effective_policies": effective, "blocks": blocks, "exemptions": []},
        "reporting": {"sanitized_only": True, "redaction_fail_closed": True},
        "ci": {"accepted_result_codes": accepted},
    }
    return validate_config(config)


def load_config(path: Path) -> dict:
    try:
        raw = path.read_bytes()
        document = tomllib.loads(raw.removeprefix(b"\xef\xbb\xbf").decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ContractViolation("CONFIG_UNREADABLE", f"cannot read {path}: {exc}") from exc
    return validate_config(document)


def load_project_config(repo_root: Path) -> tuple[dict, dict]:
    """Load exactly one source. Dual files are a hard failure, never a merge."""
    repo_root = Path(repo_root)
    unified = repo_root / UNIFIED_NAME
    legacy = repo_root / LEGACY_NAME
    if unified.exists() and legacy.exists():
        raise ContractViolation(
            "CONFIG_DUAL_SOURCE",
            "both .rncscanner.toml and security.config exist; choose one explicitly before scanning",
        )
    if unified.exists():
        return load_config(unified), {"source": UNIFIED_NAME, "origin": "repository", "migrated": False}
    if legacy.exists():
        try:
            raw = legacy.read_bytes()
            legacy_document = tomllib.loads(raw.removeprefix(b"\xef\xbb\xbf").decode("utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            raise ContractViolation("CONFIG_UNREADABLE", f"cannot read {legacy}: {exc}") from exc
        config = migrate_legacy(legacy_document, legacy_digest=record_digest(legacy_document))
        return config, {"source": LEGACY_NAME, "origin": "repository", "migrated": True}
    config = default_config()
    return config, {"source": None, "origin": "repository", "migrated": False}


def config_digest(config: dict) -> str:
    return record_digest(config)
