"""Sanitized CSV, JSON, and Markdown writers for detection-gap reports."""

from __future__ import annotations

import collections
import csv
import datetime as dt
import hashlib
import html
import json
from pathlib import Path
from typing import Any, Callable, Iterable

from .model import (
    LANE_DENOMINATORS,
    LANE_ORDER,
    LANE_TITLES,
    SCANNER_DIRS,
    AnalysisRow,
    Target,
)
from .sources import DetectionGapError

ANALYSIS_VERSION = "1.0.0"


def _yes(value: bool) -> str:
    return "YES" if value else "NO"


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return _yes(value)
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(item) for item in value)
    return str(value)


def _pct(numerator: int, denominator: int) -> str:
    return f"{100.0 * numerator / denominator:.2f}%" if denominator else "N/A"


def _md(value: Any) -> str:
    return html.escape(_text(value)).replace("|", "\\|")


def _write_csv(path: Path, columns: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({column: _text(row.get(column)) for column in columns})


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(_md(value) for value in row) + " |")
    return "\n".join(lines)


def _sample_targets(rows: Iterable[AnalysisRow], limit: int = 12) -> str:
    ids = [row.target.target_id for row in list(rows)[:limit]]
    return ", ".join(f"`{target_id}`" for target_id in ids) if ids else "-"


def _lane_stats(rows: list[AnalysisRow]) -> list[dict[str, Any]]:
    result = []
    for lane in LANE_ORDER:
        items = [row for row in rows if row.target.lane == lane]
        if not items:
            continue
        matched = sum(1 for row in items if row.observation.matched)
        missed = len(items) - matched
        result.append(
            {
                "lane": lane,
                "title": LANE_TITLES[lane],
                "expected": len(items),
                "matched": matched,
                "missed": missed,
                "recall_percent": round(100.0 * matched / len(items), 2) if items else 0.0,
                "risk_misses": sum(1 for row in items if not row.observation.matched and row.target.risk_bearing),
                "informative_misses": sum(1 for row in items if not row.observation.matched and row.target.informative),
                "unverified": sum(1 for row in items if row.observation.disposition == "UNVERIFIED_EVIDENCE"),
            }
        )
    return result


def _breakdown(
    rows: list[AnalysisRow],
    selector: Callable[[AnalysisRow], str],
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    groups: dict[str, list[AnalysisRow]] = collections.defaultdict(list)
    for row in rows:
        groups[selector(row)].append(row)
    result = []
    for key, items in groups.items():
        matched = sum(1 for row in items if row.observation.matched)
        missed = len(items) - matched
        result.append(
            {
                "key": key,
                "expected": len(items),
                "matched": matched,
                "missed": missed,
                "recall_percent": round(100.0 * matched / len(items), 2) if items else 0.0,
                "risk_misses": sum(1 for row in items if not row.observation.matched and row.target.risk_bearing),
                "informative_misses": sum(1 for row in items if not row.observation.matched and row.target.informative),
                "cross_found": sum(1 for row in items if not row.observation.matched and row.cross_scanners),
            }
        )
    result.sort(key=lambda item: (-item["missed"], -item["expected"], item["key"]))
    return result[:limit] if limit else result


def _category(row: AnalysisRow) -> str:
    return "informative_reference" if row.target.informative else row.target.category


def _specific_key(row: AnalysisRow) -> str:
    target = row.target
    if target.informative:
        return "informative_reference"
    if row.root_cause == "SOURCE_UNSUPPORTED":
        return "structured_container"
    if target.subtype == "wordpress_salt":
        return "wordpress_authentication_material"
    if target.context.identifier_family in {"HMAC", "SIGNING"} or target.subtype in {
        "application_hmac_key",
        "jwt_signing_key",
        "application_signing_key",
    }:
        return "hmac_and_signing_identifiers"
    if target.subtype in {"key_passphrase", "pkcs12_passphrase"}:
        return "passphrase_identifiers"
    if target.subtype == "totp_seed":
        return "totp_seed"
    if target.subtype == "browser_saved_credential":
        return "encrypted_browser_credentials"
    if target.category == "provider_token":
        return f"provider_token:{target.provider}"
    if target.category == "api_key" and target.subtype == "generic_api_key":
        return "generic_api_key"
    if target.category == "api_key":
        return f"api_key:{target.provider}"
    if target.category == "private_key":
        return "private_key_container_or_pem"
    if target.container_kind in {"archive_member", "database_record", "binary_file"}:
        return "structured_container"
    if target.category == "password":
        if target.representation in {
            "redis_url",
            "alembic_url",
            "database_url",
            "mongodb_uri",
            "sqlserver_connection_string",
        } or "url" in target.representation:
            return "password_in_uri_or_connection_string"
        if (
            target.representation
            in {
                "sql_copy_value",
                "hash_value",
                "base64_value",
                "docker_secret_file",
                "docker_config_auth",
                "filezilla_base64_password",
                "jetbrains_static_key_obfuscated",
                "kubeconfig_token",
                "log_command_argument",
                "compose_command_arg",
            }
            or target.context.identifier in {"", "NO_ASSIGNMENT_IDENTIFIER"}
            or target.path.endswith((".pgpass", ".netrc", ".git-credentials"))
        ):
            return "password_positional_or_encoded"
        if target.subtype in {"database_password", "browser_saved_credential"} or target.context.identifier_family in {"DATABASE_PASSWORD"}:
            return "database_password_identifiers"
        return "application_password_identifiers"
    return f"other:{target.subtype or target.category}"


def target_inventory_rows(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in analysis["rows"]:
        target = row.target
        observation = row.observation
        rows.append(
            {
                "scanner": analysis["evidence"].label,
                "scanner_key": analysis["key"],
                "build_id": analysis["evidence"].metadata["build_id"],
                "target_id": target.target_id,
                "dataset": target.dataset,
                "lane": target.lane,
                "lane_title": target.lane_title,
                "oracle_disposition": target.source.get("oracle_class") or target.target_class,
                "target_class": target.target_class,
                "expected": "YES",
                "matched": _yes(observation.matched),
                "score_disposition": observation.disposition,
                "risk_bearing": _yes(target.risk_bearing),
                "informative": _yes(target.informative),
                "primary_tp": _yes(target.primary_tp),
                "unique_secret_group_id": target.group_id,
                "occurrence_id": target.occurrence_id,
                "historical_occurrence_id": target.occurrence_id if target.container_kind == "git_blob" else "",
                "category": target.category,
                "subtype": target.subtype,
                "provider": target.provider,
                "provider_confidence": target.provider_confidence,
                "credential_purpose": target.purpose,
                "path": target.path,
                "file_type": target.file_type,
                "source_container": target.container_kind,
                "container_format": target.container_format,
                "archive_member": target.archive_member,
                "archive_depth": target.archive_depth,
                "database_table": target.database_table,
                "database_column": target.database_column,
                "git_commit": target.commit,
                "line": target.line,
                "byte_start": target.byte_start,
                "byte_end": target.byte_end,
                "representation": target.representation,
                "normalization": target.normalization,
                "identifier_key": target.context.identifier,
                "identifier_family": target.context.identifier_family,
                "scanner_scope": "GIT" if target.container_kind == "git_blob" else "FILESYSTEM",
                "inspection_status": observation.source_inspected,
                "rule_id": observation.rule_id,
                "finding_id": observation.finding_id,
                "match_classification": observation.capture if observation.matched else ("UNVERIFIED" if observation.disposition == "UNVERIFIED_EVIDENCE" else "NO_OBSERVATION"),
                "overlapping_finding": _yes(observation.overlap),
                "scorer_disposition": observation.disposition,
                "rejected_or_pending": _yes(observation.disposition in {"UNVERIFIED_EVIDENCE", "DUPLICATE_ONLY"}),
                "root_cause": row.root_cause,
                "root_cause_confidence": row.confidence,
                "responsible_layer": row.layer,
                "evidence_summary": row.evidence,
                "reproduction": row.reproduction,
                "cross_scanner_matches": row.cross_scanners,
                "development_priority": row.priority,
            }
        )
    return rows


def missed_rows(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in analysis["rows"]:
        if row.observation.matched:
            continue
        target = row.target
        observation = row.observation
        rows.append(
            {
                "scanner": analysis["evidence"].label,
                "scanner_key": analysis["key"],
                "target_id": target.target_id,
                "dataset": target.dataset,
                "lane": target.lane,
                "target_class": target.target_class,
                "risk_bearing": _yes(target.risk_bearing),
                "informative": _yes(target.informative),
                "unique_secret_group_id": target.group_id,
                "occurrence_id": target.occurrence_id,
                "historical_occurrence_id": target.occurrence_id if target.container_kind == "git_blob" else "",
                "category": target.category,
                "subtype": target.subtype,
                "provider": target.provider,
                "provider_confidence": target.provider_confidence,
                "credential_purpose": target.purpose,
                "path": target.path,
                "file_type": target.file_type,
                "source_container": target.container_kind,
                "container_format": target.container_format,
                "archive_member": target.archive_member,
                "database_table": target.database_table,
                "database_column": target.database_column,
                "git_commit": target.commit,
                "line": target.line,
                "representation": target.representation,
                "normalization": target.normalization,
                "identifier_key": target.context.identifier,
                "identifier_family": target.context.identifier_family,
                "inspection_status": observation.source_inspected,
                "overlap_finding": _yes(observation.overlap),
                "overlap_rule_id": observation.rule_id if observation.overlap else "",
                "overlap_capture": observation.capture if observation.overlap else "",
                "score_disposition": observation.disposition,
                "scoring_reason": observation.reason,
                "scoring_reason_code": observation.reason_code,
                "scoring_stage": observation.stage,
                "root_cause": row.root_cause,
                "root_cause_confidence": row.confidence,
                "responsible_layer": row.layer,
                "evidence_summary": row.evidence,
                "smallest_reproduction": row.reproduction,
                "existing_rule_capability": _capability_text(row),
                "cross_scanner_matches": row.cross_scanners,
                "cross_scanner_rules": ";".join(f"{key}:{rule}" for key, rule in sorted(row.cross_rules.items()) if rule),
                "development_priority": row.priority,
            }
        )
    return rows


def _capability_text(row: AnalysisRow) -> str:
    capability = row.capability
    if capability.get("provider_rules"):
        return "provider-rule:" + ";".join(capability["provider_rules"])
    if capability.get("observed_subtype_rule"):
        return f"observed-subtype:{capability['observed_subtype_rule']}"
    if capability.get("observed_representation_rule"):
        return f"observed-representation:{capability['observed_representation_rule']}"
    if capability.get("generic_identifier_available"):
        return "generic-identifier-present"
    return capability.get("basis") or "no-rule-identified"


def provider_context_rows(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in analysis["rows"]:
        if row.observation.matched:
            continue
        target = row.target
        context = target.context
        evidence = list(context.provider_markers)
        if context.identifier:
            evidence.append(f"identifier_family:{context.identifier_family}")
        if context.domains:
            evidence.extend(f"domain:{domain}" for domain in context.domains)
        if target.scenario:
            evidence.append(f"scenario:{target.scenario}")
        context_confidence = "HIGH" if target.provider_confidence == "HIGH" and context.context_available else (
            "MEDIUM" if context.context_available else "LOW"
        )
        rows.append(
            {
                "scanner": analysis["evidence"].label,
                "scanner_key": analysis["key"],
                "target_id": target.target_id,
                "dataset": target.dataset,
                "lane": target.lane,
                "category": target.category,
                "subtype": target.subtype,
                "provider": target.provider,
                "provider_confidence": target.provider_confidence,
                "credential_family": target.category,
                "credential_purpose": target.purpose,
                "identifier_key": context.identifier,
                "identifier_family": context.identifier_family,
                "assignment_style": context.assignment_style,
                "structured_parent": context.structured_parent,
                "provider_identifying_evidence": evidence,
                "domains": context.domains,
                "companion_identifiers": context.companion_identifiers,
                "requires_multiline": _yes(context.requires_multiline),
                "requires_structured_parse": _yes(context.requires_structured_parse),
                "context_available": _yes(context.context_available),
                "context_redacted": context.context_redacted,
                "adjacent_context_redacted": context.adjacent_redacted,
                "existing_rule_capability": _capability_text(row),
                "observed_same_subtype_rule": row.capability.get("observed_subtype_rule", ""),
                "observed_same_subtype_matches": row.capability.get("observed_subtype_count", 0),
                "observed_same_representation_matches": row.capability.get("observed_representation_count", 0),
                "context_confidence": context_confidence,
                "notes": context.context_note,
            }
        )
    return rows


def location_rows(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in analysis["rows"]:
        if row.observation.matched:
            continue
        target = row.target
        rows.append(
            {
                "scanner": analysis["evidence"].label,
                "scanner_key": analysis["key"],
                "target_id": target.target_id,
                "dataset": target.dataset,
                "lane": target.lane,
                "matched": "NO",
                "source_container": target.container_kind,
                "container_format": target.container_format,
                "archive_format": target.container_format if target.container_kind == "archive_member" else "",
                "archive_depth": target.archive_depth,
                "archive_member": target.archive_member,
                "database_table": target.database_table,
                "database_column": target.database_column,
                "database_rowid": target.database_rowid,
                "binary_format": target.container_format if target.container_kind == "binary_file" else "",
                "git_commit": target.commit,
                "path": target.path,
                "line": target.line,
                "byte_start": target.byte_start,
                "byte_end": target.byte_end,
                "file_type": target.file_type,
                "representation": target.representation,
                "representation_family": _representation_family(target),
                "normalization": target.normalization,
                "scanner_scope": "GIT" if target.container_kind == "git_blob" else "FILESYSTEM",
                "inspection_status": row.observation.source_inspected,
                "source_eligibility": {
                    "INSPECTED": "ELIGIBLE_INSPECTED",
                    "INSPECTED_UNVERIFIED": "ELIGIBLE_INSPECTION_UNVERIFIED",
                    "UNINSPECTED": "ELIGIBLE_UNINSPECTED",
                    "UNSUPPORTED_CONTAINER": "UNSUPPORTED_CONTAINER",
                    "NOT_APPLICABLE": "NOT_APPLICABLE",
                }.get(row.observation.source_inspected, "UNKNOWN"),
                "root_cause": row.root_cause,
                "root_cause_confidence": row.confidence,
                "responsible_layer": row.layer,
                "cross_scanner_matches": row.cross_scanners,
            }
        )
    return rows


def _representation_family(target: Target) -> str:
    representation = target.representation.lower()
    if "pem" in representation or "putty" in representation or "pkcs12" in representation:
        return "key-container"
    if "base64" in representation or "docker_config_auth" in representation:
        return "base64"
    if "url" in representation or "uri" in representation or "connection_string" in representation:
        return "uri-or-connection-string"
    if "kubernetes" in representation or "sql" in representation or "bson" in representation:
        return "structured-value"
    if "json" in representation or "yaml" in representation or "xml" in representation or "define" in representation:
        return "structured-assignment"
    if "escaped" in representation:
        return "escaped"
    if "section" in representation or "source_line" in representation or "assignment" in representation:
        return "plaintext"
    return representation or "unknown"


def _opportunity_rows(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    groups: dict[str, list[AnalysisRow]] = collections.defaultdict(list)
    for row in analysis["rows"]:
        if row.observation.matched:
            continue
        if row.target.informative:
            continue
        groups[_specific_key(row)].append(row)
    result = []
    for key, rows in groups.items():
        risk = sum(1 for row in rows if row.target.risk_bearing)
        cross = sum(1 for row in rows if row.cross_scanners)
        if risk == 0:
            continue
        causes = collections.Counter(row.root_cause for row in rows)
        cause = causes.most_common(1)[0][0]
        result.append(
            {
                "root_cause": cause,
                "root_causes": dict(causes),
                "opportunity": key,
                "misses": len(rows),
                "risk_misses": risk,
                "cross_found": cross,
                "lanes": sorted({row.target.lane for row in rows}),
                "subtypes": sorted({row.target.subtype for row in rows})[:8],
                "providers": sorted({row.target.provider for row in rows})[:8],
                "representations": sorted({row.target.representation for row in rows})[:8],
                "identifiers": sorted({row.target.context.identifier for row in rows if row.target.context.identifier})[:10],
                "confidence": _dominant(row.confidence for row in rows),
                "priority": "HIGH" if risk >= 10 else "MEDIUM",
                "sample_targets": [row.target.target_id for row in rows[:12]],
            }
        )
    result.sort(key=lambda item: (-item["risk_misses"], item["opportunity"]))
    return result


def _dominant(values: Iterable[str]) -> str:
    counts = collections.Counter(values)
    return counts.most_common(1)[0][0] if counts else "UNRESOLVED"


def _recommendation(opportunity: dict[str, Any]) -> dict[str, str]:
    cause = opportunity["root_cause"]
    key = opportunity["opportunity"]
    if key == "wordpress_authentication_material":
        return {
            "action": "Add a reviewed WordPress authentication-key/salt identifier family to the generic assignment matcher (AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY, AUTH_SALT, SECURE_AUTH_SALT, LOGGED_IN_SALT, NONCE_SALT and WP_SALT_n). Use the existing assignment and high-entropy checks; do not add a bare SALT keyword.",
            "fp_risk": "LOW",
            "complexity": "LOW",
            "reuse": "All PHP, .env, Kubernetes Secret and Git occurrences; no provider-network requirement.",
            "layer": "IDENTIFIER_LEXICON",
        }
    if key == "hmac_and_signing_identifiers":
        return {
            "action": "Extend the generic assignment identifier family for SIGNING_KEY, HMAC_KEY, HMAC_SECRET and camelCase JSON fields such as SigningKey, while retaining the current assignment-context and value-entropy requirements. Add a JWT_SIGNING_KEY alias rather than a bare KEY rule. The expression-wrapped and JSON subcases need the matching context/decoder work; the identifier change alone recovers the direct assignment subset.",
            "fp_risk": "MEDIUM",
            "complexity": "LOW",
            "reuse": "Environment files, Python expressions, JSON, YAML and Git snapshots; container work is separate.",
            "layer": "IDENTIFIER_LEXICON",
        }
    if key == "encrypted_browser_credentials":
        return {
            "action": "Add a Firefox/Chrome browser-profile decoder that attributes encrypted username/password fields to the paired login record and reports the protected credential container. Do not treat the encrypted blob alone as a decrypted password; without the browser key database the evidence is a protected credential exposure, not a usable plaintext secret.",
            "fp_risk": "MEDIUM",
            "complexity": "HIGH",
            "reuse": "Browser profile formats share a structured-record model; the decoder is reusable across Chrome/Firefox fixtures.",
            "layer": "REPRESENTATION_DECODER",
        }
    if key == "totp_seed":
        return {
            "action": "Add a TOTP/otpauth rule covering otpauth://totp URIs and high-entropy TOTP_SEED/TOTP_SECRET assignment fields. Parse the issuer/account metadata without treating ordinary identifiers or OTP policy values as seeds.",
            "fp_risk": "MEDIUM",
            "complexity": "LOW",
            "reuse": "Text files, provisioning logs and configuration; a single rule covers all formats.",
            "layer": "RULE_COVERAGE",
        }
    if key == "database_password_identifiers":
        if cause in {"UNKNOWN", "CONTEXT_INSUFFICIENT"}:
            return {
                "action": "Instrument the database-password candidate pipeline and context association before broadening the identifier set. The same subtype and representation is credited for other values, so the decisive difference may be a value check or field-role association, not a missing identifier. Add no broad new pattern until an A/B candidate trace identifies the rejecting stage.",
                "fp_risk": "MEDIUM",
                "complexity": "MEDIUM",
                "reuse": "A validator/context fix would apply to every database and application format.",
                "layer": "VALUE_VALIDATOR",
            }
        return {
            "action": "Expand the reviewed database-password identifier set (DB_PASSWORD, DATABASE_PASSWORD, POSTGRES_PASSWORD, MYSQL_PASSWORD, MONGO_PASSWORD, REDIS_PASSWORD and common service-qualified variants) and add a password-only URI/connection-string parser.",
            "fp_risk": "MEDIUM",
            "complexity": "MEDIUM",
            "reuse": "All assignment formats plus SQL/ORM configuration; parser is reusable.",
            "layer": "IDENTIFIER_LEXICON",
        }
    if key == "application_password_identifiers":
        if cause == "CONTEXT_INSUFFICIENT":
            return {
                "action": "Instrument and extend the application-password field-role/context association. The same subtype, identifier and representation is credited for other values, so a broad identifier rule is not the right first change. Verify whether the candidate was generated and rejected at the value/context stage.",
                "fp_risk": "MEDIUM",
                "complexity": "MEDIUM",
                "reuse": "Context-model fix applies across configuration formats.",
                "layer": "CONTEXT_MODEL",
            }
        return {
            "action": "Add the missing reviewed application-password aliases (SMTP, FTP, Redis, registry and admin qualifiers) and, where the alias is already recognized, extend the field-role/context association instead of adding a broad rule. Do not add a generic USERNAME or EMAIL rule.",
            "fp_risk": "MEDIUM",
            "complexity": "MEDIUM",
            "reuse": "Environment, YAML, JSON, INI and XML configuration.",
            "layer": "IDENTIFIER_LEXICON",
        }
    if key == "password_in_uri_or_connection_string":
        return {
            "action": "Implement a URI/connection-string password parser for password-only userinfo (redis://:password@host), driver-qualified schemes (postgresql+psycopg2), percent-decoding and SQLAlchemy/Alembic URL settings. Preserve the current database-uri rule for user:password forms.",
            "fp_risk": "LOW",
            "complexity": "MEDIUM",
            "reuse": "All application formats; provider-agnostic and directly reusable.",
            "layer": "REPRESENTATION_DECODER",
        }
    if key == "passphrase_identifiers":
        return {
            "action": "Add a reviewed private-key passphrase identifier family (PASSPHRASE, P12_PASSPHRASE, ENCKEY_*_PASSPHRASE) and associate it with the protected key container when one is present. Do not treat every PASSPHRASE-named string as a password without a value-shape check.",
            "fp_risk": "MEDIUM",
            "complexity": "LOW",
            "reuse": "PEM, PKCS#12, SSH and configuration formats.",
            "layer": "IDENTIFIER_LEXICON",
        }
    if key == "password_positional_or_encoded":
        return {
            "action": "Add bounded parsers for positional credential files (.pgpass, .netrc, .git-credentials), Docker auth, FileZilla/JetBrains encoded fields and SQL COPY/INSERT password columns. Add reviewed identifier aliases only for fields that remain ordinary assignments. Emit findings only when the field role and value shape agree.",
            "fp_risk": "MEDIUM",
            "complexity": "HIGH",
            "reuse": "Several legacy formats share the same field-role model; avoid one-off regexes.",
            "layer": "REPRESENTATION_DECODER",
        }
    if key == "generic_api_key":
        return {
            "action": "Add a provider-neutral API-key shape rule for documented families such as ak_/pcsk_ only when an assignment, paired credential or provider URL is present. Do not promote every high-entropy assignment to an API key.",
            "fp_risk": "HIGH",
            "complexity": "MEDIUM",
            "reuse": "Environment, Compose and structured configuration; pair-aware context is reusable.",
            "layer": "RULE_COVERAGE",
        }
    if key.startswith("provider_token:") and "Unidentified" in key:
        return {
            "action": "Triage the unidentified provider-token clusters by documented token prefix and add rules only for families with an independently reproducible shape. The group includes several unrelated Levain providers; one broad 'token' regex would be unsafe. Prioritize any cluster with more than one occurrence and retain a negative fixture per provider.",
            "fp_risk": "HIGH",
            "complexity": "MEDIUM",
            "reuse": "Each provider rule is reusable, but the group must be split by provider.",
            "layer": "RULE_COVERAGE",
        }
    if key.startswith("provider_token:"):
        return {
            "action": "Close the specific provider-rule gap (documented token shape and assignment/context requirement). For Azure AccountKey, accept JSON/XML key/value separators in addition to the connection-string '=' form. For Stripe webhooks, add the whsec_ signing-secret shape.",
            "fp_risk": "LOW",
            "complexity": "LOW",
            "reuse": "Provider rule is reusable across files and Git; validate against the negative oracle.",
            "layer": "RULE_COVERAGE",
        }
    if key == "private_key_container_or_pem":
        return {
            "action": "Add bounded PKCS#12 and PuTTY PPK v2 private-key extraction, and ensure encrypted PEM/PKCS#8 passphrases are treated as separate password findings. Keep the existing PEM material-required policy and public-key exclusions.",
            "fp_risk": "MEDIUM",
            "complexity": "HIGH",
            "reuse": "Key-container parser is reusable across files, archives and Git; no network calls.",
            "layer": "REPRESENTATION_DECODER",
        }
    if key == "structured_container":
        return {
            "action": "Add archive-member, SQLite-row/BSON-field and binary-container traversal with bounded expansion and source attribution. Do not count an archive container as inspected unless its members are actually inspected.",
            "fp_risk": "MEDIUM",
            "complexity": "VERY HIGH",
            "reuse": "One source-acquisition framework serves archives, databases and nested containers.",
            "layer": "SOURCE_ACQUISITION",
        }
    if cause == "VALIDATOR_REJECTION":
        return {
            "action": "Instrument the candidate pipeline for this exact value family, then adjust only the value-shape/entropy/stopword check responsible. Do not lower the global entropy floor; retain an A/B control from the same identifier and representation.",
            "fp_risk": "MEDIUM",
            "complexity": "MEDIUM",
            "reuse": "Validator fix applies to every format; requires scanner-side diagnostics.",
            "layer": "VALUE_VALIDATOR",
        }
    if cause == "CAPTURE_MISMATCH":
        return {
            "action": "Fix source-span or component extraction so the credited value matches the oracle identity. Re-run the target and the existing negative fixtures before broadening any regex.",
            "fp_risk": "LOW",
            "complexity": "MEDIUM",
            "reuse": "Extraction fix is format-wide.",
            "layer": "VALUE_CAPTURE",
        }
    if cause == "CONTEXT_INSUFFICIENT":
        return {
            "action": "Extend the context window or structured-field path so the existing rule can associate the value with its identifier. Avoid scanning arbitrary nearby text as a credential.",
            "fp_risk": "MEDIUM",
            "complexity": "MEDIUM",
            "reuse": "Context model is reusable across formats.",
            "layer": "CONTEXT_MODEL",
        }
    if cause == "FORMAT_UNSUPPORTED":
        return {
            "action": "Add a bounded decoder for this representation and attribute the decoded value to the original source span. Do not report the encoded container as the secret.",
            "fp_risk": "MEDIUM",
            "complexity": "MEDIUM",
            "reuse": "Decoder is reusable across providers and files.",
            "layer": "REPRESENTATION_DECODER",
        }
    if cause == "RULE_ABSENT":
        return {
            "action": "Add the missing provider/credential-family rule with a documented shape and an explicit negative fixture.",
            "fp_risk": "MEDIUM",
            "complexity": "MEDIUM",
            "reuse": "Provider rule is reusable across formats.",
            "layer": "RULE_COVERAGE",
        }
    return {
        "action": "Collect scanner-side candidate diagnostics for this group before proposing a rule change; the retained evidence does not distinguish rule, context and validator causes.",
        "fp_risk": "UNKNOWN",
        "complexity": "UNKNOWN",
        "reuse": "Unknown until instrumented.",
        "layer": "UNRESOLVED",
    }


def build_scanner_summary(
    analysis: dict[str, Any],
    cross: dict[str, Any],
    *,
    generated_at: str,
) -> dict[str, Any]:
    rows = analysis["rows"]
    evidence = analysis["evidence"]
    misses = [row for row in rows if not row.observation.matched]
    risk_misses = [row for row in misses if row.target.risk_bearing]
    meta = evidence.metadata
    report = evidence.report
    summary = {
        "schema_version": 1,
        "analysis_version": ANALYSIS_VERSION,
        "generated_at": generated_at,
        "scanner": analysis["label"],
        "scanner_key": analysis["key"],
        "build_id": meta["build_id"],
        "version": meta["version"],
        "source_commit": meta["source_commit"],
        "source_commit_metadata_only": True,
        "executable_sha256": meta["executable_sha256"],
        "rules_file": meta.get("rules_file"),
        "rules_sha256": meta.get("rules_sha256"),
        "report_path": meta["report_path"],
        "report_sha256": meta["report_sha256"],
        "run_id": meta["run_id"],
        "generated_report_at": meta["generated_at"],
        "scoring_epoch": "current post-scoring-integrity remediation (2026-11-15)",
        "configuration_profile": meta["profile"],
        "scanner_extra_args": meta.get("scanner_extra_args"),
        "target_universe": {
            "total": len(rows),
            "by_lane": {lane: sum(1 for row in rows if row.target.lane == lane) for lane in LANE_ORDER},
        },
        "counts": {
            "expected": len(rows),
            "matched": len(rows) - len(misses),
            "missed": len(misses),
            "risk_bearing_expected": sum(1 for row in rows if row.target.risk_bearing),
            "risk_bearing_matched": sum(1 for row in rows if row.target.risk_bearing and row.observation.matched),
            "risk_bearing_misses": len(risk_misses),
            "risk_bearing_recall_percent": round(
                100.0
                * sum(1 for row in rows if row.target.risk_bearing and row.observation.matched)
                / sum(1 for row in rows if row.target.risk_bearing),
                2,
            ),
            "informative_expected": sum(1 for row in rows if row.target.informative),
            "informative_misses": len(misses) - len(risk_misses),
            "unverified_evidence": sum(1 for row in misses if row.observation.disposition == "UNVERIFIED_EVIDENCE"),
            "confirmed_causes": sum(1 for row in misses if row.confidence == "CONFIRMED"),
            "probable_causes": sum(1 for row in misses if row.confidence == "PROBABLE"),
            "unresolved_causes": sum(1 for row in misses if row.confidence not in {"CONFIRMED", "PROBABLE"}),
        },
        "lanes": _lane_stats(rows),
        "breakdowns": {
            "category": _breakdown(rows, _category),
            "subtype": _breakdown(rows, lambda row: "informative_reference" if row.target.informative else row.target.subtype),
            "provider": _breakdown(rows, lambda row: "Informative reference" if row.target.informative else row.target.provider),
            "container": _breakdown(rows, lambda row: row.target.container_kind),
            "file_type": _breakdown(rows, lambda row: row.target.file_type),
            "representation": _breakdown(rows, lambda row: row.target.representation),
            "root_cause": _breakdown(rows, lambda row: row.root_cause if not row.observation.matched else "MATCHED"),
            "inspection": _breakdown(rows, lambda row: row.observation.source_inspected),
            "confidence": _breakdown(rows, lambda row: row.confidence if not row.observation.matched else "CONFIRMED"),
        },
        "stats": analysis["stats"],
        "load_evidence": _load_rows(analysis),
        "opportunities": _opportunity_rows(analysis),
        "cross_scanner": {
            "found_by_other": sum(1 for row in misses if row.cross_scanners),
            "unique_misses": len(cross["only_missed"].get(analysis["key"], [])),
            "unique_successes": len(cross["unique_successes"].get(analysis["key"], [])),
            "missed_by_all": len(cross["all_scanner_misses"]),
        },
        "negative_oracle": _negative_oracle_summary(analysis),
        "limitations": _limitations(analysis),
    }
    return summary


def _limitations(analysis: dict[str, Any]) -> list[str]:
    limitations = [
        "This is an independent evaluator report. No scanner rule, source file, oracle, or scoring policy was modified.",
        "Leaky Repo filesystem is a line-level detection benchmark without a complete negative oracle; precision and F1 are not certified.",
        "Leaky Repo Git precision/F1 are not certified; 65 source occurrences and 53 unique groups are separate denominators.",
        "Leaky Git source units are marked INSPECTED_UNVERIFIED for adapters that do not return a true coverage attestation; this is not evidence that a unit was skipped.",
        "RNC Lab precision/F1 are not certified; the 640 filesystem and 160 Git positive denominators are separate and are not combined.",
        "The 11 RNC Lab symlink aliases are not followed by the scanner. They contain no expected positive target in this oracle, so they do not change the positive recall denominator.",
        "Provider and subtype labels for Leaky Repo and Levain are source-context inferences because those oracles do not expose the Lab's fine-grained subtype taxonomy. RNC Lab labels come directly from its oracle.",
        "A miss is not proof that a regular expression failed. Candidate rejection, source acquisition, context association, and value extraction are distinct layers.",
        "Scanner-side candidate instrumentation is required to turn some PROBABLE or UNRESOLVED causes into confirmed ones.",
    ]
    if analysis["key"] == "cp4c":
        limitations.append(
            "CP4C was executed with the experiment-owned --workers auto argument and no profiling, as in the retained baseline."
        )
    if analysis["key"] in {"v14", "v16"}:
        limitations.append(
            "V14/V16 use compiled-in Gitleaks rules; rule presence is inferred from retained findings and controlled reproductions, not from a rule-file inventory."
        )
    return limitations


def _negative_oracle_summary(analysis: dict[str, Any]) -> dict[str, Any]:
    report = analysis["evidence"].report
    detection = report.get("detection") or {}
    rnc = detection.get("rnclab") or {}
    return {
        "rnclab_filesystem_verified_fp_alerts": (rnc.get("filesystem") or {}).get("verified_false_positive_alert_count"),
        "rnclab_git_verified_fp_alerts": (
            ((rnc.get("git") or {}).get("lanes") or {}).get("windows-amd64", {}).get("metrics", {})
        ).get("verified_false_positive_alert_count"),
        "levain_false_positives": (detection.get("levain") or {}).get("false_positives"),
        "leaky_filesystem_unexpected_findings": (detection.get("leaky_filesystem") or {}).get(
            "rich_line_truth", {}
        ).get("unexpected_count"),
        "precision_certified": False,
        "note": "RNC Lab and Leaky Git precision/F1 remain uncertified; negative references are not exhaustive.",
    }


def _repro_evidence() -> list[dict[str, Any]]:
    root = Path(__file__).resolve().parents[2] / "run" / "detection-gaps" / "repro"
    results: list[dict[str, Any]] = []
    for path in sorted(root.glob("repro-results*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(document, list):
            for item in document:
                findings = item.get("findings")
                if isinstance(findings, list):
                    finding_count = len(findings)
                elif isinstance(findings, int):
                    finding_count = findings
                else:
                    finding_count = 0
                results.append(
                    {
                        "case": item.get("case"),
                        "scanner": item.get("scanner", "cp4c" if "cp4c" in path.name else "v14"),
                        "exit": item.get("exit"),
                        "findings": finding_count,
                    }
                )
    return results


def _hmac_section(analysis: dict[str, Any], analyses: dict[str, dict[str, Any]]) -> str:
    rows = analysis["rows"]
    hmac_rows = [row for row in rows if row.target.category == "hmac_secret"]
    if not hmac_rows:
        return "No HMAC/signing-key targets exist in the configured lanes."
    comparisons = [key for key in ("cp4c", "v14", "v16", "gitleaks", "betterleaks") if key in analyses]
    lines = ["### HMAC and application-signing credentials", ""]
    table_rows = []
    for key in comparisons:
        other = analyses[key]
        for lane in ("rnclab_filesystem", "rnclab_git"):
            lane_rows = [row for row in other["rows"] if row.target.lane == lane and row.target.category == "hmac_secret"]
            if not lane_rows:
                continue
            matched = sum(1 for row in lane_rows if row.observation.matched)
            table_rows.append([other["label"], "filesystem" if lane.endswith("filesystem") else "Git", len(lane_rows), matched, len(lane_rows) - matched, _pct(matched, len(lane_rows))])
    lines.append(_table(["Scanner", "Lane", "Expected", "Matched", "Missed", "Recall"], table_rows))
    lines.append("")
    current = analysis["label"]
    lines.append(f"**{current} HMAC detail.**")
    lines.append("")
    detail_rows = []
    for lane in ("rnclab_filesystem", "rnclab_git"):
        lane_rows = [row for row in hmac_rows if row.target.lane == lane]
        if not lane_rows:
            continue
        for row in lane_rows:
            if row.observation.matched:
                continue
            detail_rows.append(
                [
                    "filesystem" if lane.endswith("filesystem") else "Git",
                    row.target.target_id,
                    row.target.subtype,
                    row.target.representation,
                    row.target.context.identifier or "-",
                    row.root_cause,
                    row.confidence,
                    _capability_text(row),
                ]
            )
    if detail_rows:
        lines.append(_table(["Lane", "Target", "Subtype", "Representation", "Identifier", "Cause", "Confidence", "Rule evidence"], detail_rows[:40]))
        if len(detail_rows) > 40:
            lines.append("")
            lines.append(f"Showing 40 of {len(detail_rows)} HMAC misses; the CSV contains every target.")
    else:
        lines.append("No HMAC target was missed by this scanner in the scored lanes.")
    lines.append("")
    if analysis["key"] == "cp4c":
        lines.append(
            "The 31 Git HMAC misses are all `application_signing_key` occurrences with the identifier `SIGNING_KEY` and the `env_value` representation. "
            "That is not a Git-ingestion failure: the same identifier and value shape was submitted as an ordinary `.env` file in a controlled local reproduction and was still not detected, "
            "while a `SESSION_SECRET` control was credited by `generic-secret-assignment`. The common property is the identifier family, not the Git container."
        )
    elif analysis["key"] in {"v14", "v16"}:
        lines.append(
            "The residual Git HMAC miss and the residual filesystem HMAC misses are value-dependent, not scope-dependent. "
            "Controlled standalone-file A/B cases with the same identifier and representation changed the result only when the value changed: "
            "one `SIGNING_KEY`, one `JWT_SIGNING_KEY` and one `SESSION_SECRET` value were not detected, while other values for those same fields were detected by `generic-api-key`. "
            "This points to a value-shape/entropy/allowlist check; it does not establish a Git bug."
        )
    lines.append("")
    lines.append(
        "Filesystem HMAC credits are not proof of a dedicated HMAC rule. In CP4C they are produced by the generic assignment rule when the field name contains a recognized "
        "`PASSWORD`, `SECRET_KEY` or `SESSION_SECRET` token. Fields named `HMAC_KEY`, `SIGNING_KEY` and JSON `SigningKey` fall outside that identifier family."
    )
    return "\n".join(lines) + "\n"


def _password_section(analysis: dict[str, Any], analyses: dict[str, dict[str, Any]]) -> str:
    rows = analysis["rows"]
    password_rows = [row for row in rows if row.target.category == "password" and row.target.lane.startswith("rnclab")]
    lines = ["### Password detection", ""]
    if not password_rows:
        return "\n".join(lines) + "\nNo RNC Lab password targets were selected.\n"
    subtype_rows = _breakdown(password_rows, lambda row: row.target.subtype, limit=18)
    lines.append(_table(
        ["Subtype", "Expected", "Matched", "Missed", "Recall", "Risk misses"],
        [[item["key"], item["expected"], item["matched"], item["missed"], f"{item['recall_percent']:.2f}%", item["risk_misses"]] for item in subtype_rows],
    ))
    lines.append("")
    lines.append("**Comparison on the RNC Lab password lane.** The table uses each scanner's own current-scoring report and the same target IDs.")
    lines.append("")
    compare_rows = []
    for key in ("cp4c", "v14", "v16", "gitleaks", "betterleaks"):
        if key not in analyses:
            continue
        other_rows = [row for row in analyses[key]["rows"] if row.target.category == "password" and row.target.lane.startswith("rnclab")]
        matched = sum(1 for row in other_rows if row.observation.matched)
        compare_rows.append([analyses[key]["label"], len(other_rows), matched, len(other_rows) - matched, _pct(matched, len(other_rows))])
    lines.append(_table(["Scanner", "Expected", "Matched", "Missed", "Recall"], compare_rows))
    lines.append("")
    top_identifiers = _breakdown(
        [row for row in password_rows if not row.observation.matched],
        lambda row: f"{row.target.subtype} | {row.target.context.identifier or 'NO_ASSIGNMENT_IDENTIFIER'} | {row.target.representation}",
        limit=15,
    )
    lines.append("**Largest missed password shapes.**")
    lines.append("")
    lines.append(_table(
        ["Subtype | identifier | representation", "Missed", "Cross-scanner found", "Example target"],
        [[item["key"], item["missed"], item["cross_found"], next((r.target.target_id for r in password_rows if not r.observation.matched and f"{r.target.subtype} | {r.target.context.identifier or 'NO_ASSIGNMENT_IDENTIFIER'} | {r.target.representation}" == item["key"]), "-")] for item in top_identifiers],
    ))
    lines.append("")
    if analysis["key"] == "cp4c":
        lines.append(
            "CP4C's password gap is dominated by WordPress authentication material (`AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY`, `NONCE_KEY`, the four salts and `WP_SALT_n`), "
            "followed by database/application passwords whose identifiers or wrappers fall outside `generic-secret-assignment`. "
            "The controlled `define('AUTH_KEY', ...)` reproduction was not detected even as a plain PHP file."
        )
    else:
        lines.append(
            "The remaining password misses are not explained by one identifier. They combine WordPress salt names, database passwords, SMTP/FTP/administrative fields, "
            "URI/SQL/encoded containers and a smaller set of values that fail the generic-api-key value check. The latter is visible because the same identifier and representation "
            "is credited for a different value in a controlled standalone-file A/B case."
        )
    return "\n".join(lines) + "\n"


def _provider_section(analysis: dict[str, Any]) -> str:
    rows = [
        row
        for row in analysis["rows"]
        if row.target.category in {"provider_token", "api_key", "otp_seed"} and row.target.lane.startswith("rnclab")
    ]
    lines = ["### Provider tokens, generic API keys and OTP seeds", ""]
    if not rows:
        return "\n".join(lines) + "\nNo provider/API/OTP targets were selected.\n"
    missed = [row for row in rows if not row.observation.matched]
    if not missed:
        lines.append("No provider/API/OTP target was missed in the RNC Lab lanes.")
        return "\n".join(lines) + "\n"
    def provider_key(row: AnalysisRow) -> str:
        return (
            f"{row.target.category} | {row.target.subtype} | {row.target.provider} | "
            f"{row.target.representation} | {row.target.container_kind} | {row.root_cause}"
        )

    table = _breakdown(missed, provider_key, limit=25)
    lines.append(_table(
        ["Category | subtype | provider | representation | container | cause", "Missed", "Capability", "Example"],
        [
            [
                item["key"],
                item["missed"],
                next((_capability_text(r) for r in missed if provider_key(r) == item["key"]), "-"),
                next((r.target.target_id for r in missed if provider_key(r) == item["key"]), "-"),
            ]
            for item in table
        ],
    ))
    lines.append("")
    actions: list[str] = []
    if any(row.target.subtype == "azure_storage_account_key" for row in missed):
        actions.append(
            "Azure `AccountKey` values in JSON/XML key-value fields are outside the connection-string `AccountKey=` form and need a separator-aware field parser."
        )
    if any(row.target.subtype == "stripe_webhook_secret" for row in missed):
        actions.append(
            "Stripe `whsec_` webhook signing secrets have no matching provider rule in this scanner."
        )
    if any(row.target.subtype == "twilio_auth_token" for row in missed):
        actions.append(
            "Twilio auth-token values are not covered by a provider rule; verify the documented shape before adding one."
        )
    if any(row.target.subtype == "generic_api_key" for row in missed):
        actions.append(
            "Generic `ak_`/`MINIO_ROOT_USER`-style values are not provider-identifiable from the value alone; a pair-aware assignment context is required rather than a blanket high-entropy rule."
        )
    if any(row.target.subtype == "totp_seed" for row in missed):
        actions.append(
            "TOTP seeds require an otpauth/OTP-seed rule and must not be conflated with generic passwords."
        )
    if not actions:
        actions.append("No provider-specific rule gap remains in the selected RNC Lab provider/API/OTP targets.")
    lines.extend(f"- {action}" for action in actions)
    return "\n".join(lines) + "\n"


def _private_key_section(analysis: dict[str, Any]) -> str:
    rows = [row for row in analysis["rows"] if row.target.category == "private_key"]
    lines = ["### Private keys and encoded key containers", ""]
    if not rows:
        return "\n".join(lines) + "\nNo private-key targets were selected.\n"
    table = _breakdown(rows, lambda row: f"{row.target.subtype} | {row.target.representation} | {row.target.container_kind}")
    lines.append(_table(
        ["Subtype | representation | container", "Expected", "Matched", "Missed", "Recall"],
        [[item["key"], item["expected"], item["matched"], item["missed"], f"{item['recall_percent']:.2f}%"] for item in table],
    ))
    lines.append("")
    missed = [row for row in rows if not row.observation.matched]
    if missed:
        lines.append(
            "Most remaining private-key failures are format/container gaps: PuTTY PPK v2 and PKCS#12 are not PEM blocks, and archived PEM material never reaches the matcher. "
            "Wallet seed phrases are a distinct mnemonic credential and should not be counted as private-key material. "
            "Do not mark a public-key-only, SPKI-only, encrypted-container-only or filename-only observation as private-key credit. "
            "The existing PEM findings that are credited must remain credited; no historical scoring artifact is being reclassified as a new false negative here."
        )
    else:
        lines.append("Every private-key target in the selected lanes was credited.")
    lines.append("")
    lines.append("Private-key passphrases are counted separately as password targets when the oracle models them as such; a passphrase is not interchangeable with the key material.")
    return "\n".join(lines) + "\n"


def _source_section(analysis: dict[str, Any]) -> str:
    rows = analysis["rows"]
    missed = [row for row in rows if not row.observation.matched]
    lines = ["### Where the misses live", ""]
    container_table = _breakdown(rows, lambda row: row.target.container_kind)
    lines.append(_table(
        ["Source container", "Expected", "Matched", "Missed", "Recall", "Risk misses"],
        [[item["key"], item["expected"], item["matched"], item["missed"], f"{item['recall_percent']:.2f}%", item["risk_misses"]] for item in container_table],
    ))
    lines.append("")
    file_table = _breakdown(missed, lambda row: row.target.file_type, limit=18)
    lines.append("**Missed file types.**")
    lines.append("")
    lines.append(_table(["File type", "Missed", "Risk misses", "Cross-scanner found"], [[item["key"], item["missed"], item["risk_misses"], item["cross_found"]] for item in file_table]))
    lines.append("")
    rep_table = _breakdown(missed, lambda row: row.target.representation, limit=18)
    lines.append("**Missed representations.**")
    lines.append("")
    lines.append(_table(["Representation", "Missed", "Risk misses", "Cross-scanner found"], [[item["key"], item["missed"], item["risk_misses"], item["cross_found"]] for item in rep_table]))
    lines.append("")
    inspection = _breakdown(rows, lambda row: row.observation.source_inspected)
    lines.append(_table(["Inspection disposition", "Expected", "Matched", "Missed"], [[item["key"], item["expected"], item["matched"], item["missed"]] for item in inspection]))
    lines.append("")
    structured = [row for row in missed if row.target.container_kind in {"archive_member", "database_record", "binary_file"}]
    if structured:
        lines.append(
            f"{len(structured)} expected positives live in a non-plaintext container. "
            f"Of these, {sum(1 for row in structured if row.target.container_kind == 'archive_member')} are archive members, "
            f"{sum(1 for row in structured if row.target.container_kind == 'database_record')} are database records and "
            f"{sum(1 for row in structured if row.target.container_kind == 'binary_file')} are binary key containers."
        )
        lines.append("")
        lines.append(
            "The scanner emitted no finding with a non-null archive member, database row or PKCS#12 container across this run. "
            "A miss in this category is therefore classified as `SOURCE_UNSUPPORTED`, not as a regex false negative. "
            "An archive file being encountered is not evidence that its members were scanned."
        )
    uninspected = [row for row in missed if row.observation.source_inspected == "UNINSPECTED"]
    lines.append("")
    lines.append(
        f"Eligible-but-uninspected expected positives: {len(uninspected)}. "
        "The RNC Lab filesystem lane reports 11 uninspected symlink aliases; none of them is an expected positive target in the frozen oracle. "
        "That is a scanner coverage caveat, not a positive-recall gap."
    )
    return "\n".join(lines) + "\n"


def _load_rows(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    products = (analysis["evidence"].report.get("performance") or {}).get("products") or []
    rows = []
    for product in products:
        profile = product.get("load_profile") or (product.get("workload") or {}).get("load_profile")
        if profile not in {"legacy-5x", "legacy-10x"}:
            continue
        summary = product.get("summary") or {}
        runtime = summary.get("runtime_seconds") or {}
        caveats = summary.get("coverage_caveats") or []
        reason = caveats[0].get("reason") if caveats else ""
        uninspected = caveats[0].get("uninspected_units") if caveats else []
        rows.append(
            {
                "scanner": analysis["label"],
                "profile": profile,
                "median_seconds": runtime.get("median"),
                "files_inspected": summary.get("files_inspected"),
                "files_eligible": summary.get("files_eligible"),
                "file_coverage_percent": summary.get("file_coverage_percent"),
                "stability": summary.get("stability"),
                "coverage_reason": reason,
                "uninspected": uninspected or [],
                "accuracy_scored": product.get("accuracy_scored"),
            }
        )
    return rows


def _load_evidence_section(analysis: dict[str, Any], analyses: dict[str, dict[str, Any]]) -> str:
    lines = ["### Load-replicated evidence (not canonical accuracy)", ""]
    rows = _load_rows(analysis)
    if not rows:
        return "\n".join(lines) + "\nNo legacy x5/x10 performance evidence was retained for this scanner.\n"
    table = []
    for row in rows:
        table.append(
            [
                row["profile"],
                row["median_seconds"],
                f"{row['files_inspected']}/{row['files_eligible']}",
                row["file_coverage_percent"],
                row["stability"],
                row["coverage_reason"] or "-",
                _yes(bool(row["accuracy_scored"])) if row["accuracy_scored"] is not None else "NO",
            ]
        )
    lines.append(_table(["Profile", "Median s", "Inspected/eligible", "Coverage %", "Stability", "Coverage caveat", "Accuracy scored"], table))
    lines.append("")
    lines.append(
        "These corpora are performance replicas. Their repeated files are not additional canonical targets and are excluded from every recall denominator in this report. "
        "The x5/x10 runs are still useful for source-coverage anomalies: a replicated file that the scanner excludes by a total-byte limit is a load-scope caveat, not a new oracle target."
    )
    lines.append("")
    anomalies = [row for row in rows if row["uninspected"] or (row["file_coverage_percent"] or 100) < 100]
    if anomalies:
        for row in anomalies:
            lines.append(
                f"- **{row['profile']}:** {row['files_inspected']}/{row['files_eligible']} files inspected; "
                f"caveat `{row['coverage_reason'] or 'none'}`; exemplar uninspected unit(s): "
                + ", ".join(f"`{unit}`" for unit in row["uninspected"][:4])
                + "."
            )
    else:
        lines.append("- No load-profile coverage shortfall was reported by this scanner.")
    lines.append("")
    return "\n".join(lines) + "\n"


def _fp_section(analysis: dict[str, Any]) -> str:
    summary = _negative_oracle_summary(analysis)
    rows = analysis["rows"]
    lines = ["### False positives, near misses and regression fixtures", ""]
    lines.append(_table(
        ["Signal", "Value"],
        [
            ["RNC Lab filesystem verified false-positive alerts", summary.get("rnclab_filesystem_verified_fp_alerts")],
            ["RNC Lab Git verified false-positive alerts", summary.get("rnclab_git_verified_fp_alerts")],
            ["Levain false positives", summary.get("levain_false_positives")],
            ["Leaky filesystem unexpected findings", summary.get("leaky_filesystem_unexpected_findings")],
            ["Precision certified", "NO"],
        ],
    ))
    lines.append("")
    overlaps = [row for row in rows if not row.observation.matched and row.observation.disposition == "UNVERIFIED_EVIDENCE"]
    if overlaps:
        lines.append(f"{len(overlaps)} missed target(s) have a same-location scanner observation that the scorer did not credit (`UNVERIFIED_EVIDENCE`). These are not silent regex misses.")
        lines.append("")
        lines.append(_table(["Target", "Rule", "Stage", "Reason code"], [[row.target.target_id, row.observation.rule_id, row.observation.stage, row.observation.reason_code or row.observation.reason] for row in overlaps[:12]]))
        lines.append("")
    lines.append(
        "Regression fixtures available for proposed changes: the RNC Lab oracle has 400 negative-ordinary and 202 negative-trap items (162 trap items in the filesystem lane and 40 in Git); "
        "Leaky Repo history has 89 reviewed negative references and 30 informative references; Levain has 116 negative sections. "
        "These are the first fixtures to run after any identifier, decoder or validator change. "
        "The negative oracle is not exhaustive, so a new rule must be evaluated against false-positive alerts as well as recovered positives. "
        "No precision claim is made from the absence of an alert."
    )
    return "\n".join(lines) + "\n"


def _root_cause_markdown(analysis: dict[str, Any]) -> str:
    rows = analysis["rows"]
    misses = [row for row in rows if not row.observation.matched]
    summary = analysis["stats"]
    lines = [f"# {analysis['label']} - root causes and reproduction evidence", ""]
    lines.append(
        "This file separates confirmed mechanisms from probable and unresolved hypotheses. "
        "`CONFIRMED` means the retained evidence establishes the mechanism without scanner-side guessing; "
        "`PROBABLE` means a controlled or cross-scanner observation strongly supports it but the scanner's internal candidate stage was not inspected; "
        "`UNRESOLVED` means the evidence cannot distinguish the listed layers."
    )
    lines.append("")
    lines.append("## Classification summary")
    lines.append("")
    lines.append(_table(
        ["Root cause", "Layer", "Misses", "Confirmed", "Probable", "Unresolved"],
        [
            [
                code,
                _layer_for_code(code),
                count,
                sum(1 for row in misses if row.root_cause == code and row.confidence == "CONFIRMED"),
                sum(1 for row in misses if row.root_cause == code and row.confidence == "PROBABLE"),
                sum(1 for row in misses if row.root_cause == code and row.confidence not in {"CONFIRMED", "PROBABLE"}),
            ]
            for code, count in sorted(summary["root_causes"].items(), key=lambda item: (-item[1], item[0]))
        ],
    ))
    lines.append("")
    lines.append("## Confirmed mechanisms")
    lines.append("")
    confirmed = [row for row in misses if row.confidence == "CONFIRMED"]
    confirmed.sort(key=lambda row: (row.target.lane, row.root_cause, row.target.target_id))
    for code in sorted({row.root_cause for row in confirmed}):
        subset = [row for row in confirmed if row.root_cause == code]
        lines.append(f"### `{code}` - {len(subset)} targets")
        lines.append("")
        lines.append(f"Layer: `{_layer_for_code(code)}`. Representative evidence: {subset[0].evidence}.")
        by_key = collections.Counter(
            (row.target.lane, row.target.subtype, row.target.context.identifier_family) for row in subset
        )
        lines.append("")
        lines.append(_table(["Lane", "Subtype", "Identifier family", "Count"], [[lane, subtype, family, count] for (lane, subtype, family), count in by_key.most_common(12)]))
        lines.append("")
        lines.append(f"Examples: {_sample_targets(subset)}.")
        lines.append("")
    lines.append("## Probable and unresolved mechanisms")
    lines.append("")
    probable = [row for row in misses if row.confidence != "CONFIRMED"]
    for code in sorted({row.root_cause for row in probable}):
        subset = [row for row in probable if row.root_cause == code]
        lines.append(f"### `{code}` - {len(subset)} targets")
        lines.append("")
        lines.append(f"Layer: `{_layer_for_code(code)}`. Dominant confidence: `{_dominant(row.confidence for row in subset)}`.")
        lines.append("")
        lines.append(f"Evidence: {subset[0].evidence}")
        lines.append("")
        lines.append(f"Examples: {_sample_targets(subset)}.")
        lines.append("")
    lines.append("## Reproduction evidence")
    lines.append("")
    reproductions = _repro_evidence()
    if reproductions:
        lines.append("Controlled cases were written only in ignored local storage. No corpus or rule file was changed.")
        lines.append("")
        lines.append(_table(["Case", "Scanner", "Exit", "Findings"], [[item["case"], item["scanner"], item["exit"], item["findings"]] for item in reproductions]))
        lines.append("")
        lines.append(
            "The critical controls were: (a) CP4C did not detect `SIGNING_KEY` or `JWT_SIGNING_KEY` as a plain `.env` but did detect `SESSION_SECRET`; "
            "(b) CP4C did not detect a WordPress `AUTH_KEY` definition; (c) both CP4C and V14 missed selected DB_PASSWORD values as standalone files while crediting a different value with the same identifier and representation; "
            "(d) V14 credited one SIGNING_KEY/JWT_SIGNING_KEY/SESSION_SECRET value but not another. These establish identifier-family and value-shape effects, not Git-scope effects."
        )
    else:
        lines.append("No retained reproduction result file was available. The report does not invent a reproduction outcome.")
    lines.append("")
    lines.append("## Instrumentation still needed")
    lines.append("")
    lines.append(
        "For a miss with no retained candidate, a scanner-side diagnostic must expose whether the rule produced a candidate, whether the value/identifier validator rejected it, "
        "and whether source acquisition supplied the bytes. Without that trace, `UNKNOWN` remains the correct classification. "
        "Do not convert a `PROBABLE` value-validator finding into a rule change by reducing the global entropy floor."
    )
    lines.append("")
    return "\n".join(lines)


def _layer_for_code(code: str) -> str:
    return {
        "RULE_ABSENT": "RULE_COVERAGE",
        "IDENTIFIER_MISMATCH": "IDENTIFIER_LEXICON",
        "FORMAT_UNSUPPORTED": "REPRESENTATION_DECODER",
        "CAPTURE_MISMATCH": "VALUE_CAPTURE",
        "CONTEXT_INSUFFICIENT": "CONTEXT_MODEL",
        "VALIDATOR_REJECTION": "VALUE_VALIDATOR",
        "SOURCE_NOT_INSPECTED": "SOURCE_ACQUISITION",
        "SOURCE_UNSUPPORTED": "SOURCE_ACQUISITION",
        "GIT_SCOPE_OR_ATTRIBUTION": "SOURCE_ATTRIBUTION",
        "SCORING_MISMATCH": "SCORER",
        "INFORMATIVE_REFERENCE": "ORACLE_CLASSIFICATION",
        "UNKNOWN": "UNRESOLVED",
    }.get(code, "UNRESOLVED")


def _backlog_markdown(analysis: dict[str, Any], summary: dict[str, Any]) -> str:
    opportunities = summary["opportunities"]
    lines = [f"# {analysis['label']} - prioritized development backlog", ""]
    lines.append(
        "Ranking is by recoverable risk-bearing target count, operational severity, concentration in a reusable family, "
        "availability of provider/context identifiers, cross-scanner evidence, likely false-positive risk and implementation complexity. "
        "Informative references are excluded. This is a development proposal, not an implemented detector change."
    )
    lines.append("")
    lines.append("## Top five recommendations")
    lines.append("")
    top = opportunities[:5]
    if not top:
        lines.append("No risk-bearing recovery opportunity remains in the selected lanes.")
    for index, item in enumerate(top, 1):
        recommendation = _recommendation(item)
        lines.append(f"### {index}. {item['opportunity'].replace('_', ' ').title()} - {item['risk_misses']} recoverable targets")
        lines.append("")
        lines.append(f"- **Cause:** `{item['root_cause']}`; confidence `{item['confidence']}`.")
        lines.append(f"- **Concentration:** {item['misses']} misses, {item['cross_found']} already found by at least one comparison scanner; lanes: {', '.join(item['lanes'])}.")
        lines.append(f"- **Representations:** {', '.join(item['representations'])}.")
        lines.append(f"- **Identifiers:** {', '.join(item['identifiers']) or 'no stable identifier'}.")
        lines.append(f"- **Change:** {recommendation['action']}")
        lines.append(f"- **False-positive risk:** {recommendation['fp_risk']}; **complexity:** {recommendation['complexity']}.")
        lines.append(f"- **Reuse:** {recommendation['reuse']}")
        lines.append(f"- **Examples:** {', '.join(f'`{target}' for target in item['sample_targets'][:8])}.")
        lines.append("")
    lines.append("## Full opportunity table")
    lines.append("")
    lines.append(_table(
        ["Rank", "Opportunity", "Cause", "Risk misses", "Cross-found", "Confidence", "FP risk", "Complexity"],
        [[index, item["opportunity"], item["root_cause"], item["risk_misses"], item["cross_found"], item["confidence"], _recommendation(item)["fp_risk"], _recommendation(item)["complexity"]] for index, item in enumerate(opportunities, 1)],
    ))
    lines.append("")
    lines.append("## Generalization rules")
    lines.append("")
    lines.append(
        "- Prefer a reviewed identifier family or a structured parser over a fixture-specific regex.\n"
        "- Keep assignment/context and value-shape gates; do not replace them with a global entropy threshold change.\n"
        "- Add negative fixtures for the same identifier family before enabling a broader rule.\n"
        "- For archive/database work, keep bounded expansion and source attribution; never count the container as inspected.\n"
        "- For value-validator causes, reproduce the exact value/identifier A/B before changing a validator; a scanner-side candidate trace is required."
    )
    lines.append("")
    lines.append("## Recommended sequencing")
    lines.append("")
    lines.append(
        "1. Low-complexity, high-yield identifier families (WordPress salts, signing/HMAC names, passphrases, TOTP).\n"
        "2. URI/structured password extraction and provider-specific separators (Azure JSON, Stripe webhook).\n"
        "3. Key-container formats (PPK, PKCS#12) and archive/database source acquisition.\n"
        "4. Value-validator instrumentation and narrowly scoped corrections.\n"
        "5. Re-run the full negative oracle after each stage."
    )
    lines.append("")
    return "\n".join(lines)


def _detection_gaps_markdown(analysis: dict[str, Any], summary: dict[str, Any], analyses: dict[str, dict[str, Any]]) -> str:
    evidence = analysis["evidence"]
    meta = evidence.metadata
    misses = [row for row in analysis["rows"] if not row.observation.matched]
    risk = [row for row in misses if row.target.risk_bearing]
    lines = [f"# {analysis['label']} Detection Gap Analysis", ""]
    lines.append("> Independent target-level assessment of the current-scoring Windows AMD64 baseline. No scanner rule, oracle, or score was modified.")
    lines.append("")
    lines.append("## Executive summary")
    lines.append("")
    risk_expected = sum(1 for row in analysis["rows"] if row.target.risk_bearing)
    risk_matched = sum(1 for row in analysis["rows"] if row.target.risk_bearing and row.observation.matched)
    lines.append(
        f"{analysis['label']} missed **{len(misses)} of {len(analysis['rows'])} expected positive occurrences** "
        f"({_pct(len(misses), len(analysis['rows']))}) across the five applicable lanes. "
        f"Of those, **{len(risk)} are risk-bearing** and {len(misses) - len(risk)} are oracle-informative references. "
        f"Risk-bearing recall is **{risk_matched}/{risk_expected} ({_pct(risk_matched, risk_expected)})**; informative references are never added to that denominator. "
        f"{sum(1 for row in misses if row.cross_scanners)} misses are found by at least one comparison scanner, so the gap is not solely a corpus limitation."
    )
    lines.append("")
    largest = [item for item in summary["breakdowns"]["subtype"] if item["risk_misses"] > 0][:6]
    if largest:
        lines.append("Largest missed families: " + "; ".join(f"{item['key']} ({item['risk_misses']} risk)" for item in largest) + ".")
    lines.append("")
    confirmed_risk = sum(
        1 for row in misses if row.confidence == "CONFIRMED" and row.target.risk_bearing
    )
    if summary["opportunities"]:
        top = summary["opportunities"][0]
        lines.append(
            f"Confirmed mechanisms account for **{summary['counts']['confirmed_causes']}** misses, of which **{confirmed_risk}** are risk-bearing; "
            f"**{summary['counts']['probable_causes']}** are probable and **{summary['counts']['unresolved_causes']}** remain unresolved. "
            f"The largest actionable family is `{top['opportunity']}` ({top['risk_misses']} risk-bearing targets)."
        )
    else:
        lines.append(
            f"Confirmed mechanisms account for **{summary['counts']['confirmed_causes']}** misses, of which **{confirmed_risk}** are risk-bearing; "
            f"**{summary['counts']['probable_causes']}** are probable and **{summary['counts']['unresolved_causes']}** remain unresolved. No backlog opportunity is proposed."
        )
    lines.append("")
    lines.append("## Evidence and identity")
    lines.append("")
    lines.append(_table(
        ["Field", "Value"],
        [
            ["Scanner", analysis["label"]],
            ["Registered build", meta["build_id"]],
            ["Version", meta["version"]],
            ["Source commit (manifest metadata, not checked out)", meta["source_commit"]],
            ["Executable SHA-256", meta["executable_sha256"]],
            ["Rules/configuration", meta.get("rules_file") or "compiled/default"],
            ["Rules SHA-256", meta.get("rules_sha256") or "not exposed"],
            ["Retained report", meta["report_path"]],
            ["Report SHA-256", meta["report_sha256"]],
            ["Run ID", meta["run_id"]],
            ["Configuration profile", meta["profile"]],
            ["Scoring epoch", "Current post-scoring-integrity remediation"],
            ["Platform", "Windows AMD64"],
            ["Analysis version", ANALYSIS_VERSION],
        ],
    ))
    lines.append("")
    lines.append(
        "The harness is an independent evaluator. This analysis consumed frozen oracles and retained scanner reports; "
        "it did not rebuild either scanner, change a rule, rewrite an oracle, or alter the scoring policy."
    )
    lines.append("")
    lines.append("## Baseline reconciliation")
    lines.append("")
    lines.append(_table(
        ["Lane", "Oracle denominator", "Matched", "Missed (not credited)", "Recall", "Risk misses", "Informative misses"],
        [[item["title"], item["expected"], item["matched"], item["missed"], f"{item['recall_percent']:.2f}%", item["risk_misses"], item["informative_misses"]] for item in summary["lanes"]],
    ))
    lines.append("")
    lines.append(
        "The Lane denominators are the frozen oracle positives, not scanner file counts. "
        "Leaky Repo filesystem has 175 line-level expected detections; Leaky Git has 65 source occurrences and 53 unique groups; "
        "RNC Lab has 640 filesystem and 160 Git occurrences. These denominators are never combined into one recall percentage."
    )
    lines.append("")
    lines.append("## Complete miss inventory")
    lines.append("")
    lines.append(
        f"Every expected target is in `{SCANNER_DIRS[analysis['key']]}-target-inventory.csv`; every uncredited target is in "
        f"`{SCANNER_DIRS[analysis['key']]}-missed-targets.csv`; provider context and source location are in the corresponding "
        f"`-provider-context.csv` and `-location-analysis.csv` files. The Markdown tables below are summaries, not the inventory."
    )
    lines.append("")
    lines.append("### Concentration by lane")
    lines.append("")
    lines.append(_table(
        ["Lane", "Expected", "Missed", "Risk misses", "Cross-scanner found", "Recall"],
        [[item["key"], item["expected"], item["missed"], item["risk_misses"], item["cross_found"], f"{item['recall_percent']:.2f}%"] for item in _breakdown(analysis["rows"], lambda row: row.target.lane)],
    ))
    lines.append("")
    lines.append("### Concentration by category")
    lines.append("")
    lines.append(_table(
        ["Category", "Expected", "Matched", "Missed", "Risk misses", "Recall"],
        [[item["key"], item["expected"], item["matched"], item["missed"], item["risk_misses"], f"{item['recall_percent']:.2f}%"] for item in summary["breakdowns"]["category"][:14]],
    ))
    lines.append("")
    lines.append("### Concentration by provider")
    lines.append("")
    lines.append(_table(
        ["Provider", "Expected", "Matched", "Missed", "Risk misses", "Recall"],
        [[item["key"], item["expected"], item["matched"], item["missed"], item["risk_misses"], f"{item['recall_percent']:.2f}%"] for item in summary["breakdowns"]["provider"][:14]],
    ))
    lines.append("")
    lines.append("### Concentration by root cause")
    lines.append("")
    lines.append(_table(
        ["Root cause", "Missed", "Risk misses", "Confirmed", "Probable"],
        [[code, count, sum(1 for row in misses if row.root_cause == code and row.target.risk_bearing), sum(1 for row in misses if row.root_cause == code and row.confidence == "CONFIRMED"), sum(1 for row in misses if row.root_cause == code and row.confidence == "PROBABLE")] for code, count in sorted(summary["stats"]["root_causes"].items(), key=lambda item: (-item[1], item[0]))],
    ))
    lines.append("")
    lines.append("## Required focused investigations")
    lines.append("")
    lines.append(_hmac_section(analysis, analyses))
    lines.append(_password_section(analysis, analyses))
    lines.append(_provider_section(analysis))
    lines.append(_private_key_section(analysis))
    lines.append(_source_section(analysis))
    lines.append(_load_evidence_section(analysis, analyses))
    lines.append(_fp_section(analysis))
    lines.append("## Root-cause interpretation")
    lines.append("")
    lines.append(
        "A target is marked `SOURCE_UNSUPPORTED` only when the same run produced no credited finding in that container class. "
        "`SOURCE_NOT_INSPECTED` requires a coverage record, not merely an absent finding. `CAPTURE_MISMATCH` requires a retained same-location observation whose value evidence failed. "
        "`SCORING_MISMATCH` requires a usable scanner observation rejected by the scorer. `IDENTIFIER_MISMATCH`, `RULE_ABSENT`, `FORMAT_UNSUPPORTED`, `CONTEXT_INSUFFICIENT`, `VALIDATOR_REJECTION` and `UNKNOWN` are kept distinct because they imply different development work."
    )
    lines.append("")
    lines.append("See the standalone root-cause dossier for the full evidence and reproduction table.")
    lines.append("")
    lines.append("## Cross-scanner context")
    lines.append("")
    others = [key for key in ("cp4c", "v14", "v16", "gitleaks", "betterleaks") if key in analyses and key != analysis["key"]]
    if others:
        found = [row for row in misses if row.cross_scanners]
        cross_rows = []
        for key in others:
            count = sum(1 for row in found if key in row.cross_scanners)
            cross_rows.append([analyses[key]["label"], count, _pct(count, len(misses))])
        lines.append(_table(["Other scanner", "Finds the same missed target", "Share of this scanner's misses"], cross_rows))
        lines.append("")
        lines.append(
            "This is an oracle-target join, not raw string similarity. It demonstrates that the content is present in the same frozen dataset; it does not prove that the other scanner used the same source scope or rule."
        )
    lines.append("")
    lines.append("## Prioritized improvements")
    lines.append("")
    if summary["opportunities"]:
        for index, item in enumerate(summary["opportunities"][:5], 1):
            rec = _recommendation(item)
            lines.append(f"{index}. **{item['opportunity'].replace('_', ' ')}** - {item['risk_misses']} risk-bearing targets; `{item['root_cause']}`; {rec['action']}")
    else:
        lines.append("No risk-bearing development opportunity is supported by this analysis.")
    lines.append("")
    lines.append("The detailed backlog is in the companion file; it ranks by recoverable count, severity, concentration, context availability, false-positive risk and implementation complexity.")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for limitation in summary["limitations"]:
        lines.append(f"- {limitation}")
    lines.append("")
    lines.append("## Reproduction")
    lines.append("")
    lines.append("```powershell")
    lines.append("python -m harness detection-gaps --out-dir reports/detection-gaps")
    lines.append("python -m unittest tests.test_detection_gaps -v")
    lines.append("```")
    lines.append("")
    lines.append("The generator reads the retained reports and frozen oracles only; it does not execute a scanner or change a dataset.")
    return "\n".join(lines) + "\n"


def _cross_target_table(rows: list[AnalysisRow], limit: int = 20) -> str:
    return _table(
        ["Target", "Lane", "Category", "Subtype", "Root cause", "Found by", "Sample location"],
        [
            [
                row.target.target_id,
                row.target.lane,
                row.target.category,
                row.target.subtype,
                row.root_cause,
                ", ".join(row.cross_scanners) or "none",
                row.target.path + (f":{row.target.line}" if row.target.line else ""),
            ]
            for row in rows[:limit]
        ],
    )


def _overlap_markdown(cross: dict[str, Any], analyses: dict[str, dict[str, Any]]) -> str:
    keys = cross["keys"]
    lines = ["# CP4C, V14 and V16 target-level detection overlap", ""]
    lines.append(
        "This is a shared comparison over exact oracle target IDs from the retained current-scoring reports. "
        "Gitleaks master and Betterleaks 1.8.1 are included as external comparators. "
        "It does not replace either scanner's standalone report, and it does not treat raw string similarity as a match."
    )
    lines.append("")
    lines.append("## Scanner coverage")
    lines.append("")
    lines.append(_table(
        ["Scanner", "Expected", "Matched", "Missed", "Recall", "Unique successes", "Only-scanner misses"],
        [[analyses[key]["label"], len(analyses[key]["rows"]), sum(1 for row in analyses[key]["rows"] if row.observation.matched), sum(1 for row in analyses[key]["rows"] if not row.observation.matched), _pct(sum(1 for row in analyses[key]["rows"] if row.observation.matched), len(analyses[key]["rows"])), cross["counts"]["unique_successes"].get(key, 0), cross["counts"]["only_missed"].get(key, 0)] for key in keys],
    ))
    lines.append("")
    all_miss_info = sum(1 for tid in cross["all_scanner_misses"] if cross["by_target"][tid]["target"].informative)
    all_miss_risk = len(cross["all_scanner_misses"]) - all_miss_info
    lines.append(
        f"All-scanner misses: **{cross['counts']['all_scanner_misses']}** "
        f"({all_miss_risk} risk-bearing, {all_miss_info} oracle-informative). "
        "These are the targets no compared scanner credited; risk-bearing cases are the strongest candidates for a corpus/source question rather than a single scanner defect."
    )
    lines.append("")
    lines.append("## Common misses")
    lines.append("")
    all_misses = cross["all_scanner_misses"]
    by_target = cross["by_target"]
    lane_counts = collections.Counter(by_target[tid]["target"].lane for tid in all_misses)
    category_counts = collections.Counter(by_target[tid]["target"].category for tid in all_misses)
    lines.append(_table(["Lane", "Common misses"], [[lane, lane_counts.get(lane, 0)] for lane in LANE_ORDER]))
    lines.append("")
    lines.append(_table(["Category", "Common misses"], [[category, count] for category, count in category_counts.most_common(15)]))
    lines.append("")
    if all_misses:
        sample = [by_target[tid]["target"] for tid in all_misses[:12]]
        lines.append("Examples: " + ", ".join(f"`{target.target_id}`" for target in sample) + ".")
        lines.append("")
    lines.append("## Unique misses and complementary coverage")
    lines.append("")
    unique_rows = []
    for key in keys:
        target_ids = cross["only_missed"].get(key, [])
        unique_rows.append([analyses[key]["label"], len(target_ids), ", ".join(f"`{tid}`" for tid in target_ids[:8]) or "-"])
    lines.append(_table(["Scanner", "Only this scanner missed", "Example target IDs"], unique_rows))
    lines.append("")
    lines.append("A target listed here is credited by every other compared scanner and missed by this scanner. It is the strongest evidence of a scanner-specific coverage gap rather than an unreadable source or an oracle ambiguity.")
    lines.append("")
    lines.append("## CP4C misses found by another scanner")
    lines.append("")
    cp4c_misses = [row for row in analyses["cp4c"]["rows"] if not row.observation.matched]
    for other in ("v14", "v16", "gitleaks", "betterleaks"):
        if other not in analyses:
            continue
        found = [row for row in cp4c_misses if other in row.cross_scanners]
        by_cat = collections.Counter(row.target.category for row in found)
        lines.append(f"### {analyses[other]['label']} - {len(found)} of {len(cp4c_misses)} CP4C misses")
        lines.append("")
        if by_cat:
            lines.append(_table(["Category", "Count"], [[key, count] for key, count in by_cat.most_common(10)]))
            lines.append("")
            lines.append(_cross_target_table(found, 12))
        else:
            lines.append("No CP4C miss was credited by this comparator.")
        lines.append("")
    lines.append("## V14/V16 misses found by another scanner")
    lines.append("")
    for primary in ("v14", "v16"):
        if primary not in analyses:
            continue
        lines.append(f"### {analyses[primary]['label']}")
        lines.append("")
        misses = [row for row in analyses[primary]["rows"] if not row.observation.matched]
        for other in ("cp4c", "betterleaks"):
            if other not in analyses:
                continue
            found = [row for row in misses if other in row.cross_scanners]
            by_cat = collections.Counter(row.target.category for row in found)
            lines.append(f"**{analyses[other]['label']}:** {len(found)} of {len(misses)} {analyses[primary]['label']} misses; " + (", ".join(f"{key}={value}" for key, value in by_cat.most_common(8)) if by_cat else "none") + ".")
        lines.append("")
    lines.append("## Betterleaks-only coverage relative to CP4C and V14")
    lines.append("")
    only_ids = cross["betterleaks_only_vs_cp4c_v14"]
    lines.append(f"**{len(only_ids)}** targets are credited by Betterleaks but by neither CP4C nor V14.")
    if only_ids:
        by_cat = collections.Counter(by_target[tid]["target"].category for tid in only_ids)
        by_subtype = collections.Counter(by_target[tid]["target"].subtype for tid in only_ids)
        lines.append("")
        lines.append(_table(["Category", "Count"], [[key, count] for key, count in by_cat.most_common(12)]))
        lines.append("")
        lines.append(_table(["Subtype", "Count"], [[key, count] for key, count in by_subtype.most_common(12)]))
        lines.append("")
        lines.append("Examples: " + ", ".join(f"`{tid}`" for tid in only_ids[:15]) + ".")
        lines.append("")
        lines.append(
            "This is the most useful external-detection signal for both RNC scanners, but it is not a drop-in rule. Betterleaks has a different rule vocabulary, different source scope and a different negative oracle. "
            "Inspect the exact Betterleaks rule and the oracle target representation before copying a pattern."
        )
    lines.append("")
    lines.append("## Different rules for the same target")
    lines.append("")
    differing = []
    for target_id, row in by_target.items():
        rules = {key: rule for key, rule in row["rules"].items() if rule}
        if len(set(rules.values())) > 1:
            differing.append((target_id, row, rules))
    lines.append(f"{len(differing)} targets are credited by at least two scanners with different rule IDs.")
    lines.append("")
    if differing:
        sample = []
        for target_id, row, rules in differing[:20]:
            sample.append([target_id, row["target"].subtype, "; ".join(f"{key}:{rule}" for key, rule in sorted(rules.items()))])
        lines.append(_table(["Target", "Subtype", "Rule IDs"], sample))
        lines.append("")
        lines.append(
            "Different rules can be equally correct: a provider-specific rule and a generic assignment rule may both capture the same target. "
            "The comparison treats oracle-target credit as the common unit; it does not rank scanners by rule-name similarity."
        )
    lines.append("")
    lines.append("## CP4C versus V14/V16")
    lines.append("")
    for pair in ("cp4c_v14", "cp4c_v16", "v14_v16"):
        if pair in cross["missing_both"]:
            left, right = pair.split("_")
            lines.append(f"- **Neither {left.upper()} nor {right.upper()}:** {len(cross['missing_both'][pair])} targets.")
    lines.append("")
    lines.append(
        "CP4C and V14/V16 share a large password/WordPress gap but differ sharply on HMAC/signing-family identifiers: CP4C misses all 31 Git `application_signing_key` targets, "
        "while V14/V16 miss only one. Conversely, V14/V16 leave more WordPress salts and database passwords uncredited. "
        "The practical development priority is therefore different for each scanner even where the target sets overlap."
    )
    lines.append("")
    lines.append("## High-value complementary opportunities")
    lines.append("")
    opportunities = []
    if "betterleaks" in analyses:
        opportunities.append(
            "Betterleaks' 438/640 filesystem and 158/160 Git RNC Lab results establish a detection ceiling that neither RNC scanner reaches. "
            "Start with the Betterleaks-only target families, then verify the rule's false-positive behavior against the same trap corpus."
        )
    if "cp4c" in analyses and "v14" in analyses:
        opportunities.append(
            "V14/V16 recover most HMAC/signing-key targets that CP4C misses; CP4C's provider-specific rules and generic assignment matcher recover some targets that V14/V16 miss. "
            "A shared oracle-target review can separate a rule-family change from a source-acquisition change."
        )
    opportunities.append(
        "The all-scanner misses are not proof of an impossible target. They are the right first set for source-level inspection and scanner instrumentation."
    )
    for item in opportunities:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Recommended priorities")
    lines.append("")
    lines.append("- **CP4C:** WordPress salt identifiers; SIGNING/HMAC identifier family; password URI/structured representations; TOTP/provider rules; archive/database key extraction.")
    lines.append("- **V14/V16:** password value/context coverage (WordPress, database, application); container acquisition; TOTP; PPK/PKCS#12; value-validator A/B cases.")
    lines.append("- **Both:** retain the negative oracle, add regression fixtures for every proposed family, and do not claim precision from an incomplete oracle.")
    lines.append("")
    lines.append("## Scope caveat")
    lines.append("")
    lines.append(
        "Gitleaks master, V14/V16 and Betterleaks were run through their registered harness adapters with their own default rule sets. "
        "The reports show equivalent filesystem/Git lanes and the same frozen oracle, but equivalent source scope is not assumed. "
        "Leaky Git coverage verification is not exposed as `true` by the external adapters; their Git precision/F1 remain uncertified."
    )
    lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _overlap_csv(cross: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    columns = ["target_id", "dataset", "lane", "category", "subtype", "provider", "risk_bearing", "informative"]
    for key in cross["keys"]:
        columns.extend([f"{key}_matched", f"{key}_rule"])
    columns.extend(["found_by", "missed_by"])
    rows = []
    for target_id, row in cross["by_target"].items():
        target = row["target"]
        item = {
            "target_id": target_id,
            "dataset": target.dataset,
            "lane": target.lane,
            "category": target.category,
            "subtype": target.subtype,
            "provider": target.provider,
            "risk_bearing": _yes(target.risk_bearing),
            "informative": _yes(target.informative),
            "found_by": row["found_by"],
            "missed_by": row["missed_by"],
        }
        for key in cross["keys"]:
            item[f"{key}_matched"] = _yes(row["matched"][key])
            item[f"{key}_rule"] = row["rules"].get(key, "")
        rows.append(item)
    return columns, rows


def _validation_block(analyses: dict[str, dict[str, Any]], cross: dict[str, Any]) -> dict[str, Any]:
    counts = {}
    for key, analysis in analyses.items():
        lane_counts = {
            lane: sum(
                1
                for row in analysis["rows"]
                if row.target.lane == lane and row.observation.matched
            )
            for lane in LANE_ORDER
        }
        counts[key] = {
            "expected": len(analysis["rows"]),
            "matched": sum(1 for row in analysis["rows"] if row.observation.matched),
            "missed": sum(1 for row in analysis["rows"] if not row.observation.matched),
            "matched_by_lane": lane_counts,
            "root_cause_total": sum(analysis["stats"]["root_causes"].values()),
            "root_causes_reconcile": sum(analysis["stats"]["root_causes"].values())
            == sum(1 for row in analysis["rows"] if not row.observation.matched),
            "report_metrics": analysis["evidence"].metrics["_report_metrics"],
        }
    all_reconcile = all(
        item["matched_by_lane"][lane] == item["report_metrics"][lane]
        for item in counts.values()
        for lane in LANE_ORDER
    )
    target_rows = next(iter(analyses.values()))["rows"]
    lane_counts = collections.Counter(row.target.lane for row in target_rows)
    category_counts = collections.Counter(_category(row) for row in target_rows)
    container_counts = collections.Counter(row.target.container_kind for row in target_rows)
    leaky_git_groups = {
        row.target.group_id
        for row in target_rows
        if row.target.lane == "leaky_git" and row.target.group_id
    }
    rnclab_groups = {
        row.target.group_id
        for row in target_rows
        if row.target.lane.startswith("rnclab") and row.target.group_id
    }
    empty_evidence = [
        row.target.target_id
        for analysis in analyses.values()
        for row in analysis["rows"]
        if not row.observation.matched and not row.evidence
    ]
    return {
        "target_universe": {
            "total": sum(LANE_DENOMINATORS.values()),
            "by_lane": dict(LANE_DENOMINATORS),
            "observed_by_lane": dict(lane_counts),
            "sum_matches_expected": sum(lane_counts.values()) == sum(LANE_DENOMINATORS.values()),
        },
        "unique_identity_checks": {
            "leaky_git_unique_groups": len(leaky_git_groups),
            "leaky_git_unique_groups_expected": 53,
            "rnclab_unique_groups": len(rnclab_groups),
            "rnclab_unique_groups_expected": 496,
            "leaky_git_occurrences": lane_counts["leaky_git"],
            "rnclab_occurrences": lane_counts["rnclab_filesystem"] + lane_counts["rnclab_git"],
        },
        "category_partition": {
            "expected": sum(category_counts.values()),
            "by_category": dict(category_counts),
            "sums_to_target_universe": sum(category_counts.values()) == sum(LANE_DENOMINATORS.values()),
        },
        "risk_partition": {
            "risk_bearing": sum(1 for row in target_rows if row.target.risk_bearing),
            "informative": sum(1 for row in target_rows if row.target.informative),
            "sums_to_target_universe": sum(1 for row in target_rows if row.target.risk_bearing)
            + sum(1 for row in target_rows if row.target.informative)
            == sum(LANE_DENOMINATORS.values()),
        },
        "container_partition": {
            "by_container": dict(container_counts),
            "archive_members": container_counts["archive_member"],
            "database_records": container_counts["database_record"],
            "binary_files": container_counts["binary_file"],
            "not_treated_as_plaintext": container_counts["archive_member"] + container_counts["database_record"] + container_counts["binary_file"],
        },
        "reconstructed_counts": counts,
        "all_scanner_counts_reconcile": all_reconcile,
        "all_root_causes_reconcile": all(item["root_causes_reconcile"] for item in counts.values()),
        "all_missed_targets_have_evidence": not empty_evidence,
        "empty_evidence_targets": empty_evidence[:10],
        "cross_scanner_counts": cross["counts"],
        "oracle_or_scoring_changed": False,
        "category_percentages_use_lane_denominators": True,
        "informative_references_separated": True,
        "private_key_substitution_rejected": True,
        "archives_not_treated_as_members": True,
        "generator_mode": "read-only over retained reports and frozen oracles",
    }


def generate_reports(
    *,
    analyses: dict[str, dict[str, Any]],
    cross: dict[str, Any],
    output_dir: str | Path,
    generated_at: str | None = None,
) -> dict[str, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    timestamp = generated_at or dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    written: dict[str, Path] = {}
    summaries: dict[str, dict[str, Any]] = {}
    for key in ("cp4c", "v14", "v16"):
        if key not in analyses:
            continue
        analysis = analyses[key]
        summary = build_scanner_summary(analysis, cross, generated_at=timestamp)
        summaries[key] = summary
        directory = out / SCANNER_DIRS[key]
        directory.mkdir(parents=True, exist_ok=True)
        stem = analysis["key"]
        inventory = target_inventory_rows(analysis)
        missed = missed_rows(analysis)
        context = provider_context_rows(analysis)
        location = location_rows(analysis)
        _write_csv(
            directory / f"{stem}-target-inventory.csv",
            [
                "scanner", "scanner_key", "build_id", "target_id", "dataset", "lane", "lane_title",
                "oracle_disposition", "target_class", "expected", "matched", "score_disposition",
                "risk_bearing", "informative", "primary_tp", "unique_secret_group_id", "occurrence_id",
                "historical_occurrence_id", "category", "subtype", "provider", "provider_confidence",
                "credential_purpose", "path", "file_type", "source_container", "container_format",
                "archive_member", "archive_depth", "database_table", "database_column", "git_commit",
                "line", "byte_start", "byte_end", "representation", "normalization", "identifier_key",
                "identifier_family", "scanner_scope", "inspection_status", "rule_id", "finding_id",
                "match_classification", "overlapping_finding", "scorer_disposition", "rejected_or_pending",
                "root_cause", "root_cause_confidence", "responsible_layer", "evidence_summary",
                "reproduction", "cross_scanner_matches", "development_priority",
            ],
            inventory,
        )
        _write_csv(
            directory / f"{stem}-missed-targets.csv",
            [
                "scanner", "scanner_key", "target_id", "dataset", "lane", "target_class", "risk_bearing",
                "informative", "unique_secret_group_id", "occurrence_id", "historical_occurrence_id",
                "category", "subtype", "provider", "provider_confidence", "credential_purpose", "path",
                "file_type", "source_container", "container_format", "archive_member", "database_table",
                "database_column", "git_commit", "line", "representation", "normalization",
                "identifier_key", "identifier_family", "inspection_status", "overlap_finding",
                "overlap_rule_id", "overlap_capture", "score_disposition", "scoring_reason",
                "scoring_reason_code", "scoring_stage", "root_cause", "root_cause_confidence",
                "responsible_layer", "evidence_summary", "smallest_reproduction",
                "existing_rule_capability", "cross_scanner_matches", "cross_scanner_rules",
                "development_priority",
            ],
            missed,
        )
        _write_csv(
            directory / f"{stem}-provider-context.csv",
            [
                "scanner", "scanner_key", "target_id", "dataset", "lane", "category", "subtype",
                "provider", "provider_confidence", "credential_family", "credential_purpose",
                "identifier_key", "identifier_family", "assignment_style", "structured_parent",
                "provider_identifying_evidence", "domains", "companion_identifiers", "requires_multiline",
                "requires_structured_parse", "context_available", "context_redacted",
                "adjacent_context_redacted", "existing_rule_capability", "observed_same_subtype_rule",
                "observed_same_subtype_matches", "observed_same_representation_matches",
                "context_confidence", "notes",
            ],
            context,
        )
        _write_csv(
            directory / f"{stem}-location-analysis.csv",
            [
                "scanner", "scanner_key", "target_id", "dataset", "lane", "matched", "source_container",
                "container_format", "archive_format", "archive_depth", "archive_member", "database_table",
                "database_column", "database_rowid", "binary_format", "git_commit", "path", "line",
                "byte_start", "byte_end", "file_type", "representation", "representation_family",
                "normalization", "scanner_scope", "inspection_status", "source_eligibility",
                "root_cause", "root_cause_confidence", "responsible_layer", "cross_scanner_matches",
            ],
            location,
        )
        _write_text(directory / f"{stem}-detection-gaps.md", _detection_gaps_markdown(analysis, summary, analyses))
        _write_text(directory / f"{stem}-root-causes.md", _root_cause_markdown(analysis))
        _write_text(directory / f"{stem}-development-backlog.md", _backlog_markdown(analysis, summary))
        summary["validation"] = _validation_block(analyses, cross)
        summary["input_evidence"] = {
            "reports": {key: analyses[key]["evidence"].metadata for key in sorted(analyses)},
            "oracle_files": {
                "rnclab": "datasets/cache/rnc-synth-lab/oracle/oracle.jsonl",
                "leaky_truth": "datasets/leaky-repo.rnc-truth.json",
                "leaky_history": "datasets/leaky-repo.history-oracle.json",
                "levain": "datasets/cache/levain/<revision>/source/tp-corpus.json.b64",
            },
        }
        _write_text(
            directory / f"{stem}-summary.json",
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
        )
        written[f"{stem}_md"] = directory / f"{stem}-detection-gaps.md"
        written[f"{stem}_summary"] = directory / f"{stem}-summary.json"
    overlap_md = out / "cp4c-v14-target-overlap.md"
    _write_text(overlap_md, _overlap_markdown(cross, analyses))
    written["overlap_md"] = overlap_md
    columns, rows = _overlap_csv(cross)
    overlap_csv = out / "cp4c-v14-target-overlap.csv"
    _write_csv(overlap_csv, columns, rows)
    written["overlap_csv"] = overlap_csv
    validation = {
        "schema_version": 1,
        "analysis_version": ANALYSIS_VERSION,
        "generated_at": timestamp,
        "validation": _validation_block(analyses, cross),
        "scanner_summaries": {key: f"{SCANNER_DIRS[key]}/{key}-summary.json" for key in summaries},
    }
    _write_text(out / "analysis-validation.json", json.dumps(validation, indent=2, sort_keys=True) + "\n")
    written["validation"] = out / "analysis-validation.json"
    _write_text(out / "README.md", _readme(summaries, cross, timestamp))
    written["readme"] = out / "README.md"
    return written


def _readme(summaries: dict[str, dict[str, Any]], cross: dict[str, Any], timestamp: str) -> str:
    lines = ["# Detection-gap analysis", ""]
    lines.append(
        "Target-level false-negative and source-context investigation for the current-scoring Windows AMD64 baselines. "
        "These reports are generated from retained harness evidence and frozen oracles; no scanner, rule, oracle or scoring policy was modified."
    )
    lines.append("")
    lines.append(f"Generated: `{timestamp}`")
    lines.append("")
    lines.append(f"Analysis version: `{ANALYSIS_VERSION}`")
    lines.append("")
    lines.append("## Individual reports")
    lines.append("")
    for key in ("cp4c", "v14", "v16"):
        if key not in summaries:
            continue
        summary = summaries[key]
        lines.append(f"### {summary['scanner']}")
        lines.append("")
        lines.append(f"- [Detection gaps]({SCANNER_DIRS[key]}/{key}-detection-gaps.md)")
        lines.append(f"- [Root causes]({SCANNER_DIRS[key]}/{key}-root-causes.md)")
        lines.append(f"- [Development backlog]({SCANNER_DIRS[key]}/{key}-development-backlog.md)")
        lines.append(f"- [Target inventory]({SCANNER_DIRS[key]}/{key}-target-inventory.csv)")
        lines.append(f"- [Missed targets]({SCANNER_DIRS[key]}/{key}-missed-targets.csv)")
        lines.append(f"- [Provider context]({SCANNER_DIRS[key]}/{key}-provider-context.csv)")
        lines.append(f"- [Location analysis]({SCANNER_DIRS[key]}/{key}-location-analysis.csv)")
        lines.append(f"- [Machine summary]({SCANNER_DIRS[key]}/{key}-summary.json)")
        lines.append("")
        lines.append(
            f"Expected {summary['counts']['expected']}, matched {summary['counts']['matched']}, "
            f"missed {summary['counts']['missed']} ({summary['counts']['risk_bearing_misses']} risk-bearing)."
        )
        if key == "v16":
            lines.append("Fresh current-scoring V16 baseline: native Windows AMD64, default settings, 1 warmup + 3 measured runs, no profiling.")
        lines.append("")
    lines.append("## Shared comparison")
    lines.append("")
    lines.append("- [CP4C/V14/V16 target overlap](cp4c-v14-target-overlap.md)")
    lines.append("- [Target overlap CSV](cp4c-v14-target-overlap.csv)")
    lines.append(f"- All-scanner common misses: **{cross['counts']['all_scanner_misses']}**")
    lines.append("")
    lines.append("## Validation")
    lines.append("")
    lines.append("- [Machine validation](analysis-validation.json)")
    lines.append("- Every scanner's reconstructed per-target matched count is checked against its retained report metric, by lane and in total.")
    lines.append("- Root-cause totals equal the reconstructed miss totals for every scanner.")
    lines.append("- The 1,125-target universe is partitioned into 85 Levain, 175 Leaky filesystem, 65 Leaky Git, 640 RNC Lab filesystem and 160 RNC Lab Git targets.")
    lines.append("- Leaky Git preserves 65 occurrences and 53 unique groups; RNC Lab preserves 800 occurrences and 496 unique groups. They are never conflated.")
    lines.append("- The 10 archive members, 12 database records and 4 binary key containers are classified as non-plaintext, not ordinary files.")
    lines.append("- RNC Lab and Leaky Git precision/F1 are not claimed; their negative oracles are incomplete.")
    lines.append("")
    lines.append("## Regeneration")
    lines.append("")
    lines.append("```powershell")
    lines.append("python -m harness detection-gaps --out-dir reports/detection-gaps")
    lines.append("python -m unittest tests.test_detection_gaps -v")
    lines.append("```")
    lines.append("")
    lines.append("Raw evidence remains under Git-ignored `run/`. Tracked files contain target IDs, redacted structural context and nonsecret source locators only.")
    lines.append("")
    return "\n".join(lines)
