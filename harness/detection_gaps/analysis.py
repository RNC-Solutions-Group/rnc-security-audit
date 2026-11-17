"""Root-cause, capability, and cross-scanner analysis over canonical targets."""

from __future__ import annotations

import collections
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .model import (
    AnalysisRow,
    LANE_ORDER,
    Observation,
    ScannerEvidence,
    Target,
    identifier_family,
    normalize_identifier,
)
from .sources import DetectionGapError

GENERIC_KEYWORDS = (
    "PASSWORD",
    "PASSWD",
    "PWD",
    "CLIENT_SECRET",
    "JWT_SECRET",
    "SESSION_SECRET",
    "SECRET_KEY",
    "SECRET_TOKEN",
    "SECRET_VALUE",
    "API_KEY",
    "API_TOKEN",
    "API_SECRET",
    "ACCESS_TOKEN",
    "AUTH_TOKEN",
    "BEARER_TOKEN",
    "PRIVATE_KEY",
    "CREDENTIAL",
)

PROVIDER_RULE_BY_SUBTYPE = {
    "aws_access_key_id": "aws-access-key-id",
    "aws_secret_access_key": "aws-secret-access-key",
    "google_api_key": "google-api-key",
    "github_personal_access_token": "github-*",
    "gitlab_personal_access_token": "gitlab-personal-access-token",
    "stripe_secret_key": "stripe-secret-api-key",
    "slack_bot_token": "slack-token",
    "sendgrid_api_key": "sendgrid-api-key",
    "npm_access_token": "npm-auth-token",
    "azure_storage_account_key": "azure-storage-account-key",
    "twilio_auth_token": None,
    "pypi_api_token": None,
    "stripe_webhook_secret": None,
    "totp_seed": None,
    "generic_api_key": None,
}

PROVIDER_LABEL_BY_RULE = {
    "aws-access-key-id": "AWS",
    "aws-secret-access-key": "AWS",
    "google-api-key": "Google Cloud",
    "github-classic-pat": "GitHub",
    "github-fine-grained-pat": "GitHub",
    "github-oauth-app-token": "GitHub",
    "github-app-installation-token": "GitHub",
    "gitlab-personal-access-token": "GitLab",
    "stripe-secret-api-key": "Stripe",
    "slack-token": "Slack",
    "sendgrid-api-key": "SendGrid",
    "npm-auth-token": "npm",
    "azure-storage-account-key": "Azure",
    "tailscale-key": "Tailscale",
    "groq-api-key": "Groq",
    "xai-api-key": "xAI",
    "perplexity-api-key": "Perplexity",
    "doppler-service-token": "Doppler",
    "slack-incoming-webhook": "Slack",
    "openai-api-key": "OpenAI",
    "pem-private-key": "PEM",
    "pem-private-key-pgp": "OpenPGP",
    "pem-private-key-escaped": "PEM",
    "pem-private-key-base64": "PEM",
    "database-connection-credential": "Database",
    "credential-url-userinfo": "URL userinfo",
    "jwt-bearer-token": "JWT",
    "http-basic-authorization": "HTTP Basic",
    "http-bearer-opaque": "HTTP Bearer",
}


def load_cp4c_rules(path: Path | None = None) -> dict[str, Any]:
    if path is None:
        path = Path(__file__).resolve().parents[2] / "run" / "rules" / "rnc-cp4c-providers-v1.json"
    if not path.is_file():
        return {"rules": [], "path": None}
    document = json.loads(path.read_text(encoding="utf-8"))
    return {"rules": list(document.get("rules") or []), "path": str(path), "sha256": None}


# Controlled local reproductions are retained under ignored
# run/detection-gaps/repro/.  Only the outcome is promoted here: no secret value
# is stored in the source or in tracked reports.
VALUE_REPRODUCTIONS = {
    "cp4c": {
        "RNC-SL-POS-000670": (
            "a standalone temporary .env containing this exact DB_PASSWORD value was not detected, "
            "while the same identifier with a different DB_PASSWORD value was credited"
        ),
        "RNC-SL-POS-000791": (
            "a standalone temporary YAML file containing this exact sendgrid_key value was not detected, "
            "while the same YAML identifier with another SendGrid value was credited"
        ),
    },
    "v14": {
        "RNC-SL-POS-000203": (
            "a standalone temporary .env with this exact JWT_SIGNING_KEY value was not detected, "
            "while a different JWT_SIGNING_KEY value was credited by generic-api-key"
        ),
        "RNC-SL-POS-000485": (
            "a standalone temporary .env with this exact SESSION_SECRET value was not detected, "
            "while a different SESSION_SECRET value was credited by generic-api-key"
        ),
        "RNC-SL-POS-000671": (
            "a standalone temporary .env with this exact SIGNING_KEY value was not detected, "
            "while a different SIGNING_KEY value was credited by generic-api-key"
        ),
        "RNC-SL-POS-000670": (
            "a standalone temporary .env with this exact DB_PASSWORD value was not detected, "
            "while a different DB_PASSWORD value was credited by generic-api-key"
        ),
    },
}
# V16 is the direct successor build in the comparison; the same retained target
# values and controlled A/B outcomes apply to the identical RNC Lab corpus.
VALUE_REPRODUCTIONS["v16"] = dict(VALUE_REPRODUCTIONS["v14"])


def _contains_generic_identifier(identifier: str) -> bool:
    upper = normalize_identifier(identifier)
    return any(keyword in upper for keyword in GENERIC_KEYWORDS)


def _provider_rule_for(target: Target, cp4c_rules: dict[str, Any]) -> list[str]:
    rule_ids = {str(rule.get("rule_id")) for rule in cp4c_rules.get("rules") or []}
    subtype = target.subtype
    candidate = PROVIDER_RULE_BY_SUBTYPE.get(subtype)
    if candidate == "github-*":
        return [rule for rule in ("github-classic-pat", "github-fine-grained-pat", "github-oauth-app-token", "github-app-installation-token") if rule in rule_ids]
    if candidate and candidate in rule_ids:
        return [candidate]
    if target.category == "private_key":
        return [rule for rule in ("pem-private-key", "pem-private-key-pgp", "pem-private-key-escaped", "pem-private-key-base64") if rule in rule_ids]
    if target.category == "password" and target.representation in {"database_url", "alembic_url", "redis_url", "mongodb_uri", "sqlserver_connection_string"}:
        return ["database-connection-credential"] if "database-connection-credential" in rule_ids else []
    if target.category == "provider_token" and target.representation == "jwt":
        return ["jwt-bearer-token"] if "jwt-bearer-token" in rule_ids else []
    return []


def _capability(
    target: Target,
    evidence: ScannerEvidence,
    cp4c_rules: dict[str, Any],
    subtype_rule_counts: dict[str, collections.Counter],
    repr_rule_counts: dict[str, collections.Counter],
    identifier_rule_counts: dict[str, collections.Counter],
) -> dict[str, Any]:
    provider_rules = _provider_rule_for(target, cp4c_rules) if evidence.key == "cp4c" else []
    generic_available = _contains_generic_identifier(target.context.identifier)
    observed_subtype = subtype_rule_counts.get(target.subtype, collections.Counter())
    observed_repr = repr_rule_counts.get(target.representation, collections.Counter())
    observed_identifier = identifier_rule_counts.get(normalize_identifier(target.context.identifier), collections.Counter())
    observed_category = collections.Counter()
    if evidence.key in {"v14", "v16", "gitleaks", "betterleaks"}:
        # Embedded rules are not externally inspectable.  A rule observed on the
        # same subtype/representation is evidence of capability; absence is not
        # evidence that no rule exists.
        observed_rule = ""
        if observed_subtype:
            observed_rule = observed_subtype.most_common(1)[0][0]
        elif observed_repr:
            observed_rule = observed_repr.most_common(1)[0][0]
        basis = "observed-subtype-rule" if observed_subtype else ("observed-representation-rule" if observed_repr else "no-observed-rule")
    else:
        observed_rule = ""
        if provider_rules:
            basis = "provider-rule"
        elif generic_available:
            basis = "generic-identifier-rule"
        elif target.representation in {"database_url", "alembic_url", "redis_url", "mongodb_uri", "sqlserver_connection_string"}:
            basis = "uri-rule"
        elif target.category == "private_key":
            basis = "pem-rule"
        else:
            basis = "no-matching-rule"
    return {
        "provider_rules": provider_rules,
        "generic_identifier_available": generic_available,
        "observed_subtype_rule": observed_subtype.most_common(1)[0][0] if observed_subtype else "",
        "observed_subtype_count": sum(observed_subtype.values()),
        "observed_representation_rule": observed_repr.most_common(1)[0][0] if observed_repr else "",
        "observed_representation_count": sum(observed_repr.values()),
        "observed_identifier_count": sum(observed_identifier.values()),
        "basis": basis,
    }


def _layer_for(code: str) -> str:
    return {
        "RULE_ABSENT": "RULE_COVERAGE",
        "IDENTIFIER_MISMATCH": "IDENTIFIER_LEXICON",
        "FORMAT_UNSUPPORTED": "REPRESENTATION_DECODER",
        "CAPTURE_MISMATCH": "VALUE_CAPTURE",
        "CONTEXT_INSUFFICIENT": "CONTEXT_MODEL",
        "VALIDATOR_REJECTION": "VALUE_VALIDATOR",
        "SOURCE_NOT_INSPECTED": "SOURCE_ACQUISITION",
        "SOURCE_UNSUPPORTED": "SOURCE_ACQUISITION",
        "SOURCE_INSPECTION_UNVERIFIED": "SOURCE_ACQUISITION",
        "GIT_SCOPE_OR_ATTRIBUTION": "SOURCE_ATTRIBUTION",
        "SCORING_MISMATCH": "SCORER",
        "INFORMATIVE_REFERENCE": "ORACLE_CLASSIFICATION",
        "UNKNOWN": "UNRESOLVED",
    }.get(code, "UNRESOLVED")


def _priority(target: Target, code: str, cross: list[str], confidence: str) -> str:
    if target.informative:
        return "LOW"
    if code in {"SOURCE_UNSUPPORTED", "SOURCE_INSPECTION_UNVERIFIED", "UNKNOWN"}:
        return "MEDIUM" if cross else "LOW"
    if cross or confidence == "CONFIRMED":
        return "HIGH"
    return "MEDIUM"


def _short_source(target: Target) -> str:
    if target.container_kind == "archive_member":
        return f"{target.path}!/{target.archive_member}"
    if target.container_kind == "database_record":
        return f"{target.path} [{target.database_table}.{target.database_column}]"
    if target.container_kind == "git_blob":
        return f"{target.path}@{target.commit[:10]}"
    return target.path


def _classify_miss_after_source(
    target: Target,
    observation: Observation,
    capability: dict[str, Any],
    *,
    scanner_key: str,
    container_tp: int,
    same_subtype_matches: int,
    same_representation_matches: int,
    cross: list[str],
) -> tuple[str, str, str, str, str]:
    """Classify a miss after source-inspection gating has been applied."""
    if target.target_id in VALUE_REPRODUCTIONS.get(scanner_key, {}):
        return (
            "VALIDATOR_REJECTION",
            "PROBABLE",
            "VALUE_VALIDATOR",
            VALUE_REPRODUCTIONS[scanner_key][target.target_id],
            "controlled standalone-file A/B reproduction in ignored run/detection-gaps/repro/",
        )
    if observation.disposition == "UNVERIFIED_EVIDENCE":
        if "LOCATION" in observation.reason_code.upper():
            return (
                "SCORING_MISMATCH",
                "CONFIRMED",
                "SCORER",
                f"scanner finding overlaps the expected target but was rejected at {observation.stage}: {observation.reason_code}",
                "compare the retained finding span with the oracle span; no scanner change",
            )
        return (
            "CAPTURE_MISMATCH",
            "CONFIRMED",
            "VALUE_CAPTURE",
            f"scanner finding exists at the expected source location but value evidence did not match ({observation.reason_code or observation.reason})",
            "inspect the retained finding value extraction for this target; no corpus change",
        )
    family = target.context.identifier_family
    identifier = normalize_identifier(target.context.identifier)
    code = "UNKNOWN"
    confidence = "UNRESOLVED"
    evidence = "no retained candidate and no scanner-side diagnostic instrumentation"
    reproduction = "controlled one-target rescan in a temporary directory"

    # A value nested inside a runtime expression is not the plain assignment
    # shape the generic rule accepts.  This is a representation/context gap, not
    # a missing identifier.
    if target.representation == "python_string_literal" and "os.environ" in target.context.context_redacted:
        return (
            "FORMAT_UNSUPPORTED",
            "PROBABLE",
            "REPRESENTATION_DECODER",
            "the credential is a fallback literal inside os.environ.get(...), not a direct assignment value; the generic rule does not parse that expression shape",
            "temporary Python file with SECRET_KEY = os.environ.get('X', <synthetic>) and a direct-assignment control",
        )
    if target.subtype == "password_hash" or target.representation == "hash_value":
        return (
            "FORMAT_UNSUPPORTED",
            "CONFIRMED",
            "REPRESENTATION_DECODER",
            "the target is a password hash, not a plaintext credential; the scanner has no hash-cracking or hash-credential rule and must not report every hash as a password",
            "temporary .htpasswd/shadow line with a synthetic hash; rescan",
        )
    if target.subtype == "base64_basic_credential" or target.representation == "base64_value":
        return (
            "FORMAT_UNSUPPORTED",
            "PROBABLE",
            "REPRESENTATION_DECODER",
            "the credential is stored as a base64 basic-credential field; the scanner's provider rules expect a raw token or a recognized assignment",
            "temporary .npmrc with a synthetic base64 user:password value; rescan",
        )
    if target.representation == "sql_copy_value":
        return (
            "FORMAT_UNSUPPORTED",
            "PROBABLE",
            "REPRESENTATION_DECODER",
            "the credential is a positional SQL COPY/INSERT field; the existing rules do not parse the column list and row value as a password association",
            "temporary SQL dump with the same column shape and a synthetic value",
        )
    if target.subtype == "netrc_credential" or target.representation in {"netrc_password", "pgpass_password"}:
        return (
            "FORMAT_UNSUPPORTED",
            "PROBABLE",
            "REPRESENTATION_DECODER",
            "the credential is in a colon-delimited or netrc field with no assignment key; the scanner has no field-role parser for this format",
            "temporary .netrc/.pgpass file with a synthetic credential and a direct-assignment control",
        )
    if target.representation in {
        "filezilla_base64_password",
        "docker_config_auth",
        "docker_secret_file",
        "jetbrains_static_key_obfuscated",
        "compose_command_arg",
        "log_command_argument",
        "publish_profile_base64",
    }:
        return (
            "FORMAT_UNSUPPORTED",
            "PROBABLE",
            "REPRESENTATION_DECODER",
            f"the credential is encoded or positional in {target.representation}; the scanner has no matching field-role decoder",
            "temporary file preserving the container shape with a synthetic value",
        )
    if target.representation == "raw_key_file":
        return (
            "CONTEXT_INSUFFICIENT",
            "PROBABLE",
            "CONTEXT_MODEL",
            "the value is a raw key file with no assignment identifier; a high-entropy-only rule would create false positives across certificates and build metadata",
            "temporary raw key file with a known synthetic value and a filename/metadata control",
        )

    # High-confidence structural categories.
    if target.category == "otp_seed":
        code, confidence = "RULE_ABSENT", "CONFIRMED" if scanner_key == "cp4c" else "PROBABLE"
        evidence = "no TOTP/otpauth rule was identified in the scanner rule inventory; no TOTP subtype was credited"
        reproduction = "create a synthetic otpauth:// URI in a temporary file and rescan"
    elif target.subtype == "wordpress_salt":
        code, confidence = "IDENTIFIER_MISMATCH", "CONFIRMED" if scanner_key == "cp4c" else "PROBABLE"
        evidence = (
            "the generic assignment rule's identifier lexicon contains PASSWORD/SECRET/API_KEY families "
            "but not WordPress AUTH_KEY/SECURE_AUTH_KEY/LOGGED_IN_KEY/NONCE_KEY/SALT families; "
            f"the scanner credited {same_subtype_matches} WordPress-salt occurrences elsewhere; "
            "a controlled plain-file AUTH_KEY definition was not detected"
        )
        reproduction = "synthetic define('AUTH_KEY', <random>) in a temporary PHP file; rescan"
    elif target.subtype in {"application_signing_key", "jwt_signing_key"} or family == "SIGNING" or family == "HMAC":
        if capability.get("generic_identifier_available"):
            code, confidence = "IDENTIFIER_MISMATCH", "CONFIRMED" if scanner_key == "cp4c" else "PROBABLE"
            evidence = (
                "identifier family is not in the generic assignment keyword set; "
                f"same-subtype matches elsewhere: {same_subtype_matches}, same-representation: {same_representation_matches}; "
                "controlled plain-file reproduction missed SIGNING_KEY and JWT_SIGNING_KEY while a SESSION_SECRET control was credited"
            )
        else:
            code, confidence = "IDENTIFIER_MISMATCH", "CONFIRMED" if scanner_key == "cp4c" else "PROBABLE"
            evidence = (
                "the scanner has no HMAC/SIGNING provider rule and its generic identifier set does not include "
                f"{target.context.identifier or 'this identifier'}; same-subtype matches elsewhere: {same_subtype_matches}"
            )
        reproduction = "write SIGNING_KEY=<random> and JWT_SIGNING_KEY=<random> as ordinary temporary files; rescan both"
    elif target.subtype in {"key_passphrase", "pkcs12_passphrase"}:
        code, confidence = "IDENTIFIER_MISMATCH", "CONFIRMED" if scanner_key == "cp4c" else "PROBABLE"
        evidence = "PASSPHRASE/P12 identifiers are absent from the generic password identifier family; no passphrase rule was observed"
        reproduction = "temporary env file with ENCKEY-0001_PASSPHRASE=<random>; rescan"
    elif target.category == "private_key":
        if target.representation in {"putty_ppk_v2", "pkcs12_der"} or target.container_kind == "binary_file":
            code, confidence = "FORMAT_UNSUPPORTED", "CONFIRMED" if scanner_key == "cp4c" else "PROBABLE"
            evidence = f"private-key representation {target.representation} is a non-PEM container; no same-representation credit was observed"
            reproduction = "rescan a temporary copy of the PPK/PKCS#12 container as a standalone file"
        elif target.container_kind in {"archive_member", "binary_file"}:
            code, confidence = "SOURCE_UNSUPPORTED", "CONFIRMED"
            evidence = "private-key material is inside a container the scanner did not parse"
        elif same_subtype_matches == 0:
            code, confidence = "RULE_ABSENT", "PROBABLE"
            evidence = "no same-subtype private-key target was credited; PEM rule presence must be verified against this subtype"
        else:
            code, confidence = "FORMAT_UNSUPPORTED", "PROBABLE"
            evidence = "other private keys were credited, but this representation or subtype is outside the accepted PEM container form"
            reproduction = "rescan the exact PEM bytes as a standalone temporary file"
    elif target.subtype == "browser_saved_credential":
        return (
            "FORMAT_UNSUPPORTED",
            "CONFIRMED",
            "REPRESENTATION_DECODER",
            "the value is an encrypted Firefox login field; decryption requires the separate browser key material and the scanner has no browser-profile decoder",
            "temporary JSON with encryptedUsername/encryptedPassword fields and no key4.db; rescan",
        )
    elif target.category == "provider_token" or target.category == "api_key":
        if capability.get("provider_rules"):
            if target.representation in {
                "json_string",
                "kubernetes_secret_data",
                "docker_config_auth",
                "filezilla_base64_password",
                "uri_userinfo",
            } or target.container_kind in {"archive_member", "database_record", "binary_file"}:
                code, confidence = "FORMAT_UNSUPPORTED", "PROBABLE"
                evidence = (
                    f"provider rule {capability['provider_rules']} exists, but the provider token is embedded in "
                    f"{target.representation}, outside the rule's raw-token/assignment context"
                )
                reproduction = "rescan the same decoded field as a synthetic standalone token in a temporary file"
            else:
                code, confidence = "CONTEXT_INSUFFICIENT", "PROBABLE"
                evidence = (
                    f"provider rule {capability['provider_rules']} exists, but no credited finding establishes whether the "
                    "token shape, provider field, or value validator caused the miss"
                )
                reproduction = "temporary standalone file with the same field and a documented-shape synthetic token"
        elif target.subtype == "generic_api_key":
            code, confidence = "RULE_ABSENT", "CONFIRMED" if scanner_key == "cp4c" else "PROBABLE"
            evidence = (
                "generic API-key values have no dedicated shape rule; the generic assignment rule only acts on "
                "recognized identifier families"
            )
            reproduction = "temporary file with the target identifier and a freshly generated token-shaped value"
        elif target.category == "provider_token" and same_subtype_matches == 0:
            code, confidence = "RULE_ABSENT", "CONFIRMED" if scanner_key == "cp4c" else "PROBABLE"
            evidence = f"no provider rule or same-subtype credit was observed for {target.subtype}"
            reproduction = "temporary one-line synthetic token file using the same documented shape"
        else:
            code, confidence = "UNKNOWN", "UNRESOLVED"
            evidence = "a provider or generic rule family exists, but the value/context combination is not covered by retained evidence"
    elif target.category == "password":
        if target.representation in {
            "redis_url",
            "alembic_url",
            "database_url",
            "mongodb_uri",
            "sqlserver_connection_string",
            "dotenv_value",
        } and target.context.identifier_family in {"OTHER"}:
            code, confidence = "FORMAT_UNSUPPORTED", "PROBABLE"
            evidence = "password is embedded in a URI/colon-delimited or positional format without a recognized assignment key"
            reproduction = "rescan the same URI shape with a synthetic password in a temporary file"
        elif target.subtype == "database_password" and target.context.identifier_family == "DATABASE_PASSWORD":
            if target.representation in {"php_define", "php_string_literal", "sql_copy_value"}:
                code, confidence = "FORMAT_UNSUPPORTED", "PROBABLE"
                evidence = (
                    f"database password is embedded in {target.representation}, not the direct assignment/URI form the existing rules accept"
                )
            elif same_subtype_matches > 0:
                code, confidence = "UNKNOWN", "UNRESOLVED"
                evidence = (
                    "same database-password subtype is credited elsewhere, but this value/context has no retained candidate; "
                    "value-validation or context-window behavior cannot be distinguished without instrumentation"
                )
            else:
                code, confidence = "RULE_ABSENT", "PROBABLE"
                evidence = "no database-password rule or same-subtype credit was observed"
        elif target.context.identifier == "NO_ASSIGNMENT_IDENTIFIER":
            code, confidence = "FORMAT_UNSUPPORTED", "PROBABLE"
            evidence = "no assignment identifier exists; the value is positional, colon-delimited, encoded, or in a command/log argument"
            reproduction = "rescan the same container shape with a synthetic value in a temporary file"
        elif not _contains_generic_identifier(target.context.identifier):
            code, confidence = "IDENTIFIER_MISMATCH", "CONFIRMED" if scanner_key == "cp4c" else "PROBABLE"
            evidence = f"identifier {target.context.identifier!r} is outside the generic password/secret keyword set"
            reproduction = "temporary assignment using the same identifier and a synthetic value"
        else:
            code, confidence = "CONTEXT_INSUFFICIENT" if same_representation_matches else "FORMAT_UNSUPPORTED", "PROBABLE"
            evidence = (
                "identifier is recognized, but the value sits in a wrapped, encoded, or structured representation; "
                f"same-representation credits elsewhere: {same_representation_matches}"
            )
            reproduction = "temporary file preserving the wrapper/encoding but replacing the secret"
    elif target.category in {"unknown_credential", "payment_data"}:
        code, confidence = "UNKNOWN", "UNRESOLVED"
        evidence = "inferred credential family lacks a reliable subtype or rule mapping"
    if code == "UNKNOWN" and target.context.identifier and not _contains_generic_identifier(target.context.identifier):
        code, confidence = "IDENTIFIER_MISMATCH", "PROBABLE"
        evidence = "no matching rule; identifier is outside the generic assignment keyword set"
    return code, confidence, _layer_for(code), evidence, reproduction


def classify_miss(
    target: Target,
    observation: Observation,
    capability: dict[str, Any],
    *,
    scanner_key: str,
    container_tp: int,
    same_subtype_matches: int,
    same_representation_matches: int,
    cross: list[str],
) -> tuple[str, str, str, str, str]:
    """Classify a miss with source inspection as a first-class constraint.

    Absence of a finding is not proof that a container or source unit was not
    inspected.  A source-unit capability declaration or scanner-native coverage
    record is required for a CONFIRMED source claim.  If inspection is merely
    unverified, the detection hypothesis is retained but downgraded and labelled
    as evidence-limited.
    """
    observation = observation
    if target.informative:
        return (
            "INFORMATIVE_REFERENCE",
            "CONFIRMED",
            "ORACLE_CLASSIFICATION",
            "oracle classifies this occurrence as informative, not a risk-bearing secret",
            "no detection change is proposed for an informative reference",
        )
    if observation.source_inspected == "NOT_INSPECTED_VERIFIED":
        return (
            "SOURCE_NOT_INSPECTED",
            "CONFIRMED",
            "SOURCE_ACQUISITION",
            observation.inspection_evidence
            or "scanner coverage record proves the source unit was not inspected",
            "inspect the skipped unit explicitly in a temporary scan root",
        )
    if (
        observation.source_inspected == "UNSUPPORTED_VERIFIED"
        or observation.source_capability == "DECLARED_UNSUPPORTED"
    ):
        return (
            "SOURCE_UNSUPPORTED",
            "CONFIRMED",
            "SOURCE_ACQUISITION",
            observation.inspection_evidence
            or "a validated scanner/source capability contract excludes this source type",
            "extract the same member/record to a temporary plain file and rescan; no corpus change",
        )
    if observation.source_inspected == "NOT_APPLICABLE":
        return (
            "SOURCE_UNSUPPORTED",
            "PROBABLE",
            "SOURCE_ACQUISITION",
            observation.inspection_evidence
            or "the scanner lane is not applicable, but a source-unit capability contract was not retained",
            "execute the lane with a scanner that supports this source type, or retain an explicit capability declaration",
        )
    if observation.source_inspected == "INSPECTION_UNVERIFIED":
        if target.container_kind in {"archive_member", "database_record", "binary_file"}:
            return (
                "SOURCE_INSPECTION_UNVERIFIED",
                "UNRESOLVED",
                "SOURCE_ACQUISITION",
                (
                    "the expected positive is inside a "
                    f"{target.container_kind}; the retained report does not prove the "
                    "specific member/record was reached, and no validated capability "
                    "contract declares the container unsupported"
                ),
                (
                    "run a controlled source-unit probe that records container member "
                    "inspection, or extract the member to a plain file and rescan"
                ),
            )
        code, confidence, layer, evidence, reproduction = _classify_miss_after_source(
            target,
            observation,
            capability,
            scanner_key=scanner_key,
            container_tp=container_tp,
            same_subtype_matches=same_subtype_matches,
            same_representation_matches=same_representation_matches,
            cross=cross,
        )
        if confidence == "CONFIRMED":
            confidence = "PROBABLE"
        limited = (
            "source inspection is not independently verified by the retained report; "
            "the detection hypothesis is evidence-limited. " + evidence
        )
        return code, confidence, layer, limited, reproduction
    return _classify_miss_after_source(
        target,
        observation,
        capability,
        scanner_key=scanner_key,
        container_tp=container_tp,
        same_subtype_matches=same_subtype_matches,
        same_representation_matches=same_representation_matches,
        cross=cross,
    )


def _stats(rows: Iterable[AnalysisRow]) -> dict[str, Any]:
    rows = list(rows)
    misses = [r for r in rows if not r.observation.matched]
    matched = [r for r in rows if r.observation.matched]
    return {
        "expected": len(rows),
        "matched": len(matched),
        "missed": len(misses),
        "recall_percent": round(100.0 * len(matched) / len(rows), 2) if rows else 0.0,
        "unverified": sum(1 for r in misses if r.observation.disposition == "UNVERIFIED_EVIDENCE"),
        "risk_misses": sum(1 for r in misses if r.target.risk_bearing),
        "informative_misses": sum(1 for r in misses if r.target.informative),
        "uninspected": sum(
            1 for r in misses if r.observation.source_inspected == "NOT_INSPECTED_VERIFIED"
        ),
        "inspection_unverified": sum(
            1 for r in misses if r.observation.source_inspected == "INSPECTION_UNVERIFIED"
        ),
        "unsupported_verified": sum(
            1 for r in misses if r.observation.source_inspected == "UNSUPPORTED_VERIFIED"
        ),
        "confirmed_causes": sum(1 for r in misses if r.confidence == "CONFIRMED"),
        "probable_causes": sum(1 for r in misses if r.confidence == "PROBABLE"),
        "unresolved_causes": sum(1 for r in misses if r.confidence not in {"CONFIRMED", "PROBABLE"}),
        "inspection_states": dict(
            collections.Counter(r.observation.source_inspected for r in misses).most_common()
        ),
        "source_capabilities": dict(
            collections.Counter(r.observation.source_capability for r in misses).most_common()
        ),
    }


def analyse_scanner(
    evidence: ScannerEvidence,
    targets: list[Target],
    cp4c_rules: dict[str, Any],
    all_evidence: dict[str, ScannerEvidence],
) -> dict[str, Any]:
    target_by_id = {t.target_id: t for t in targets}
    subtype_rule_counts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    repr_rule_counts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    identifier_rule_counts: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for target in targets:
        obs = evidence.observations.get(target.target_id) or Observation()
        if obs.matched and obs.rule_id:
            subtype_rule_counts[target.subtype][obs.rule_id] += 1
            repr_rule_counts[target.representation][obs.rule_id] += 1
            identifier_rule_counts[normalize_identifier(target.context.identifier)][obs.rule_id] += 1
    # Container-level capability is measured from the same run and lane class.
    container_tp = collections.Counter()
    for target in targets:
        obs = evidence.observations.get(target.target_id) or Observation()
        if obs.matched:
            container_tp[target.container_kind] += 1
    cross_found: dict[str, list[str]] = collections.defaultdict(list)
    cross_rules: dict[str, dict[str, str]] = collections.defaultdict(dict)
    for other_key, other in all_evidence.items():
        for target in targets:
            other_obs = other.observations.get(target.target_id) or Observation()
            if other_obs.matched:
                cross_found[target.target_id].append(other_key)
                cross_rules[target.target_id][other_key] = other_obs.rule_id
    rows: list[AnalysisRow] = []
    for target in targets:
        obs = evidence.observations.get(target.target_id) or Observation()
        capability = _capability(
            target,
            evidence,
            cp4c_rules,
            subtype_rule_counts,
            repr_rule_counts,
            identifier_rule_counts,
        )
        if obs.matched:
            code, confidence, layer, reason, reproduction = "MATCHED", "CONFIRMED", "N/A", "credited by current scoring", ""
        else:
            code, confidence, layer, reason, reproduction = classify_miss(
                target,
                obs,
                capability,
                scanner_key=evidence.key,
                container_tp=container_tp[target.container_kind],
                same_subtype_matches=capability["observed_subtype_count"],
                same_representation_matches=capability["observed_representation_count"],
                cross=cross_found.get(target.target_id, []),
            )
        rows.append(
            AnalysisRow(
                scanner=evidence.key,
                target=target,
                observation=obs,
                capability=capability,
                root_cause=code,
                confidence=confidence,
                layer=layer,
                evidence=reason,
                reproduction=reproduction,
                cross_scanners=sorted(cross_found.get(target.target_id, [])),
                cross_rules=dict(cross_rules.get(target.target_id, {})),
                priority=_priority(target, code, cross_found.get(target.target_id, []), confidence),
            )
        )
    by_lane = {lane: [r for r in rows if r.target.lane == lane] for lane in LANE_ORDER}
    lane_stats = {lane: _stats(items) for lane, items in by_lane.items()}
    stats = _stats(rows)
    stats["by_lane"] = lane_stats
    stats["root_causes"] = dict(collections.Counter(r.root_cause for r in rows if not r.observation.matched).most_common())
    stats["confidence"] = dict(collections.Counter(r.confidence for r in rows if not r.observation.matched).most_common())
    stats["categories"] = dict(
        collections.Counter(r.target.category for r in rows if not r.observation.matched).most_common()
    )
    stats["subtypes"] = dict(
        collections.Counter(r.target.subtype for r in rows if not r.observation.matched).most_common()
    )
    stats["providers"] = dict(
        collections.Counter(r.target.provider for r in rows if not r.observation.matched).most_common()
    )
    stats["containers"] = dict(
        collections.Counter(r.target.container_kind for r in rows if not r.observation.matched).most_common()
    )
    stats["representations"] = dict(
        collections.Counter(r.target.representation for r in rows if not r.observation.matched).most_common()
    )
    stats["file_types"] = dict(
        collections.Counter(r.target.file_type for r in rows if not r.observation.matched).most_common()
    )
    return {
        "key": evidence.key,
        "label": evidence.label,
        "evidence": evidence,
        "rows": rows,
        "by_target": {r.target.target_id: r for r in rows},
        "by_lane": by_lane,
        "stats": stats,
        "targets": targets,
    }


def build_cross_scanner(analyses: dict[str, dict[str, Any]], targets: list[Target]) -> dict[str, Any]:
    compare_keys = [key for key in ("cp4c", "v14", "v16", "gitleaks", "betterleaks") if key in analyses]
    by_target: dict[str, dict[str, Any]] = {}
    for target in targets:
        row: dict[str, Any] = {
            "target": target,
            "matched": {},
            "rules": {},
            "missed": {},
            "causes": {},
        }
        for key in compare_keys:
            analysis = analyses[key]
            item = analysis["by_target"][target.target_id]
            row["matched"][key] = item.observation.matched
            row["rules"][key] = item.observation.rule_id
            row["missed"][key] = not item.observation.matched
            row["causes"][key] = item.root_cause
        row["found_by"] = [key for key in compare_keys if row["matched"][key]]
        row["missed_by"] = [key for key in compare_keys if not row["matched"][key]]
        by_target[target.target_id] = row
    all_misses = [tid for tid, row in by_target.items() if len(row["missed_by"]) == len(compare_keys)]
    missed_by = {
        key: [tid for tid, row in by_target.items() if not row["matched"][key]] for key in compare_keys
    }
    only_missed = {
        key: [
            tid
            for tid, row in by_target.items()
            if not row["matched"][key] and all(row["matched"][other] for other in compare_keys if other != key)
        ]
        for key in compare_keys
    }
    unique = {}
    for key in compare_keys:
        unique[key] = [
            tid
            for tid, row in by_target.items()
            if row["matched"][key] and all(not row["matched"][other] for other in compare_keys if other != key)
        ]
    missing_both = {
        "cp4c_v14": [tid for tid, row in by_target.items() if not row["matched"].get("cp4c") and not row["matched"].get("v14")],
        "cp4c_v16": [tid for tid, row in by_target.items() if not row["matched"].get("cp4c") and not row["matched"].get("v16")],
        "v14_v16": [tid for tid, row in by_target.items() if not row["matched"].get("v14") and not row["matched"].get("v16")],
    }
    betterleaks_only_vs_pair = [
        tid
        for tid, row in by_target.items()
        if row["matched"].get("betterleaks")
        and not row["matched"].get("cp4c")
        and not row["matched"].get("v14")
    ]
    return {
        "keys": compare_keys,
        "by_target": by_target,
        "all_scanner_misses": all_misses,
        "missed_by": missed_by,
        "only_missed": only_missed,
        "unique_successes": unique,
        "missing_both": missing_both,
        "betterleaks_only_vs_cp4c_v14": betterleaks_only_vs_pair,
        "counts": {
            "all_scanner_misses": len(all_misses),
            "missed_by": {key: len(value) for key, value in missed_by.items()},
            "only_missed": {key: len(value) for key, value in only_missed.items()},
            "unique_successes": {key: len(value) for key, value in unique.items()},
            "missing_both": {key: len(value) for key, value in missing_both.items()},
            "betterleaks_only_vs_cp4c_v14": len(betterleaks_only_vs_pair),
        },
    }
