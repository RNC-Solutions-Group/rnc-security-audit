"""Shared data model and text helpers for detection-gap analysis.

The analysis is intentionally independent of scanner execution: it consumes the
retained, current-scoring harness reports and the frozen source oracles.  No
function in this package changes an oracle, a scanner rule set, or a score.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LANE_ORDER = (
    "levain",
    "leaky_filesystem",
    "leaky_git",
    "rnclab_filesystem",
    "rnclab_git",
)

# Source inspection is separate from detection outcome and source capability.
# Only INSPECTED_VERIFIED and UNSUPPORTED_VERIFIED may support a CONFIRMED claim.
INSPECTION_INSPECTED_VERIFIED = "INSPECTED_VERIFIED"
INSPECTION_NOT_INSPECTED_VERIFIED = "NOT_INSPECTED_VERIFIED"
INSPECTION_UNVERIFIED = "INSPECTION_UNVERIFIED"
INSPECTION_UNSUPPORTED_VERIFIED = "UNSUPPORTED_VERIFIED"
INSPECTION_NOT_APPLICABLE = "NOT_APPLICABLE"

INSPECTION_STATES = (
    INSPECTION_INSPECTED_VERIFIED,
    INSPECTION_NOT_INSPECTED_VERIFIED,
    INSPECTION_UNVERIFIED,
    INSPECTION_UNSUPPORTED_VERIFIED,
    INSPECTION_NOT_APPLICABLE,
)

SOURCE_CAPABILITY_SUPPORTED = "CLAIMED_SUPPORTED"
SOURCE_CAPABILITY_UNSUPPORTED = "DECLARED_UNSUPPORTED"
SOURCE_CAPABILITY_UNKNOWN = "NOT_DECLARED"

LANE_TITLES = {
    "levain": "Levain credential corpus",
    "leaky_filesystem": "Leaky Repo filesystem",
    "leaky_git": "Leaky Repo Git history",
    "rnclab_filesystem": "RNC Synthetic Secrets Lab v3 filesystem",
    "rnclab_git": "RNC Synthetic Secrets Lab v3 Git history",
}

LANE_DENOMINATORS = {
    "levain": 85,
    "leaky_filesystem": 175,
    "leaky_git": 65,
    "rnclab_filesystem": 640,
    "rnclab_git": 160,
}

TOTAL_DENOMINATOR = sum(LANE_DENOMINATORS.values())

SCANNER_LABELS = {
    "cp4c": "RNC Scanner CP4C",
    "v14": "RNC-Mod V14",
    "v16": "RNC-Mod V16",
    "gitleaks": "Gitleaks master",
    "betterleaks": "Betterleaks 1.8.1",
}

SCANNER_DIRS = {
    "cp4c": "cp4c",
    "v14": "rnc-mod-v14",
    "v16": "rnc-mod-v16",
}

SCANNER_FILE_STEMS = {
    "cp4c": "cp4c",
    "v14": "v14",
    "v16": "v16",
}

REPORT_GLOBS = {
    "cp4c": "run/reports/all-windows-baselines/rnc-cp4c/*.json",
    "v14": "run/reports/all-windows-baselines/gl-rnc-mod-v14/*.json",
    "v16": "run/reports/all-windows-baselines/gl-rnc-mod-v16/*full*.json",
    "gitleaks": "run/reports/all-windows-baselines/gitleaks-master/*.json",
    "betterleaks": "run/reports/all-windows-baselines/betterleaks-lts/*.json",
}

REPORT_LABEL = {
    "cp4c": "CP4C",
    "v14": "RNC-Mod V14",
    "v16": "RNC-Mod V16",
    "gitleaks": "Gitleaks master",
    "betterleaks": "Betterleaks 1.8.1",
}

# Provider attribution is deliberately conservative.  A provider is only marked
# HIGH when the oracle subtype or a documented token shape establishes it.
PROVIDER_BY_SUBTYPE = {
    "aws_access_key_id": ("Amazon Web Services (AWS)", "HIGH", "IAM access-key identifier"),
    "aws_access_key_id_without_secret": ("Amazon Web Services (AWS)", "HIGH", "IAM access-key identifier"),
    "aws_secret_access_key": ("Amazon Web Services (AWS)", "HIGH", "IAM secret access key"),
    "azure_storage_account_key": ("Microsoft Azure Storage", "HIGH", "storage account key"),
    "github_personal_access_token": ("GitHub", "HIGH", "personal access token"),
    "github_token_lookalike": ("GitHub (lookalike)", "HIGH", "credential-shaped lookalike"),
    "gitlab_personal_access_token": ("GitLab", "HIGH", "personal access token"),
    "npm_access_token": ("npm", "HIGH", "access token"),
    "pypi_api_token": ("PyPI", "HIGH", "API token"),
    "sendgrid_api_key": ("Twilio SendGrid", "HIGH", "API key"),
    "slack_bot_token": ("Slack", "HIGH", "bot token"),
    "stripe_secret_key": ("Stripe", "HIGH", "secret API key"),
    "stripe_webhook_secret": ("Stripe", "HIGH", "webhook signing secret"),
    "twilio_auth_token": ("Twilio", "HIGH", "auth token"),
    "wordpress_salt": ("WordPress", "HIGH", "authentication key or salt"),
    "application_hmac_key": ("Application HMAC", "MEDIUM", "message authentication key"),
    "jwt_signing_key": ("JWT / application", "MEDIUM", "token signing key"),
    "application_signing_key": ("Application signing", "MEDIUM", "application signing key"),
    "generic_api_key": ("Unidentified API provider", "LOW", "generic API key"),
    "database_password": ("Database service", "MEDIUM", "database authentication"),
    "application_password": ("Application service", "LOW", "application authentication"),
    "admin_password": ("Administrative account", "MEDIUM", "privileged authentication"),
    "smtp_password": ("SMTP service", "MEDIUM", "mail submission authentication"),
    "ftp_password": ("FTP/SFTP service", "MEDIUM", "file-transfer authentication"),
    "redis_password": ("Redis", "HIGH", "database authentication"),
    "http_basic_password": ("HTTP Basic authentication", "MEDIUM", "HTTP authentication"),
    "key_passphrase": ("Private-key container", "HIGH", "private-key protection"),
    "pkcs12_passphrase": ("PKCS#12 container", "HIGH", "keystore protection"),
    "totp_seed": ("TOTP / OTP", "HIGH", "one-time-password seed"),
    "rsa_private_key_pkcs1": ("PEM / RSA", "HIGH", "asymmetric private key"),
    "rsa_private_key_pkcs8": ("PEM / RSA", "HIGH", "asymmetric private key"),
    "ec_private_key_sec1": ("PEM / EC", "HIGH", "asymmetric private key"),
    "ed25519_private_key_pkcs8": ("PEM / Ed25519", "HIGH", "asymmetric private key"),
    "openssh_private_key_rsa": ("OpenSSH", "HIGH", "SSH private key"),
    "openssh_private_key_ed25519": ("OpenSSH", "HIGH", "SSH private key"),
    "tls_private_key_pkcs8": ("PKCS#12 / TLS", "HIGH", "TLS private key"),
}

PURPOSE_BY_CATEGORY = {
    "password": "authentication",
    "hmac_secret": "message or token signing",
    "jwt": "token signing",
    "otp_seed": "one-time-password generation",
    "private_key": "asymmetric authentication or signing",
    "provider_token": "provider API authentication",
    "api_key": "API authentication",
}

GENERIC_IDENTIFIER_RE = re.compile(
    r"(?i)(?:^|[^A-Z0-9_])("
    r"[A-Z0-9_.-]{0,64}(?:"
    r"PASSWORD|PASSWD|PWD|"
    r"(?:CLIENT|JWT|SESSION)[_-]?SECRET|"
    r"SECRET[_-]?(?:KEY|TOKEN|VALUE)|"
    r"API[_-]?(?:KEY|TOKEN|SECRET)|"
    r"ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|BEARER[_-]?TOKEN|"
    r"PRIVATE[_-]?KEY|CREDENTIALS?"
    r")(?:(?:[_-](?:VALUE|SECRET|KEY|PROD|DEV|STAGING|TEST|1|2))|(?:[_-]?BASE))?[0-9]{0,2}"
    r")$"
)

TOKEN_PREFIX_CLASSES = (
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("github_classic_pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github_oauth", re.compile(r"gh[our]_[A-Za-z0-9]{20,}")),
    ("gitlab_pat", re.compile(r"glpat-[A-Za-z0-9_-]{15,}")),
    ("stripe_secret", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("stripe_webhook", re.compile(r"whsec_[A-Za-z0-9+/=]{16,}")),
    ("sendgrid", re.compile(r"SG\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}")),
    ("slack", re.compile(r"(?:xox[baprs]|xapp)-[A-Za-z0-9-]{15,}")),
    ("npm", re.compile(r"npm_[A-Za-z0-9]{20,}")),
    ("pypi", re.compile(r"pypi-[A-Za-z0-9_-]{20,}")),
    ("aws_access_key", re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    ("azure_account_key", re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")),
    ("twilio", re.compile(r"SK[0-9a-fA-F]{32}")),
    ("google_api", re.compile(r"AIza[0-9A-Za-z_-]{30,}")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("putty_ppk", re.compile(r"PuTTY-User-Key-File-[23]")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("otpauth", re.compile(r"otpauth://", re.I)),
)

HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_\-]{12,}")
PRIVATE_KEY_MARKER = "PRIVATE KEY-----"

ASSIGNMENT_IDENTIFIER_PATTERNS = (
    re.compile(r"define\s*\(\s*['\"]([^'\"]+)['\"]", re.I),
    re.compile(r"^\s*\{\s*['\"]([^'\"]+)['\"]\s*:", re.I),
    re.compile(r"^\s*[\"']([^\"']+)[\"']\s*:", re.I),
    re.compile(r"^\s*-\s*([A-Za-z0-9_.-]+)\s*:", re.I),
    re.compile(r"^\s*(?:export\s+)?([A-Za-z_][\w.-]*)\s*(?::=|=>|=|:)\s*", re.I),
    re.compile(r"<\s*([A-Za-z0-9_.:-]+)(?:\s|>|=)", re.I),
    re.compile(r"\b(?:SET|set)\s+([A-Za-z_][\w.]*)\s*=", re.I),
    re.compile(r"\b([A-Za-z_][\w.]*)\s*=", re.I),
    re.compile(r"\b([A-Za-z_][\w.-]*)\s*:\s*(?:$|[^\s])", re.I),
)

YAML_BLOCK_RE = re.compile(r"^(\s*)([A-Za-z0-9_.-]+)\s*:\s*(.*)$")
DOTENV_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][\w.-]*)\s*=")
URL_RE = re.compile(r"\b([a-z][a-z0-9+.-]{1,20})://([^\s'\"<>]+)", re.I)
HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)

PRIVATE_PATH_HINTS = (
    "private",
    "id_rsa",
    "id_ed25519",
    "key",
    "pem",
    "ppk",
    "p12",
    "pfx",
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def file_type(path: str | None) -> str:
    if not path:
        return "unknown"
    name = Path(path.replace("\\", "/")).name.lower()
    suffix = Path(name).suffix.lower()
    special = {
        ".env": "env",
        ".netrc": "netrc",
        "_netrc": "netrc",
        ".pgpass": "pgpass",
        ".npmrc": "npmrc",
        ".dockercfg": "docker-config",
        ".git-credentials": "git-credentials",
        ".s3cfg": "s3cfg",
        ".esmtprc": "esmtprc",
        ".ftpconfig": "ftpconfig",
        "wp-config.php": "php",
        "config": "config",
        ".bash_profile": "shell",
        ".bashrc": "shell",
    }
    if name in special:
        return special[name]
    return {
        ".php": "php",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".sh": "shell",
        ".sql": "sql",
        ".sqlite": "sqlite",
        ".sqlite3": "sqlite",
        ".db": "sqlite",
        ".bson": "bson",
        ".ini": "ini",
        ".conf": "config",
        ".config": "config",
        ".tfvars": "terraform",
        ".pem": "pem",
        ".ppk": "ppk",
        ".p12": "pkcs12",
        ".log": "log",
        ".txt": "text",
        ".properties": "properties",
        ".pubxml": "xml",
        ".az": "yaml",
    }.get(suffix, suffix.lstrip(".") or "no-extension")


def normalization_of(value: dict[str, Any]) -> str:
    return str(value.get("normalization") or "unknown")


def representation_of(value: dict[str, Any]) -> str:
    return str(value.get("representation") or "unknown")


def display_length(value: dict[str, Any]) -> int | None:
    length = value.get("length")
    return length if isinstance(length, int) else None


def redact_span(line: str, column: int | None, length: int | None) -> str:
    """Return a structural line with every value-bearing part removed.

    The caller handles private-key blocks separately.  This helper intentionally
    keeps only the identifier and punctuation so a report can show *where* the
    evidence lived without publishing the credential.
    """
    if not line:
        return ""
    text = line.rstrip("\r\n")
    if PRIVATE_KEY_MARKER in text or "PuTTY-User-Key-File" in text:
        return "[PRIVATE-KEY MATERIAL REDACTED]"
    if "otpauth://" in text.lower():
        parsed = re.match(r"(?i)^(.*?otpauth://[^?]*\?[^=]*=)[^&\s]+(.*)$", text)
        if parsed:
            return parsed.group(1) + "[REDACTED]" + parsed.group(2)
    # XML attributes are common in .NET/Java/FileZilla configuration.  Mask the
    # value attribute itself, not everything after the opening tag.
    text = re.sub(
        r'(?i)(\b(?:value|password|passwd|pwd|secret|token|api[_-]?key)\s*=\s*["\'])[^"\']*(["\'])',
        r"\1[REDACTED]\2",
        text,
    )
    # Secret-bearing words that occur mid-line, including log messages such as
    # "smtp login ... password=...".
    text = re.sub(
        r"(?i)(\b(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|authorization)\b\s*[:=]\s*)"
        r"(\"[^\"]*\"|'[^']*'|[^\s,;]+)",
        r"\1[REDACTED]",
        text,
    )
    # netrc-style "password value" and Redis "requirepass value" directives.
    text = re.sub(
        r"(?i)\b(password|passphrase|requirepass)\s+([^\s]+)",
        r"\1 [REDACTED]",
        text,
    )
    # XML/JSON/YAML/assignment: keep everything through the separator, mask the
    # remainder.  This also masks companion values on the same line.
    patterns = (
        re.compile(r"^(\s*define\s*\(\s*['\"][^'\"]+['\"]\s*,\s*).*$", re.I),
        re.compile(r'^(\s*["\'][^"\']+["\']\s*:\s*).*$'),
        re.compile(r"^(\s*-\s*[A-Za-z0-9_.-]+\s*:\s*).*$"),
        re.compile(r"^(\s*(?:export\s+)?\$?[A-Za-z_][\w.$-]*\s*(?::=|=>|=|:)\s*).*$"),
        re.compile(r"^(\s*<[^>]+>\s*).*$", re.I),
    )
    for pattern in patterns:
        match = pattern.match(text)
        if match:
            return match.group(1) + "[REDACTED]"
    # URI userinfo: keep scheme/host shape, mask credentials.
    text = re.sub(
        r"(?i)(\b[a-z][a-z0-9+.-]{1,20}://)([^@\s/]+)@",
        r"\1[REDACTED]@",
        text,
    )
    # Exact-span fallback.  column is 1-based; if it is unavailable, fall back
    # to masking every long high-entropy run.
    if column and length and column > 0:
        start = column - 1
        end = start + max(1, length)
        if start < len(text):
            return text[:start] + "[REDACTED]" + text[end:]
    return HIGH_ENTROPY_RE.sub("[REDACTED]", text)


def extract_identifier(line: str) -> str:
    if not line:
        return ""
    for pattern in ASSIGNMENT_IDENTIFIER_PATTERNS:
        match = pattern.search(line)
        if match:
            value = match.group(1).strip()
            if value and value not in {"http", "https"}:
                return value[:120]
    return ""


def normalize_identifier(identifier: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", identifier).strip("_").upper()


def safe_identifier(value: str) -> str:
    """Avoid promoting an encoded credential value into the identifier column."""
    import base64
    import string

    text = (value or "").strip()
    if not text:
        return ""
    if len(text) > 120:
        return "LONG_IDENTIFIER_REDACTED"
    if token_prefix_class(text) in {"github_pat", "github_classic_pat", "gitlab_pat", "stripe_secret", "sendgrid", "slack", "npm", "pypi", "aws_access_key", "jwt"}:
        return "TOKEN_VALUE_REDACTED"
    if len(text) >= 20 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", text):
        try:
            padded = text + "=" * (-len(text) % 4)
            decoded = base64.b64decode(padded, validate=True)
        except Exception:
            decoded = b""
        if decoded:
            printable = sum(chr(byte) in string.printable for byte in decoded) / len(decoded)
            if printable > 0.85 and (b":" in decoded or b"@" in decoded or printable > 0.95):
                return "ENCODED_VALUE_REDACTED"
    return text[:120]


def identifier_family(identifier: str) -> str:
    upper = normalize_identifier(identifier)
    checks = (
        ("HMAC", ("HMAC",)),
        ("SIGNING", ("SIGNING", "SIGNATURE")),
        ("JWT", ("JWT",)),
        ("SESSION", ("SESSION",)),
        ("WORDPRESS_SALT", ("AUTH_KEY", "SECURE_AUTH", "LOGGED_IN", "NONCE", "SALT", "WP_SALT")),
        ("DATABASE_PASSWORD", ("DB_PASSWORD", "DATABASE_PASSWORD", "MYSQL_PASSWORD", "POSTGRES_PASSWORD", "MONGO_PASSWORD", "REDIS_PASSWORD")),
        ("PRIVATE_KEY_PASSPHRASE", ("PASSPHRASE", "P12_", "ENCKEY")),
        ("API_KEY", ("API_KEY", "APIKEY", "API_TOKEN", "CLIENT_SECRET")),
        ("TOKEN", ("TOKEN",)),
        ("PASSWORD", ("PASSWORD", "PASSWD", "PWD", "PASS")),
        ("ACCESS_KEY", ("ACCESS_KEY", "ROOT_USER")),
    )
    for family, markers in checks:
        if any(marker in upper for marker in markers):
            return family
    return "OTHER"


def token_prefix_class(value: str) -> str:
    for label, pattern in TOKEN_PREFIX_CLASSES:
        if pattern.search(value):
            return label
    return ""


def provider_for(
    subtype: str,
    category: str,
    identifier: str,
    path: str,
    scenario: str,
    value: str,
) -> tuple[str, str, list[str]]:
    provider, confidence, purpose = PROVIDER_BY_SUBTYPE.get(
        subtype,
        (f"Unidentified {category.replace('_', ' ')}", "LOW", PURPOSE_BY_CATEGORY.get(category, "unknown")),
    )
    markers: list[str] = []
    prefix = token_prefix_class(value)
    if prefix:
        markers.append(f"token_format:{prefix}")
        if prefix.startswith("github") and provider == "Unidentified API provider":
            provider, confidence = "GitHub", "HIGH"
        elif prefix.startswith("stripe") and provider == "Unidentified API provider":
            provider, confidence = "Stripe", "HIGH"
        elif prefix == "sendgrid" and provider == "Unidentified API provider":
            provider, confidence = "Twilio SendGrid", "HIGH"
        elif prefix == "slack" and provider == "Unidentified API provider":
            provider, confidence = "Slack", "HIGH"
        elif prefix == "npm" and provider == "Unidentified API provider":
            provider, confidence = "npm", "HIGH"
        elif prefix == "pypi" and provider == "Unidentified API provider":
            provider, confidence = "PyPI", "HIGH"
        elif prefix == "aws_access_key" and provider == "Unidentified API provider":
            provider, confidence = "Amazon Web Services (AWS)", "HIGH"
        elif prefix == "gitlab_pat" and provider == "Unidentified API provider":
            provider, confidence = "GitLab", "HIGH"
        elif prefix == "twilio" and provider == "Unidentified API provider":
            provider, confidence = "Twilio", "HIGH"
        elif prefix == "google_api" and provider == "Unidentified API provider":
            provider, confidence = "Google Cloud", "HIGH"
    upper_identifier = normalize_identifier(identifier)
    for word, hinted in (
        ("MINIO", "MinIO"),
        ("DJANGO", "Django"),
        ("WORDPRESS", "WordPress"),
        ("WP_", "WordPress"),
        ("STRIPE", "Stripe"),
        ("SENDGRID", "Twilio SendGrid"),
        ("GITHUB", "GitHub"),
        ("GITLAB", "GitLab"),
        ("SLACK", "Slack"),
        ("TWILIO", "Twilio"),
        ("AZURE", "Microsoft Azure"),
        ("AWS", "Amazon Web Services (AWS)"),
        ("NPM", "npm"),
        ("PYPI", "PyPI"),
        ("REDIS", "Redis"),
        ("POSTGRES", "PostgreSQL"),
        ("MYSQL", "MySQL"),
        ("MONGO", "MongoDB"),
        ("SMTP", "SMTP"),
        ("FTP", "FTP/SFTP"),
        ("JWT", "JWT / application"),
        ("HMAC", "Application HMAC"),
        ("SIGNING", "Application signing"),
    ):
        if word in upper_identifier:
            markers.append(f"identifier:{hinted}")
            if provider.startswith("Unidentified"):
                provider, confidence = hinted, "MEDIUM"
            break
    lowered_path = path.lower()
    for token, hinted in (
        ("wp-config", "WordPress"),
        ("wordpress", "WordPress"),
        ("docker-compose", "Docker Compose"),
        ("k8s", "Kubernetes"),
        ("kubernetes", "Kubernetes"),
        ("filezilla", "FileZilla"),
        ("jetbrains", "JetBrains"),
        ("putty", "PuTTY"),
        ("alembic", "SQLAlchemy/Alembic"),
        ("terraform", "Terraform"),
        ("github", "GitHub"),
        ("gitlab", "GitLab"),
        ("npm", "npm"),
        (".env", "application environment"),
    ):
        if token in lowered_path:
            markers.append(f"path:{hinted}")
            if provider.startswith("Unidentified") and hinted in {
                "WordPress",
                "FileZilla",
                "JetBrains",
                "PuTTY",
                "SQLAlchemy/Alembic",
                "Terraform",
                "GitHub",
                "GitLab",
                "npm",
            }:
                provider, confidence = hinted, "LOW"
            break
    if scenario:
        markers.append(f"scenario:{scenario}")
    if provider.startswith("Unidentified") and prefix:
        provider, confidence = prefix.replace("_", " ").title(), "MEDIUM"
    if provider.startswith("Unidentified") and not markers:
        markers.append("no_provider_specific_evidence")
    return provider, confidence, markers


def assignment_style(representation: str, path: str) -> str:
    rep = representation.lower()
    mapping = {
        "dotenv_value": "dotenv",
        "env_value": "env",
        "assignment": "env",
        "source_line": "unknown",
        "shell_assignment": "shell",
        "php_define": "php_define",
        "php_string_literal": "php_literal",
        "yaml_value": "yaml",
        "json_string": "json",
        "python_string_literal": "python_literal",
        "ts_string_literal": "typescript_literal",
        "kubernetes_secret_data": "kubernetes_secret_data",
        "compose_environment_value": "compose_environment",
        "docker_secret_file": "docker_secret_file",
        "docker_config_auth": "docker_config_auth",
        "filezilla_base64_password": "xml_base64_attribute",
        "jetbrains_static_key_obfuscated": "xml_obfuscated_value",
        "xml_attribute_value": "xml_attribute",
        "ini_value": "ini",
        "hcl_string": "hcl",
        "terraform": "terraform",
        "redis_url": "uri",
        "database_url": "uri",
        "alembic_url": "uri",
        "mongodb_uri": "uri",
        "sqlserver_connection_string": "connection_string",
        "otpauth_secret": "otpauth_uri",
        "browser_encrypted_value": "json_encrypted_value",
        "base64_value": "base64_value",
        "hash_value": "password_hash",
        "raw_key_file": "raw_key_file",
        "netrc_password": "netrc",
        "pgpass_password": "pgpass",
        "putty_ppk_v2": "ppk_block",
        "pkcs12_der": "binary_container",
        "pem_pkcs1": "pem_block",
        "pem_pkcs8": "pem_block",
        "pem_sec1": "pem_block",
        "openssh_private_key_file": "openssh_block",
        "sqlite_table_cell": "database_cell",
        "bson_string_value": "bson_document",
        "sql_copy_value": "sql_copy",
        "cloud_init_password": "cloud_init_yaml",
        "kubeconfig_token": "kubeconfig",
        "publish_profile_base64": "xml_base64",
        "stackexchange_redis_config": "config_key_value",
        "log_kv_value": "log_kv",
        "log_quoted_value": "log_quoted",
        "log_command_argument": "log_command",
        "compose_command_arg": "compose_command",
    }
    if rep in mapping:
        return mapping[rep]
    suffix = Path(path).suffix.lower()
    return {
        ".env": "dotenv",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".php": "php",
        ".py": "python",
        ".xml": "xml",
        ".ini": "ini",
        ".sql": "sql",
    }.get(suffix, "unknown")


def needs_structured_parse(representation: str, container_kind: str) -> bool:
    if container_kind in {"archive_member", "database_record", "binary_file"}:
        return True
    return representation.lower() in {
        "kubernetes_secret_data",
        "sqlite_table_cell",
        "bson_string_value",
        "docker_config_auth",
        "docker_secret_file",
        "filezilla_base64_password",
        "jetbrains_static_key_obfuscated",
        "publish_profile_base64",
        "pkcs12_der",
        "putty_ppk_v2",
        "sql_copy_value",
        "cloud_init_password",
        "kubeconfig_token",
        "stackexchange_redis_config",
        "otpauth_secret",
    }


def needs_multiline(representation: str) -> bool:
    return representation.lower() in {
        "pem_pkcs1",
        "pem_pkcs8",
        "pem_sec1",
        "pem_private_key",
        "openssh_private_key_file",
        "putty_ppk_v2",
        "pkcs8_encrypted_aes256",
    }


def representation_family(representation: str) -> str:
    rep = representation.lower()
    if "pem" in rep or "putty" in rep or "openssh" in rep or "pkcs12" in rep:
        return "key-container"
    if "base64" in rep or "docker_config_auth" in rep:
        return "base64"
    if "url" in rep or "uri" in rep or "connection_string" in rep:
        return "uri-or-connection-string"
    if "kubernetes" in rep or "sql" in rep or "bson" in rep:
        return "structured-value"
    if "json" in rep or "yaml" in rep or "xml" in rep or "define" in rep:
        return "structured-assignment"
    if "escaped" in rep:
        return "escaped"
    return "plaintext"

@dataclass
class Context:
    identifier: str = ""
    identifier_family: str = "OTHER"
    assignment_style: str = "unknown"
    structured_parent: str = ""
    provider_markers: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    companion_identifiers: list[str] = field(default_factory=list)
    context_redacted: str = ""
    adjacent_redacted: str = ""
    requires_multiline: bool = False
    requires_structured_parse: bool = False
    context_available: bool = False
    context_note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "identifier_family": self.identifier_family,
            "assignment_style": self.assignment_style,
            "structured_parent": self.structured_parent,
            "provider_markers": ";".join(self.provider_markers),
            "domains": ";".join(self.domains),
            "companion_identifiers": ";".join(self.companion_identifiers),
            "context_redacted": self.context_redacted,
            "adjacent_redacted": self.adjacent_redacted,
            "requires_multiline": self.requires_multiline,
            "requires_structured_parse": self.requires_structured_parse,
            "context_available": self.context_available,
            "context_note": self.context_note,
        }


@dataclass
class Target:
    target_id: str
    dataset: str
    lane: str
    category: str
    subtype: str
    provider: str
    provider_confidence: str
    provider_markers: list[str]
    purpose: str
    group_id: str
    occurrence_id: str
    risk_bearing: bool
    informative: bool
    primary_tp: bool
    path: str
    line: int | None
    byte_start: int | None
    byte_end: int | None
    commit: str
    container_kind: str
    container_format: str
    archive_member: str
    archive_depth: int
    database_table: str
    database_column: str
    database_rowid: str
    file_type: str
    representation: str
    normalization: str
    scenario: str
    difficulty: str
    source: dict[str, Any]
    value: dict[str, Any]
    context: Context = field(default_factory=Context)

    @property
    def lane_title(self) -> str:
        return LANE_TITLES[self.lane]

    @property
    def target_class(self) -> str:
        if self.informative:
            return "INFORMATIVE"
        return "RISK_BEARING" if self.risk_bearing else "POSITIVE_NON_RISK"


@dataclass
class Observation:
    matched: bool = False
    disposition: str = "MISSED"
    rule_id: str = ""
    finding_id: str = ""
    capture: str = "NO_OBSERVATION"
    overlap: bool = False
    exception_status: str = ""
    reason: str = ""
    reason_code: str = ""
    stage: str = ""
    duplicate: bool = False
    source_inspected: str = INSPECTION_UNVERIFIED
    source_capability: str = SOURCE_CAPABILITY_UNKNOWN
    inspection_evidence: str = (
        "retained report contains no independent proof that this source unit was inspected"
    )
    score_metric_status: str = "SCORED"

    def as_dict(self) -> dict[str, Any]:
        return {
            "matched": self.matched,
            "disposition": self.disposition,
            "rule_id": self.rule_id,
            "finding_id": self.finding_id,
            "capture": self.capture,
            "overlap": self.overlap,
            "exception_status": self.exception_status,
            "reason": self.reason,
            "reason_code": self.reason_code,
            "stage": self.stage,
            "duplicate": self.duplicate,
            "source_inspected": self.source_inspected,
            "source_capability": self.source_capability,
            "inspection_evidence": self.inspection_evidence,
            "score_metric_status": self.score_metric_status,
        }


@dataclass
class ScannerEvidence:
    key: str
    label: str
    report_path: Path
    report: dict[str, Any]
    observations: dict[str, Observation]
    metadata: dict[str, Any]
    metrics: dict[str, Any]


@dataclass
class AnalysisRow:
    scanner: str
    target: Target
    observation: Observation
    capability: dict[str, Any]
    root_cause: str
    confidence: str
    layer: str
    evidence: str
    reproduction: str
    cross_scanners: list[str]
    cross_rules: dict[str, str]
    priority: str

    @property
    def missed(self) -> bool:
        return not self.observation.matched
