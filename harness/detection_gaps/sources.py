"""Canonical target inventory and retained-report observation extraction."""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import re
import sqlite3
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Iterable

from ..errors import HarnessError
from ..provenance import redact_argv
from ..safe_text import safe_message, safe_path
from ..util import sha256_bytes, slugify
from .inputs import InputSelectionError, ReportSelection, select_report
from .model import (
    Context,
    LANE_DENOMINATORS,
    LANE_ORDER,
    PURPOSE_BY_CATEGORY,
    SCANNER_LABELS,
    Target,
    Observation,
    ScannerEvidence,
    assignment_style,
    extract_identifier,
    file_type,
    identifier_family,
    needs_multiline,
    needs_structured_parse,
    normalization_of,
    provider_for,
    redact_span,
    representation_of,
    safe_identifier,
    token_prefix_class,
)


class DetectionGapError(HarnessError):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def find_report(
    key: str,
    explicit: str | Path | None = None,
    *,
    lock_path: str | Path | None = None,
    root: Path | None = None,
) -> Path:
    """Select a retained report deterministically.

    The default path is the pinned analysis input lock.  Modification time is
    deliberately never consulted.  An explicit path remains supported for
    investigation and is recorded as an override by the CLI.
    """
    try:
        return select_report(
            key,
            explicit=explicit,
            lock_path=lock_path,
            root=root,
        ).path
    except InputSelectionError as exc:
        raise DetectionGapError(str(exc)) from exc


def load_json(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DetectionGapError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise DetectionGapError(f"{path} is not a JSON object")
    return document


def _read_line(text: str, line: int | None) -> str:
    if not line or line < 1:
        return ""
    lines = text.splitlines()
    return lines[line - 1] if line <= len(lines) else ""


def _line_of_offset(text: str, offset: int | None) -> int | None:
    if offset is None or offset < 0:
        return None
    return text.count("\n", 0, offset) + 1


def _find_line_for_value(text: str, value: str, cursor: int = 0) -> tuple[int | None, int]:
    index = text.find(value, cursor)
    if index < 0:
        return None, cursor
    return text.count("\n", 0, index) + 1, index + len(value)


def _oracle_path(value: dict[str, Any]) -> str:
    container = value.get("container") or {}
    source = value.get("source") or {}
    return str(container.get("path") or source.get("path") or "")


def _container_kind(value: dict[str, Any]) -> str:
    kind = str((value.get("container") or {}).get("kind") or "file")
    return {
        "file": "ordinary_file",
        "git": "git_blob",
        "archive": "archive_member",
        "database": "database_record",
        "binary_file": "binary_file",
    }.get(kind, kind)


def _category_for_levain(kind: str) -> str:
    lower = kind.lower()
    if "private_key" in lower or "seed_phrase" in lower or "wallet" in lower:
        return "private_key"
    if "password" in lower or "passwd" in lower or "http_basic" in lower:
        return "password"
    if "hmac" in lower or "signing" in lower:
        return "hmac_secret"
    if "otp" in lower or "totp" in lower:
        return "otp_seed"
    if "payment_card" in lower:
        return "payment_data"
    if "api_key" in lower or "token" in lower or "pat" in lower or "webhook" in lower:
        return "provider_token"
    if "aws_access" in lower or "access_key_id" in lower:
        return "api_key"
    if "aws_secret" in lower:
        return "provider_token"
    return "unknown_credential"


def _subtype_for_levain(kind: str) -> str:
    return {
        "aws_access_key_id": "aws_access_key_id",
        "aws_secret_access_key": "aws_secret_access_key",
        "github_pat_classic": "github_personal_access_token",
        "github_pat_fine_grained": "github_personal_access_token",
        "github_oauth_token": "github_personal_access_token",
        "slack_bot_token": "slack_bot_token",
        "slack_app_level_token": "slack_bot_token",
        "stripe_secret_key": "stripe_secret_key",
        "sendgrid_api_key": "sendgrid_api_key",
        "npm_token": "npm_access_token",
        "private_key_pem": "rsa_private_key_pkcs1",
        "private_key_escaped_json": "rsa_private_key_pkcs1",
        "pgp_private_key_block": "rsa_private_key_pkcs1",
        "wallet_seed_phrase": "wallet_seed_phrase",
        "url_password": "url_password",
        "generic_assignment": "application_secret",
        "http_basic_auth": "http_basic_password",
        "jwt": "jwt",
        "bearer_token": "bearer_token",
        "payment_card": "payment_card",
        "shapeless_password": "application_password",
        "wrapped_token": "application_signing_key",
        "capability_url_segment": "url_password",
        "custom_internal_format": "application_secret",
    }.get(kind, kind)


def _provider_for_levain(kind: str, identifier: str = "") -> tuple[str, str]:
    provider, confidence, _purpose = provider_for(
        _subtype_for_levain(kind), _category_for_levain(kind), identifier, "", "", ""
    )
    return provider, confidence


def _infer_credential(line: str, path: str, *, category_hint: str = "") -> tuple[str, str]:
    """Infer a coarse credential family and subtype from source context.

    This is not an oracle substitution.  Leaky Repo and Levain expose a provider
    or a section/kind label rather than the Lab's fine-grained subtype taxonomy.
    The inferred value is clearly labelled as inferred in generated reports.
    """
    lower = line.lower()
    lower_path = path.lower()
    ident = extract_identifier(line)
    upper = re.sub(r"[^A-Z0-9]+", "_", ident.upper()).strip("_")
    if lower_path.endswith("logins.json") and upper in {"ENCRYPTEDUSERNAME", "ENCRYPTEDPASSWORD"}:
        return "password", "browser_saved_credential"
    if lower_path.endswith(".npmrc") and upper in {"_AUTH", "AUTH", "_AUTHTOKEN"}:
        return "password", "base64_basic_credential"
    if lower_path.endswith(".netrc"):
        return "password", "netrc_credential"
    if lower_path.endswith(".pgpass"):
        return "password", "database_password"
    if lower_path.endswith(".git-credentials"):
        return "password", "url_password"
    if lower_path.endswith(".s3cfg"):
        return "provider_token", "aws_secret_access_key"
    if lower_path.endswith(".sql") and not ident:
        return "password", "database_password"
    if lower_path.endswith((".htpasswd", "shadow")):
        return "password", "password_hash"
    if lower_path.endswith("master.key"):
        return "hmac_secret", "application_secret"
    if "begin" in lower and "private key" in lower:
        return "private_key", "pem_private_key"
    if "putty-user-key-file" in lower:
        return "private_key", "putty_ppk_private_key"
    if "AUTH_KEY" in upper or "SECURE_AUTH" in upper or "LOGGED_IN" in upper or "NONCE_" in upper or upper.endswith("_SALT"):
        return "password", "wordpress_salt"
    if "HMAC" in upper:
        return "hmac_secret", "application_hmac_key"
    if "SIGNING_KEY" in upper or "SIGNING" in upper:
        return "hmac_secret", "application_signing_key"
    if "PASSPHRASE" in upper or "passphrase" in lower_path:
        return "password", "key_passphrase"
    if "AWS_SECRET" in upper or "SECRET_ACCESS_KEY" in upper:
        return "provider_token", "aws_secret_access_key"
    if "ACCESS_KEY" in upper or re.search(r"\bAKIA[A-Z0-9]{16}\b", line):
        return "api_key", "aws_access_key_id"
    if "sendgrid" in lower or re.search(r"\bSG\.[A-Za-z0-9_-]{10,}\.", line):
        return "provider_token", "sendgrid_api_key"
    if "stripe" in lower or re.search(r"\b(?:sk|rk)_(?:live|test)_", line):
        return "provider_token", "stripe_secret_key"
    if "github" in lower or re.search(r"\bgh[pousr]_[A-Za-z0-9]{20,}", line):
        return "provider_token", "github_personal_access_token"
    if "gitlab" in lower or "glpat-" in line:
        return "provider_token", "gitlab_personal_access_token"
    if "slack" in lower or re.search(r"\bxox[baprs]-", line):
        return "provider_token", "slack_bot_token"
    if "npm" in lower or "npm_" in line:
        return "provider_token", "npm_access_token"
    if "twilio" in lower or re.search(r"\bSK[0-9a-f]{32}\b", line):
        return "provider_token", "twilio_auth_token"
    if "azure" in lower or "accountkey" in lower:
        return "api_key", "azure_storage_account_key"
    if "private_key" in lower or lower_path.endswith((".pem", ".ppk", ".p12")):
        return "private_key", "pem_private_key"
    if "database_password" in category_hint or "DB_PASSWORD" in upper or "DATABASE_PASSWORD" in upper:
        return "password", "database_password"
    if "postgres" in lower or "mysql" in lower or "mariadb" in lower:
        return "password", "database_password"
    if "mongo" in lower:
        return "password", "database_password"
    if "redis" in lower and ("password" in lower or "requirepass" in lower):
        return "password", "redis_password"
    if "smtp" in lower or ".esmtprc" in lower_path:
        return "password", "smtp_password"
    if "ftp" in lower or "filezilla" in lower_path or ".ftpconfig" in lower_path:
        return "password", "ftp_password"
    if "docker" in lower_path and ("auth" in lower or "password" in lower):
        return "password", "docker_registry_password"
    if "PASSWORD" in upper or "PASSWD" in upper or "PWD" in upper or "password" in lower:
        return "password", "application_password"
    if "SECRET" in upper or "secret" in lower:
        return "hmac_secret", "application_secret"
    if "TOKEN" in upper or "API_KEY" in upper or "APIKEY" in upper:
        return "provider_token", "generic_token"
    if "://" in line and "@" in line:
        return "password", "url_password"
    if category_hint:
        mapped = category_hint.lower()
        if "password" in mapped:
            return "password", "application_password"
        if "aws" in mapped:
            return "provider_token", "aws_secret_access_key"
        if "wordpress" in mapped:
            return "password", "wordpress_salt"
        if "private" in mapped:
            return "private_key", "pem_private_key"
        if "docker" in mapped:
            return "password", "docker_registry_password"
        if "npm" in mapped:
            return "provider_token", "npm_access_token"
        if "smtp" in mapped:
            return "password", "smtp_password"
        if "ftp" in mapped:
            return "password", "ftp_password"
        if "environment" in mapped or "application" in mapped:
            return "password", "application_password"
    return "unknown_credential", "unspecified_credential"


def _representation_from_line(line: str, path: str) -> str:
    stripped = line.lstrip()
    if "BEGIN" in line and "PRIVATE KEY" in line:
        return "pem_block"
    if "PuTTY-User-Key-File" in line:
        return "putty_ppk_v2"
    if path.lower().endswith("logins.json") and re.search(r'"(?:encryptedUsername|encryptedPassword)"\s*:', line, re.I):
        return "browser_encrypted_value"
    if path.lower().endswith(".npmrc") and re.search(r"(?i)^\s*_?auth(?:token)?\s*=", line):
        return "base64_value"
    if path.lower().endswith(".netrc"):
        return "netrc_password"
    if path.lower().endswith(".pgpass"):
        return "pgpass_password"
    if path.lower().endswith(".git-credentials"):
        return "uri_userinfo"
    if path.lower().endswith(".s3cfg"):
        return "ini_value"
    if path.lower().endswith(".sql"):
        return "sql_copy_value"
    if path.lower().endswith((".htpasswd", "shadow")):
        return "hash_value"
    if path.lower().endswith("master.key"):
        return "raw_key_file"
    if "otpauth://" in line.lower():
        return "otpauth_secret"
    if "://" in line and "@" in line:
        return "uri_userinfo"
    if stripped.startswith(("define(", "define (")):
        return "php_define"
    if re.match(r"^\s*<", stripped):
        return "xml_element_or_attribute"
    if stripped.startswith("{"):
        return "json_string"
    if re.match(r"^\s*-\s+[A-Za-z0-9_.-]+\s*:", stripped):
        return "yaml_value"
    if re.match(r"^\s*[\"'][^\"']+[\"']\s*:", stripped):
        return "json_string"
    if "=" in line:
        if Path(path).suffix.lower() in {".yml", ".yaml"}:
            return "yaml_value"
        return "assignment"
    if ":" in line and Path(path).suffix.lower() in {".yml", ".yaml"}:
        return "yaml_value"
    return "source_line"


def _structured_parent_for(style: str, identifier: str, target_path: str) -> str:
    if style == "php_define":
        return "php.define"
    if style == "php_literal":
        return "php.variable"
    if style == "json":
        return f"json.{identifier or 'value'}"
    if style == "yaml":
        return f"yaml.{identifier or 'value'}"
    if style == "kubernetes_secret_data":
        return f"Secret.data.{identifier or 'value'}"
    if style == "xml_attribute":
        return f"xml.attribute.{identifier or 'value'}"
    if style == "database_cell":
        return f"database.{Path(target_path).stem}.{identifier or 'column'}"
    if style == "dotenv":
        return f"environment.{identifier or 'variable'}"
    return identifier or ""


def _domains(line: str) -> list[str]:
    domains: list[str] = []
    for match in re.finditer(r"(?i)\bhttps?://([^/\s:'\"<>]+)", line):
        host = match.group(1).lower()
        if "@" not in host and host not in {"localhost", "127.0.0.1"}:
            domains.append(host)
    for match in re.finditer(r"(?i)\b(?:host|server|endpoint)\s*[:=]\s*['\"]?([a-z0-9.-]+\.[a-z]{2,})", line):
        domains.append(match.group(1).lower())
    return sorted(set(domains))[:5]


def _companion_identifiers(lines: list[str], index: int) -> list[str]:
    keys: list[str] = []
    for offset in (-2, -1, 1, 2):
        pos = index + offset
        if 0 <= pos < len(lines):
            ident = safe_identifier(extract_identifier(lines[pos]))
            if ident and ident not in keys:
                keys.append(ident)
    return keys[:4]


class SourceResolver:
    def __init__(
        self,
        *,
        rnclab_root: Path,
        leaky_root: Path,
        levain_root: Path,
    ) -> None:
        self.rnclab_root = rnclab_root
        self.leaky_root = leaky_root
        self.levain_root = levain_root
        self._text_cache: dict[str, str] = {}
        self._git_cache: dict[tuple[str, str, str], str] = {}
        self._levain_sections: dict[str, str] | None = None

    def _git_text(self, root: Path, commit: str, path: str) -> str:
        key = (str(root), commit, path)
        if key in self._git_cache:
            return self._git_cache[key]
        import subprocess

        try:
            proc = subprocess.run(
                ["git", "-C", str(root), "show", f"{commit}:{path}"],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
            )
        except OSError:
            text = ""
        else:
            text = proc.stdout if proc.returncode == 0 else ""
        self._git_cache[key] = text
        return text

    def _read(self, path: Path) -> str:
        key = str(path)
        if key not in self._text_cache:
            try:
                self._text_cache[key] = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                self._text_cache[key] = ""
        return self._text_cache[key]

    def _levain_section_texts(self) -> dict[str, str]:
        if self._levain_sections is not None:
            return self._levain_sections
        # The section name is carried in target.source; populate lazily from the
        # decoded answer key elsewhere.  This fallback is empty if not prepared.
        self._levain_sections = getattr(self, "_prepared_levain_sections", {})
        return self._levain_sections

    def prepare_levain(self, sections: dict[str, str]) -> None:
        self._prepared_levain_sections = sections
        self._levain_sections = sections

    def _extract_archive_member(self, target: Target) -> str:
        outer = self.rnclab_root / "corpus" / "filesystem" / target.path
        if not outer.is_file():
            return ""
        try:
            data = outer.read_bytes()
        except OSError:
            return ""
        member = target.archive_member
        if not member:
            return ""
        segments = [part for part in member.split("!/") if part]
        current = data
        current_name = outer.name
        for index, segment in enumerate(segments):
            try:
                current = self._member_bytes(current_name, current, segment)
            except Exception:
                return ""
            current_name = segment
        return current.decode("utf-8", errors="replace")

    @staticmethod
    def _member_bytes(name: str, data: bytes, member: str) -> bytes:
        lower = name.lower()
        if lower.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                return archive.read(member)
        if lower.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar")):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                handle = archive.extractfile(member)
                if handle is None:
                    raise KeyError(member)
                return handle.read()
        if lower.endswith(".gz"):
            return gzip.decompress(data)
        raise ValueError(f"unsupported archive {name}")

    def _sqlite_value(self, target: Target) -> str:
        path = self.rnclab_root / "corpus" / "filesystem" / target.path
        if not path.is_file() or not target.database_table or not target.database_column:
            return ""
        connection = None
        try:
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            query = (
                f'SELECT "{target.database_column}" FROM "{target.database_table}" '
                f"WHERE rowid = ?"
            )
            row = connection.execute(query, (int(target.database_rowid or 1),)).fetchone()
        except (sqlite3.Error, ValueError, TypeError):
            return ""
        finally:
            if connection is not None:
                connection.close()
        if not row or row[0] is None:
            return ""
        value = row[0]
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)

    @staticmethod
    def _bson_strings(data: bytes) -> dict[str, str]:
        result: dict[str, str] = {}

        def parse_document(blob: bytes, prefix: str = "") -> None:
            if len(blob) < 5:
                return
            total = struct.unpack_from("<i", blob, 0)[0]
            if total < 5 or total > len(blob):
                return
            offset = 4
            while offset < total - 1:
                kind = blob[offset]
                offset += 1
                end = blob.find(b"\x00", offset)
                if end < 0:
                    return
                key = blob[offset:end].decode("utf-8", "replace")
                offset = end + 1
                if kind == 0x02:
                    if offset + 4 > total:
                        return
                    size = struct.unpack_from("<i", blob, offset)[0]
                    offset += 4
                    if size < 1 or offset + size > total:
                        return
                    result[f"{prefix}{key}"] = blob[offset : offset + size - 1].decode("utf-8", "replace")
                    offset += size
                elif kind in (0x10, 0x12, 0x01, 0x09, 0x0A):
                    offset += {0x10: 4, 0x12: 8, 0x01: 8, 0x09: 8, 0x0A: 0}[kind]
                elif kind in (0x03, 0x04):
                    if offset + 4 > total:
                        return
                    size = struct.unpack_from("<i", blob, offset)[0]
                    if size < 5 or offset + size > total:
                        return
                    parse_document(blob[offset : offset + size], prefix + key + ".")
                    offset += size
                elif kind == 0x07:
                    offset += 12
                elif kind == 0x08:
                    offset += 1
                elif kind == 0x05:
                    if offset + 5 > total:
                        return
                    size = struct.unpack_from("<i", blob, offset)[0]
                    offset += 5 + size
                else:
                    return

        try:
            parse_document(data)
        except (struct.error, ValueError):
            return {}
        return result

    def _bson_value(self, target: Target) -> str:
        path = self.rnclab_root / "corpus" / "filesystem" / target.path
        if not path.is_file():
            return ""
        try:
            data = path.read_bytes()
        except OSError:
            return ""
        values = self._bson_strings(data)
        key = target.database_column
        for name, value in values.items():
            if name == key or name.endswith("." + key):
                return value
        return ""

    def line_for(self, target: Target) -> tuple[str, str]:
        """Return (line, note) without exposing the credential in logs."""
        if target.dataset == "Levain":
            section = str(target.source.get("section_name") or "")
            text = self._levain_section_texts().get(section, "")
            return _read_line(text, target.line), "decoded Levain section"
        if target.dataset.startswith("RNC Synthetic"):
            if target.container_kind == "git_blob":
                text = self._git_text(self.rnclab_root / "corpus" / "history", target.commit, target.path)
                return _read_line(text, target.line), "git show commit:path"
            if target.container_kind == "archive_member":
                text = self._extract_archive_member(target)
                return _read_line(text, target.line), "archive member extracted in memory"
            if target.container_kind == "database_record":
                if target.container_format == "sqlite":
                    return self._sqlite_value(target), "SQLite cell read read-only"
                if target.container_format == "bson":
                    return self._bson_value(target), "BSON string field parsed"
                return "", "database value unavailable"
            if target.container_kind == "binary_file":
                return "", "binary PKCS#12 container; no line representation"
            text = self._read(self.rnclab_root / "corpus" / "filesystem" / target.path)
            return _read_line(text, target.line), "filesystem read"
        if target.dataset.startswith("Leaky Repo"):
            if target.container_kind == "git_blob":
                text = self._git_text(self.leaky_root, target.commit, target.path)
                return _read_line(text, target.line), "git show commit:path"
            text = self._read(self.leaky_root / target.path)
            return _read_line(text, target.line), "filesystem read"
        return "", "unknown dataset source"

    def raw_text_for(self, target: Target) -> str:
        if target.dataset == "Levain":
            return self._levain_section_texts().get(str(target.source.get("section_name") or ""), "")
        if target.dataset.startswith("RNC Synthetic"):
            if target.container_kind == "git_blob":
                return self._git_text(self.rnclab_root / "corpus" / "history", target.commit, target.path)
            if target.container_kind == "archive_member":
                return self._extract_archive_member(target)
            if target.container_kind == "ordinary_file":
                return self._read(self.rnclab_root / "corpus" / "filesystem" / target.path)
            return ""
        if target.dataset.startswith("Leaky Repo"):
            if target.container_kind == "git_blob":
                return self._git_text(self.leaky_root, target.commit, target.path)
            return self._read(self.leaky_root / target.path)
        return ""

    def context_for(self, target: Target) -> Context:
        raw_lines: list[str] = []
        line, note = self.line_for(target)
        if target.container_kind == "database_record":
            raw_text = ""
        else:
            raw_text = self.raw_text_for(target)
            raw_lines = raw_text.splitlines()
        index = max(0, (target.line or 1) - 1)
        if not line and raw_lines:
            line = raw_lines[index] if index < len(raw_lines) else ""
        if target.container_kind == "database_record":
            identifier = target.database_column
            style = "database_cell"
        else:
            identifier = extract_identifier(line)
            style = "unknown"
            if line:
                inferred = _representation_from_line(line, target.path)
                style = assignment_style(inferred, target.path)
                if style == "unknown" and "=" in line:
                    style = "dotenv" if target.path.endswith((".env", ".log", ".txt")) else "env"
            if style == "unknown":
                style = assignment_style(target.representation, target.path)
            if style == "env" and target.path.endswith(".env"):
                style = "dotenv"
        if target.path.endswith(".pgpass"):
            identifier = "pgpass_password_field"
        elif target.path.endswith(".netrc"):
            identifier = "netrc_password"
        elif target.path.endswith(".git-credentials"):
            identifier = "git_credentials_url"
        elif target.path.endswith(".npmrc") and target.context.identifier_family == "OTHER":
            identifier = "_authToken"
        elif target.path.endswith(".s3cfg"):
            identifier = "aws_secret_key"
        elif not identifier:
            if target.representation == "pem_block" or target.category == "private_key":
                identifier = "PRIVATE_KEY_BLOCK"
            elif target.representation in {"putty_ppk_v2", "pkcs12_der"}:
                identifier = "PRIVATE_KEY_CONTAINER"
            elif "docker" in target.path.lower():
                identifier = "docker_auth"
            else:
                identifier = "NO_ASSIGNMENT_IDENTIFIER"
        identifier = safe_identifier(identifier)
        structured_parent = _structured_parent_for(style, identifier, target.path)
        if target.container_kind == "database_record":
            structured_parent = f"{target.database_table}.{target.database_column}"
        elif target.container_kind == "archive_member":
            structured_parent = f"archive:{target.archive_member}" + (f"|{structured_parent}" if structured_parent else "")
        if target.container_kind == "git_blob":
            structured_parent = f"git:{target.path}" + (f"|{structured_parent}" if structured_parent else "")
        # The exact column is not required: redact_span keeps only the
        # identifier and punctuation for assignment-shaped sources.  For
        # binary/structured containers no source line is emitted at all.
        if target.representation in {"pem_pkcs1", "pem_pkcs8", "pem_sec1", "openssh_private_key_file"}:
            redacted = "[PRIVATE-KEY BLOCK REDACTED]"
        elif target.representation == "pkcs12_der":
            redacted = "[PKCS#12 CONTAINER REDACTED]"
        elif target.representation == "putty_ppk_v2":
            redacted = "[PUTTY PPK BLOCK REDACTED]"
        elif target.container_kind == "database_record":
            redacted = f"[{target.database_column or 'DATABASE CELL'} VALUE REDACTED]"
        elif target.container_kind == "binary_file":
            redacted = "[BINARY CONTAINER REDACTED]"
        elif target.representation in {
            "hash_value",
            "sql_copy_value",
            "raw_key_file",
            "docker_secret_file",
            "base64_value",
        } or target.path.endswith((".netrc", ".pgpass", ".htpasswd", "shadow")):
            redacted = f"{identifier}=[REDACTED]" if identifier else "[SOURCE VALUE REDACTED]"
        elif line:
            redacted = redact_span(line, None, None)
        adjacent = ""
        if raw_lines and 0 <= index < len(raw_lines) and target.representation not in {
            "hash_value",
            "sql_copy_value",
            "raw_key_file",
            "docker_secret_file",
            "base64_value",
        }:
            adjacent_lines = []
            for offset in (-1, 1):
                pos = index + offset
                if 0 <= pos < len(raw_lines) and raw_lines[pos].strip():
                    adjacent_lines.append(redact_span(raw_lines[pos], None, None))
            adjacent = " | ".join(adjacent_lines[:2])
        markers = list(target.provider_markers)
        prefix = token_prefix_class(line)
        if prefix:
            markers.append(f"token_format:{prefix}")
        domains = _domains(line)
        companions = _companion_identifiers(raw_lines, index) if raw_lines else []
        if target.container_kind in {"archive_member", "database_record", "binary_file"}:
            context_available = bool(line) or target.container_kind != "binary_file"
            note = note + "; container context is structural"
        else:
            context_available = bool(line)
        context = Context(
            identifier=identifier[:120],
            identifier_family=identifier_family(identifier),
            assignment_style=style,
            structured_parent=structured_parent,
            provider_markers=sorted(dict.fromkeys(markers)),
            domains=domains,
            companion_identifiers=companions,
            context_redacted=redacted,
            adjacent_redacted=adjacent,
            requires_multiline=needs_multiline(target.representation),
            requires_structured_parse=needs_structured_parse(target.representation, target.container_kind),
            context_available=context_available,
            context_note=note,
        )
        # Fill provider fields on the target when a contextual provider is stronger
        # than the oracle-level placeholder.
        if context.provider_markers and target.provider.startswith(
            ("Unidentified", "Application ", "Database service", "JWT / application")
        ):
            for marker in context.provider_markers:
                if marker.startswith("identifier:"):
                    target.provider = marker.split(":", 1)[1]
                    target.provider_confidence = "MEDIUM"
                    break
        return context


def load_rnclab_targets(root: Path) -> tuple[list[Target], dict[str, str]]:
    oracle = root / "oracle" / "oracle.jsonl"
    if not oracle.is_file():
        raise DetectionGapError(f"RNC Lab oracle missing: {oracle}")
    targets: list[Target] = []
    for line in oracle.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        if item.get("classification") != "POSITIVE":
            continue
        container = item.get("container") or {}
        source = item.get("source") or {}
        value = item.get("value") or {}
        kind = _container_kind(item)
        path = str(container.get("path") or source.get("path") or "")
        subtype = str(item.get("subtype") or "")
        category = str(item.get("category") or "")
        identifier = ""
        provider, confidence, markers = provider_for(
            subtype, category, identifier, path, str(item.get("scenario") or ""), str(value.get("display") or "")
        )
        targets.append(
            Target(
                target_id=str(item["item_id"]),
                dataset="RNC Synthetic Secrets Lab v3",
                lane="rnclab_git" if item.get("lane") == "git" else "rnclab_filesystem",
                category=category,
                subtype=subtype,
                provider=provider,
                provider_confidence=confidence,
                provider_markers=markers,
                purpose=PURPOSE_BY_CATEGORY.get(category, "unknown"),
                group_id=str((item.get("expected") or {}).get("group_id") or ""),
                occurrence_id=str(item.get("occurrence_id") or ""),
                risk_bearing=True,
                informative=False,
                primary_tp=bool((item.get("expected") or {}).get("primary_tp", True)),
                path=path,
                line=(item.get("location") or {}).get("line"),
                byte_start=(item.get("location") or {}).get("byte_start"),
                byte_end=(item.get("location") or {}).get("byte_end"),
                commit=str(source.get("commit") or ""),
                container_kind=kind,
                container_format=str(container.get("format") or source.get("format") or ""),
                archive_member=str(container.get("member") or source.get("member") or ""),
                archive_depth=int(container.get("depth") or source.get("depth") or 0),
                database_table=str(container.get("table") or ""),
                database_column=str(container.get("column") or ""),
                database_rowid=str(container.get("rowid") or ""),
                file_type=file_type(path),
                representation=representation_of(value),
                normalization=normalization_of(value),
                scenario=str(item.get("scenario") or ""),
                difficulty=str(item.get("difficulty") or ""),
                source={**source, "oracle_class": "POSITIVE"},
                value=value,
            )
        )
    return targets, {}


def _load_levain_answer_key(root: Path) -> tuple[dict[str, Any], str]:
    candidates = sorted(root.glob("*/source/tp-corpus.json.b64"))
    if not candidates:
        candidates = sorted(root.glob("*/source/tp-corpus.json"))
    if not candidates:
        raise DetectionGapError(f"Levain answer key missing under {root}")
    path = candidates[0]
    if path.suffix == ".b64":
        data = base64.b64decode(path.read_text(encoding="ascii"))
    else:
        data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    return json.loads(data.decode("utf-8")), digest


def load_levain_targets(root: Path) -> tuple[list[Target], dict[str, str], str]:
    document, digest = _load_levain_answer_key(root)
    targets: list[Target] = []
    sections: dict[str, str] = {}
    for s_index, section in enumerate(document.get("sections") or [], 1):
        name = str(section.get("name") or "")
        text = str(section.get("text") or "")
        sections[name] = text
        filename = f"{s_index:03d}-{slugify(name)}.log"
        cursor = 0
        for k_index, secret in enumerate(section.get("secrets") or [], 1):
            kind = str(secret.get("kind") or "unknown")
            secret_text = str(secret.get("text") or "")
            line, cursor = _find_line_for_value(text, secret_text, cursor)
            target_id = f"LEV-S{s_index:02d}-K{k_index:02d}"
            category = _category_for_levain(kind)
            subtype = _subtype_for_levain(kind)
            identifier = extract_identifier(_read_line(text, line))
            provider, confidence = _provider_for_levain(kind, identifier)
            target = Target(
                target_id=target_id,
                dataset="Levain",
                lane="levain",
                category=category,
                subtype=subtype,
                provider=provider,
                provider_confidence=confidence,
                provider_markers=[f"levain_kind:{kind}"],
                purpose=PURPOSE_BY_CATEGORY.get(category, "unknown"),
                group_id="",
                occurrence_id=target_id,
                risk_bearing=True,
                informative=False,
                primary_tp=not bool(section.get("hard")),
                path=filename,
                line=line,
                byte_start=None,
                byte_end=None,
                commit="",
                container_kind="ordinary_file",
                container_format="",
                archive_member="",
                archive_depth=0,
                database_table="",
                database_column="",
                database_rowid="",
                file_type="log",
                representation="section_text",
                normalization="identity_direct",
                scenario=str(section.get("name") or ""),
                difficulty="hard" if section.get("hard") else "core",
                source={
                    "section_name": name,
                    "section_index": s_index,
                    "secret_index": k_index,
                    "kind": kind,
                    "hard": bool(section.get("hard")),
                    "oracle_class": "EXPECTED_SECRET",
                    "answer_key_sha256": digest,
                },
                value={
                    "identity_sha256": hashlib.sha256(secret_text.encode("utf-8")).hexdigest(),
                    "length": len(secret_text.encode("utf-8")),
                    "representation": "section_text",
                },
            )
            targets.append(target)
    return targets, sections, digest


def load_leaky_fs_targets(truth_path: Path) -> list[Target]:
    document = load_json(truth_path)
    targets: list[Target] = []
    for item in document.get("items") or []:
        if item.get("classification") != "EXPECTED_DETECTION":
            continue
        path = str(item.get("path") or "")
        line_no = item.get("line_start")
        risk = bool(item.get("risk_bearing"))
        target = Target(
            target_id=str(item.get("finding_id")),
            dataset="Leaky Repo",
            lane="leaky_filesystem",
            category="",
            subtype="",
            provider="Unidentified credential",
            provider_confidence="LOW",
            provider_markers=[],
            purpose="unknown",
            group_id="",
            occurrence_id=str(item.get("finding_id")),
            risk_bearing=risk,
            informative=not risk,
            primary_tp=risk,
            path=path,
            line=line_no,
            byte_start=None,
            byte_end=None,
            commit="",
            container_kind="ordinary_file",
            container_format="",
            archive_member="",
            archive_depth=0,
            database_table="",
            database_column="",
            database_rowid="",
            file_type=file_type(path),
            representation="source_line",
            normalization="source_line_truth",
            scenario=str(item.get("source_reference") or ""),
            difficulty="",
            source={
                "oracle_class": "informative" if not risk else "risk",
                "category_conflict": bool(item.get("category_conflict")),
                "fingerprint_sha256": item.get("fingerprint_sha256"),
                "upstream_row": item.get("upstream_row"),
            },
            value={
                "identity_sha256": item.get("fingerprint_sha256"),
                "length": None,
                "representation": "source_line",
            },
        )
        targets.append(target)
    return targets


def load_leaky_history_targets(oracle_path: Path) -> list[Target]:
    document = load_json(oracle_path)
    targets: list[Target] = []
    for item in document.get("items") or []:
        if item.get("disposition") != "POSITIVE":
            continue
        source = item.get("source") or {}
        identity = item.get("identity") or {}
        category = str(item.get("category") or "")
        target = Target(
            target_id=str(item.get("id") or ""),
            dataset="Leaky Repo",
            lane="leaky_git",
            category="",
            subtype="",
            provider="Unidentified credential",
            provider_confidence="LOW",
            provider_markers=[],
            purpose="unknown",
            group_id=str(identity.get("unique_group") or ""),
            occurrence_id=str(item.get("id") or ""),
            risk_bearing=True,
            informative=False,
            primary_tp=True,
            path=str(source.get("path") or ""),
            line=source.get("line_start"),
            byte_start=None,
            byte_end=None,
            commit=str(source.get("introduced_at") or ""),
            container_kind="git_blob",
            container_format="",
            archive_member="",
            archive_depth=0,
            database_table="",
            database_column="",
            database_rowid="",
            file_type=file_type(str(source.get("path") or "")),
            representation="source_line",
            normalization="source_occurrence",
            scenario=str(source.get("evidence_url") or ""),
            difficulty="",
            source={
                "oracle_class": "POSITIVE",
                "oracle_category": category,
                "review": item.get("review") or {},
                "blob": source.get("git_blob_sha"),
                "current_path": source.get("current_path"),
                "current_presence": source.get("current_presence"),
                "secret_sha256": identity.get("secret_sha256"),
            },
            value={
                "identity_sha256": identity.get("secret_sha256"),
                "length": None,
                "representation": "source_line",
            },
        )
        targets.append(target)
    return targets


def enrich_inferred_targets(targets: Iterable[Target], resolver: SourceResolver) -> None:
    """Infer Leaky Repo's coarse family/subtype directly from frozen source."""
    for target in targets:
        if target.dataset != "Leaky Repo":
            continue
        raw = resolver.raw_text_for(target)
        line = _read_line(raw, target.line)
        if not line and target.path.startswith("web/var/www/public_html/wp-config.php"):
            line = raw
        hint = str(target.source.get("oracle_category") or "")
        category, subtype = _infer_credential(line, target.path, category_hint=hint)
        target.category = category
        target.subtype = subtype
        target.representation = _representation_from_line(line, target.path)
        target.provider, target.provider_confidence, markers = provider_for(
            subtype, category, extract_identifier(line), target.path, target.scenario, line
        )
        target.provider_markers = markers
        target.purpose = PURPOSE_BY_CATEGORY.get(category, "unknown")
        target.source["inference"] = "source-context heuristic (not oracle subtype)"
        target.source["line_sha256"] = hashlib.sha256(line.encode("utf-8", "replace")).hexdigest() if line else ""


def load_canonical_targets(
    *,
    rnclab_root: Path,
    leaky_root: Path,
    levain_root: Path,
    leaky_truth: Path,
    leaky_oracle: Path,
    resolver: SourceResolver,
) -> list[Target]:
    rnclab, _ = load_rnclab_targets(rnclab_root)
    leaky_fs = load_leaky_fs_targets(leaky_truth)
    leaky_git = load_leaky_history_targets(leaky_oracle)
    levain, sections, _key_digest = load_levain_targets(levain_root)
    resolver.prepare_levain(sections)
    enrich_inferred_targets(leaky_fs, resolver)
    enrich_inferred_targets(leaky_git, resolver)
    # Context is populated once and reused by every scanner report.
    for target in [*levain, *leaky_fs, *leaky_git, *rnclab]:
        target.context = resolver.context_for(target)
    targets = [*levain, *leaky_fs, *leaky_git, *rnclab]
    validate_target_universe(targets)
    return targets


def validate_target_universe(targets: list[Target]) -> None:
    if len(targets) != sum(LANE_DENOMINATORS.values()):
        raise DetectionGapError(
            f"target universe has {len(targets)} entries, expected {sum(LANE_DENOMINATORS.values())}"
        )
    ids = [t.target_id for t in targets]
    if len(set(ids)) != len(ids):
        duplicates = sorted({value for value in ids if ids.count(value) > 1})
        raise DetectionGapError(f"duplicate canonical target IDs: {duplicates[:5]}")
    for lane, expected in LANE_DENOMINATORS.items():
        actual = sum(1 for t in targets if t.lane == lane)
        if actual != expected:
            raise DetectionGapError(f"lane {lane} has {actual} targets, expected {expected}")


def _mark_targets(
    targets: list[Target],
    observations: dict[str, Observation],
    *,
    matched_ids: Iterable[str],
    findings: dict[str, dict[str, Any]],
    findings_class: dict[str, dict[str, Any]] | None = None,
    duplicate_ids: Iterable[str] = (),
) -> None:
    matched = set(matched_ids)
    for target_id in matched:
        obs = observations.setdefault(target_id, Observation())
        obs.matched = True
        obs.disposition = "CREDITED"
        finding = findings.get(target_id) or {}
        obs.rule_id = str(finding.get("rule_id") or obs.rule_id)
        obs.finding_id = str(finding.get("finding_id") or obs.finding_id)
        obs.capture = "EXACT_OR_NORMALIZED_VALUE"
        obs.reason = str(finding.get("reason") or "credited by the harness")
        obs.reason_code = str(finding.get("reason_code") or "")
        obs.stage = str(finding.get("stage") or "ATTRIBUTION")
        obs.source_inspected = "INSPECTED"
    for target_id in duplicate_ids:
        obs = observations.setdefault(target_id, Observation())
        obs.duplicate = True
    if findings_class:
        for target_id, finding in findings_class.items():
            obs = observations.setdefault(target_id, Observation())
            if finding.get("classification") == "UNVERIFIED_EVIDENCE":
                obs.disposition = "UNVERIFIED_EVIDENCE"
                obs.overlap = True
                obs.capture = "AMBIGUOUS_OR_INCORRECT_VALUE"
                obs.rule_id = str(finding.get("rule_id") or obs.rule_id)
                obs.finding_id = str(finding.get("finding_id") or obs.finding_id)
                obs.reason = str(finding.get("reason") or "")
                obs.reason_code = str(finding.get("reason_code") or "")
                obs.stage = str(finding.get("stage") or "VALUE")
                obs.exception_status = "UNVERIFIED_EVIDENCE"


def _metadata_for_report(
    key: str,
    report: dict[str, Any],
    path: Path,
    selection: ReportSelection | None = None,
) -> dict[str, Any]:
    build = report.get("registered_build") or {}
    summary = report.get("summary") or {}
    profile = report.get("profile") or {}
    scanner = report.get("scanner") or {}
    options = report.get("report_options") or {}
    raw_args = options.get("scanner_extra_args") or []
    redacted_args, _redactions = redact_argv(list(raw_args))
    policy = options.get("argument_policy") or profile.get("argument_policy")
    safe_policy = None
    if isinstance(policy, dict):
        safe_policy = json.loads(json.dumps(policy))
        for argument in safe_policy.get("arguments") or []:
            if not isinstance(argument, dict):
                continue
            for field in ("token", "value"):
                if isinstance(argument.get(field), str):
                    argument[field] = safe_message(argument[field])
    metadata = {
        "key": key,
        "label": SCANNER_LABELS[key],
        "build_id": str(build.get("id") or summary.get("build_id") or ""),
        "version": str(build.get("version") or scanner.get("version") or ""),
        "source_commit": str(build.get("source_commit") or summary.get("source_commit") or ""),
        "executable_sha256": str(build.get("executable_sha256") or ""),
        "rules_file": build.get("rules_file"),
        "rules_sha256": str(build.get("rules_sha256") or ""),
        "report_path": safe_path(path),
        "run_id": str(report.get("run_id") or ""),
        "generated_at": str(report.get("generated_at") or ""),
        "profile": str(profile.get("name") or "default"),
        "overall": str(summary.get("overall") or ""),
        "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "scanner_extra_args": redacted_args,
        "scanner_extra_args_sha256": options.get("scanner_extra_args_sha256")
        or sha256_bytes(json.dumps(raw_args, separators=(",", ":")).encode("utf-8")),
        "scanner_extra_args_redacted": bool(
            options.get("scanner_extra_args_redacted") or _redactions
        ),
        "argument_policy": safe_policy,
        "history_coverage": None,
    }
    if selection is not None:
        metadata["input_selection"] = selection.to_dict()
        metadata["report_sha256"] = selection.sha256
    return metadata


def _match_levain(
    report: dict[str, Any],
    targets: list[Target],
    observations: dict[str, Observation],
) -> int:
    runs = (
        ((report.get("suites") or {}).get("levain") or {})
        .get("details", {})
        .get("lanes", {})
        .get("windows-amd64", {})
        .get("runs", [])
    )
    positive = next((run for run in runs if run.get("corpus") == "positive"), None)
    if not positive:
        return 0
    results = positive.get("results") or {}
    matched = list(results.get("matched_secrets") or [])
    candidates: dict[tuple[str, str], list[Target]] = {}
    for target in targets:
        if target.lane != "levain":
            continue
        key = (str(target.source.get("section_name")), str(target.source.get("kind")))
        candidates.setdefault(key, []).append(target)
    used: set[str] = set()
    for item in matched:
        section = str(item.get("section") or "")
        kind = str(item.get("kind") or "")
        line = item.get("line")
        pool = [t for t in candidates.get((section, kind), []) if t.target_id not in used]
        target = next((t for t in pool if t.line == line), None)
        if target is None and pool:
            target = pool[0]
        if target is None:
            continue
        used.add(target.target_id)
        observations[target.target_id] = Observation(
            matched=True,
            disposition="CREDITED",
            rule_id=str(item.get("rule_id") or ""),
            finding_id="",
            capture=str(item.get("match_type") or "COMPLETE").upper(),
            reason="Levain planted secret matched by extracted value",
            stage="VALUE",
            source_inspected="INSPECTED" if results.get("coverage_verified") else "INSPECTED_UNVERIFIED",
        )
    return int(results.get("true_positives") or 0)


def _match_leaky_fs(
    report: dict[str, Any],
    observations: dict[str, Observation],
) -> int:
    lane = (
        ((report.get("suites") or {}).get("leaky-repo") or {})
        .get("details", {})
        .get("lanes", {})
        .get("windows-amd64", {})
        .get("rich", {})
    )
    evaluations = lane.get("evaluations") or []
    by_id: dict[str, list[dict[str, Any]]] = {}
    for evaluation in evaluations:
        by_id.setdefault(str(evaluation.get("expected_id") or ""), []).append(evaluation)
    credited = 0
    for target_id, items in by_id.items():
        expected = items[0].get("expected") or {}
        if expected.get("classification") != "EXPECTED_DETECTION":
            continue
        matched = next((e for e in items if e.get("classification") == "EXPECTED_DETECTION"), None)
        unverified = next((e for e in items if e.get("classification") == "UNVERIFIED_EVIDENCE"), None)
        if matched:
            observed = matched.get("observed") or {}
            metadata = observed.get("metadata") or {}
            observations[target_id] = Observation(
                matched=True,
                disposition="CREDITED",
                rule_id=str(observed.get("rule_id") or ""),
                finding_id=str(observed.get("finding_id") or ""),
                capture="EXACT_OR_NORMALIZED_VALUE",
                reason=str(matched.get("reason") or "line and value fingerprint matched"),
                stage="ATTRIBUTION",
                source_inspected="INSPECTED",
            )
            credited += 1
        elif unverified:
            observed = unverified.get("observed") or {}
            observations[target_id] = Observation(
                matched=False,
                disposition="UNVERIFIED_EVIDENCE",
                rule_id=str(observed.get("rule_id") or ""),
                finding_id=str(observed.get("finding_id") or ""),
                capture="AMBIGUOUS_OR_INCORRECT_VALUE",
                overlap=True,
                exception_status="UNVERIFIED_EVIDENCE",
                reason=str(unverified.get("reason") or ""),
                stage="VALUE",
                source_inspected="INSPECTED",
            )
    return credited


def _match_leaky_git(
    report: dict[str, Any],
    observations: dict[str, Observation],
) -> tuple[int, dict[str, Any]]:
    lane = (
        ((report.get("suites") or {}).get("leaky-repo") or {})
        .get("details", {})
        .get("history_lanes", {})
        .get("windows-amd64", {})
    )
    history = lane.get("history") or {}
    evaluations = history.get("evaluations") or []
    by_id: dict[str, list[dict[str, Any]]] = {}
    for evaluation in evaluations:
        by_id.setdefault(str(evaluation.get("expected_id") or ""), []).append(evaluation)
    credited = 0
    for target_id, items in by_id.items():
        expected = items[0].get("expected") or {}
        if expected.get("disposition") != "POSITIVE":
            continue
        matched = next((e for e in items if e.get("classification") == "EXPECTED_DETECTION"), None)
        unverified = next((e for e in items if e.get("classification") == "UNVERIFIED_EVIDENCE"), None)
        duplicates = [e for e in items if e.get("classification") == "DUPLICATE"]
        if matched:
            observed = matched.get("observed") or {}
            observations[target_id] = Observation(
                matched=True,
                disposition="CREDITED",
                rule_id=str(observed.get("rule_id") or ""),
                finding_id=str(observed.get("finding_id") or ""),
                capture="EXACT_SOURCE_OCCURRENCE",
                reason=str(matched.get("reason") or "source occurrence matched"),
                stage="ATTRIBUTION",
                duplicate=bool(duplicates),
                source_inspected="INSPECTED",
            )
            credited += 1
        elif unverified:
            observed = unverified.get("observed") or {}
            observations[target_id] = Observation(
                matched=False,
                disposition="UNVERIFIED_EVIDENCE",
                rule_id=str(observed.get("rule_id") or ""),
                finding_id=str(observed.get("finding_id") or ""),
                capture="AMBIGUOUS_OR_INCORRECT_VALUE",
                overlap=True,
                exception_status="UNVERIFIED_EVIDENCE",
                reason=str(unverified.get("reason") or ""),
                stage="VALUE",
                source_inspected="INSPECTED",
            )
    return credited, lane


def _match_rnclab(
    report: dict[str, Any],
    observations: dict[str, Observation],
) -> tuple[dict[str, int], dict[str, Any]]:
    suite = ((report.get("suites") or {}).get("rnclab") or {}).get("details", {}).get("lanes", {}).get(
        "windows-amd64", {}
    )
    counts: dict[str, int] = {}
    coverage: dict[str, Any] = {}
    for lane_key, lane_name in (("filesystem", "rnclab_filesystem"), ("git", "rnclab_git")):
        lane = suite.get(lane_key) or {}
        matched = list(lane.get("matched_positive_ids") or [])
        findings = {
            str(f.get("expected_id")): f
            for f in (lane.get("findings") or [])
            if f.get("classification") == "TRUE_POSITIVE" and f.get("expected_id")
        }
        for target_id in matched:
            finding = findings.get(target_id, {})
            observations[target_id] = Observation(
                matched=True,
                disposition="CREDITED",
                rule_id=str(finding.get("rule_id") or ""),
                finding_id=str(finding.get("finding_id") or ""),
                capture="EXACT_IDENTITY_DIGEST" if finding.get("evidence_kind") == "identity_digest" else "EXACT_SOURCE_SPAN",
                reason="positive identity and source location credited",
                stage="ATTRIBUTION",
                source_inspected="INSPECTED",
            )
        exceptions = lane.get("exceptions") or []
        for exception in exceptions:
            target_id = str(exception.get("expected_id") or "")
            if not target_id:
                continue
            if exception.get("classification") == "UNVERIFIED_EVIDENCE":
                observation = observations.setdefault(target_id, Observation())
                if observation.matched:
                    continue
                observation.overlap = True
                observation.disposition = "UNVERIFIED_EVIDENCE"
                observation.exception_status = "UNVERIFIED_EVIDENCE"
                observation.rule_id = str(exception.get("rule_id") or observation.rule_id)
                observation.reason = str(exception.get("reason") or "")
                observation.reason_code = str(exception.get("reason_code") or "")
                observation.stage = str(exception.get("stage") or "VALUE")
                observation.capture = "AMBIGUOUS_OR_INCORRECT_VALUE"
        coverage[lane_name] = lane.get("coverage_caveat")
        counts[lane_name] = int(lane.get("metrics", {}).get("true_positive_occurrences") or len(matched))
    return counts, coverage


def load_scanner_evidence(
    key: str,
    report_path: Path,
    targets: list[Target],
    *,
    selection: ReportSelection | None = None,
) -> ScannerEvidence:
    report = load_json(report_path)
    metadata = _metadata_for_report(key, report, report_path, selection)
    observations: dict[str, Observation] = {}
    metrics: dict[str, Any] = {}
    if key in {"cp4c", "v14", "v16"}:
        expected_build = {"cp4c": "rnc-cp4c", "v14": "gl-rnc-mod-v14", "v16": "gl-rnc-mod-v16"}[key]
        if metadata["build_id"] != expected_build:
            raise DetectionGapError(
                f"{report_path} is build {metadata['build_id']!r}, expected {expected_build!r}"
            )
    levain_expected = _match_levain(report, targets, observations)
    leaky_fs_expected = _match_leaky_fs(report, observations)
    leaky_git_expected, history_lane = _match_leaky_git(report, observations)
    rnclab_expected, coverage = _match_rnclab(report, observations)
    metadata["history_coverage"] = history_lane.get("coverage")
    # Fill source inspection states from scanner-native evidence only.  A
    # parseable report or an absent finding is not inspection proof.
    uninspected: set[str] = set()
    caveats: dict[str, dict[str, Any]] = {}
    for lane_name, caveat in coverage.items():
        if isinstance(caveat, dict):
            caveats[lane_name] = caveat
            uninspected.update(str(item) for item in (caveat.get("uninspected_units") or []))
    rnclab_lanes = (
        ((report.get("suites") or {}).get("rnclab") or {})
        .get("details", {})
        .get("lanes", {})
        .get("windows-amd64", {})
    )
    leaky_lanes = (
        ((report.get("suites") or {}).get("leaky-repo") or {})
        .get("details", {})
        .get("lanes", {})
        .get("windows-amd64", {})
    )
    levain_lane = (
        ((report.get("suites") or {}).get("levain") or {})
        .get("details", {})
        .get("lanes", {})
        .get("windows-amd64", {})
    )

    def set_inspection(
        observation: Observation,
        state: str,
        capability: str,
        evidence: str,
    ) -> None:
        observation.source_inspected = state
        observation.source_capability = capability
        observation.inspection_evidence = evidence

    for target in targets:
        observation = observations.setdefault(target.target_id, Observation())
        if observation.matched:
            set_inspection(
                observation,
                "INSPECTED_VERIFIED",
                "CLAIMED_SUPPORTED",
                "a credited finding at this source location proves the unit was reached",
            )
            continue
        if target.lane == "rnclab_filesystem":
            lane = rnclab_lanes.get("filesystem") or {}
            caveat = caveats.get("rnclab_filesystem") or lane.get("coverage_caveat")
            lane_status = str(lane.get("status") or "")
            if lane_status in {"BLOCKED", "NOT_RUN"}:
                set_inspection(
                    observation,
                    "NOT_INSPECTED_VERIFIED",
                    "NOT_DECLARED",
                    f"RNC Lab filesystem lane status is {lane_status}; no completed inspection is recorded",
                )
            elif target.container_kind in {"archive_member", "database_record", "binary_file"}:
                set_inspection(
                    observation,
                    "INSPECTION_UNVERIFIED",
                    "NOT_DECLARED",
                    (
                        "the retained report has no unit/member/record identity for this "
                        "container target, and no validated capability contract says the "
                        "container type is unsupported"
                    ),
                )
            elif target.path in uninspected:
                set_inspection(
                    observation,
                    "NOT_INSPECTED_VERIFIED",
                    "CLAIMED_SUPPORTED",
                    "scanner-native coverage caveat lists this unit as uninspected",
                )
            elif isinstance(caveat, dict) and caveat.get("accepted") and int(
                caveat.get("inspected_units") or 0
            ) > 0:
                set_inspection(
                    observation,
                    "INSPECTED_VERIFIED",
                    "CLAIMED_SUPPORTED",
                    (
                        "scanner-native coverage record reports regular source units "
                        "inspected and this unit is not in the uninspected list"
                    ),
                )
            else:
                set_inspection(
                    observation,
                    "INSPECTION_UNVERIFIED",
                    "CLAIMED_SUPPORTED",
                    "no scanner-native source-unit coverage record is retained for this lane",
                )
        elif target.lane == "rnclab_git":
            lane = rnclab_lanes.get("git") or {}
            capability = lane.get("capability") or {}
            lane_status = str(lane.get("status") or "")
            if lane_status == "NOT_APPLICABLE" or capability.get("supported") is False:
                set_inspection(
                    observation,
                    "UNSUPPORTED_VERIFIED",
                    "DECLARED_UNSUPPORTED",
                    "the retained scanner capability record marks Git-history mode unsupported",
                )
            elif target.container_kind in {"archive_member", "database_record", "binary_file"}:
                set_inspection(
                    observation,
                    "INSPECTION_UNVERIFIED",
                    "NOT_DECLARED",
                    "no container member/record inspection identity is retained",
                )
            elif lane_status in {"BLOCKED", "NOT_RUN"}:
                set_inspection(
                    observation,
                    "NOT_INSPECTED_VERIFIED",
                    "CLAIMED_SUPPORTED",
                    f"RNC Lab Git lane status is {lane_status}; no completed inspection is recorded",
                )
            else:
                set_inspection(
                    observation,
                    "INSPECTION_UNVERIFIED",
                    "CLAIMED_SUPPORTED",
                    "Git lane completed, but the retained report has no per-unit coverage attestation",
                )
        elif target.lane == "leaky_git":
            if not history_lane:
                set_inspection(
                    observation,
                    "UNSUPPORTED_VERIFIED",
                    "DECLARED_UNSUPPORTED",
                    "no Leaky Repo history lane or scanner Git capability is retained",
                )
            else:
                history_verified = bool(
                    history_lane.get("coverage_verified")
                    or (history_lane.get("coverage") or {}).get("verified")
                )
                if target.container_kind in {"archive_member", "database_record", "binary_file"}:
                    set_inspection(
                        observation,
                        "INSPECTION_UNVERIFIED",
                        "NOT_DECLARED",
                        "no container member/record inspection identity is retained",
                    )
                elif history_verified:
                    set_inspection(
                        observation,
                        "INSPECTED_VERIFIED",
                        "CLAIMED_SUPPORTED",
                        "scanner-native history coverage record proves the selected ref scope was inspected",
                    )
                else:
                    set_inspection(
                        observation,
                        "INSPECTION_UNVERIFIED",
                        "CLAIMED_SUPPORTED",
                        "history execution completed without a retained per-unit coverage attestation",
                    )
        elif target.lane == "leaky_filesystem":
            if target.container_kind in {"archive_member", "database_record", "binary_file"}:
                set_inspection(
                    observation,
                    "INSPECTION_UNVERIFIED",
                    "NOT_DECLARED",
                    "no container member/record inspection identity is retained",
                )
            elif str((leaky_lanes.get("rich") or {}).get("execution_status") or "") != "PASS":
                set_inspection(
                    observation,
                    "NOT_INSPECTED_VERIFIED",
                    "CLAIMED_SUPPORTED",
                    "Leaky Repo rich scoring did not record a completed execution",
                )
            else:
                set_inspection(
                    observation,
                    "INSPECTION_UNVERIFIED",
                    "CLAIMED_SUPPORTED",
                    "no scanner-native per-file coverage attestation is retained for Leaky Repo filesystem",
                )
        elif target.lane == "levain":
            if target.container_kind in {"archive_member", "database_record", "binary_file"}:
                set_inspection(
                    observation,
                    "INSPECTION_UNVERIFIED",
                    "NOT_DECLARED",
                    "no container member/record inspection identity is retained",
                )
            elif (levain_lane.get("metrics") or {}).get("coverage_verified") is True:
                set_inspection(
                    observation,
                    "INSPECTED_VERIFIED",
                    "CLAIMED_SUPPORTED",
                    "scanner-native Levain coverage record proves the corpus units were inspected",
                )
            else:
                set_inspection(
                    observation,
                    "INSPECTION_UNVERIFIED",
                    "CLAIMED_SUPPORTED",
                    "no scanner-native Levain coverage attestation is retained",
                )
        else:
            set_inspection(
                observation,
                "INSPECTION_UNVERIFIED",
                "NOT_DECLARED",
                "unrecognized lane; no source coverage evidence is available",
            )
    # Report metrics are the authoritative checkpoint and must reconcile with
    # the reconstructed per-target observations.
    detection = report.get("detection") or {}
    rnc = detection.get("rnclab") or {}
    fs_metrics = (rnc.get("filesystem") or {}).get("true_positive_occurrences")
    git_lanes = (rnc.get("git") or {}).get("lanes") or {}
    git_metrics = (
        (git_lanes.get("windows-amd64") or {}).get("metrics", {}).get("true_positive_occurrences")
        if git_lanes
        else 0
    )
    metrics = {
        "levain": levain_expected,
        "leaky_filesystem": leaky_fs_expected,
        "leaky_git": leaky_git_expected,
        "rnclab_filesystem": int(fs_metrics if fs_metrics is not None else rnclab_expected.get("rnclab_filesystem", 0)),
        "rnclab_git": int(git_metrics if git_metrics is not None else rnclab_expected.get("rnclab_git", 0)),
    }
    report_metrics = {
        "levain": int((((report.get("suites") or {}).get("levain") or {}).get("metrics") or {}).get("true_positives") or 0),
        "leaky_filesystem": int(
            ((((report.get("suites") or {}).get("leaky-repo") or {}).get("metrics") or {}).get("rich_matched_count"))
            or 0
        ),
        "leaky_git": int(
            ((((report.get("suites") or {}).get("leaky-repo") or {}).get("metrics") or {}).get("history_matched_occurrences"))
            or 0
        ),
        "rnclab_filesystem": int(
            ((((report.get("suites") or {}).get("rnclab") or {}).get("metrics") or {}).get("true_positive_occurrences"))
            or 0
        ),
        "rnclab_git": int(
            (
                ((((report.get("suites") or {}).get("rnclab") or {}).get("metrics") or {}).get("git", {}))
                or {}
            ).get("true_positive_occurrences")
            or (
                (git_lanes.get("windows-amd64") or {}).get("metrics", {}).get("true_positive_occurrences")
                if git_lanes
                else 0
            )
            or 0
        ),
    }
    for lane in LANE_ORDER:
        if metrics[lane] != report_metrics[lane]:
            raise DetectionGapError(
                f"{key} {lane}: reconstructed {metrics[lane]} matches, report says {report_metrics[lane]}"
            )
    # Add scanner-wide metrics for report summaries.
    metrics["_report_metrics"] = report_metrics
    metrics["_detection"] = detection
    return ScannerEvidence(
        key=key,
        label=SCANNER_LABELS[key],
        report_path=report_path,
        report=report,
        observations=observations,
        metadata=metadata,
        metrics=metrics,
    )
