"""Canonical Gitleaks JSON report parsing.

One parser is shared by the legacy detection harness and the scanner adapter so
there is no second, subtly different Gitleaks parser in the codebase.
"""

from __future__ import annotations

from ..errors import ReportError
from ..util import basename, sha256_bytes
from .strict_json import load_findings_document

FILE_KEYS = ("File", "file", "path")
SECRET_KEYS = ("Secret", "secret", "Match", "match", "Raw", "raw", "value")
RULE_KEYS = ("RuleID", "RuleId", "rule_id", "ruleId", "Description", "description")
LINE_KEYS = ("StartLine", "start_line", "startLine", "Line", "line", "line_number")


def coerce_line(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def coerce_text(entry: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _document(data: bytes):
    return load_findings_document(data)


def parse_entries(data: bytes) -> list[dict]:
    """Return raw entry dictionaries with stable, scanner-independent fields."""
    entries: list[dict] = []
    for index, entry in enumerate(_document(data)):
        if not isinstance(entry, dict):
            raise ReportError(f"scanner report entry {index} is not an object")
        file_value = coerce_text(entry, FILE_KEYS)
        if not file_value:
            raise ReportError(f"scanner report entry {index} has no file path")
        secret = coerce_text(entry, SECRET_KEYS)
        match = coerce_text(entry, ("Match", "match", "Raw", "raw"))
        entries.append(
            {
                "file": file_value.replace("\\", "/"),
                "basename": basename(file_value),
                "line": coerce_line(
                    next((entry.get(key) for key in LINE_KEYS if key in entry), None)
                ),
                "rule_id": coerce_text(entry, RULE_KEYS),
                "commit": coerce_text(entry, ("Commit", "commit")) or None,
                "fingerprint": coerce_text(entry, ("Fingerprint", "fingerprint")) or None,
                "secret": secret,
                "match": match,
                "secret_sha256": sha256_bytes(secret.encode("utf-8"))
                if secret
                else None,
                "match_sha256": sha256_bytes(match.encode("utf-8")) if match else None,
                "secret_redacted": secret == "REDACTED",
            }
        )
    return entries


def parse_normalized(data: bytes) -> list[dict]:
    """Return report entries without raw matched values."""
    return [
        {
            "file": item["file"],
            "line": item["line"],
            "rule_id": item["rule_id"],
            "commit": item.get("commit"),
            "fingerprint": item.get("fingerprint"),
            "secret_sha256": item["secret_sha256"],
            "match_sha256": item["match_sha256"],
            "secret_redacted": item["secret_redacted"],
        }
        for item in parse_entries(data)
    ]
