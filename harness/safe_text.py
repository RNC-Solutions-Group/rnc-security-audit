"""Safe rendering helpers for externally readable reports and CSV files.

These helpers are deliberately conservative.  They do not attempt to classify
every possible secret shape; they neutralise spreadsheet formulas, make Markdown
table cells structurally safe, and redact the credential-bearing forms that the
harness itself can emit (URL userinfo, sensitive assignments and headers).
"""

from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any

_FORMULA_PREFIX = re.compile(r"^[\s\u0000-\u001f\ufeff]*[=+\-@]")
_NUMERIC = re.compile(
    r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$"
)
_URL_USERINFO = re.compile(
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)"
    r"(?P<user>[^/@\s:]+):(?P<password>[^/@\s]+)@"
)
_AUTH_HEADER = re.compile(
    r"(?i)\b(authorization|proxy-authorization)\s*:\s*"
    r"(basic|bearer|token)\s+[^\s,;]+"
)
_ASSIGNMENT = re.compile(
    r"(?i)([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|"
    r"client[_-]?secret|access[_-]?key|credential))"
    r"(\s*[=:]\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_CLI_SENSITIVE = re.compile(
    r"(?i)(--(?:token|password|passwd|secret|api[-_]?key|"
    r"access[-_]?key|client[-_]?secret|credential|auth)\s+)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_SENSITIVE_PATH_SEGMENT = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|"
    r"client[_-]?secret|access[_-]?key|credential)=([^/\\\s]+)"
)
_LONG_CREDENTIAL = re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")


def text(value: Any) -> str:
    """Render a report value without converting None to a misleading string."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "YES" if value else "NO"
    if isinstance(value, (list, tuple, set)):
        return ";".join(text(item) for item in value)
    return str(value)


def csv_cell(value: Any) -> str:
    """Neutralise a CSV cell against spreadsheet formula interpretation.

    Quoting is performed by :mod:`csv`, but quoting alone does not stop a
    spreadsheet from interpreting a leading formula character.  Numeric values,
    including negative numbers, are preserved.
    """
    rendered = text(value)
    if not rendered:
        return rendered
    if _NUMERIC.fullmatch(rendered):
        return rendered
    if _FORMULA_PREFIX.match(rendered):
        return "'" + rendered
    return rendered


def markdown_cell(value: Any) -> str:
    """Escape a Markdown table cell, including embedded newlines and pipes."""
    rendered = html.escape(text(value), quote=False)
    rendered = rendered.replace("\r\n", "\n").replace("\r", "\n")
    rendered = rendered.replace("\n", "<br>")
    return rendered.replace("|", "\\|")


def markdown_code(value: Any) -> str:
    """Return a valid Markdown code span even when the value contains backticks."""
    rendered = text(value)
    if not rendered:
        return "`(empty)`"
    fence = "`"
    while fence in rendered:
        fence += "`"
    if fence == "`" and (rendered.startswith("`") or rendered.endswith("`")):
        fence = "``"
    if rendered.startswith("`") or rendered.endswith("`") or "\n" in rendered:
        return f"{fence} {rendered} {fence}"
    return f"{fence}{rendered}{fence}"


def redact_text(value: Any) -> str:
    """Redact common credential forms embedded in a free-text value."""
    rendered = text(value)
    if not rendered:
        return rendered
    rendered = _URL_USERINFO.sub(
        lambda match: f"{match.group('scheme')}{match.group('user')}:<redacted>@",
        rendered,
    )
    rendered = _AUTH_HEADER.sub(
        lambda match: f"{match.group(1)}: {match.group(2)} <redacted>", rendered
    )
    rendered = _ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>", rendered
    )
    rendered = _CLI_SENSITIVE.sub(
        lambda match: f"{match.group(1)}<redacted>", rendered
    )
    return rendered


def safe_message(value: Any) -> str:
    """A bounded, credential-redacted diagnostic string."""
    rendered = redact_text(value).replace("\r", " ").replace("\n", " ")
    return rendered[:1000]


def safe_path(value: Any) -> str:
    """Render a path without volatile absolute prefixes or credential segments.

    Repository-relative paths remain relative.  A path outside the repository is
    reduced to its final component under ``<external>`` so an absolute developer
    home or temporary directory is not published incidentally.
    """
    if value is None or str(value) == "":
        return ""
    rendered = str(value).replace("\\", "/")
    rendered = _URL_USERINFO.sub(
        lambda match: f"{match.group('scheme')}{match.group('user')}:<redacted>@",
        rendered,
    )
    rendered = _SENSITIVE_PATH_SEGMENT.sub(
        lambda match: f"{match.group(1)}=<redacted>", rendered
    )
    path = Path(str(value))
    if path.is_absolute():
        try:
            root = Path(__file__).resolve().parents[1]
            return path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            name = path.name or "<unknown>"
            return f"<external>/{name}"
    return rendered


def command_redaction_reason(value: str) -> bool:
    """Return true when a token still resembles a credential-bearing value."""
    if _URL_USERINFO.search(value) or _AUTH_HEADER.search(value):
        return True
    return bool(_ASSIGNMENT.search(value))


__all__ = [
    "csv_cell",
    "markdown_cell",
    "markdown_code",
    "redact_text",
    "safe_message",
    "safe_path",
    "text",
]
