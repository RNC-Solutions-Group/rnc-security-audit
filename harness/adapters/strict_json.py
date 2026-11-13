"""Strict JSON report loading shared by scanner adapters.

A valid empty array is a legitimate zero-finding report. Empty bytes, malformed
JSON, JSON Lines with a damaged line, or a document without a findings array are
report errors and must never be interpreted as zero findings.
"""

from __future__ import annotations

import json
from typing import Any

from ..errors import ReportError


def load_findings_document(data: bytes) -> list[Any]:
    if data is None:
        raise ReportError("scanner report is missing")
    if not isinstance(data, (bytes, bytearray)):
        raise ReportError("scanner report is not bytes")
    text = bytes(data).decode("utf-8-sig").strip()
    if not text:
        raise ReportError("scanner report is empty")

    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = _load_json_lines(text)
    if document is None:
        # Betterleaks v1 emits JSON null for a successful scan with no findings.
        return []
    if isinstance(document, dict):
        for key in ("findings", "Findings", "leaks", "Leaks", "results", "Results"):
            if isinstance(document.get(key), list):
                return document[key]
        if _looks_like_finding(document):
            return [document]
        raise ReportError("scanner report has no findings array")
    if not isinstance(document, list):
        raise ReportError("scanner report does not contain a findings list")
    return document


def _load_json_lines(text: str) -> list[dict]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise ReportError("scanner report is not valid JSON")
    entries: list[dict] = []
    for index, line in enumerate(lines, 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReportError(f"scanner report line {index} is not valid JSON") from exc
        if isinstance(value, dict):
            entries.append(value)
        elif isinstance(value, list):
            entries.extend(value)
        else:
            raise ReportError(f"scanner report line {index} is not an object")
    if not all(isinstance(entry, dict) for entry in entries):
        raise ReportError("scanner report contains a non-object finding entry")
    return entries


def _looks_like_finding(value: dict) -> bool:
    return any(
        isinstance(value.get(key), str) and value.get(key).strip()
        for key in ("File", "file", "path", "Path")
    )
