"""In-memory model shared by dataset loading, execution, and scoring.

Raw secret-shaped values live only in these objects while a run is in memory.
They are never written to a report or emitted to a console by the harness.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExpectedSecret:
    kind: str
    text: str


@dataclass(frozen=True)
class Section:
    name: str
    text: str
    secrets: tuple[ExpectedSecret, ...]
    personal_data: tuple[str, ...]
    hard: bool
    filename: str
    lines: int


@dataclass(frozen=True)
class Finding:
    """A scanner finding. `secret` and `match` are sensitive and never serialized."""

    file: str
    line: int | None
    rule_id: str
    secret: str
    match: str


@dataclass(frozen=True)
class ControlResult:
    file: str
    reported: bool
    file_encountered: bool
    findings_on_file: int
    credential_findings: int
    kinds_detected: tuple[str, ...]
    kinds_echoed: tuple[str, ...]
    planted: tuple[str, ...]
    unmatched_findings: int
    notes: tuple[str, ...]
