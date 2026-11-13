#!/usr/bin/env python3
"""Controlled scanner test double for CP1.

This is NOT Gitleaks. It writes a Gitleaks-shaped JSON report so the harness's
execution, parsing, scoring, control, and redaction paths can be exercised
without an executable or Go toolchain.

Modes (environment variable STUB_MODE):
  all-lines    one finding per non-empty line in every .log file
  control-only one finding naming the control file
  oracle       emit exact answer-key secrets (STUB_ANSWER_KEY); test double only
  silent       an empty report
  fail         exit 2 without a report
  no-report    exit 0 without writing a report
  malformed    write a non-JSON report
  duplicate    two identical control findings
  hang         sleep before writing a report (for timeout tests)
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

CONTROL_FILE = "000-control.log"


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "section"


def _oracle(target: Path, answer_key: Path) -> list[dict]:
    """Emit the published answer key. This is an oracle, not a scanner."""
    document = json.loads(answer_key.read_text(encoding="utf-8"))
    findings: list[dict] = []
    for index, section in enumerate(document["sections"], 1):
        path = target / f"{index:03d}-{_slug(section['name'])}.log"
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for secret in section.get("secrets", []):
            value = secret["text"]
            offset = text.find(value)
            line = text[:offset].count("\n") + 1 if offset >= 0 else None
            findings.append(_finding(path, line, value, "stub.oracle"))
    control = target / CONTROL_FILE
    if control.is_file():
        for number, line in enumerate(control.read_text(encoding="utf-8").splitlines(), 1):
            if "aws_access_key_id=" in line:
                findings.append(_finding(control, number, line.split("=", 1)[1].strip(), "stub.control"))
                break
    return findings


def _args(argv: list[str]) -> tuple[Path, Path]:
    target = None
    report = None
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "--source" and index + 1 < len(argv):
            target = Path(argv[index + 1])
            index += 2
            continue
        if argument == "--report-path" and index + 1 < len(argv):
            report = Path(argv[index + 1])
            index += 2
            continue
        if target is None and index == 1:
            target = Path(argument)
        index += 1
    if target is None or report is None:
        print("stub: could not locate target or report path", file=sys.stderr)
        raise SystemExit(2)
    return target, report


def _finding(path: Path, line: int | None, secret: str, rule: str = "stub") -> dict:
    return {
        "RuleID": rule,
        "Description": "controlled stub finding",
        "File": str(path),
        "StartLine": line,
        "EndLine": line,
        "Secret": secret,
        "Match": secret,
    }


def _all_lines(target: Path) -> list[dict]:
    findings: list[dict] = []
    for path in sorted(target.glob("*.log")):
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if line.strip():
                findings.append(_finding(path, number, line.strip()))
    return findings


def _control_finding(target: Path) -> dict | None:
    path = target / CONTROL_FILE
    if not path.is_file():
        return None
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if "aws_access_key_id=" in line:
            return _finding(path, number, line.split("=", 1)[1].strip(), "stub.control")
    return None


def main(argv: list[str]) -> int:
    mode = os.environ.get("STUB_MODE", "all-lines")
    target, report = _args(argv)
    report.parent.mkdir(parents=True, exist_ok=True)

    if mode == "hang":
        time.sleep(10)
    if mode == "fail":
        print("stub: deliberate failure", file=sys.stderr)
        return 2
    if mode == "no-report":
        return 0

    if mode == "malformed":
        report.write_text("{ this is not json", encoding="utf-8")
        return 0
    if mode == "silent":
        findings: list[dict] = []
    elif mode == "control-only":
        finding = _control_finding(target)
        findings = [finding] if finding else []
    elif mode == "oracle":
        answer_key = os.environ.get("STUB_ANSWER_KEY")
        if not answer_key:
            print("stub: oracle mode requires STUB_ANSWER_KEY", file=sys.stderr)
            return 2
        findings = _oracle(target, Path(answer_key))
    elif mode == "duplicate":
        finding = _control_finding(target)
        findings = [finding, finding] if finding else []
    else:
        findings = _all_lines(target)

    report.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
