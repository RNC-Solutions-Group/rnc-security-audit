"""Gitleaks-specific fixture lane execution used by the scanner adapter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .. import native_fixtures
from .. import status as statuses
from ..util import sha256_bytes

ROOT = Path(__file__).resolve().parents[2]


def run_native(
    fixtures,
    executable: Path | str,
    work_dir: Path | str,
    timeout: int = 120,
    on_invocation=None,
) -> dict:
    return native_fixtures.run(
        fixtures,
        executable,
        work_dir,
        timeout=timeout,
        on_invocation=on_invocation,
    )


def run_docker(
    fixtures,
    image_tag: str,
    image_id: str,
    reports_dir: Path | str,
    timeout: int,
) -> dict:
    reports_dir = Path(reports_dir).resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "harness.docker.validate",
        "--image",
        image_tag,
        "--fixture-root",
        str(fixtures.root),
        "--fixture-revision",
        fixtures.revision,
        "--reports-dir",
        str(reports_dir),
        "--timeout",
        str(timeout),
    ]
    env = {**os.environ, "GITLEAKS_FIXTURE_ROOT": str(fixtures.root)}
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout * 4 + 120,
            env=env,
            cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        return {
            "status": statuses.BLOCKED,
            "reason": "Docker fixture lane timed out",
            "functional_result": "NOT RUN",
            "coverage_result": "NOT RUN",
            "coverage_complete": False,
            "parity": {
                "scenarios": 0,
                "assertions": 0,
                "docker_applicable_fixtures": 0,
                "expected_scenarios": fixtures.spec.expected.get("scenarios"),
                "expected_assertions": fixtures.spec.expected.get("assertions"),
                "expected_docker_applicable_fixtures": fixtures.spec.expected.get(
                    "docker_applicable_fixtures"
                ),
                "matches": False,
            },
            "summary": {},
            "tests": [],
            "assertions": [],
        }
    duration = round(time.perf_counter() - started, 3)
    reports = sorted(
        reports_dir.glob("runs/*/execution.json"), key=lambda path: path.stat().st_mtime
    )
    document = {}
    if reports:
        try:
            document = json.loads(reports[-1].read_text(encoding="utf-8"))
        except (OSError, ValueError):
            document = {}
    summary = document.get("summary", {})
    functional = document.get("functional_result", "NOT RUN")
    coverage = document.get("coverage_result", "NOT RUN")
    overall = document.get("overall_acceptance", "NOT COMPLETE")
    expected = fixtures.spec.expected
    parity = {
        "scenarios": len(document.get("tests", [])),
        "assertions": len(document.get("assertions", [])),
        "docker_applicable_fixtures": summary.get("docker_applicable_fixtures", 0),
        "expected_scenarios": expected.get("scenarios"),
        "expected_assertions": expected.get("assertions"),
        "expected_docker_applicable_fixtures": expected.get("docker_applicable_fixtures"),
    }
    parity["matches"] = (
        parity["scenarios"] == parity["expected_scenarios"]
        and parity["assertions"] == parity["expected_assertions"]
        and parity["docker_applicable_fixtures"] == parity["expected_docker_applicable_fixtures"]
    )
    coverage_complete = bool(
        functional == "PASS"
        and parity["matches"]
        and not int(summary.get("assertion_failed") or 0)
    )
    overall = (
        "PASS"
        if coverage_complete
        else "FAIL"
        if functional == "FAIL"
        else "INCOMPLETE"
    )
    coverage = "PASS" if coverage_complete else "INCOMPLETE"
    if functional == "PASS":
        lane_status = statuses.PASS
    elif document:
        lane_status = statuses.FAIL
    else:
        lane_status = statuses.BLOCKED
    invocations = []
    for test in document.get("tests", []):
        execution = test.get("execution") or {}
        command = execution.get("docker_command")
        if not command:
            continue
        invocations.append(
            {
                "id": test.get("id"),
                "command": list(command),
                "exit_code": test.get("actual_exit_code"),
                "duration_seconds": test.get("duration_seconds"),
                "timed_out": "timeout" in str(test.get("diagnostic") or "").lower(),
            }
        )
    return {
        "status": lane_status,
        "command": command,
        "exit_code": result.returncode,
        "duration_seconds": duration,
        "stdout_sha256": sha256_bytes(result.stdout),
        "stderr_sha256": sha256_bytes(result.stderr),
        "functional_result": functional,
        "coverage_result": coverage,
        "coverage_complete": coverage_complete,
        "overall_acceptance": overall,
        "parity": parity,
        "summary": {
            key: summary.get(key)
            for key in (
                "scenario_total",
                "scenario_passed",
                "assertion_total",
                "assertion_passed",
                "assertion_failed",
                "docker_applicable_fixtures",
                "docker_validated_fixtures",
                "validated_fixtures",
                "unvalidated_fixtures",
            )
        },
        "tests": document.get("tests", []),
        "assertions": document.get("assertions", []),
        "invocations": invocations,
        "image_id": document.get("image", {}).get("image_id") or image_id,
        "fixture_source_revision": document.get("fixture_source_revision"),
        "report": str(reports[-1]) if reports else None,
    }
