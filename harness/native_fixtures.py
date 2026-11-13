"""Native-executable execution of the portable pinned Gitleaks scenarios.

The Docker lane remains the authority for container-path and Linux-symlink
assertions.  This lane runs the same scenario manifest against the built
executable, omits only assertions that are explicitly Docker-specific, and
reports platform-unavailable scenarios as ``NOT_APPLICABLE``.
"""

from __future__ import annotations

import copy
import json
import os
import re
import time
from pathlib import Path

from . import status as statuses
from .docker.evidence import evaluate_finding_assertions
from .docker.validate import fixture_id_for_case, fixture_id_from_report_path, materialize_git_fixture
from .execution import resolve_binary, run_process
from .util import sha256_bytes

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _source_path(prepared, spec: str) -> Path:
    if spec.startswith("testdata/"):
        return (Path(prepared.root) / spec).resolve()
    if spec.startswith("fixtures/"):
        return (Path(prepared.docker_dir) / spec).resolve()
    raise ValueError(f"scenario path must start with testdata/ or fixtures/: {spec}")


def _canonical_path(value: str, prepared, staged_source: Path | None) -> str:
    normalized = str(value).replace("\\", "/")
    for prefix in ("../testdata/", "../local/"):
        if normalized.startswith(prefix):
            normalized = normalized[len("../") :]
    bases = (
        ((Path(prepared.root) / "testdata").resolve(), "testdata/"),
        ((Path(prepared.docker_dir) / "fixtures").resolve(), "local/"),
    )
    for base, prefix in bases:
        base_text = str(base).replace("\\", "/").rstrip("/")
        if normalized == base_text:
            return prefix.rstrip("/")
        if normalized.startswith(base_text + "/"):
            return prefix + normalized[len(base_text) + 1 :]
    if staged_source is not None:
        base_text = str(staged_source.resolve()).replace("\\", "/").rstrip("/")
        if normalized == base_text:
            return "."
        if normalized.startswith(base_text + "/"):
            return normalized[len(base_text) + 1 :]
    return normalized


def _safe_finding(finding: dict, prepared, staged_source: Path | None) -> dict:
    secret = str(finding.get("Secret", ""))
    match = str(finding.get("Match", ""))
    return {
        "rule_id": finding.get("RuleID", ""),
        "file": _canonical_path(str(finding.get("File", "")), prepared, staged_source),
        "symlink_file": _canonical_path(
            str(finding.get("SymlinkFile", "")), prepared, staged_source
        )
        if finding.get("SymlinkFile")
        else "",
        "commit": finding.get("Commit", ""),
        "start_line": finding.get("StartLine", 0),
        "end_line": finding.get("EndLine", 0),
        "start_column": finding.get("StartColumn", 0),
        "end_column": finding.get("EndColumn", 0),
        "description": finding.get("Description", ""),
        "entropy": finding.get("Entropy", 0),
        "secret_sha256": sha256_bytes(secret.encode("utf-8")) if secret else None,
        "match_sha256": sha256_bytes(match.encode("utf-8")) if match else None,
        "secret_redacted": secret == "REDACTED",
    }


def _stderr_traces(case: dict) -> tuple[list[str], list[str]]:
    traces = [str(item) for item in case.get("assert_stderr_contains", [])]
    portable = [item for item in traces if "/rnc/" not in item]
    docker_only = [item for item in traces if "/rnc/" in item]
    return portable, docker_only


def _redacted_argv(argv: list[str], prepared, work_dir: Path, report_path: Path, executable: Path) -> list[str]:
    replacements = {
        str(Path(executable).resolve()): "<executable>",
        str(Path(prepared.root).resolve()): "<fixture-root>",
        str((Path(prepared.docker_dir) / "fixtures").resolve()): "<synthetic-fixtures>",
        str(Path(work_dir).resolve()): "<work>",
        str(Path(report_path).resolve()): "<report>",
    }
    rendered = []
    for argument in argv:
        value = argument
        for source, replacement in replacements.items():
            value = value.replace(source, replacement)
        rendered.append(value)
    return rendered


def _base_case_result(case: dict) -> dict:
    return {
        "id": case["id"],
        "name": case["name"],
        "fixture": case["fixture"],
        "expected": case.get("expectation", ""),
        "status": statuses.NOT_RUN,
        "actual": "not executed",
        "actual_exit_code": None,
        "expected_exit_code": case.get("expected_exit_code"),
        "duration_seconds": 0.0,
        "findings": [],
        "missing_findings": [],
        "added_findings": [],
        "changed_findings": [],
        "assertions": [],
        "diagnostic": None,
        "applicable": True,
        "applicability": "applicable",
        "docker_only_assertions": [],
        "execution": None,
        "read_only_mounts": False,
    }


def _not_applicable(case: dict, reason: str) -> dict:
    result = _base_case_result(case)
    result.update(
        status=statuses.NOT_APPLICABLE,
        actual="not executed: not applicable to the native host",
        applicable=False,
        applicability="not_applicable",
        diagnostic=reason,
    )
    return result


def _stage_path(spec: str, prepared, destination_root: Path) -> str:
    source = _source_path(prepared, spec)
    if spec.startswith("testdata/"):
        relative = Path(spec[len("testdata/") :])
        destination = destination_root / "testdata" / relative
    elif spec.startswith("fixtures/"):
        relative = Path(spec[len("fixtures/") :])
        destination = destination_root / "local" / relative
    else:
        raise ValueError(f"scenario path must start with testdata/ or fixtures/: {spec}")
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            import shutil

            shutil.copytree(source, destination)
        else:
            import shutil

            shutil.copy2(source, destination)
    return "../" + destination.relative_to(destination_root).as_posix()


def _stage_relative_layout(case: dict, prepared, case_work: Path) -> tuple[Path, str, str, str | None]:
    """Mirror the Docker workdir-relative layout for path-sensitive scenarios.

    The pinned ignore file and baseline use paths such as
    ``../testdata/repos/nogit/api.go``.  Running from an equivalent relative
    layout keeps those expectations intact instead of rewriting the fixtures.
    """
    root = case_work / "root"
    work = root / "work"
    work.mkdir(parents=True, exist_ok=True)
    source_arg = _stage_path(case["source"], prepared, root)
    if case.get("gitleaks_ignore_path"):
        ignore_arg = _stage_path(case["gitleaks_ignore_path"], prepared, root)
    else:
        ignore_arg = str((case_work / "empty-ignore").resolve())
        (case_work / "empty-ignore").write_bytes(b"")
    baseline_arg = (
        _stage_path(case["baseline_path"], prepared, root)
        if case.get("baseline_path")
        else None
    )
    return work, source_arg, ignore_arg, baseline_arg


def _run_case(case: dict, executable: Path, digest: str, prepared, work_dir: Path, timeout: int) -> dict:
    result = _base_case_result(case)
    if case.get("requires_linux_symlink") and os.name == "nt":
        return _not_applicable(
            case,
            "Linux-native symlink staging is not available on Windows; the Docker lane preserves this scenario.",
        )

    case_work = work_dir / case["id"]
    case_work.mkdir(parents=True, exist_ok=True)
    report_path = case_work / "report.json"
    staged_source: Path | None = None
    fixture_adaptation = None
    run_cwd: Path | None = None

    try:
        if case.get("prepare_git_copy"):
            original = _source_path(prepared, case["source"])
            staged, issue, adaptation = materialize_git_fixture(
                original, case_work / "git-repository"
            )
            if issue:
                result.update(
                    status=statuses.BLOCKED,
                    actual="not executed: Git fixture could not be staged",
                    diagnostic=issue,
                )
                return result
            staged_source = staged
            fixture_adaptation = adaptation
        if case.get("relative_source"):
            run_cwd, source_arg, ignore_arg, baseline_arg = _stage_relative_layout(
                case, prepared, case_work
            )
            if staged_source is not None:
                raise ValueError("relative_source and prepare_git_copy cannot be combined")
        else:
            source = staged_source or _source_path(prepared, case["source"])
            if not source.exists():
                result.update(
                    status=statuses.BLOCKED,
                    actual="not executed: fixture source is missing",
                    diagnostic="Fixture source was not found in the pinned checkout.",
                )
                return result
            source_arg = str(source)
            ignore_arg = (
                str(_source_path(prepared, case["gitleaks_ignore_path"]))
                if case.get("gitleaks_ignore_path")
                else str(case_work / "empty-ignore")
            )
            if not case.get("gitleaks_ignore_path"):
                (case_work / "empty-ignore").write_bytes(b"")
            baseline_arg = (
                str(_source_path(prepared, case["baseline_path"]))
                if case.get("baseline_path")
                else None
            )
        config = str(_source_path(prepared, case["config"]))
    except (OSError, ValueError) as exc:
        result.update(
            status=statuses.BLOCKED,
            actual="not executed: fixture preparation failed",
            diagnostic=str(exc)[:300],
        )
        return result

    argv = [
        str(executable),
        case["command"],
        "--config",
        config,
        "--no-banner",
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--exit-code",
        "1",
        "--gitleaks-ignore-path",
        ignore_arg,
    ]
    for option in case.get("options") or []:
        argv.extend(str(item) for item in option)
    if baseline_arg is not None:
        argv.extend(["--baseline-path", baseline_arg])
    argv.append(source_arg)

    portable_traces, docker_only = _stderr_traces(case)
    result["docker_only_assertions"] = [
        {
            "expected": trace,
            "status": statuses.NOT_APPLICABLE,
            "reason": "Assertion depends on a Docker container path.",
        }
        for trace in docker_only
    ]
    result["execution"] = {
        "argv": _redacted_argv(argv, prepared, case_work, report_path, executable),
        "container": False,
        "image_pull": None,
        "network": "not restricted by harness",
        "fixture_adaptation": fixture_adaptation,
    }

    started = time.perf_counter()
    invocation = run_process(
        argv,
        binary_path=str(executable),
        binary_sha256=digest,
        mode=case["command"],
        report_path=report_path,
        timeout_seconds=float(case.get("timeout_seconds", timeout)),
        cwd=run_cwd,
    )
    result["duration_seconds"] = round(time.perf_counter() - started, 3)
    result["actual_exit_code"] = invocation.exit_code
    result["stdout_sha256"] = invocation.stdout_sha256
    result["stderr_sha256"] = invocation.stderr_sha256
    result["fixture_adaptation"] = fixture_adaptation

    if invocation.timed_out:
        result.update(status=statuses.BLOCKED, actual="not executed: timed out", diagnostic="Native scan exceeded the scenario timeout.")
        return result
    if invocation.error_code:
        result.update(status=statuses.BLOCKED, actual="not executed: invocation failed", diagnostic=invocation.error_message)
        return result
    if invocation.exit_code is None:
        result.update(status=statuses.BLOCKED, actual="not executed: no exit status", diagnostic="Native scanner did not return an exit status.")
        return result

    stderr = ANSI.sub("", invocation.stderr.decode("utf-8", "replace"))
    if case.get("expect_config_error"):
        contains = case["expect_config_error"]
        passed = invocation.exit_code == case.get("expected_exit_code") and contains in stderr
        result["assertions"] = [
            {
                "assertion_id": f"{case['id']}.exit_code",
                "type": "exit_code",
                "fixture_id": fixture_id_for_case(case),
                "expected": case.get("expected_exit_code"),
                "actual": invocation.exit_code,
                "status": statuses.PASS
                if invocation.exit_code == case.get("expected_exit_code")
                else statuses.FAIL,
            },
            {
                "assertion_id": f"{case['id']}.config_error",
                "type": "configuration_rejected",
                "fixture_id": fixture_id_for_case(case),
                "expected": "known invalid allowlist diagnostic",
                "actual": "matched" if contains in stderr else "not matched",
                "status": statuses.PASS if contains in stderr else statuses.FAIL,
            },
        ]
        result.update(
            status=statuses.PASS if passed else statuses.FAIL,
            actual="expected config rejection" if passed else "config error did not match expectation",
            diagnostic=None if passed else "Expected config diagnostic was absent; raw stderr was omitted.",
        )
        return result

    try:
        raw = json.loads(invocation.report_bytes.decode("utf-8-sig") if invocation.report_bytes else "")
        if not isinstance(raw, list):
            raise ValueError("report is not an array")
    except (ValueError, TypeError, AttributeError):
        result.update(
            status=statuses.FAIL,
            actual="scanner report was not a JSON findings array",
            diagnostic="Native scanner did not return a parseable JSON findings array.",
        )
        return result

    normalized = [_safe_finding(item, prepared, staged_source) for item in raw]
    expected_findings = copy.deepcopy(case.get("expected_findings", []))
    forbidden_findings = copy.deepcopy(case.get("forbidden_findings", []))
    for finding in expected_findings:
        finding.setdefault(
            "fixture_id",
            fixture_id_from_report_path(finding.get("symlink_file", ""))
            or fixture_id_from_report_path(finding.get("file", ""))
            or fixture_id_for_case(case),
        )
        related = fixture_id_from_report_path(finding.get("file", ""))
        if related and related != finding["fixture_id"]:
            finding["related_fixture_ids"] = [related]
    for finding in forbidden_findings:
        finding.setdefault("fixture_id", fixture_id_from_report_path(finding.get("file", "")))
    comparison, assertions = evaluate_finding_assertions(
        case["id"], expected_findings, normalized, forbidden_findings
    )
    result["findings"] = normalized
    result["missing_findings"] = comparison["missing"]
    result["added_findings"] = comparison["added"]
    result["changed_findings"] = comparison["changed"]
    result["unexpected_forbidden_findings"] = comparison["unexpected_forbidden"]
    result["assertions"] = assertions
    scenario_fixture_id = fixture_id_for_case(case)
    for assertion in result["assertions"]:
        if not assertion.get("fixture_id") and scenario_fixture_id:
            assertion["fixture_id"] = scenario_fixture_id
    result["assertions"].append(
        {
            "assertion_id": f"{case['id']}.json_report",
            "type": "json_report_valid",
            "fixture_id": scenario_fixture_id,
            "expected": "JSON array",
            "actual": "JSON array",
            "status": statuses.PASS,
        }
    )
    result["assertions"].append(
        {
            "assertion_id": f"{case['id']}.exit_code",
            "type": "exit_code",
            "fixture_id": scenario_fixture_id,
            "expected": case.get("expected_exit_code"),
            "actual": invocation.exit_code,
            "status": statuses.PASS
            if invocation.exit_code == case.get("expected_exit_code")
            else statuses.FAIL,
        }
    )
    if case.get("baseline_path"):
        result["assertions"].append(
            {
                "assertion_id": f"{case['id']}.baseline_suppression",
                "type": "baseline_suppression",
                "fixture_id": fixture_id_from_report_path(
                    "local/" + case["baseline_path"][len("fixtures/") :]
                ),
                "expected": "known finding suppressed by explicit baseline",
                "actual": "no findings" if not normalized else f"{len(normalized)} finding(s) remain",
                "status": statuses.PASS if not normalized else statuses.FAIL,
            }
        )
    for index, trace in enumerate(portable_traces, 1):
        observed = trace in stderr
        result["assertions"].append(
            {
                "assertion_id": f"{case['id']}.traversal.{index}",
                "type": "fixture_traversal",
                "fixture_id": fixture_id_for_case(case),
                "expected": trace,
                "actual": "observed" if observed else "not observed",
                "status": statuses.PASS if observed else statuses.FAIL,
            }
        )

    passed = (
        invocation.exit_code == case.get("expected_exit_code")
        and not comparison["missing"]
        and not comparison["added"]
        and not comparison["changed"]
        and not comparison["unexpected_forbidden"]
        and all(item["status"] == statuses.PASS for item in result["assertions"])
    )
    result["actual"] = f"exit {invocation.exit_code}; {len(normalized)} finding(s)"
    result["status"] = statuses.PASS if passed else statuses.FAIL
    if not passed:
        result["diagnostic"] = "Exit code or finding-level expectations differed; see finding diff fields."
    return result


def run(prepared, executable: Path | str, work_dir: Path | str, timeout: int = 120) -> dict:
    """Run all portable manifest scenarios against a native executable."""
    executable, digest = resolve_binary(executable)
    work_dir = Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = Path(prepared.docker_dir) / "cases.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {
            "status": statuses.BLOCKED,
            "adapter": "executable",
            "reason": f"cannot load pinned scenario manifest: {exc}",
            "tests": [],
            "assertions": [],
            "summary": {},
        }

    tests: list[dict] = []
    for case in manifest.get("cases", []):
        tests.append(_run_case(case, executable, digest, prepared, work_dir, timeout))

    assertions = [item for case in tests for item in case.get("assertions", [])]
    applicable = [case for case in tests if case["status"] != statuses.NOT_APPLICABLE]
    if any(case["status"] == statuses.FAIL for case in tests):
        lane_status = statuses.FAIL
    elif any(case["status"] == statuses.BLOCKED for case in tests):
        lane_status = statuses.BLOCKED
    elif any(case["status"] == statuses.NOT_RUN for case in applicable):
        lane_status = statuses.NOT_RUN
    elif applicable and all(case["status"] == statuses.PASS for case in applicable):
        lane_status = statuses.PASS
    else:
        lane_status = statuses.NOT_RUN

    docker_only = [
        assertion
        for case in tests
        for assertion in case.get("docker_only_assertions", [])
    ]
    summary = {
        "scenario_total": len(tests),
        "scenario_applicable": len(applicable),
        "scenario_executed": sum(case.get("actual_exit_code") is not None for case in tests),
        "scenario_passed": sum(case["status"] == statuses.PASS for case in tests),
        "scenario_failed": sum(case["status"] == statuses.FAIL for case in tests),
        "scenario_blocked": sum(case["status"] == statuses.BLOCKED for case in tests),
        "scenario_not_run": sum(case["status"] == statuses.NOT_RUN for case in tests),
        "scenario_not_applicable": sum(
            case["status"] == statuses.NOT_APPLICABLE for case in tests
        ),
        "assertion_total": len(assertions),
        "assertion_passed": sum(item["status"] == statuses.PASS for item in assertions),
        "assertion_failed": sum(item["status"] == statuses.FAIL for item in assertions),
        "docker_only_assertions": len(docker_only),
        "coverage_complete": bool(applicable)
        and all(case["status"] == statuses.PASS for case in applicable),
    }
    return {
        "status": lane_status,
        "adapter": "executable",
        "coverage_complete": summary["coverage_complete"],
        "coverage_result": statuses.PASS if summary["coverage_complete"] else "INCOMPLETE",
        "executable_sha256": digest,
        "fixture_source_revision": prepared.revision,
        "scenario_manifest": {
            "path": "harness/docker/cases.json",
            "sha256": sha256_bytes(manifest_path.read_bytes()),
            "scenario_total": len(tests),
        },
        "summary": summary,
        "tests": tests,
        "assertions": assertions,
        "docker_only_assertions": docker_only,
        "limitations": [
            "The native lane omits assertions that reference Docker container paths.",
            "Linux-only symlink staging is NOT_APPLICABLE on Windows; the Docker lane still covers it.",
        ],
    }
