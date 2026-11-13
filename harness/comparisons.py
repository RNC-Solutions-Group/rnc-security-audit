"""Cross-target comparisons for fixture and Levain lanes."""

from __future__ import annotations

from . import status as statuses

_IDENTITY_FIELDS = (
    "rule_id",
    "file",
    "symlink_file",
    "commit",
    "start_line",
    "start_column",
    "secret_sha256",
)


def _identity(finding: dict) -> tuple:
    return tuple(finding.get(field, "") for field in _IDENTITY_FIELDS)


def _findings(result: dict) -> list[tuple]:
    return sorted(_identity(item) for item in result.get("findings", []))


def _assertions(result: dict) -> dict[str, str]:
    return {
        item.get("assertion_id", ""): item.get("status", "")
        for item in result.get("assertions", [])
        if item.get("assertion_id")
    }


def compare_fixtures(executable: dict | None, docker: dict | None) -> dict:
    """Compare native and Docker results without counting Docker-only assertions."""
    if not executable or not docker:
        return {
            "status": statuses.NOT_APPLICABLE,
            "reason": "Both executable and Docker fixture lanes must be selected and built.",
            "shared_scenarios": 0,
            "identical_scenarios": 0,
            "different_scenarios": 0,
            "not_comparable_scenarios": 0,
            "differences": [],
        }
    if (
        executable.get("status") == statuses.NOT_APPLICABLE
        or docker.get("status") == statuses.NOT_APPLICABLE
    ):
        return {
            "status": statuses.NOT_APPLICABLE,
            "reason": "Cross-target comparison requires both target selections.",
            "shared_scenarios": 0,
            "identical_scenarios": 0,
            "different_scenarios": 0,
            "not_comparable_scenarios": 0,
            "differences": [],
        }
    if executable.get("status") == statuses.BLOCKED or docker.get("status") == statuses.BLOCKED:
        return {
            "status": statuses.BLOCKED,
            "reason": "At least one target did not produce fixture evidence.",
            "shared_scenarios": 0,
            "identical_scenarios": 0,
            "different_scenarios": 0,
            "not_comparable_scenarios": 0,
            "differences": [],
        }

    by_executable = {item["id"]: item for item in executable.get("tests", [])}
    by_docker = {item["id"]: item for item in docker.get("tests", [])}
    differences: list[dict] = []
    identical = 0
    not_comparable = 0
    shared = 0
    assertion_ids: set[str] = set()

    for case_id in sorted(set(by_executable) | set(by_docker)):
        left = by_executable.get(case_id)
        right = by_docker.get(case_id)
        if left is None or right is None:
            not_comparable += 1
            differences.append(
                {
                    "scenario": case_id,
                    "fields": ["presence"],
                    "executable": left is not None,
                    "docker": right is not None,
                }
            )
            continue
        if left.get("status") == statuses.NOT_APPLICABLE or right.get("status") == statuses.NOT_APPLICABLE:
            not_comparable += 1
            continue
        shared += 1
        fields: list[str] = []
        if left.get("status") != right.get("status"):
            fields.append("status")
        if left.get("actual_exit_code") != right.get("actual_exit_code"):
            fields.append("exit_code")
        if _findings(left) != _findings(right):
            fields.append("findings")
        left_assertions = _assertions(left)
        right_assertions = _assertions(right)
        common = set(left_assertions) & set(right_assertions)
        assertion_ids.update(common)
        changed_assertions = sorted(
            assertion_id
            for assertion_id in common
            if left_assertions[assertion_id] != right_assertions[assertion_id]
        )
        if changed_assertions:
            fields.append("assertions")
        if fields:
            differences.append(
                {
                    "scenario": case_id,
                    "fields": fields,
                    "executable": {
                        "status": left.get("status"),
                        "exit_code": left.get("actual_exit_code"),
                        "findings": [
                            dict(zip(_IDENTITY_FIELDS, item)) for item in _findings(left)
                        ],
                    },
                    "docker": {
                        "status": right.get("status"),
                        "exit_code": right.get("actual_exit_code"),
                        "findings": [
                            dict(zip(_IDENTITY_FIELDS, item)) for item in _findings(right)
                        ],
                    },
                    "changed_assertions": changed_assertions,
                }
            )
        else:
            identical += 1

    return {
        "status": statuses.FAIL if differences else statuses.PASS,
        "shared_scenarios": shared,
        "identical_scenarios": identical,
        "different_scenarios": sum(1 for item in differences if item["fields"] != ["presence"]),
        "not_comparable_scenarios": not_comparable,
        "assertions_compared": len(assertion_ids),
        "differences": differences,
        "reason": None,
    }


def compare_levain(executable: dict | None, docker: dict | None) -> dict:
    if not executable or not docker:
        return {
            "status": statuses.NOT_APPLICABLE,
            "reason": "Both executable and Docker Levain lanes must be selected and built.",
            "differences": [],
        }
    if (
        executable.get("status") == statuses.NOT_APPLICABLE
        or docker.get("status") == statuses.NOT_APPLICABLE
    ):
        return {
            "status": statuses.NOT_APPLICABLE,
            "reason": "Cross-target Levain comparison requires both target selections.",
            "differences": [],
        }
    if executable.get("status") == statuses.BLOCKED or docker.get("status") == statuses.BLOCKED:
        return {
            "status": statuses.BLOCKED,
            "reason": "At least one target did not produce Levain evidence.",
            "differences": [],
        }
    differences: list[dict] = []
    left_runs = {item["corpus"]: item for item in executable.get("runs", [])}
    right_runs = {item["corpus"]: item for item in docker.get("runs", [])}
    for corpus in sorted(set(left_runs) | set(right_runs)):
        left = left_runs.get(corpus)
        right = right_runs.get(corpus)
        if left is None or right is None:
            differences.append(
                {
                    "corpus": corpus,
                    "field": "presence",
                    "executable": left is not None,
                    "docker": right is not None,
                }
            )
            continue
        if left.get("status") != right.get("status"):
            differences.append(
                {
                    "corpus": corpus,
                    "field": "status",
                    "executable": left.get("status"),
                    "docker": right.get("status"),
                }
            )
        left_results = left.get("results") or {}
        right_results = right.get("results") or {}
        for key in (
            "false_positives",
            "duplicates",
            "sections_tripped",
            "true_positives",
            "expected_secrets",
            "partial_matches",
            "ambiguous_findings",
            "unexpected_findings",
            "findings_total",
        ):
            if left_results.get(key) != right_results.get(key):
                differences.append(
                    {
                        "corpus": corpus,
                        "field": key,
                        "executable": left_results.get(key),
                        "docker": right_results.get(key),
                    }
                )
    if executable.get("status") != docker.get("status"):
        differences.append(
            {
                "corpus": "overall",
                "field": "status",
                "executable": executable.get("status"),
                "docker": docker.get("status"),
            }
        )
    return {
        "status": statuses.FAIL if differences else statuses.PASS,
        "differences": differences,
        "reason": None,
    }
