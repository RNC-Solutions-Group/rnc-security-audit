"""Pure helpers for fixture assertions and cumulative acceptance evidence."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .inventory_lock import reconcile_execution_inventory

IDENTITY_FIELDS = ("rule_id", "file", "commit", "start_line", "start_column", "secret_sha256")


def compare_findings(expected: list[dict[str, Any]], actual: list[dict[str, Any]]) -> dict[str, Any]:
    remaining = list(enumerate(actual))
    missing: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    matches: list[dict[str, Any]] = []

    for expected_finding in expected:
        candidate = next(
            (
                position for position, (_, observed) in enumerate(remaining)
                if all(
                    field not in expected_finding or expected_finding[field] == observed.get(field)
                    for field in IDENTITY_FIELDS
                )
            ),
            None,
        )
        if candidate is None:
            similar = next(
                (
                    position for position, (_, observed) in enumerate(remaining)
                    if expected_finding.get("rule_id") == observed.get("rule_id")
                    and expected_finding.get("file") == observed.get("file")
                    and expected_finding.get("commit", "") == observed.get("commit", "")
                ),
                None,
            )
            if similar is None:
                missing.append(expected_finding)
                continue
            _, observed = remaining.pop(similar)
            differences = {
                key: {"expected": value, "actual": observed.get(key)}
                for key, value in expected_finding.items()
                if key in observed and observed.get(key) != value
            }
            changed.append({"expected": expected_finding, "actual": observed, "differences": differences})
            continue

        _, observed = remaining.pop(candidate)
        differences = {
            key: {"expected": value, "actual": observed.get(key)}
            for key, value in expected_finding.items()
            if key in observed and observed.get(key) != value
        }
        match = {"expected": expected_finding, "actual": observed, "differences": differences}
        matches.append(match)
        if differences:
            changed.append(match)

    return {"missing": missing, "added": [item for _, item in remaining], "changed": changed, "matches": matches}


def evaluate_finding_assertions(
    case_id: str,
    expected: list[dict[str, Any]],
    actual: list[dict[str, Any]],
    forbidden: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    forbidden = forbidden or []
    comparison = compare_findings(expected, actual)
    assertions: list[dict[str, Any]] = []
    unmatched_expected = list(comparison["missing"])
    changed_expected = [item["expected"] for item in comparison["changed"]]
    for index, expected_finding in enumerate(expected, 1):
        public_expected = {key: value for key, value in expected_finding.items() if not key.startswith("_")}
        if expected_finding in unmatched_expected:
            status = "FAIL"
            observed = None
        elif expected_finding in changed_expected:
            status = "FAIL"
            observed = next(item["actual"] for item in comparison["changed"] if item["expected"] == expected_finding)
        else:
            status = "PASS"
            observed = next(
                (item["actual"] for item in comparison["matches"] if item["expected"] == expected_finding),
                None,
            )
        assertions.append({
            "assertion_id": f"{case_id}.finding.{index}",
            "type": "expected_finding",
            "fixture_id": expected_finding.get("fixture_id"),
            "related_fixture_ids": expected_finding.get("related_fixture_ids", []),
            "expected": public_expected,
            "actual": observed,
            "status": status,
        })

    assertions.append({
        "assertion_id": f"{case_id}.finding_count",
        "type": "finding_count",
        "expected": len(expected),
        "actual": len(actual),
        "status": "PASS" if len(expected) == len(actual) else "FAIL",
    })
    assertions.append({
        "assertion_id": f"{case_id}.no_unexpected_findings",
        "type": "no_unexpected_findings",
        "expected": 0,
        "actual": len(comparison["added"]),
        "status": "PASS" if not comparison["added"] else "FAIL",
    })

    unexpected_forbidden = [
        finding for finding in actual
        if any(all(finding.get(key) == value for key, value in spec.items() if key != "fixture_id") for spec in forbidden)
    ]
    for index, spec in enumerate(forbidden, 1):
        found = [
            finding for finding in actual
            if all(finding.get(key) == value for key, value in spec.items() if key != "fixture_id")
        ]
        assertions.append({
            "assertion_id": f"{case_id}.forbidden_finding.{index}",
            "type": "suppression_absence",
            "fixture_id": spec.get("fixture_id"),
            "expected": "suppressed",
            "actual": len(found),
            "status": "PASS" if not found else "FAIL",
        })
    return {**comparison, "unexpected_forbidden": unexpected_forbidden}, assertions


def fixture_exclusions(fixtures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    applicable = {"ASSERTABLE", "EXERCISED", "INTERNAL_GO", "UNTESTED", "UNSUPPORTED"}
    return [
        fixture for fixture in fixtures
        if fixture.get("fixture_type") != "scenario-bundle"
        and fixture.get("classification") in applicable
        and fixture.get("coverage_status") not in ("VALIDATED", "GO_TEST_VALIDATED")
    ]


def aggregate_executions(
    executions: list[dict[str, Any]],
    image_id: str,
    inventory_lock: dict[str, Any],
    harness_version: str,
    harness_identity: str,
    inventory_integrity_errors: list[str] | None = None,
    incompatible_executions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    compatible: list[dict[str, Any]] = []
    incompatible = list(incompatible_executions or [])
    integrity_errors = list(inventory_integrity_errors or [])
    manifest_digest = inventory_lock.get("manifest_digest")
    fixture_source_revision = inventory_lock.get("fixture_source_revision")
    for execution in executions:
        image = execution.get("image", {})
        key_matches = (
            image.get("image_id") == image_id
            and execution.get("manifest_digest") == inventory_lock.get("manifest_digest")
            and execution.get("fixture_source_revision") == inventory_lock.get("fixture_source_revision")
            and execution.get("fixture_inventory_digest") == inventory_lock.get("inventory_digest")
            and execution.get("harness_version") == harness_version
            and execution.get("harness_identity") == harness_identity
            and execution.get("manifest_version") == inventory_lock.get("manifest_version")
            and execution.get("inventory_lock_version") == inventory_lock.get("lock_version")
        )
        if not key_matches or execution.get("report_version") != 2:
            incompatible.append({
                "execution_id": execution.get("execution_id"),
                "image_id": image.get("image_id"),
                "reason": "image, manifest, fixture revision, or harness schema is incompatible",
            })
            continue
        report_errors = reconcile_execution_inventory(
            execution,
            inventory_lock["entries"],
            inventory_lock,
            harness_identity,
        )
        if report_errors:
            integrity_errors.extend(
                f"{execution.get('execution_id', 'unknown')}: {error}" for error in report_errors
            )
            continue
        compatible.append(execution)

    fixture_records: dict[str, dict[str, Any]] = {
        entry["fixture_id"]: {
            key: entry.get(key)
            for key in ("fixture_id", "path", "classification", "fixture_type", "expected_behavior", "scenarios", "required_assertions", "origin", "source_revision", "content_sha256")
        } | {"successful_execution_ids": [], "failed_execution_ids": [], "unsupported_execution_ids": []}
        for entry in inventory_lock.get("entries", [])
    }
    assertion_history: dict[str, list[dict[str, Any]]] = defaultdict(list)
    platforms: dict[str, dict[str, Any]] = {}
    for execution in compatible:
        environment = execution.get("environment", {})
        platform_key = " / ".join((environment.get("host_system", "unknown"), environment.get("docker_daemon_platform", "unknown")))
        platform_result = platforms.setdefault(platform_key, {"execution_ids": [], "fixture_outcomes": {}})
        platform_result["execution_ids"].append(execution.get("execution_id"))
        for assertion in execution.get("assertions", []):
            assertion_history[assertion.get("assertion_id", "unknown")].append({
                "execution_id": execution.get("execution_id"),
                "status": assertion.get("status"),
                "expected": assertion.get("expected"),
                "actual": assertion.get("actual"),
            })
        for fixture in execution.get("fixture_coverage", []):
            fixture_id = fixture["fixture_id"]
            current = fixture_records[fixture_id]
            if fixture.get("coverage_status") in ("VALIDATED", "GO_TEST_VALIDATED"):
                current["successful_execution_ids"].append(execution.get("execution_id"))
            elif fixture.get("coverage_status") == "FAILED":
                current["failed_execution_ids"].append(execution.get("execution_id"))
            elif fixture.get("coverage_status") == "UNSUPPORTED":
                current["unsupported_execution_ids"].append(execution.get("execution_id"))
            platform_result["fixture_outcomes"].setdefault(fixture_id, []).append({
                "execution_id": execution.get("execution_id"),
                "coverage_status": fixture.get("coverage_status"),
            })

    required = sorted(
        entry["fixture_id"] for entry in inventory_lock.get("entries", [])
        if entry.get("fixture_type") != "scenario-bundle"
        and entry.get("classification") in {"ASSERTABLE", "EXERCISED", "INTERNAL_GO", "UNTESTED", "UNSUPPORTED"}
    )
    validated = sorted(fixture_id for fixture_id in required if fixture_records[fixture_id]["successful_execution_ids"])
    physical_records = [
        fixture for fixture in fixture_records.values()
        if fixture.get("fixture_type") != "scenario-bundle"
    ]
    docker_required = [
        fixture_id for fixture_id in required
        if fixture_records[fixture_id].get("classification") != "INTERNAL_GO"
    ]
    scenario_bundles = [
        fixture for fixture in fixture_records.values()
        if fixture.get("fixture_type") == "scenario-bundle"
    ]
    unvalidated = [fixture_records[fixture_id] for fixture_id in required if fixture_id not in set(validated)]
    unvalidated_bundles = [fixture for fixture in scenario_bundles if not fixture["successful_execution_ids"]]
    internal_go = [fixture for fixture in physical_records if fixture.get("classification") == "INTERNAL_GO"]
    supporting = [fixture for fixture in physical_records if fixture.get("classification") == "SUPPORTING"]
    exercised = [
        fixture for fixture in physical_records
        if fixture.get("classification") == "EXERCISED" and not fixture["successful_execution_ids"]
    ]
    unsupported = [
        fixture for fixture in physical_records
        if fixture.get("unsupported_execution_ids") and not fixture["successful_execution_ids"]
    ]
    unresolved_failures = [
        {"assertion_id": assertion_id, "history": history}
        for assertion_id, history in assertion_history.items()
        if any(item["status"] == "FAIL" for item in history)
    ]
    physical_coverage_complete = bool(required) and len(validated) == len(required)
    scenario_coverage_complete = bool(scenario_bundles) and not unvalidated_bundles
    coverage_complete = physical_coverage_complete and scenario_coverage_complete
    functional_pass = not unresolved_failures
    integrity_errors = sorted(set(integrity_errors))
    overall = (
        "FAIL" if not functional_pass or integrity_errors
        else "INCOMPLETE" if incompatible
        else "PASS" if coverage_complete and not unvalidated
        else "INCOMPLETE"
    )
    return {
        "image_id": image_id,
        "manifest_digest": inventory_lock.get("manifest_digest"),
        "fixture_inventory_digest": inventory_lock.get("inventory_digest"),
        "fixture_source_revision": inventory_lock.get("fixture_source_revision"),
        "harness_version": harness_version,
        "harness_identity": harness_identity,
        "execution_ids": [item.get("execution_id") for item in compatible],
        "incompatible_executions": incompatible,
        "inventory_integrity_status": "PASS" if not integrity_errors else "FAIL",
        "inventory_integrity_errors": integrity_errors,
        "functional_result": "PASS" if functional_pass else "FAIL",
        "coverage_result": "PASS" if coverage_complete else "INCOMPLETE",
        "overall_acceptance": overall,
        "required_fixture_count": len(required),
        "validated_fixture_count": len(validated),
        "validated_fixture_ids": validated,
        "physical_fixture_discovered": len(physical_records),
        "docker_applicable_fixture_count": len(docker_required),
        "docker_validated_fixture_count": sum(fixture_records[fixture_id]["successful_execution_ids"] != [] for fixture_id in docker_required),
        "internal_go_fixture_count": len(internal_go),
        "internal_go_validated_count": sum(bool(fixture["successful_execution_ids"]) for fixture in internal_go),
        "internal_go_pending_count": sum(not fixture["successful_execution_ids"] for fixture in internal_go),
        "supporting_fixture_count": len(supporting),
        "exercised_unvalidated_count": len(exercised),
        "unsupported_fixture_count": len(unsupported),
        "scenario_bundle_count": len(scenario_bundles),
        "scenario_bundle_validated_count": sum(bool(fixture["successful_execution_ids"]) for fixture in scenario_bundles),
        "scenario_bundle_unvalidated_count": len(unvalidated_bundles),
        "fixtures": fixture_records,
        "unvalidated_fixtures": unvalidated,
        "unvalidated_scenario_bundles": unvalidated_bundles,
        "assertion_history": dict(assertion_history),
        "unresolved_failures": unresolved_failures,
        "platforms": platforms,
    }