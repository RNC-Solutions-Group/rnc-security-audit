#!/usr/bin/env python3
"""Aggregate compatible Docker acceptance executions by immutable image."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence import aggregate_executions
from .inventory_lock import reconcile_execution_inventory, verify_inventory_lock
from .validate import HARNESS_VERSION, REPO_ROOT, create_fixture_inventory_lock, git_value, harness_implementation_identity


BRAND = [
    "RRRRR  N   N  CCCCC",
    "R   R  NN  N  C",
    "RRRRR  N N N  C",
    "R  R   N  NN  C",
    "R   R  N   N  CCCCC",
]


def markdown_report(aggregate: dict[str, Any]) -> str:
    required = aggregate["required_fixture_count"]
    validated = aggregate["validated_fixture_count"]
    percent = 100.0 if required == 0 else validated * 100.0 / required
    rows = [
        "# RNC Solutions Group, Inc. | Gitleaks Cumulative Acceptance",
        "",
        "```text",
        *BRAND,
        "```",
        "",
        "**RNC Solutions Group, Inc.**<br>",
        "Turning Complexity into Clarity.<br>",
        "[www.rncsolutionsgroup.com](http://www.rncsolutionsgroup.com)<br>",
        "Contributed by: Dave Woods (@davidwoods15)",
        "",
        "## Aggregate Executive Summary",
        "",
        f"- Image ID: `{aggregate['image_id']}`",
        f"- Inventory digest: `{aggregate.get('fixture_inventory_digest', 'unknown')}`",
        f"- Harness identity: `{aggregate.get('harness_identity', 'unknown')}`",
        f"- Functional result: **{aggregate['functional_result']}**",
        f"- Coverage result: **{aggregate['coverage_result']}** ({validated}/{required}, {percent:.1f}%)",
        f"- Overall acceptance: **{aggregate['overall_acceptance']}**",
        f"- Physical fixtures: {aggregate['physical_fixture_discovered']} discovered; {aggregate['docker_validated_fixture_count']}/{aggregate['docker_applicable_fixture_count']} Docker-applicable validated",
        f"- INTERNAL_GO: {aggregate['internal_go_validated_count']}/{aggregate['internal_go_fixture_count']} validated; SUPPORTING: {aggregate['supporting_fixture_count']}",
        f"- Scenario bundles: {aggregate['scenario_bundle_validated_count']}/{aggregate['scenario_bundle_count']} validated",
        f"- Aggregator source commit: `{aggregate.get('aggregator_source_commit', 'unknown')}`",
        f"- Compatible executions: {len(aggregate['execution_ids'])}",
        "",
        "## Included Executions",
        "",
        "| Execution ID | Tag | Runtime | Source commit | Host | Generated |",
        "|---|---|---|---|---|---|",
    ]
    for execution in aggregate["included_executions"]:
        rows.append(
            f"| {execution['execution_id']} | {execution['tag']} | {execution['runtime']} | {execution['source_commit']} | "
            f"{execution['host']} / {execution['daemon']} | {execution['timestamp']} |"
        )
    rows.extend([
        "",
        "## Cumulative Assertion Results",
        "",
        "| Assertion | PASS | FAIL | Unsupported/Not Run |",
        "|---|---:|---:|---:|",
    ])
    for assertion_id, history in sorted(aggregate["assertion_history"].items()):
        rows.append(
            f"| {assertion_id} | {sum(item['status'] == 'PASS' for item in history)} | "
            f"{sum(item['status'] == 'FAIL' for item in history)} | "
            f"{sum(item['status'] not in ('PASS', 'FAIL') for item in history)} |"
        )
    rows.extend([
        "",
        "## Cumulative Physical Fixture Coverage",
        "",
        f"- Discovered: {aggregate['physical_fixture_discovered']}",
        f"- Docker-applicable: {aggregate['docker_applicable_fixture_count']}",
        f"- Docker-validated: {aggregate['docker_validated_fixture_count']}",
        f"- Exercised without individual proof: {aggregate['exercised_unvalidated_count']}",
        f"- Internal Go only: {aggregate['internal_go_fixture_count']} ({aggregate['internal_go_validated_count']} validated, {aggregate['internal_go_pending_count']} pending)",
        f"- Supporting: {aggregate['supporting_fixture_count']}",
        f"- Unsupported: {aggregate['unsupported_fixture_count']}",
        "",
        "| Classification | Physical fixtures |",
        "|---|---:|",
    ])
    classifications: dict[str, int] = {}
    for fixture in aggregate["fixtures"].values():
        if fixture.get("fixture_type") == "scenario-bundle":
            continue
        classification = fixture.get("classification", "UNKNOWN")
        classifications[classification] = classifications.get(classification, 0) + 1
    for classification, count in sorted(classifications.items()):
        rows.append(f"| {classification} | {count} |")
    rows.extend([
        "",
        "## Cumulative Scenario Coverage",
        "",
        f"- Scenario bundles: {aggregate['scenario_bundle_validated_count']} / {aggregate['scenario_bundle_count']} validated",
        f"- Scenario bundles unvalidated: {aggregate['scenario_bundle_unvalidated_count']}",
    ])
    rows.extend(["", f"Validated at least once: {validated} / {required}", "", "## Platform-Specific Results", "", "| Host / daemon | Executions | Fixture outcomes |", "|---|---:|---:|"])
    for platform, result in sorted(aggregate["platforms"].items()):
        validated_platform = sum(
            any(item["coverage_status"] == "VALIDATED" for item in outcomes)
            for outcomes in result["fixture_outcomes"].values()
        )
        rows.append(f"| {platform} | {len(result['execution_ids'])} | {validated_platform} validated fixture IDs |")
    rows.extend(["", "## Unresolved Failures", ""])
    if aggregate["unresolved_failures"]:
        for failure in aggregate["unresolved_failures"]:
            statuses = ", ".join(item["status"] for item in failure["history"])
            rows.append(f"- `{failure['assertion_id']}`: historical outcomes `{statuses}`; failure remains unresolved.")
    else:
        rows.append("NONE")
    rows.extend(["", "## Inventory Integrity", "", f"Status: **{aggregate.get('inventory_integrity_status', 'UNKNOWN')}**", ""])
    if aggregate.get("inventory_integrity_errors"):
        for error in aggregate["inventory_integrity_errors"]:
            rows.append(f"- {error}")
    else:
        rows.append("No inventory integrity errors.")
    rows.extend(["", "## Incompatible Executions", ""])
    if aggregate.get("incompatible_executions"):
        for item in aggregate["incompatible_executions"]:
            rows.append(f"- `{item.get('execution_id')}` image `{item.get('image_id')}`: {item.get('reason')}")
    else:
        rows.append("NONE")
    rows.extend([
        "",
        "## Aggregate Fixture Exclusions",
        "",
        f"Required fixtures: {required}",
        f"Validated at least once: {validated}",
        f"Never validated: {len(aggregate['unvalidated_fixtures'])}",
        "",
        "UNVALIDATED FIXTURES",
        "--------------------------------------------------",
    ])
    if aggregate["unvalidated_fixtures"]:
        for fixture in aggregate["unvalidated_fixtures"]:
            scenarios = ", ".join(fixture.get("scenarios", [])) or "none"
            rows.append(
                f"- `{fixture['path']}` | {fixture['classification']} | "
                f"{fixture.get('aggregate_exclusion_reason', '')} | scenarios: {scenarios}"
            )
    else:
        rows.append("NONE")
    rows.extend(["", "UNVALIDATED SCENARIO BUNDLES", "--------------------------------------------------"])
    if aggregate["unvalidated_scenario_bundles"]:
        for bundle in aggregate["unvalidated_scenario_bundles"]:
            rows.append(f"- `{bundle['path']}` | scenarios: {', '.join(bundle.get('scenarios', [])) or 'none'}")
    else:
        rows.append("NONE")
    rows.extend([
        "",
        f"AGGREGATE COVERAGE: {aggregate['coverage_result']} ({validated}/{required}, {percent:.1f}%)",
        f"OVERALL ACCEPTANCE: {aggregate['overall_acceptance']}",
        "",
        f"Generated: {aggregate['generated_utc']}",
    ])
    return "\n".join(rows) + "\n"


def read_execution_reports(reports_dir: Path) -> tuple[list[dict[str, Any]], list[str]]:
    executions: list[dict[str, Any]] = []
    invalid_reports: list[str] = []
    for path in sorted((reports_dir / "runs").glob("*/execution.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            invalid_reports.append(f"{path}: unreadable or invalid JSON")
            continue
        if (
            not isinstance(data, dict)
            or not data
            or not data.get("execution_id")
            or not isinstance(data.get("image"), dict)
            or not data.get("image", {}).get("image_id")
        ):
            invalid_reports.append(f"{path}: missing execution ID or immutable image metadata")
            continue
        executions.append(data)
    execution_ids = [item.get("execution_id") for item in executions]
    duplicates = sorted({item for item in execution_ids if execution_ids.count(item) > 1})
    invalid_reports.extend(f"duplicate execution ID: {item}" for item in duplicates)
    return executions, invalid_reports


def aggregate_groups(
    executions: list[dict[str, Any]],
    image_id: str | None,
    inventory_lock: dict[str, Any],
    harness_version: str,
    harness_identity: str,
    invalid_reports: list[str] | None = None,
) -> list[dict[str, Any]]:
    invalid_reports = invalid_reports or []
    image_ids = sorted({
        execution.get("image", {}).get("image_id")
        for execution in executions
        if execution.get("image", {}).get("image_id") and (not image_id or execution["image"]["image_id"] == image_id)
    })
    outputs = []
    for actual_image_id in image_ids:
        candidates = [item for item in executions if item.get("image", {}).get("image_id") == actual_image_id]
        compatible: list[dict[str, Any]] = []
        incompatible: list[dict[str, Any]] = []
        integrity_errors = [f"invalid execution report: {item}" for item in invalid_reports]
        for execution in candidates:
            base_identity_matches = (
                execution.get("manifest_digest") == inventory_lock.get("manifest_digest")
                and execution.get("fixture_source_revision") == inventory_lock.get("fixture_source_revision")
                and execution.get("harness_version") == harness_version
                and execution.get("harness_identity") == harness_identity
            )
            if not base_identity_matches:
                incompatible.append({
                    "execution_id": execution.get("execution_id"),
                    "image_id": actual_image_id,
                    "reason": "manifest, fixture revision, harness version, or implementation identity differs",
                })
                continue
            if (
                execution.get("report_version") != 2
                or execution.get("manifest_version") != inventory_lock.get("manifest_version")
                or execution.get("inventory_lock_version") != inventory_lock.get("lock_version")
                or execution.get("fixture_inventory_digest") != inventory_lock.get("inventory_digest")
            ):
                integrity_errors.append(f"{execution.get('execution_id')}: current-identity report has invalid schema or inventory digest")
                continue
            report_errors = reconcile_execution_inventory(
                execution,
                inventory_lock["entries"],
                inventory_lock,
                harness_identity,
            )
            if report_errors:
                integrity_errors.extend(f"{execution.get('execution_id')}: {error}" for error in report_errors)
                continue
            compatible.append(execution)

        summary = aggregate_executions(
            compatible,
            actual_image_id,
            inventory_lock,
            harness_version,
            harness_identity,
            integrity_errors,
            incompatible,
        )
        latest = compatible[-1] if compatible else candidates[-1]
        summary["report_version"] = 1
        summary["image"] = latest.get("image", {})
        summary["manifest_version"] = inventory_lock.get("manifest_version")
        summary["inventory_lock_version"] = inventory_lock.get("lock_version")
        summary["fixture_inventory_digest"] = inventory_lock.get("inventory_digest")
        summary["generated_utc"] = datetime.now(timezone.utc).isoformat()
        summary["source_commits"] = sorted({item.get("environment", {}).get("source_commit", "unknown") for item in compatible})
        summary["included_executions"] = [
            {
                "execution_id": item.get("execution_id"),
                "tag": item.get("image", {}).get("requested_tag", "unknown"),
                "runtime": item.get("runtime", {}).get("version_output") or "unavailable",
                "host": item.get("environment", {}).get("host_system", "unknown"),
                "daemon": item.get("environment", {}).get("docker_daemon_platform", "unknown"),
                "source_commit": item.get("environment", {}).get("source_commit", "unknown"),
                "source_worktree_clean": item.get("environment", {}).get("source_worktree_clean"),
                "timestamp": item.get("environment", {}).get("timestamp_utc", "unknown"),
            }
            for item in compatible
        ]
        for fixture in summary["unvalidated_fixtures"]:
            if fixture.get("failed_execution_ids"):
                fixture["aggregate_exclusion_reason"] = "A required assertion failed in one or more executions; no resolution record exists."
            elif fixture.get("unsupported_execution_ids"):
                fixture["aggregate_exclusion_reason"] = "Scenario was unsupported and the fixture has no successful assertion."
            else:
                fixture["aggregate_exclusion_reason"] = "No compatible execution has a successful fixture-specific assertion."
        outputs.append(summary)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate compatible Gitleaks Docker acceptance executions by immutable image.")
    parser.add_argument("--reports-dir", type=Path, default=Path(__file__).resolve().parent / "reports")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parent / "cases.json")
    parser.add_argument("--inventory-lock", type=Path, default=Path(__file__).resolve().parent / "fixture-inventory.lock.json")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--image-id", help="aggregate only this exact immutable Docker image ID")
    args = parser.parse_args()

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        inventory_lock = json.loads(args.inventory_lock.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"Cannot load pinned manifest or fixture inventory lock: {exc}")
        return 1

    source_revision = git_value("merge-base", "HEAD", "origin/master")
    if not source_revision:
        print("Cannot verify the fixture source revision: origin/master merge base is unavailable.")
        return 1
    expected_lock = create_fixture_inventory_lock(manifest, source_revision)
    lock_errors = verify_inventory_lock(inventory_lock, expected_lock)
    if lock_errors:
        print("Fixture inventory lock integrity failure:")
        for error in lock_errors:
            print(f"- {error}")
        return 1

    reports, invalid_reports = read_execution_reports(args.reports_dir)
    if invalid_reports and not reports:
        print("No valid execution reports; refusing to aggregate:")
        for error in invalid_reports:
            print(f"- {error}")
        return 1
    current_identity = harness_implementation_identity()
    aggregates = aggregate_groups(
        reports,
        args.image_id,
        inventory_lock,
        HARNESS_VERSION,
        current_identity,
        invalid_reports,
    )
    if not aggregates:
        print("No execution reports found for the requested image.")
        return 2

    repository_root = Path(__file__).resolve().parent.parent
    commit_result = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    status_result = subprocess.run(
        ["git", "-C", str(repository_root), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    aggregator_commit = commit_result.stdout.strip() if commit_result.returncode == 0 else None
    aggregator_tree_clean = status_result.returncode == 0 and not status_result.stdout.strip()

    output_dir = args.output_dir or args.reports_dir / "aggregates"
    output_dir.mkdir(parents=True, exist_ok=True)
    for aggregate in aggregates:
        aggregate["aggregator_source_commit"] = aggregator_commit
        aggregate["aggregator_worktree_clean"] = aggregator_tree_clean
        image_suffix = re.sub(r"[^A-Za-z0-9]+", "", aggregate["image_id"])[-12:]
        harness_suffix = re.sub(r"[^A-Za-z0-9]+", "", aggregate["harness_version"])
        file_stem = f"{image_suffix}-{aggregate['manifest_digest'][:12]}-{aggregate['fixture_source_revision'][:8]}-{harness_suffix}"
        json_path = output_dir / f"{file_stem}.json"
        markdown_path = output_dir / f"{file_stem}.md"
        json_path.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        markdown_path.write_text(markdown_report(aggregate), encoding="utf-8")
        print(f"{aggregate['image_id']} {aggregate['overall_acceptance']} {aggregate['validated_fixture_count']}/{aggregate['required_fixture_count']}")
        print(f"  JSON: {json_path}")
        print(f"  Markdown: {markdown_path}")

    if any(item["overall_acceptance"] == "FAIL" for item in aggregates):
        return 1
    if any(item["overall_acceptance"] != "PASS" for item in aggregates):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())