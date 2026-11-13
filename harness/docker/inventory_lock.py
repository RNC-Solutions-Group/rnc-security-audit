#!/usr/bin/env python3
"""Deterministic fixture inventory locking and integrity checks."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

LOCK_VERSION = 2
PHYSICAL_TYPES = {"missing-pattern"}
LOCKED_FIELDS = (
    "fixture_id",
    "path",
    "origin",
    "source_revision",
    "content_sha256",
    "git_mode",
    "git_blob_id",
    "git_content_sha256",
    "link_target",
    "fixture_type",
    "purpose",
    "expected_behavior",
    "scenarios",
    "required_assertions",
    "validation_method",
    "classification",
    "upstream_tests",
)


def canonical_digest(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fixture_content_sha256(path: Path) -> str:
    if path.is_symlink():
        content = os.readlink(path).encode("utf-8", errors="surrogateescape")
    else:
        content = path.read_bytes()
    return hashlib.sha256(content).hexdigest()


def git_fixture_metadata(repository_root: Path, source_revision: str | None, relative_path: str) -> dict[str, Any]:
    if not source_revision:
        return {"git_mode": None, "git_blob_id": None, "link_target": None, "git_content_sha256": None}
    tree = subprocess.run(
        ["git", "-C", str(repository_root), "ls-tree", source_revision, "--", relative_path],
        capture_output=True,
        check=False,
    )
    if tree.returncode != 0 or not tree.stdout.strip():
        return {"git_mode": None, "git_blob_id": None, "link_target": None, "git_content_sha256": None}
    header = tree.stdout.split(b"\t", 1)[0].decode("ascii", errors="replace").split()
    if len(header) != 3:
        return {"git_mode": None, "git_blob_id": None, "link_target": None, "git_content_sha256": None}
    mode, object_type, blob_id = header
    result: dict[str, Any] = {
        "git_mode": mode,
        "git_blob_id": blob_id if object_type == "blob" else None,
        "link_target": None,
        "git_content_sha256": None,
    }
    if object_type == "blob":
        blob = subprocess.run(
            ["git", "-C", str(repository_root), "cat-file", "blob", f"{source_revision}:{relative_path}"],
            capture_output=True,
            check=False,
        )
        if blob.returncode == 0:
            result["git_content_sha256"] = hashlib.sha256(blob.stdout).hexdigest()
        else:
            return {"git_mode": None, "git_blob_id": None, "link_target": None, "git_content_sha256": None}
        if mode == "120000":
            result["link_target"] = blob.stdout.decode("utf-8", errors="surrogateescape")
    return result


def discover_fixture_ids(repository_root: Path, build_dir: Path) -> set[str]:
    discovered: set[str] = set()
    roots = (("upstream", repository_root / "testdata"), ("synthetic", build_dir / "fixtures"))
    for origin, root in roots:
        for path in root.rglob("*"):
            if path.is_file() or path.is_symlink():
                relative = path.relative_to(root).as_posix()
                if origin == "synthetic":
                    relative = f"fixtures/{relative}"
                else:
                    relative = f"testdata/{relative}"
                discovered.add(f"{origin}:{relative}")
    return discovered


def build_inventory_lock(
    manifest: dict[str, Any],
    entries: list[dict[str, Any]],
    repository_root: Path,
    build_dir: Path,
    fixture_source_revision: str | None,
    manifest_digest: str,
) -> dict[str, Any]:
    integrity_errors: list[str] = []
    rule_owners: dict[str, int] = {}
    scenario_ids = {case.get("id") for case in manifest.get("cases", [])}
    # Detect accidental overlapping globs; intentional precedence must be declared in the manifest.
    for rule_index, rule in enumerate(manifest.get("inventory", [])):
        referenced_scenarios = list(rule.get("tests", []))
        for scenarios in rule.get("scenario_fixtures", {}).values():
            referenced_scenarios.extend(scenarios)
        unknown_scenarios = sorted(set(referenced_scenarios) - scenario_ids)
        if unknown_scenarios:
            integrity_errors.append(
                f"inventory rule {rule_index} references unknown scenarios: {', '.join(unknown_scenarios)}"
            )
        root_name = rule.get("root", "repo")
        root = repository_root if root_name == "repo" else build_dir
        for path in sorted(root.glob(rule["glob"])):
            if not (path.is_file() or path.is_symlink()):
                continue
            origin = "upstream" if root_name == "repo" else "synthetic"
            fixture_key = f"{origin}:{path.relative_to(root).as_posix()}"
            previous = rule_owners.get(fixture_key)
            if previous is not None and not rule.get("override", False):
                integrity_errors.append(f"duplicate manifest coverage for {fixture_key} in rules {previous} and {rule_index}")
            rule_owners[fixture_key] = rule_index

    fixture_records = [dict(entry) for entry in entries]
    ids = [entry.get("fixture_id") for entry in fixture_records]
    if len(ids) != len(set(ids)):
        integrity_errors.append("expanded fixture inventory contains duplicate fixture IDs")
    if any(entry.get("fixture_type") == "missing-pattern" for entry in fixture_records):
        integrity_errors.append("one or more manifest inventory patterns have no matching fixture")

    physical_records = [entry for entry in fixture_records if entry.get("fixture_type") != "scenario-bundle"]
    expected_file_ids = {entry["fixture_id"] for entry in physical_records}
    discovered = discover_fixture_ids(repository_root, build_dir)
    missing_from_manifest = sorted(discovered - expected_file_ids)
    unexpected_in_manifest = sorted(expected_file_ids - discovered)
    if missing_from_manifest:
        integrity_errors.append("fixtures missing from manifest: " + ", ".join(missing_from_manifest))
    if unexpected_in_manifest:
        integrity_errors.append("manifest paths missing from checkout: " + ", ".join(unexpected_in_manifest))

    physical_by_id: dict[str, dict[str, Any]] = {}
    for entry in physical_records:
        origin = entry.get("origin")
        base = repository_root if origin == "upstream" else build_dir
        path = base / entry["path"]
        if not path.exists() and not path.is_symlink():
            integrity_errors.append(f"fixture path does not exist: {entry.get('fixture_id')}")
            continue
        git_metadata = git_fixture_metadata(repository_root, fixture_source_revision, entry["path"]) if entry["origin"] == "upstream" else {
            "git_mode": None,
            "git_blob_id": None,
            "link_target": None,
            "git_content_sha256": None,
        }
        if origin == "upstream" and git_metadata.get("git_content_sha256"):
            content_sha256 = git_metadata["git_content_sha256"]
        else:
            content_sha256 = fixture_content_sha256(path)
        entry["content_sha256"] = content_sha256
        entry.update(git_metadata)
        entry["source_revision"] = (
            fixture_source_revision if origin == "upstream" else f"sha256:{content_sha256}"
        )
        physical_by_id[entry["fixture_id"]] = entry

    for entry in fixture_records:
        if entry.get("fixture_type") != "scenario-bundle":
            continue
        bundle_origin = entry["origin"]
        prefix = entry["path"].rstrip("/") + "/"
        children = sorted(
            (item["path"], item.get("content_sha256", ""))
            for item in physical_by_id.values()
            if item["origin"] == bundle_origin and item["path"].startswith(prefix)
        )
        if not children:
            integrity_errors.append(f"scenario bundle has no physical fixture members: {entry['fixture_id']}")
        entry["source_revision"] = f"sha256:{canonical_digest(children)}"
        entry["content_sha256"] = None

    fixture_ids = {entry["fixture_id"] for entry in fixture_records}
    required_assertions: dict[str, set[str]] = {fixture_id: set() for fixture_id in fixture_ids}

    def fixture_reference_id(reference: str | None, case: dict[str, Any]) -> str | None:
        if not reference:
            return None
        if reference.startswith("upstream:") or reference.startswith("synthetic:"):
            return reference.rstrip("/")
        value = reference.replace("\\", "/")
        if value.startswith("../testdata/"):
            value = value[len("../"):]
        if value.startswith("testdata/"):
            return f"upstream:{value.split('!', 1)[0].rstrip('/')}"
        if value.startswith("../local/"):
            value = value[len("../"):]
        if value.startswith("local/"):
            return f"synthetic:fixtures/{value[len('local/'):].split('!', 1)[0].rstrip('/')}"
        if value.startswith("fixtures/"):
            return f"synthetic:{value.rstrip('/')}"
        source = str(case.get("source", ""))
        if source.startswith("testdata/") and not str(case.get("fixture", "")).endswith("/"):
            candidate = f"upstream:{source.rstrip('/')}/{value}".rstrip("/")
            return candidate if candidate in fixture_ids else None
        return None

    case_by_id = {case.get("id"): case for case in manifest.get("cases", [])}
    for case in manifest.get("cases", []):
        case_id = case.get("id")
        if not case_id:
            continue
        fallback_id = fixture_reference_id(str(case.get("fixture", "")), case)
        bundle_id = None
        if str(case.get("fixture", "")).endswith("/"):
            bundle_id = fallback_id

        assertion_targets: dict[str, set[str]] = {}
        expected_findings = case.get("expected_findings", [])
        for index, finding in enumerate(expected_findings, 1):
            assertion_id = f"{case_id}.finding.{index}"
            refs = {
                fixture_reference_id(finding.get("fixture_id"), case),
                fixture_reference_id(finding.get("file"), case),
                fixture_reference_id(finding.get("symlink_file"), case),
            }
            assertion_targets[assertion_id] = {ref for ref in refs if ref in fixture_ids}

        common_ids = [f"{case_id}.finding_count", f"{case_id}.no_unexpected_findings"]
        if not case.get("expect_config_error"):
            common_ids.extend([f"{case_id}.json_report", f"{case_id}.exit_code"])
        elif case.get("expected_exit_code") is not None:
            common_ids = [f"{case_id}.exit_code", f"{case_id}.config_error"]
        for assertion_id in common_ids:
            if fallback_id in fixture_ids:
                assertion_targets[assertion_id] = {fallback_id}

        for index, finding in enumerate(case.get("forbidden_findings", []), 1):
            assertion_id = f"{case_id}.forbidden_finding.{index}"
            target = fixture_reference_id(finding.get("fixture_id"), case) or fixture_reference_id(finding.get("file"), case)
            assertion_targets[assertion_id] = {target} if target in fixture_ids else set()

        if case.get("gitleaks_ignore_path"):
            ignore = fixture_reference_id(
                case["gitleaks_ignore_path"].rstrip("/") + "/.gitleaksignore", case
            )
            suppression_ids = [
                assertion_id for assertion_id, targets in assertion_targets.items()
                if assertion_id.startswith(f"{case_id}.forbidden_finding.")
            ]
            if ignore in fixture_ids:
                for assertion_id in suppression_ids:
                    assertion_targets[assertion_id].add(ignore)

        if case.get("baseline_path"):
            baseline_id = fixture_reference_id(case["baseline_path"], case)
            assertion_id = f"{case_id}.baseline_suppression"
            assertion_targets[assertion_id] = {baseline_id} if baseline_id in fixture_ids else set()

        for index, _ in enumerate(case.get("assert_stderr_contains", []), 1):
            assertion_id = f"{case_id}.traversal.{index}"
            if fallback_id in fixture_ids:
                assertion_targets[assertion_id] = {fallback_id}

        for assertion_id, targets in assertion_targets.items():
            for target in targets:
                required_assertions[target].add(assertion_id)
        if bundle_id in fixture_ids:
            for assertion_id in assertion_targets:
                required_assertions[bundle_id].add(assertion_id)

    for entry in fixture_records:
        entry["required_assertions"] = sorted(required_assertions[entry["fixture_id"]])

    lock_entries = [
        {field: entry.get(field) for field in LOCKED_FIELDS}
        for entry in sorted(fixture_records, key=lambda item: item["fixture_id"])
    ]
    lock_body = {
        "lock_version": LOCK_VERSION,
        "manifest_version": manifest.get("manifest_version"),
        "manifest_digest": manifest_digest,
        "fixture_source_revision": fixture_source_revision,
        "entries": lock_entries,
    }
    lock_body["inventory_digest"] = canonical_digest(lock_body)
    return {**lock_body, "integrity_errors": integrity_errors}


def verify_inventory_lock(actual_lock: dict[str, Any], expected_lock: dict[str, Any]) -> list[str]:
    errors = list(expected_lock.get("integrity_errors", []))
    if actual_lock.get("lock_version") != LOCK_VERSION:
        errors.append("fixture inventory lock version is unsupported")
    for field in ("manifest_version", "manifest_digest", "fixture_source_revision", "inventory_digest"):
        if actual_lock.get(field) != expected_lock.get(field):
            errors.append(f"fixture inventory lock mismatch: {field}")
    if actual_lock.get("entries") != expected_lock.get("entries"):
        errors.append("fixture inventory lock entries differ from the current manifest/source tree")
    if actual_lock.get("integrity_errors"):
        errors.extend(actual_lock["integrity_errors"])
    return sorted(set(errors))


def reconcile_execution_inventory(
    execution: dict[str, Any],
    required_entries: list[dict[str, Any]],
    expected_lock: dict[str, Any],
    expected_harness_identity: str,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(execution, dict) or not execution:
        return ["execution report is empty or malformed"]
    if execution.get("report_version") != 2:
        errors.append("execution report schema is unsupported")
    if execution.get("inventory_lock_version") != expected_lock.get("lock_version"):
        errors.append("execution inventory lock version is incompatible")
    if not execution.get("execution_id"):
        errors.append("execution report has no execution ID")
    if not execution.get("image", {}).get("image_id"):
        errors.append("execution report has no immutable image ID")
    if not execution.get("environment", {}).get("source_commit"):
        errors.append("execution report has no source commit provenance")
    if execution.get("manifest_version") != expected_lock.get("manifest_version"):
        errors.append("execution manifest version is incompatible with the pinned lock")
    if execution.get("harness_identity") != expected_harness_identity:
        errors.append("execution harness implementation identity is incompatible")
    if execution.get("manifest_digest") != expected_lock["manifest_digest"]:
        errors.append("execution manifest digest is incompatible with the pinned inventory lock")
    if execution.get("fixture_inventory_digest") != expected_lock["inventory_digest"]:
        errors.append("execution fixture inventory digest is incompatible with the pinned inventory lock")
    if execution.get("fixture_source_revision") != expected_lock["fixture_source_revision"]:
        errors.append("execution fixture source revision is incompatible with the pinned inventory lock")

    actual_entries = execution.get("fixture_coverage")
    if not isinstance(actual_entries, list):
        return errors + ["execution fixture inventory is missing or is not a list"]
    actual_ids = [entry.get("fixture_id") for entry in actual_entries if isinstance(entry, dict)]
    if len(actual_ids) != len(actual_entries):
        errors.append("execution fixture inventory contains malformed entries")
    if len(actual_ids) != len(set(actual_ids)):
        errors.append("execution fixture inventory contains duplicate fixture IDs")

    expected_by_id = {entry["fixture_id"]: entry for entry in required_entries}
    actual_by_id = {entry.get("fixture_id"): entry for entry in actual_entries if isinstance(entry, dict)}
    missing = sorted(set(expected_by_id) - set(actual_by_id))
    unexpected = sorted(set(actual_by_id) - set(expected_by_id))
    if missing:
        errors.append("execution omitted required fixture IDs: " + ", ".join(missing))
    if unexpected:
        errors.append("execution contains unexpected fixture IDs: " + ", ".join(unexpected))

    assertions = execution.get("assertions")
    if not isinstance(assertions, list):
        return errors + ["execution assertions are missing or are not a list"]
    assertion_ids = [item.get("assertion_id") for item in assertions if isinstance(item, dict)]
    if len(assertion_ids) != len(assertions):
        errors.append("execution contains malformed assertion entries")
    if len(assertion_ids) != len(set(assertion_ids)):
        errors.append("execution contains duplicate assertion IDs")
    assertions_by_id = {item.get("assertion_id"): item for item in assertions if isinstance(item, dict)}
    allowed_assertion_statuses = {"PASS", "FAIL", "UNSUPPORTED", "NOT RUN", "BUILD FAILED"}
    for assertion in assertions_by_id.values():
        if assertion.get("status") not in allowed_assertion_statuses:
            errors.append(f"assertion {assertion.get('assertion_id')} has an invalid status")

    scenarios = execution.get("tests")
    if not isinstance(scenarios, list):
        return errors + ["execution scenario results are missing or are not a list"]
    scenario_ids = [scenario.get("id") for scenario in scenarios if isinstance(scenario, dict)]
    if len(scenario_ids) != len(scenarios) or len(scenario_ids) != len(set(scenario_ids)):
        errors.append("execution contains malformed or duplicate scenario records")
    scenario_failures = [scenario for scenario in scenarios if scenario.get("status") in ("FAIL", "ERROR")]
    assertion_failures = [assertion for assertion in assertions_by_id.values() if assertion.get("status") == "FAIL"]
    if (scenario_failures or assertion_failures) and execution.get("functional_result") != "FAIL":
        errors.append("execution claims functional success despite failed scenario/assertion evidence")
    if execution.get("functional_result") == "FAIL" and not (scenario_failures or assertion_failures):
        errors.append("execution claims functional failure without a failed scenario or assertion")

    for fixture_id, actual in actual_by_id.items():
        expected = expected_by_id.get(fixture_id)
        if expected is None:
            continue
        for field in LOCKED_FIELDS:
            if actual.get(field) != expected.get(field):
                errors.append(f"fixture record {fixture_id} has inconsistent {field}")
        if actual.get("classification") == "INTERNAL_GO" and actual.get("coverage_status") in ("VALIDATED", "GO_TEST_VALIDATED"):
            errors.append(f"INTERNAL_GO fixture {fixture_id} cannot be validated by Docker evidence")
        allowed_statuses = {
            "ASSERTABLE": {"VALIDATED", "FAILED", "UNSUPPORTED", "UNTESTED", "EXERCISED"},
            "EXERCISED": {"VALIDATED", "FAILED", "UNSUPPORTED", "UNTESTED", "EXERCISED"},
            "UNTESTED": {"VALIDATED", "FAILED", "UNSUPPORTED", "UNTESTED", "EXERCISED"},
            "UNSUPPORTED": {"VALIDATED", "FAILED", "UNSUPPORTED", "UNTESTED", "EXERCISED"},
            "INTERNAL_GO": {"INTERNAL_GO_NOT_RUN"},
            "SUPPORTING": {"SUPPORTING"},
        }
        if actual.get("coverage_status") not in allowed_statuses.get(actual.get("classification"), set()):
            errors.append(f"fixture {fixture_id} has invalid coverage status for its classification")
        if actual.get("coverage_status") == "VALIDATED":
            required_assertions = actual.get("required_assertions")
            if not isinstance(required_assertions, list) or not required_assertions:
                errors.append(f"fixture {fixture_id} claims VALIDATED without required assertion IDs")
                continue
            fixture_assertions = []
            for assertion_id in required_assertions:
                assertion = assertions_by_id.get(assertion_id)
                if assertion is None:
                    errors.append(f"fixture {fixture_id} references missing assertion {assertion_id}")
                    continue
                if assertion.get("status") != "PASS":
                    errors.append(f"fixture {fixture_id} assertion {assertion_id} is not PASS")
                related_ids = set(assertion.get("related_fixture_ids", []))
                related_ids.add(assertion.get("fixture_id"))
                scenario_bundle = actual.get("fixture_type") == "scenario-bundle"
                scenario_linked = scenario_bundle and any(assertion_id.startswith(f"{scenario}.") for scenario in actual.get("scenarios", []))
                if fixture_id not in related_ids and not scenario_linked:
                    errors.append(f"fixture {fixture_id} is not linked to assertion {assertion_id}")
                fixture_assertions.append(assertion)
            if not fixture_assertions:
                errors.append(f"fixture {fixture_id} has no passing fixture-specific assertion evidence")

    physical_entries = [entry for entry in required_entries if entry.get("fixture_type") != "scenario-bundle"]
    bundle_entries = [entry for entry in required_entries if entry.get("fixture_type") == "scenario-bundle"]
    expected_physical_count = len(physical_entries)
    expected_bundle_count = len(bundle_entries)
    applicable_entries = [
        entry for entry in physical_entries
        if entry.get("classification") in {"ASSERTABLE", "EXERCISED", "INTERNAL_GO", "UNTESTED", "UNSUPPORTED"}
    ]
    docker_entries = [entry for entry in applicable_entries if entry.get("classification") != "INTERNAL_GO"]
    validated_fixtures = sum(
        actual_by_id.get(entry["fixture_id"], {}).get("coverage_status") in ("VALIDATED", "GO_TEST_VALIDATED")
        for entry in applicable_entries
    )
    docker_validated = sum(
        actual_by_id.get(entry["fixture_id"], {}).get("coverage_status") == "VALIDATED"
        for entry in docker_entries
    )
    internal_go_validated = sum(
        actual_by_id.get(entry["fixture_id"], {}).get("coverage_status") == "GO_TEST_VALIDATED"
        for entry in physical_entries if entry.get("classification") == "INTERNAL_GO"
    )
    supporting_count = sum(entry.get("classification") == "SUPPORTING" for entry in physical_entries)
    scenario_bundle_validated = sum(
        actual_by_id.get(entry["fixture_id"], {}).get("coverage_status") == "VALIDATED"
        for entry in bundle_entries
    )
    summary = execution.get("summary")
    if not isinstance(summary, dict):
        errors.append("execution summary is missing or malformed")
    else:
        expected_summary = {
            "physical_fixture_discovered": expected_physical_count,
            "applicable_fixtures": len(applicable_entries),
            "docker_applicable_fixtures": len(docker_entries),
            "docker_validated_fixtures": docker_validated,
            "validated_fixtures": validated_fixtures,
            "internal_go_fixtures": sum(entry.get("classification") == "INTERNAL_GO" for entry in physical_entries),
            "internal_go_validated": internal_go_validated,
            "supporting_fixtures": supporting_count,
            "scenario_bundle_count": expected_bundle_count,
            "scenario_bundle_validated": scenario_bundle_validated,
            "scenario_bundle_failed": sum(actual_by_id.get(entry["fixture_id"], {}).get("coverage_status") == "FAILED" for entry in bundle_entries),
            "scenario_bundle_unvalidated": sum(actual_by_id.get(entry["fixture_id"], {}).get("coverage_status") != "VALIDATED" for entry in bundle_entries),
        }
        for field, expected_value in expected_summary.items():
            if summary.get(field) != expected_value:
                errors.append(f"execution summary {field} does not match the pinned fixture inventory and outcomes")

    expected_coverage = "PASS" if (
        applicable_entries
        and validated_fixtures == len(applicable_entries)
        and bundle_entries
        and scenario_bundle_validated == len(bundle_entries)
    ) else "INCOMPLETE"
    if execution.get("coverage_result") != expected_coverage:
        errors.append("execution coverage result does not match fixture and bundle outcomes")
    if execution.get("overall_acceptance") == "PASS":
        if execution.get("functional_result") != "PASS" or execution.get("coverage_result") != "PASS":
            errors.append("execution claims overall PASS without functional and coverage PASS")
        if execution.get("fixture_exclusions"):
            errors.append("execution claims overall PASS with fixture exclusions")

    for scenario in execution.get("tests", []):
        assertions_for_scenario = scenario.get("assertions")
        if not isinstance(assertions_for_scenario, list):
            errors.append(f"scenario {scenario.get('id', 'unknown')} has no assertion list")
            continue
        if scenario.get("status") == "PASS" and any(item.get("status") != "PASS" for item in assertions_for_scenario):
            errors.append(f"scenario {scenario.get('id', 'unknown')} is PASS but has a non-passing assertion")
        if scenario.get("status") in ("FAIL", "ERROR") and execution.get("functional_result") == "PASS":
            errors.append(f"execution claims functional PASS despite failed scenario {scenario.get('id', 'unknown')}")
    return sorted(set(errors))
