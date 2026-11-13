#!/usr/bin/env python3
"""Self-tests for acceptance assertion and aggregation logic."""

from __future__ import annotations

import unittest

from .evidence import aggregate_executions, evaluate_finding_assertions, fixture_exclusions
from .aggregate import aggregate_groups, markdown_report as aggregate_markdown_report, read_execution_reports
from .inventory_lock import reconcile_execution_inventory, verify_inventory_lock
from .validate import compare_reports


def fixture_record(fixture_id: str, classification: str, coverage_status: str, assertion_id: str | None = None) -> dict:
    origin, path = fixture_id.split(":", 1)
    return {
        "fixture_id": fixture_id,
        "path": path,
        "origin": origin,
        "source_revision": "fixture-revision-a",
        "content_sha256": "content-hash",
        "fixture_type": "file",
        "purpose": "synthetic self-test fixture",
        "expected_behavior": "explicit test contract",
        "scenarios": ["case"],
        "required_assertions": [assertion_id] if assertion_id else [],
        "validation_method": "unit self-test",
        "classification": classification,
        "upstream_tests": [],
        "coverage_status": coverage_status,
    }


def inventory_lock(fixtures: list[dict]) -> dict:
    return {
        "lock_version": 2,
        "manifest_version": 2,
        "manifest_digest": "manifest-a",
        "fixture_source_revision": "fixture-revision-a",
        "inventory_digest": "inventory-a",
        "entries": [
            {key: value for key, value in item.items() if key != "coverage_status"}
            for item in fixtures
        ],
    }


def execution(image_id: str, fixture_rows: list[dict], assertions: list[dict], execution_id: str) -> dict:
    physical_count = sum(item.get("fixture_type") != "scenario-bundle" for item in fixture_rows)
    bundle_count = sum(item.get("fixture_type") == "scenario-bundle" for item in fixture_rows)
    applicable = [item for item in fixture_rows if item.get("fixture_type") != "scenario-bundle" and item.get("classification") in {"ASSERTABLE", "EXERCISED", "INTERNAL_GO", "UNTESTED", "UNSUPPORTED"}]
    docker = [item for item in applicable if item.get("classification") != "INTERNAL_GO"]
    validated = sum(item.get("coverage_status") in ("VALIDATED", "GO_TEST_VALIDATED") for item in applicable)
    docker_validated = sum(item.get("coverage_status") == "VALIDATED" for item in docker)
    bundle_validated = sum(item.get("coverage_status") == "VALIDATED" for item in fixture_rows if item.get("fixture_type") == "scenario-bundle")
    functional = "PASS" if all(item.get("status") == "PASS" for item in assertions) else "FAIL"
    coverage = "PASS" if applicable and validated == len(applicable) and bundle_count and bundle_validated == bundle_count else "INCOMPLETE"
    return {
        "report_version": 2,
        "manifest_version": 2,
        "inventory_lock_version": 2,
        "execution_id": execution_id,
        "image": {"image_id": image_id},
        "manifest_digest": "manifest-a",
        "fixture_inventory_digest": "inventory-a",
        "fixture_source_revision": "fixture-revision-a",
        "harness_version": "2.0.0",
        "harness_identity": "identity-a",
        "functional_result": functional,
        "coverage_result": coverage,
        "overall_acceptance": "FAIL" if functional == "FAIL" else "PASS" if coverage == "PASS" else "NOT COMPLETE",
        "fixture_exclusions": [],
        "summary": {
            "physical_fixture_discovered": physical_count,
            "applicable_fixtures": len(applicable),
            "docker_applicable_fixtures": len(docker),
            "docker_validated_fixtures": docker_validated,
            "validated_fixtures": validated,
            "internal_go_fixtures": sum(item.get("classification") == "INTERNAL_GO" for item in fixture_rows),
            "internal_go_validated": sum(item.get("coverage_status") == "GO_TEST_VALIDATED" for item in fixture_rows),
            "supporting_fixtures": sum(item.get("classification") == "SUPPORTING" for item in fixture_rows),
            "scenario_bundle_count": bundle_count,
            "scenario_bundle_validated": bundle_validated,
            "scenario_bundle_failed": 0,
            "scenario_bundle_unvalidated": bundle_count - bundle_validated,
        },
        "environment": {"host_system": "Linux", "docker_daemon_platform": "linux/x86_64", "source_commit": "source-a"},
        "fixture_coverage": fixture_rows,
        "assertions": assertions,
        "tests": [{"id": "case", "status": functional, "assertions": assertions}],
    }


class FindingAssertionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.expected = [{
            "rule_id": "aws-access-key",
            "file": "testdata/sample.go",
            "start_line": 4,
            "secret_sha256": "known-hash",
        }]

    def test_missing_expected_finding_fails(self) -> None:
        comparison, assertions = evaluate_finding_assertions("case", self.expected, [])
        self.assertEqual(len(comparison["missing"]), 1)
        self.assertEqual(assertions[0]["status"], "FAIL")

    def test_unexpected_finding_fails(self) -> None:
        actual = [{**self.expected[0], "file": "testdata/other.go"}]
        _, assertions = evaluate_finding_assertions("case", [], actual)
        self.assertEqual(assertions[0]["type"], "finding_count")
        self.assertEqual(assertions[-1]["status"], "FAIL")

    def test_wrong_rule_is_missing_and_unexpected(self) -> None:
        actual = [{**self.expected[0], "rule_id": "wrong-rule"}]
        comparison, assertions = evaluate_finding_assertions("case", self.expected, actual)
        self.assertEqual(len(comparison["missing"]), 1)
        self.assertEqual(len(comparison["added"]), 1)
        self.assertEqual(assertions[0]["status"], "FAIL")

    def test_incorrect_expected_count_fails(self) -> None:
        actual = [{**self.expected[0], "file": "testdata/one.go"}, {**self.expected[0], "file": "testdata/two.go"}]
        _, assertions = evaluate_finding_assertions("case", self.expected, actual)
        count_assertion = next(item for item in assertions if item["type"] == "finding_count")
        self.assertEqual(count_assertion["status"], "FAIL")

    def test_image_comparison_reports_exit_and_scenario_status_differences(self) -> None:
        baseline = {"image": {"image_id": "baseline"}, "environment": {}, "tests": [{
            "id": "case", "status": "PASS", "actual_exit_code": 0, "findings": [],
        }]}
        candidate = [{"id": "case", "status": "FAIL", "actual_exit_code": 1, "findings": []}]
        result = compare_reports(baseline, candidate)["tests"][0]
        self.assertEqual(result["parity_status"], "DIFFERENT")
        self.assertEqual(result["exit_code_difference"], {"baseline": 0, "candidate": 1})
        self.assertEqual(result["scenario_status_difference"], {"baseline": "PASS", "candidate": "FAIL"})

    def test_image_comparison_marks_unexecuted_case_na(self) -> None:
        baseline = {"image": {"image_id": "baseline"}, "environment": {}, "tests": [{
            "id": "case", "status": "UNSUPPORTED", "actual_exit_code": None, "findings": [],
        }]}
        candidate = [{"id": "case", "status": "PASS", "actual_exit_code": 0, "findings": []}]
        result = compare_reports(baseline, candidate)["tests"][0]
        self.assertEqual(result["status"], "N/A")
        self.assertIsNone(result["exit_code_difference"]["baseline"])


class CoverageAndAggregationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertion_a = {"assertion_id": "case.a", "fixture_id": "upstream:a", "status": "PASS", "expected": 1, "actual": 1}
        self.assertion_b = {"assertion_id": "case.b", "fixture_id": "upstream:b", "status": "PASS", "expected": 1, "actual": 1}
        self.fixture_a = fixture_record("upstream:a", "ASSERTABLE", "VALIDATED", "case.a")
        self.fixture_b = fixture_record("upstream:b", "ASSERTABLE", "UNTESTED", "case.b")
        self.lock = inventory_lock([self.fixture_a, self.fixture_b])

    def test_unvalidated_fixture_is_excluded(self) -> None:
        fixtures = [
            {"fixture_id": "upstream:a", "classification": "ASSERTABLE", "coverage_status": "UNTESTED"},
            {"fixture_id": "upstream:b", "classification": "SUPPORTING", "coverage_status": "SUPPORTING"},
            {"fixture_id": "upstream:c", "classification": "INTERNAL_GO", "coverage_status": "INTERNAL_GO_NOT_RUN"},
        ]
        self.assertEqual([item["fixture_id"] for item in fixture_exclusions(fixtures)], ["upstream:a", "upstream:c"])

    def test_missing_required_fixture_record_fails_closed(self) -> None:
        run = execution("image-a", [self.fixture_a], [self.assertion_a], "run-missing")
        result = aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["inventory_integrity_status"], "FAIL")
        self.assertEqual(result["overall_acceptance"], "FAIL")
        self.assertTrue(any("omitted required fixture IDs" in error for error in result["inventory_integrity_errors"]))

    def test_incomplete_execution_cannot_pass_aggregate_group(self) -> None:
        run = execution("image-a", [self.fixture_a], [self.assertion_a], "run-missing")
        aggregate = aggregate_groups([run], None, self.lock, "2.0.0", "identity-a")[0]
        self.assertEqual(aggregate["inventory_integrity_status"], "FAIL")
        self.assertEqual(aggregate["overall_acceptance"], "FAIL")
        self.assertEqual(aggregate["validated_fixture_count"], 0)
        self.assertEqual(aggregate["required_fixture_count"], 2)

    def test_duplicate_fixture_ids_fail_closed(self) -> None:
        run = execution("image-a", [self.fixture_a, self.fixture_a], [self.assertion_a], "run-duplicate")
        result = aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["overall_acceptance"], "FAIL")
        self.assertTrue(any("duplicate fixture IDs" in error for error in result["inventory_integrity_errors"]))

    def test_duplicate_fixture_ids_are_report_integrity_failure(self) -> None:
        run = execution("image-a", [self.fixture_a, self.fixture_a, self.fixture_b], [self.assertion_a], "run-duplicate")
        result = aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["inventory_integrity_status"], "FAIL")
        self.assertEqual(result["overall_acceptance"], "FAIL")

    def test_missing_and_unexpected_fixture_ids_fail_closed(self) -> None:
        missing = execution("image-a", [self.fixture_a], [self.assertion_a], "run-missing")
        unexpected = fixture_record("upstream:extra", "ASSERTABLE", "UNTESTED")
        extra = execution("image-a", [self.fixture_a, self.fixture_b, unexpected], [self.assertion_a], "run-extra")
        results = [aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a") for run in (missing, extra)]
        self.assertTrue(all(result["overall_acceptance"] == "FAIL" for result in results))

    def test_manifest_source_and_implementation_mismatches_are_incompatible(self) -> None:
        base = execution("image-a", [self.fixture_a, self.fixture_b], [self.assertion_a], "run-identity")
        for field, value in (
            ("manifest_digest", "different"),
            ("fixture_source_revision", "different"),
            ("harness_version", "different"),
            ("harness_identity", "different"),
            ("fixture_inventory_digest", "different"),
        ):
            run = {**base, field: value}
            result = aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a")
            self.assertEqual(result["execution_ids"], [])
            self.assertEqual(len(result["incompatible_executions"]), 1)

    def test_tampered_pinned_lock_is_rejected(self) -> None:
        tampered = {**self.lock, "entries": self.lock["entries"][:-1]}
        errors = verify_inventory_lock(tampered, self.lock)
        self.assertTrue(errors)
        self.assertTrue(any("entries differ" in error for error in errors))

    def test_corrupted_execution_file_cannot_yield_aggregate_pass(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temporary:
            report_dir = Path(temporary)
            (report_dir / "runs").mkdir()
            (report_dir / "runs" / "bad").mkdir()
            (report_dir / "runs" / "bad" / "execution.json").write_text("{broken", encoding="utf-8")
            reports, errors = read_execution_reports(report_dir)
            self.assertEqual(reports, [])
            self.assertEqual(len(errors), 1)
            valid = execution("image-a", [self.fixture_a, self.fixture_b], [self.assertion_a], "run-valid")
            aggregates = aggregate_groups(
                [valid], "image-a", self.lock, "2.0.0", "identity-a", errors
            )
            self.assertEqual(aggregates[0]["overall_acceptance"], "FAIL")
            self.assertEqual(aggregates[0]["inventory_integrity_status"], "FAIL")

    def test_empty_and_malformed_reports_cannot_aggregate(self) -> None:
        errors = reconcile_execution_inventory({}, self.lock["entries"], self.lock, "identity-a")
        self.assertTrue(errors)
        self.assertTrue(any("empty or malformed" in error for error in errors))
        malformed = execution("image-a", [self.fixture_a, self.fixture_b], [self.assertion_a], "run-malformed")
        malformed["assertions"] = {"not": "a list"}
        result = aggregate_executions([malformed], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["overall_acceptance"], "FAIL")
        self.assertTrue(any("assertions are missing" in error for error in result["inventory_integrity_errors"]))

    def test_unexpected_fixture_id_fails_closed(self) -> None:
        extra = fixture_record("upstream:unexpected", "ASSERTABLE", "UNTESTED")
        run = execution("image-a", [self.fixture_a, self.fixture_b, extra], [self.assertion_a], "run-extra")
        result = aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["overall_acceptance"], "FAIL")
        self.assertTrue(any("unexpected fixture IDs" in error for error in result["inventory_integrity_errors"]))

    def test_validated_fixture_requires_linked_passing_assertion(self) -> None:
        claimed = fixture_record("upstream:a", "ASSERTABLE", "VALIDATED", "scenario.exit")
        run = execution("image-a", [claimed, self.fixture_b], [{"assertion_id": "scenario.exit", "status": "PASS"}], "run-forged")
        result = aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["overall_acceptance"], "FAIL")
        self.assertTrue(any("not linked" in error for error in result["inventory_integrity_errors"]))

    def test_passing_scenario_without_fixture_assertion_is_not_coverage(self) -> None:
        untested = fixture_record("upstream:a", "ASSERTABLE", "UNTESTED")
        run = execution("image-a", [untested, self.fixture_b], [{"assertion_id": "scenario.exit", "status": "PASS"}], "run-scenario-only")
        result = aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["validated_fixture_count"], 0)
        self.assertEqual(result["coverage_result"], "INCOMPLETE")

    def test_empty_report_fails_inventory_reconciliation(self) -> None:
        from .inventory_lock import reconcile_execution_inventory
        errors = reconcile_execution_inventory({}, self.lock["entries"], self.lock, "identity-a")
        self.assertTrue(errors)
        self.assertTrue(any("empty or malformed" in error for error in errors))

    def test_identity_mismatches_are_incompatible(self) -> None:
        run = execution("image-a", [self.fixture_a, self.fixture_b], [self.assertion_a], "run-identity")
        cases = [
            {**run, "manifest_digest": "other-manifest"},
            {**run, "fixture_source_revision": "other-source"},
            {**run, "harness_identity": "other-implementation"},
        ]
        result = aggregate_executions(cases, "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["execution_ids"], [])
        self.assertEqual(len(result["incompatible_executions"]), 3)

    def test_partial_coverage_cannot_be_complete(self) -> None:
        run = execution("image-a", [self.fixture_a, self.fixture_b], [self.assertion_a], "run-partial")
        result = aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["validated_fixture_count"], 1)
        self.assertEqual(result["coverage_result"], "INCOMPLETE")
        self.assertEqual(result["overall_acceptance"], "INCOMPLETE")

    def test_cumulative_coverage_uses_fixture_union(self) -> None:
        first = execution("image-a", [self.fixture_a, self.fixture_b], [self.assertion_a], "run-1")
        second = execution("image-a", [self.fixture_a, {**self.fixture_b, "coverage_status": "VALIDATED", "required_assertions": ["case.b"]}], [self.assertion_a, self.assertion_b], "run-2")
        result = aggregate_executions([first, second], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["validated_fixture_count"], 2)
        self.assertEqual(len(result["validated_fixture_ids"]), 2)

    def test_scenario_bundle_does_not_inflate_physical_fixture_count(self) -> None:
        bundle = {
            "fixture_id": "upstream:testdata/repos/example",
            "path": "testdata/repos/example",
            "origin": "upstream",
            "source_revision": "bundle-revision",
            "content_sha256": None,
            "fixture_type": "scenario-bundle",
            "purpose": "Git history scenario bundle",
            "expected_behavior": "one expected finding",
            "scenarios": ["case"],
            "required_assertions": ["case.a"],
            "validation_method": "structured CLI assertion",
            "classification": "ASSERTABLE",
            "upstream_tests": ["detect.TestFromGit"],
            "coverage_status": "VALIDATED",
        }
        lock = inventory_lock([self.fixture_a, self.fixture_b, bundle])
        run = execution(
            "image-a",
            [self.fixture_a, self.fixture_b, bundle],
            [self.assertion_a],
            "run-bundle",
        )
        result = aggregate_executions([run], "image-a", lock, "2.0.0", "identity-a")
        self.assertEqual(result["required_fixture_count"], 2)
        self.assertEqual(result["validated_fixture_count"], 1)
        self.assertEqual(result["scenario_bundle_count"], 1)
        self.assertEqual(result["scenario_bundle_validated_count"], 1)

    def test_different_images_are_not_aggregated(self) -> None:
        first = execution("image-a", [self.fixture_a, self.fixture_b], [self.assertion_a], "same")
        other = execution("image-b", [self.fixture_a, self.fixture_b], [self.assertion_a], "other")
        result = aggregate_executions([first, other], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["execution_ids"], ["same"])
        self.assertEqual(result["incompatible_executions"][0]["execution_id"], "other")

    def test_unsupported_fixture_is_not_successful(self) -> None:
        unsupported = fixture_record("upstream:a", "ASSERTABLE", "UNSUPPORTED")
        run = execution("image-a", [unsupported, self.fixture_b], [], "run-unsupported")
        result = aggregate_executions([run], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(result["validated_fixture_count"], 0)
        self.assertEqual(result["required_fixture_count"], 2)

    def test_later_pass_does_not_erase_prior_failure(self) -> None:
        failed_fixture = fixture_record("upstream:a", "ASSERTABLE", "FAILED", "case.a")
        passed_fixture = fixture_record("upstream:a", "ASSERTABLE", "VALIDATED", "case.a")
        failed_assertion = {**self.assertion_a, "status": "FAIL", "actual": None}
        failed = execution("image-a", [failed_fixture, self.fixture_b], [failed_assertion], "run-fail")
        passed = execution("image-a", [passed_fixture, self.fixture_b], [self.assertion_a], "run-pass")
        result = aggregate_executions([failed, passed], "image-a", self.lock, "2.0.0", "identity-a")
        self.assertEqual(len(result["unresolved_failures"]), 1)
        self.assertEqual(result["functional_result"], "FAIL")

    def test_aggregate_markdown_has_no_trailing_whitespace(self) -> None:
        aggregate = {
            "required_fixture_count": 1,
            "validated_fixture_count": 0,
            "physical_fixture_discovered": 2,
            "docker_applicable_fixture_count": 1,
            "docker_validated_fixture_count": 0,
            "internal_go_fixture_count": 1,
            "internal_go_validated_count": 0,
            "internal_go_pending_count": 1,
            "supporting_fixture_count": 0,
            "exercised_unvalidated_count": 0,
            "unsupported_fixture_count": 0,
            "scenario_bundle_count": 1,
            "scenario_bundle_validated_count": 0,
            "scenario_bundle_unvalidated_count": 1,
            "image_id": "image-a",
            "functional_result": "PASS",
            "coverage_result": "INCOMPLETE",
            "overall_acceptance": "INCOMPLETE",
            "execution_ids": [],
            "included_executions": [],
            "assertion_history": {},
            "fixtures": {"upstream:a": {"classification": "INTERNAL_GO"}},
            "platforms": {},
            "unresolved_failures": [],
            "unvalidated_fixtures": [{"path": "testdata/a", "classification": "INTERNAL_GO", "scenarios": []}],
            "unvalidated_scenario_bundles": [{"path": "testdata/a", "scenarios": []}],
            "generated_utc": "now",
        }
        rendered = aggregate_markdown_report(aggregate)
        self.assertIn("scenarios: none", rendered)
        self.assertFalse(any(line.endswith((" ", "\t")) for line in rendered.splitlines()))


if __name__ == "__main__":
    unittest.main(verbosity=2)