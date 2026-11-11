"""CP0 contract, identity, precedence and redaction regression tests."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from tools.cp0.contracts import (
    ContractViolation,
    SCHEMA_VERSION,
    assert_public_report_safe,
    assert_public_safe,
    canonical_locator,
    canonical_json,
    ci_decision,
    line_count,
    make_finding_id,
    make_unit_id,
    record_digest,
    schema_check,
    schema_registry,
    sha256_bytes,
    sorted_findings,
    validate_records,
)
from tools.cp0.corpus import load_v1
from tools.cp0.reconcile import reconcile
from tools.cp0.synthetic_stub import build
from tools.cp0.validate import validate_corpus, validate_outcomes


def _unit(locator: str, data: bytes | None, *, required: bool, disposition: str) -> dict:
    unit_id = make_unit_id("cp0-test", locator)
    value = {
        "schema_version": SCHEMA_VERSION,
        "run_id": "cp0-test-run",
        "unit_id": unit_id,
        "source_id": "cp0-test",
        "source_kind": "working_tree_file",
        "locator": locator,
        "required_scope": required,
        "disposition": disposition,
        "reason_codes": [],
    }
    if disposition == "INSPECTED":
        assert data is not None
        value.update({
            "byte_length": len(data),
            "line_count": line_count(data),
            "content_sha256": sha256_bytes(data),
        })
    else:
        value["reason_codes"] = ["TEST_UNAVAILABLE"]
    return value


def _execution(units: list[dict]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": "cp0-test-run",
        "state": "COMPLETED",
        "evidence_valid": True,
        "engine_version": "test-0.2.0",
        "ruleset_id": "synthetic-v1",
        "ruleset_digest": "sha256:" + "1" * 64,
        "source_adapter": {"id": "test", "version": "0.2.0"},
        "units": units,
        "fatal_errors": [],
        "failure_codes": [],
    }


def _empty_policy() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": "cp0-test-run",
        "policy_valid": True,
        "effective_policy_digest": "sha256:" + "0" * 64,
        "effective_policies": [],
        "requests": [],
        "applied_blocks": [],
        "dispositions": [],
    }


class CP0ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas, cls.registry = schema_registry()
        cls.bundle = build(corpus="v1", mode="perfect")
        cls.corpus = load_v1()
        cls.contents = {
            item["unit_id"]: cls.corpus["contents"][target["id"]]
            for target in cls.corpus["targets"]
            for item in [{"unit_id": make_unit_id(f"synthetic-corpus:{cls.corpus['summary']['version']}", target["path"])}]
            if target["scope"] == "INSPECTED"
        }

    def test_schema_count_and_version(self):
        self.assertEqual(len(self.schemas), 7)
        self.assertEqual(SCHEMA_VERSION, "0.2.0")

    def test_corpus_baseline_and_expansion(self):
        summary = validate_corpus()
        self.assertEqual(summary["v0"]["targets"], 9)
        self.assertEqual(summary["v0"]["known_markers"], 14)
        self.assertEqual(summary["v1"]["targets"], 21)
        self.assertEqual(summary["v1"]["expected_findings"], 25)
        self.assertEqual(summary["v1"]["known_markers"], 26)

    def test_outcome_tables_are_independently_classified(self):
        v0 = validate_outcomes(Path("tests/fixtures/synthetic-v0/outcome-cases.json"), self.schemas, self.registry)
        v1 = validate_outcomes(Path("tests/fixtures/synthetic-v1/outcome-cases.json"), self.schemas, self.registry)
        self.assertEqual((v0["cases"], v1["cases"]), (12, 16))

    def test_identity_formulas_are_stable_and_reject_traversal(self):
        first = make_unit_id("source", "nested/file.txt")
        second = make_unit_id("source", "nested/file.txt")
        self.assertEqual(first, second)
        with self.assertRaises(ContractViolation):
            canonical_locator("nested\\file.txt")
        with self.assertRaises(ContractViolation):
            canonical_locator("../outside.txt")
        with self.assertRaises(ContractViolation):
            canonical_locator("C:/outside.txt")
        digest = sha256_bytes(b"RNC_SYNTH_KEY_EXAMPLE")
        self.assertEqual(
            make_finding_id(first, "rule", "1", 3, 10, digest),
            make_finding_id(first, "rule", "1", 3, 10, digest),
        )
        self.assertNotEqual(
            make_finding_id(first, "rule", "1", 3, 10, digest),
            make_finding_id(first, "rule", "2", 3, 10, digest),
        )

    def test_canonical_locator_is_strict_and_deterministic(self):
        accepted = [
            "file.txt",
            "nested/deep/file.txt",
            "café/résumé.txt",
            "Case-Sensitive.TXT",
        ]
        for value in accepted:
            self.assertEqual(canonical_locator(value), value)

        rejected = [
            "", "./file.txt", "a//b", "a/./b", "a/../b", "a/", "/a",
            "\\a", "a\\b", "C:/a", "C:a", "//server/share", "~/a",
            "a:b", "a*b", "a?b", "a<b", "a>b", "a|b", 'a"b',
            "CON", "con.txt", "LPT1.log", "foo.", "foo ", "a/\x00b",
            "cafe\u0301.txt",  # non-NFC
            "a/\u202eb.txt",  # bidi formatting control
        ]
        for value in rejected:
            with self.subTest(locator=value), self.assertRaises(ContractViolation):
                canonical_locator(value)

        # No platform-specific path normalization: a backslash is not accepted
        # as a separator and case is never folded.
        self.assertNotEqual(make_unit_id("s", "A.txt"), make_unit_id("s", "a.txt"))

    def test_manifest_paths_use_the_same_canonical_contract(self):
        loaded = load_v1()
        for target in loaded["targets"]:
            self.assertEqual(canonical_locator(target["path"]), target["path"])

    def test_perfect_bundle_validates(self):
        summary = validate_records(
            self.bundle["execution"], self.bundle["findings"], self.bundle["policy"],
            self.bundle["result"], self.bundle["ci"], contents=self.contents,
        )
        self.assertEqual(summary["result_code"], 3)
        self.assertEqual(summary["counts"]["detected"], 25)

    def test_optional_uninspected_does_not_force_incomplete(self):
        clean = _unit("clean.txt", b"ordinary\n", required=True, disposition="INSPECTED")
        optional = _unit("optional.txt", None, required=False, disposition="UNINSPECTED")
        execution = _execution([clean, optional])
        result = reconcile(execution, [], _empty_policy(), contents={clean["unit_id"]: b"ordinary\n"})
        self.assertEqual(result["result_code"], 1)
        self.assertEqual(result["counts"]["uninspected"], 1)
        self.assertEqual(result["counts"]["required_uninspected"], 0)

    def test_clean_required_inspection_result(self):
        clean = _unit("clean.txt", b"ordinary\n", required=True, disposition="INSPECTED")
        execution = _execution([clean])
        result = reconcile(execution, [], _empty_policy(), contents={clean["unit_id"]: b"ordinary\n"})
        self.assertEqual(result["result_code"], 1)
        self.assertEqual(result["coverage"], "COMPLETE")
        self.assertEqual(result["counts"]["required_discovered"], 1)

    def test_schema_version_0_1_is_not_silently_accepted(self):
        result = copy.deepcopy(self.bundle["result"])
        result["schema_version"] = "0.1.0"
        with self.assertRaises(ContractViolation) as caught:
            schema_check(result, "result.schema.json", self.schemas, self.registry)
        self.assertEqual(caught.exception.code, "SCHEMA_INVALID")

    def test_unit_run_id_mismatch_is_rejected(self):
        execution = copy.deepcopy(self.bundle["execution"])
        execution["units"][0]["run_id"] = "other-run"
        with self.assertRaises(ContractViolation) as caught:
            validate_records(execution, self.bundle["findings"], self.bundle["policy"], contents=self.contents)
        self.assertEqual(caught.exception.code, "RUN_ID_MISMATCH")

    def test_required_uninspected_is_incomplete(self):
        clean = _unit("clean.txt", b"ordinary\n", required=True, disposition="INSPECTED")
        missing = _unit("missing.txt", None, required=True, disposition="UNINSPECTED")
        execution = _execution([clean, missing])
        result = reconcile(execution, [], _empty_policy(), contents={clean["unit_id"]: b"ordinary\n"})
        self.assertEqual(result["result_code"], 4)
        self.assertEqual(result["coverage"], "PARTIAL")
        self.assertIn("REQUIRED_COVERAGE_INCOMPLETE", result["reason_codes"])

    def test_zero_required_scope_is_never_clean(self):
        optional = _unit("optional.txt", None, required=False, disposition="UNINSPECTED")
        execution = _execution([optional])
        result = reconcile(execution, [], _empty_policy())
        self.assertEqual(result["result_code"], 4)
        self.assertEqual(result["coverage"], "NONE")

    def test_clean_schema_rejects_actionable_counts(self):
        result = copy.deepcopy(self.bundle["result"])
        result["result_code"] = 1
        result["result"] = "CLEAN"
        result["coverage"] = "COMPLETE"
        result["counts"]["actionable"] = 3
        result["counts"]["detected"] = 3
        result["reason_codes"] = []
        with self.assertRaises(ContractViolation) as caught:
            schema_check(result, "result.schema.json", self.schemas, self.registry)
        self.assertEqual(caught.exception.code, "SCHEMA_INVALID")

    def test_result_counts_must_reconcile(self):
        result = copy.deepcopy(self.bundle["result"])
        result["counts"]["detected"] += 1
        with self.assertRaises(ContractViolation) as caught:
            validate_records(
                self.bundle["execution"], self.bundle["findings"], self.bundle["policy"],
                result, self.bundle["ci"], contents=self.contents,
            )
        self.assertEqual(caught.exception.code, "RESULT_COUNT_MISMATCH")

    def test_verified_non_access_is_required(self):
        policy = copy.deepcopy(self.bundle["policy"])
        policy["applied_blocks"][0]["verified_non_access"] = False
        with self.assertRaises(ContractViolation) as caught:
            validate_records(self.bundle["execution"], self.bundle["findings"], policy, contents=self.contents)
        self.assertEqual(caught.exception.code, "SCHEMA_INVALID")

    def test_blocked_unit_cannot_carry_a_finding(self):
        findings = copy.deepcopy(self.bundle["findings"])
        blocked_unit = next(
            unit["unit_id"] for unit in self.bundle["execution"]["units"]
            if unit["disposition"] == "VERIFIED_BLOCKED"
        )
        findings[0]["unit_id"] = blocked_unit
        findings = sorted_findings(findings)
        with self.assertRaises(ContractViolation) as caught:
            validate_records(self.bundle["execution"], findings, self.bundle["policy"], contents=self.contents)
        self.assertEqual(caught.exception.code, "FINDING_OUTSIDE_INSPECTION")

    def test_finding_cannot_exceed_inspected_bytes(self):
        findings = copy.deepcopy(self.bundle["findings"])
        first = findings[0]
        first["end_byte"] = 10**9
        first["finding_id"] = make_finding_id(
            first["unit_id"], first["rule_id"], first["rule_version"],
            first["start_byte"], first["end_byte"], first["evidence_digest"],
        )
        findings = sorted_findings(findings)
        with self.assertRaises(ContractViolation) as caught:
            validate_records(self.bundle["execution"], findings, self.bundle["policy"], contents=self.contents)
        self.assertEqual(caught.exception.code, "FINDING_RANGE_OUTSIDE_UNIT")

    def test_duplicate_finding_identity_is_rejected(self):
        findings = sorted_findings(copy.deepcopy(self.bundle["findings"]) + [copy.deepcopy(self.bundle["findings"][0])])
        with self.assertRaises(ContractViolation) as caught:
            validate_records(self.bundle["execution"], findings, self.bundle["policy"], contents=self.contents)
        self.assertEqual(caught.exception.code, "FINDING_DUPLICATE")

    def test_line_and_evidence_must_match_bytes(self):
        findings = copy.deepcopy(self.bundle["findings"])
        findings[0]["line"] += 1
        with self.assertRaises(ContractViolation) as caught:
            validate_records(self.bundle["execution"], findings, self.bundle["policy"], contents=self.contents)
        self.assertEqual(caught.exception.code, "FINDING_LINE_MISMATCH")

        findings = copy.deepcopy(self.bundle["findings"])
        first = findings[0]
        first["evidence_digest"] = sha256_bytes(b"wrong evidence bytes")
        first["finding_id"] = make_finding_id(
            first["unit_id"], first["rule_id"], first["rule_version"],
            first["start_byte"], first["end_byte"], first["evidence_digest"],
        )
        with self.assertRaises(ContractViolation) as caught:
            validate_records(self.bundle["execution"], findings, self.bundle["policy"], contents=self.contents)
        self.assertEqual(caught.exception.code, "FINDING_EVIDENCE_MISMATCH")

    def test_non_deterministic_order_is_rejected(self):
        execution = copy.deepcopy(self.bundle["execution"])
        execution["units"] = list(reversed(execution["units"]))
        with self.assertRaises(ContractViolation) as caught:
            validate_records(execution, self.bundle["findings"], self.bundle["policy"], contents=self.contents)
        self.assertEqual(caught.exception.code, "ORDER_NON_DETERMINISTIC")

    def test_ci_separates_result_from_acceptance(self):
        self.assertEqual(ci_decision(2, {1, 2})["process_exit_code"], 0)
        self.assertEqual(ci_decision(2, {1})["process_exit_code"], 10)
        self.assertEqual(ci_decision(3, {1, 2})["process_exit_code"], 10)
        self.assertEqual(ci_decision(3, {1, 2, 3})["process_exit_code"], 0)
        self.assertEqual(ci_decision(4)["process_exit_code"], 20)
        self.assertEqual(ci_decision(5)["process_exit_code"], 30)
        with self.assertRaises(ContractViolation):
            ci_decision(3, {1, 2, 4})

    def test_ci_must_reference_exact_result_digest(self):
        ci = copy.deepcopy(self.bundle["ci"])
        ci["result_digest"] = "sha256:" + "f" * 64
        with self.assertRaises(ContractViolation) as caught:
            validate_records(
                self.bundle["execution"], self.bundle["findings"], self.bundle["policy"],
                self.bundle["result"], ci, contents=self.contents,
            )
        self.assertEqual(caught.exception.code, "CI_RESULT_DIGEST_MISMATCH")

    def test_post_scan_exemption_preserves_detection(self):
        exempted = next(entry for entry in self.bundle["policy"]["dispositions"] if entry["status"] == "EXEMPTED")
        finding = next(item for item in self.bundle["findings"] if item["finding_id"] == exempted["finding_id"])
        self.assertNotIn("status", finding)
        self.assertNotIn("disposition", finding)
        self.assertTrue(finding["evidence_digest"].startswith("sha256:"))
        self.assertEqual(record_digest(finding), record_digest(copy.deepcopy(finding)))

    def test_public_redaction_contract(self):
        assert_public_safe(self.bundle["result"])
        with self.assertRaises(ContractViolation):
            assert_public_safe({"reason": "found RNC_SYNTH_KEY_AWS_ALPHA"})
        with self.assertRaises(ContractViolation):
            assert_public_safe({"locator": "private/file.txt"})
        with self.assertRaises(ContractViolation):
            assert_public_safe({"path": "C:/private/file.txt"})
        with self.assertRaises(ContractViolation):
            assert_public_report_safe({"finding_id": "f-" + "a" * 64})
        with self.assertRaises(ContractViolation):
            assert_public_report_safe({"evidence_digest": "sha256:" + "a" * 64})
        with self.assertRaises(ContractViolation):
            assert_public_report_safe({"content_sha256": "sha256:" + "a" * 64})
        assert_public_report_safe(self.bundle["result"])

    def test_canonical_serialization_is_stable(self):
        self.assertEqual(
            canonical_json({"b": 1, "a": ["x", "y"]}),
            canonical_json({"a": ["x", "y"], "b": 1}),
        )
        self.assertTrue(record_digest({"a": 1}).startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
