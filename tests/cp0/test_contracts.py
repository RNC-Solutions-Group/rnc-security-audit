"""Specification-level CP0 regression checks. Not production scanner tests."""

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, ValidationError

from tools.cp0.contract_oracle import ci_decision, classify
from tools.cp0.benchmark import benchmark, write_corpus
from tools.cp0.generate_corpus import build
from tools.cp0.reconcile import reconcile
from tools.cp0.synthetic_stub import events
from tools.cp0.validate import schema_registry, validate_corpus, validate_outcomes


class CP0ContractsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas, cls.registry = schema_registry()

    def test_corpus_truth(self):
        summary = validate_corpus()
        self.assertEqual(summary["targets"], 9)
        self.assertEqual(summary["declared_markers"], 14)

    def test_result_matrix(self):
        self.assertEqual(validate_outcomes(self.schemas, self.registry)["cases"], 12)

    def test_default_ci_accepts_both_clean_and_policy_applied(self):
        self.assertEqual(ci_decision(1)["process_exit_code"], 0)
        self.assertEqual(ci_decision(2)["process_exit_code"], 0)
        self.assertEqual(ci_decision(3)["process_exit_code"], 10)
        self.assertEqual(ci_decision(2, {1})["process_exit_code"], 10)
        self.assertEqual(ci_decision(2, {1, 2})["result_code"], 2)

    def test_incomplete_and_failed_cannot_be_accepted(self):
        with self.assertRaises(ValueError):
            ci_decision(3, {1, 2, 4})
        self.assertEqual(ci_decision(4)["process_exit_code"], 20)
        self.assertEqual(ci_decision(5)["process_exit_code"], 30)

    def test_missing_inspection_never_clean(self):
        case = {"state": "COMPLETED", "fatal": False, "evidence_valid": True,
                "inspected": 0, "blocked": 0, "uninspected": 0,
                "actionable": 0, "exempted": 0}
        self.assertEqual(classify(case), 4)

    def test_malformed_result_schema_rejected(self):
        invalid = {"schema_version": "0.1.0", "run_id": "x", "result_code": 1,
                   "result": "ACTIONABLE", "counts": {"discovered": 1,
                   "inspected": 1, "verified_blocked": 0, "uninspected": 0,
                   "detected": 0, "actionable": 0, "exempted": 0},
                   "reason_codes": []}
        with self.assertRaises(ValidationError):
            Draft202012Validator(self.schemas["result.schema.json"], registry=self.registry).validate(invalid)

    def test_stub_has_predictable_errors_for_external_harness(self):
        perfect = events("perfect")
        self.assertEqual(len(perfect), 13)  # one known marker sits behind a verified block
        self.assertEqual(len(events("miss-one")), 12)
        self.assertEqual(len(events("false-positive")), 14)
        self.assertNotIn("blocked", {event["target_id"] for event in perfect})

    def test_generated_full_corpus_is_reproducible(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = build(Path(first), 1000)
            two = build(Path(second), 1000)
            self.assertEqual(one, two)
            self.assertEqual(one["target_count"], 1000)
            self.assertEqual(sum(len(t["expected_findings"]) for t in one["targets"]), 2000)
            self.assertEqual(sum(t["scope"] == "VERIFIED_BLOCKED" for t in one["targets"]), 35)

    def test_independent_ledgers_reconcile(self):
        run = "cp0-ledger"
        sha = "sha256:" + "a" * 64
        unit = lambda ident, status: {"run_id": run, "unit_id": ident, "source_id": ident,
                "source_kind": "working_tree_file", "locator": ident,
                "required_scope": True, "disposition": status}
        execution = {"schema_version": "0.1.0", "run_id": run, "state": "COMPLETED",
                     "evidence_valid": True, "fatal_errors": [], "units": [
                     unit("u1", "INSPECTED"), unit("u2", "VERIFIED_BLOCKED")]}
        finding = {"run_id": run, "finding_id": "f1", "unit_id": "u1",
                   "rule_id": "synthetic", "category": "test", "start_byte": 0,
                   "end_byte": 2, "confidence": "high", "evidence_digest": sha}
        policy = {"schema_version": "0.1.0", "run_id": run, "effective_policy_digest": sha,
                  "applied_blocks": [{"unit_id": "u2", "policy_id": "GLOBAL-1",
                                      "origin": "global", "reason": "fixture",
                                      "verified_non_access": True}],
                  "dispositions": [{"finding_id": "f1", "status": "EXEMPTED",
                                    "policy_id": "DEV-1", "origin": "repository", "reason": "synthetic"}]}
        for schema_name, value in (("execution", execution), ("finding", finding), ("policy", policy)):
            Draft202012Validator(self.schemas[f"{schema_name}.schema.json"], registry=self.registry).validate(value)
        for value in execution["units"]:
            Draft202012Validator(self.schemas["source-unit.schema.json"], registry=self.registry).validate(value)

        result = reconcile(execution, [finding], policy)
        Draft202012Validator(self.schemas["result.schema.json"], registry=self.registry).validate(result)
        self.assertEqual(result["result_code"], 2)
        self.assertEqual(result["counts"]["detected"], 1)
        self.assertEqual(result["counts"]["verified_blocked"], 1)

        policy["dispositions"] = []
        with self.assertRaises(ValueError):
            reconcile(execution, [finding], policy)

    def test_benchmark_fixture_has_exact_known_count(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bench.bin"
            digest = write_corpus(path, 64 * 1024, 16)
            self.assertEqual(path.stat().st_size, 64 * 1024)
            self.assertEqual(path.read_bytes().count(b"RNC_SYNTH_KEY_"), 16)
            self.assertEqual(len(digest), 64)

    def test_benchmark_refuses_missing_toolchains(self):
        with patch("tools.cp0.benchmark.shutil.which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "missing go toolchain"):
                benchmark(3)


if __name__ == "__main__":
    unittest.main()
