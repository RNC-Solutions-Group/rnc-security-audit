"""Tests for the concrete independent-harness handoff contract."""

from __future__ import annotations

import copy
import unittest

from tools.cp0.contracts import ContractViolation
from tools.cp0.corpus import load_v0, load_v1
from tools.cp0.harness_adapter import (
    HANDOFF_VERSION,
    assert_handoff_safe,
    build_handoff,
    conformance_score,
    export_findings,
)
from tools.cp0.synthetic_stub import build


class CP0HarnessAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loaded = load_v1()
        cls.handoff = build_handoff(build(corpus="v1", mode="perfect"), cls.loaded)

    def test_external_contract_is_pinned_and_versioned(self):
        self.assertEqual(self.handoff["handoff_version"], HANDOFF_VERSION)
        self.assertEqual(self.handoff["external_contract"]["scoring_schema_version"], 1)
        self.assertEqual(self.handoff["external_contract"]["revision"], "86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f")
        self.assertEqual(self.handoff["truth"]["schema_version"], 1)
        self.assertEqual(self.handoff["truth"]["counts"], {
            "items": 27,
            "expected_detection": 25,
            "blocked": 1,
            "skipped": 1,
        })

    def test_perfect_handoff_preserves_all_findings(self):
        score = conformance_score(self.handoff)
        self.assertEqual(score["expected"], 25)
        self.assertEqual(score["matched"], 25)
        self.assertEqual(score["missed"], 0)
        self.assertEqual(score["unexpected"], 0)
        self.assertFalse(score["external_harness_executed"])

    def test_missed_and_false_positive_handoff_scores(self):
        missed = build_handoff(build(corpus="v1", mode="miss-one"), self.loaded)
        self.assertEqual(conformance_score(missed)["missed"], 1)
        false_positive = build_handoff(build(corpus="v1", mode="false-positive"), self.loaded)
        self.assertEqual(conformance_score(false_positive)["unexpected"], 1)

    def test_v0_handoff_accounts_for_blocked_scope(self):
        loaded = load_v0()
        handoff = build_handoff(build(corpus="v0", mode="perfect"), loaded)
        self.assertEqual(handoff["truth"]["counts"], {
            "items": 14,
            "expected_detection": 13,
            "blocked": 1,
            "skipped": 0,
        })
        self.assertEqual(conformance_score(handoff)["matched"], 13)

    def test_expected_items_carry_rule_identity(self):
        for item in self.handoff["truth"]["items"]:
            if item["classification"] == "EXPECTED_DETECTION":
                self.assertTrue(item["expected_rule_id"])
                self.assertGreaterEqual(item["line_start"], 1)

    def test_policy_provenance_is_sidecar_not_scoring_input(self):
        self.assertIn("provenance", self.handoff)
        self.assertEqual(self.handoff["provenance"]["result_code"], 3)
        self.assertTrue(self.handoff["provenance"]["policy"]["policy_valid"])
        self.assertNotIn("dispositions", self.handoff["truth"])
        self.assertNotIn("policy", self.handoff["findings"][0])

    def test_findings_on_blocked_units_are_rejected(self):
        bundle = build(corpus="v1", mode="perfect")
        blocked = next(unit["unit_id"] for unit in bundle["execution"]["units"] if unit["disposition"] == "VERIFIED_BLOCKED")
        bundle["findings"][0]["unit_id"] = blocked
        with self.assertRaises(ContractViolation) as caught:
            export_findings(bundle, self.loaded)
        self.assertEqual(caught.exception.code, "HANDOFF_SCOPE_LEAK")

    def test_handoff_is_safe_and_relative(self):
        assert_handoff_safe(self.handoff)
        for item in self.handoff["truth"]["items"]:
            self.assertFalse(item["path"].startswith("/"))
            self.assertNotIn("..", item["path"].split("/"))
        for finding in self.handoff["findings"]:
            self.assertNotIn("RNC_SYNTH_KEY_", finding["file"])
            self.assertTrue(finding["secret_redacted"])

    def test_handoff_tamper_is_rejected(self):
        tampered = copy.deepcopy(self.handoff)
        tampered["truth"]["counts"]["expected_detection"] = 99
        with self.assertRaises(ContractViolation):
            assert_handoff_safe(tampered)
        tampered = copy.deepcopy(self.handoff)
        tampered["findings"][0]["file"] = "../outside.txt"
        with self.assertRaises(ContractViolation):
            assert_handoff_safe(tampered)


if __name__ == "__main__":
    unittest.main()
