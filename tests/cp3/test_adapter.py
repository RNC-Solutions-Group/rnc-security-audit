"""Adapter contract tests: actual RNC records -> independent harness handoff."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.cp0.contracts import make_finding_id, make_unit_id, sha256_bytes
from tools.cp3.adapter import HANDOFF_VERSION, AdapterError, build_handoff
from tools.cp3.materialize import materialize

ROOT = Path(__file__).resolve().parents[2]
TRUTH = json.loads((ROOT / "tests/cp3/provider-truth-tier2.json").read_text(encoding="utf-8"))
RULES = json.loads((ROOT / "rules/rnc-providers-v1.json").read_text(encoding="utf-8"))


def minimal_private(source_root: Path) -> dict:
    item = next(item for item in TRUTH["items"] if item["path"] == "aws.env")
    data = (source_root / item["path"]).read_bytes()
    token = data[item["start_byte"] : item["end_byte"]]
    unit_id = make_unit_id("local-working-tree", item["path"])
    digest = sha256_bytes(token)
    finding_id = make_finding_id(
        unit_id,
        item["expected_rule_id"],
        "2026.11.1",
        item["start_byte"],
        item["end_byte"],
        digest,
    )
    return {
        "execution": {
            "engine_version": "0.1.0",
            "state": "COMPLETED",
            "ruleset_id": "rnc-providers-v1",
            "ruleset_digest": "sha256:" + "0" * 64,
            "units": [
                {
                    "unit_id": unit_id,
                    "locator": item["path"],
                    "disposition": "INSPECTED",
                    "required_scope": True,
                }
            ],
        },
        "execution_plan": {"requested": "regex", "effective": "regex"},
        "findings": [
            {
                "finding_id": finding_id,
                "unit_id": unit_id,
                "rule_id": item["expected_rule_id"],
                "rule_version": "2026.11.1",
                "category": item["category"],
                "start_byte": item["start_byte"],
                "end_byte": item["end_byte"],
                "line": item["line_start"],
                "confidence": "high",
                "validation": ["ASCII_ONLY", "AWS_ACCESS_KEY_ID", "FORMAT_VALID"],
                "evidence_digest": digest,
            }
        ],
        "result": {"result_code": 3, "coverage": "COMPLETE"},
    }


class AdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="rnc-cp3-adapter-")
        cls.source_root = materialize("tier2", Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_handoff_preserves_byte_metadata_and_no_raw_secret(self):
        private = minimal_private(self.source_root)
        handoff = build_handoff(private, TRUTH, RULES)
        self.assertEqual(handoff["handoff_version"], HANDOFF_VERSION)
        self.assertEqual(handoff["external_contract"]["revision"], "86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f")
        self.assertFalse(handoff["external_contract"]["byte_addressable"])
        self.assertIn("one line", handoff["external_contract"]["same_line_limitation"].lower())
        self.assertEqual(len(handoff["findings"]), 1)
        finding = handoff["findings"][0]
        self.assertEqual(finding["file"], "aws.env")
        self.assertGreaterEqual(finding["metadata"]["end_byte"], finding["metadata"]["start_byte"])
        self.assertEqual(finding["metadata"]["provider_family"], "aws-credentials")
        source = (self.source_root / "aws.env").read_bytes()
        token = source[
            finding["metadata"]["start_byte"] : finding["metadata"]["end_byte"]
        ]
        serialized = json.dumps(handoff, sort_keys=True)
        self.assertNotIn(token.decode("ascii"), serialized)
        exported_item = next(item for item in handoff["truth"]["items"] if item["path"] == "aws.env")
        self.assertEqual(exported_item["path"], "aws.env")
        self.assertTrue(exported_item["metadata"]["start_byte"] is not None)

    def test_adapter_rejects_non_inspected_unit(self):
        private = minimal_private(self.source_root)
        private["execution"]["units"][0]["disposition"] = "UNINSPECTED"
        with self.assertRaises(AdapterError):
            build_handoff(private, TRUTH, RULES)

    def test_adapter_rejects_absolute_locator(self):
        private = minimal_private(self.source_root)
        private["execution"]["units"][0]["locator"] = "C:/secret.txt"
        with self.assertRaises(AdapterError):
            build_handoff(private, TRUTH, RULES)

    def test_truth_export_is_independent_and_line_addressable(self):
        handoff = build_handoff(minimal_private(self.source_root), TRUTH, RULES)
        exported = handoff["truth"]
        self.assertEqual(exported["counts"]["expected_detection"], 27)
        self.assertEqual(exported["scoring_policy"]["negative_oracle"], True)
        self.assertTrue(all(item["expected_rule_id"] for item in exported["items"]))
        self.assertTrue(all("start_byte" in item["metadata"] for item in exported["items"]))


if __name__ == "__main__":
    unittest.main()
