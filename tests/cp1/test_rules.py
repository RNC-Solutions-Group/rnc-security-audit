"""CP1 rule-bundle schema, digest and licensing-safety checks."""

from __future__ import annotations

import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from tools.cp1.rules import canonical_digest, load


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "docs/contracts/rules/rule-bundle.schema.json"
BUNDLES = (ROOT / "rules/rnc-synthetic-v0.json", ROOT / "rules/rnc-synthetic-v1.json")


class CP1RuleBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import json

        cls.schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(cls.schema)

    def test_bundles_validate(self):
        for path in BUNDLES:
            with self.subTest(path=path.name):
                document = load(path)
                self.validator.validate(document)
                self.assertGreaterEqual(len(document["rules"]), 1)
                ids = [rule["rule_id"] for rule in document["rules"]]
                self.assertEqual(len(ids), len(set(ids)))
                for rule in document["rules"]:
                    self.assertTrue(rule["pattern"])
                    self.assertTrue(rule["validators"])
                    self.assertGreater(rule["max_match_bytes"], 0)

    def test_known_digests_are_stable(self):
        self.assertEqual(
            canonical_digest(load(ROOT / "rules/rnc-synthetic-v0.json")),
            "sha256:71218980bc78e8a49fe4a73702357f7cb96058a4f0342c3ea5d610a174603f05",
        )
        self.assertEqual(
            canonical_digest(load(ROOT / "rules/rnc-synthetic-v1.json")),
            "sha256:6a68625a57f75adcf1aaebd3f8ef1470c339b68fa0b80ab85ecdfc37af33f73d",
        )

    def test_rejects_unknown_rule_fields(self):
        document = load(ROOT / "rules/rnc-synthetic-v1.json")
        document["rules"][0]["unexpected"] = True
        errors = list(self.validator.iter_errors(document))
        self.assertTrue(errors)

    def test_bundles_are_explicitly_synthetic(self):
        for path in BUNDLES:
            document = load(path)
            self.assertTrue(document["ruleset_id"].startswith("rnc-synthetic"))

    def test_no_third_party_rule_provenance(self):
        for path in BUNDLES:
            text = path.read_text(encoding="utf-8").lower()
            self.assertNotIn("gitleaks", text)
            self.assertNotIn("license", text)
            self.assertNotIn("internal/", text)


if __name__ == "__main__":
    unittest.main()
