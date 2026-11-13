"""Provider catalog, schema, truth and fixture-safety checks."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from tools.cp1.rules import canonical_digest, load
from tools.cp3.materialize import materialize

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules/rnc-providers-v1.json"
SCHEMA = ROOT / "docs/contracts/rules/provider-rule-bundle.schema.json"
TRUTH2 = ROOT / "tests/cp3/provider-truth-tier2.json"
TRUTH3 = ROOT / "tests/cp3/provider-truth-tier3-heldout.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def der_children(data: bytes) -> list[bytes]:
    if data[0] != 0x30:
        raise ValueError("not a sequence")
    length = data[1]
    position = 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[2 : 2 + count], "big")
        position += count
    end = position + length
    children = []
    while position < end:
        tag = data[position]
        size = data[position + 1]
        header = 2
        if size & 0x80:
            count = size & 0x7F
            size = int.from_bytes(data[position + 2 : position + 2 + count], "big")
            header += count
        start = position + header
        children.append(data[position:start + size])
        position = start + size
    return children


def der_integer(raw: bytes) -> int:
    if raw[0] != 0x02:
        raise ValueError("not an integer")
    length = raw[1]
    return int.from_bytes(raw[2 : 2 + length], "big")


class ProviderCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = load(RULES)
        cls.truth2 = load_json(TRUTH2)
        cls.truth3 = load_json(TRUTH3)
        cls.rules = {rule["rule_id"]: rule for rule in cls.document["rules"]}
        cls._tmp = tempfile.TemporaryDirectory(prefix="rnc-cp3-fixtures-")
        cls.tier2 = materialize("tier2", Path(cls._tmp.name))
        cls.tier3 = materialize("tier3", Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_schema_validates(self):
        schema = load_json(SCHEMA)
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(self.document))
        self.assertEqual(errors, [])

    def test_catalog_shape_and_digest(self):
        self.assertEqual(self.document["schema_version"], "0.2.0")
        self.assertEqual(len(self.document["rules"]), 37)
        self.assertEqual(
            len({rule["family"] for rule in self.document["rules"]}), 22
        )
        self.assertEqual(
            canonical_digest(self.document),
            "sha256:901008d7cf64ee7387599eb13720bc3b78a2ab8868aae6e779fea1843c22dfb9",
        )

    def test_every_rule_has_bounded_candidate_and_provenance(self):
        for rule in self.document["rules"]:
            with self.subTest(rule=rule["rule_id"]):
                self.assertGreater(rule["max_candidate_bytes"], 0)
                self.assertLessEqual(rule["max_candidate_bytes"], rule["max_match_bytes"])
                self.assertTrue(rule["fixture_set"])
                self.assertTrue(rule["provenance"]["references"])
                self.assertTrue(rule["provenance"]["references"][0].startswith("https://"))

    def test_truth_references_only_catalog_rules_and_families(self):
        for truth_path, document, expected in (
            (TRUTH2, self.truth2, 27),
            (TRUTH3, self.truth3, 15),
        ):
            with self.subTest(truth=truth_path.name):
                self.assertEqual(document["counts"]["expected_items"], expected)
                self.assertFalse(document["provenance"]["detector_output_used"])
                for item in document["items"]:
                    rule = self.rules.get(item["expected_rule_id"])
                    self.assertIsNotNone(rule, item["expected_rule_id"])
                    self.assertEqual(item["metadata"]["provider_family"], rule["family"])
                    self.assertEqual(item["metadata"]["credential_type"], rule["credential_type"])

    def test_truth_hashes_match_source_bytes(self):
        for truth_path, source_root in ((TRUTH2, self.tier2), (TRUTH3, self.tier3)):
            document = load_json(truth_path)
            for item in document["items"]:
                data = (source_root / item["path"]).read_bytes()
                digest = hashlib.sha256(
                    data[item["start_byte"] : item["end_byte"]]
                ).hexdigest()
                self.assertEqual(digest, item["secret_sha256"])
                self.assertEqual(item["finding_id"][:2], "t-")

    def test_fixture_pem_is_not_a_coherent_private_key(self):
        pem = (self.tier2 / "pem/private-rsa.pem").read_text(encoding="ascii")
        body = "".join(
            line
            for line in pem.splitlines()
            if not line.startswith("-----")
        )
        decoded = base64.b64decode(body)
        children = der_children(decoded)
        self.assertGreaterEqual(len(children), 9)
        modulus = der_integer(children[1])
        private_exponent = der_integer(children[3])
        prime_one = der_integer(children[4])
        prime_two = der_integer(children[5])
        self.assertNotEqual(prime_one * prime_two, modulus)
        self.assertNotEqual(private_exponent, 0)

    def test_public_and_certificate_containers_are_not_private_keys(self):
        public = (self.tier2 / "pem/public.pem").read_text(encoding="ascii")
        certificate = (self.tier2 / "pem/certificate.pem").read_text(encoding="ascii")
        self.assertIn("BEGIN PUBLIC KEY", public)
        self.assertIn("BEGIN CERTIFICATE", certificate)
        self.assertNotIn("PRIVATE KEY", public)
        self.assertNotIn("PRIVATE KEY", certificate)

    def test_fixtures_are_small_and_harmless(self):
        for root in (self.tier2, self.tier3):
            for path in root.rglob("*"):
                if path.is_file():
                    self.assertLess(path.stat().st_size, 8192, path)
                    data = path.read_bytes()
                    self.assertNotIn(b"PRIVATE KEY-----BEGIN", data)

    def test_no_third_party_rule_source_is_embedded(self):
        text = RULES.read_text(encoding="utf-8").lower()
        self.assertNotIn("gitleaks", text)
        self.assertNotIn("betterleaks", text)
        self.assertNotIn("copied from", text)


if __name__ == "__main__":
    unittest.main()
