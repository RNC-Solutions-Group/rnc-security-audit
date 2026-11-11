"""CP3 security and evidence-privacy checks."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from tools.cp3.privacy_check import check

ROOT = Path(__file__).resolve().parents[2]


class CP3SecurityTests(unittest.TestCase):
    def test_public_artifacts_contain_no_raw_fixture_values_or_host_paths(self):
        result = check()
        self.assertIn(result["status"], {"PASS", "SKIPPED"})
        self.assertEqual(result.get("findings"), [])

    def test_fixture_truth_never_contains_raw_credential_text(self):
        for name in ("provider-truth-tier2.json", "provider-truth-tier3-heldout.json"):
            document = json.loads((ROOT / "tests/cp3" / name).read_text(encoding="utf-8"))
            for item in document["items"]:
                self.assertNotIn("text", item)
                self.assertNotIn("secret", item)
                self.assertRegex(item["secret_sha256"], r"^[0-9a-f]{64}$")

    def test_validator_errors_are_static_and_do_not_embed_candidates(self):
        # The Rust unit tests exercise every provider validator. This check keeps
        # the invariant visible at the Python evidence layer: truth records carry
        # hashes and byte spans, not raw values.
        text = (ROOT / "crates/rnc-core/src/validate.rs").read_text(encoding="utf-8")
        self.assertIn("pub struct ValidationError", text)
        self.assertIn('reason: &\'static str', text)
        self.assertNotIn("candidate: String", text)


if __name__ == "__main__":
    unittest.main()
