"""Detection-scope annotation tests (does not alter TP/FN scoring)."""

from __future__ import annotations

import unittest

from harness.scope import classify, summarize


class ScopeTests(unittest.TestCase):
    def test_known_scope_classes(self):
        self.assertEqual(classify("email")[0], "out_of_scope")
        self.assertEqual(classify("wallet_seed_phrase")[0], "out_of_scope")
        self.assertEqual(classify("url_password")[0], "unknown")
        self.assertEqual(classify("github_pat_classic")[0], "in_scope")

    def test_summary_separates_out_of_scope_unknown_and_in_scope(self):
        missed = [
            {"section": "s1", "kind": "email", "hard": False},
            {"section": "s2", "kind": "url_password", "hard": False},
            {"section": "s3", "kind": "github_pat_classic", "hard": False},
        ]
        summary = summarize(missed, "builtin-default")
        self.assertTrue(summary["available"])
        self.assertEqual(summary["counts"], {"out_of_scope": 1, "unknown": 1, "in_scope": 1})
        self.assertEqual(summary["out_of_scope"][0]["kind"], "email")
        self.assertEqual(summary["unknown"][0]["kind"], "url_password")
        self.assertEqual(summary["in_scope_misses"][0]["kind"], "github_pat_classic")

    def test_custom_config_disables_scope_annotation(self):
        summary = summarize([{"section": "s", "kind": "email", "hard": False}], "file")
        self.assertFalse(summary["available"])
        self.assertEqual(summary["counts"]["out_of_scope"], 0)


if __name__ == "__main__":
    unittest.main()
