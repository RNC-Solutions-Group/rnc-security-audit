"""Pinned RNC Scanner Git-history integration (requires a local CP5 build).

These tests are skipped in a clean checkout. They are executed in the CP5
workspace against the exact pinned source build and the pinned Leaky Repo cache;
they never modify the scanner, scoring code, or oracle.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from harness import leaky_repo
from harness.adapters.rnc import RNCAdapter
from harness.history_matching import score_history
from harness.history_oracle import load

ROOT = Path(".").resolve()
BINARY = ROOT / "work/cp5/rnc-source/target/release/rnc.exe"
RULES = ROOT / "work/cp5/rnc-source/rules/rnc-providers-v1.json"
CACHE = ROOT / "datasets/cache/leaky-repo/2e951359cac53addbee56437da3ffb546e3dfe24/source"


@unittest.skipUnless(
    BINARY.is_file() and RULES.is_file() and CACHE.is_dir(),
    "pinned CP5 RNC build and Leaky Repo cache are unavailable",
)
class PinnedRNCHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = leaky_repo.prepare(offline=True)
        cls.scope = json.loads(
            (ROOT / "datasets/leaky-repo.history-scope.json").read_text(encoding="utf-8")
        )
        cls.oracle = load(
            ROOT / "datasets/leaky-repo.history-oracle.json",
            source_root=cls.prepared.source,
            scope_path=ROOT / "datasets/leaky-repo.history-scope.json",
        )
        cls.adapter = RNCAdapter()
        cls.adapter._rules_path = RULES
        cls.adapter._history_supported = True
        cls.adapter._ruleset = cls.adapter._describe_rules(RULES)
        with tempfile.TemporaryDirectory() as tmp:
            invocation = cls.adapter._rules_validate_native(
                BINARY, RULES, Path(tmp), None
            )
        match = re.search(
            r"^Digest:\s+(sha256:[0-9a-f]{64})$",
            invocation.stdout.decode("utf-8", "replace"),
            re.MULTILINE,
        )
        cls.adapter._ruleset["digest"] = match.group(1) if match else None

    def test_native_history_scan_is_covered_and_scored(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            invocation = self.adapter.invoke_native(
                BINARY,
                self.prepared.source,
                out / "report.json",
                mode="git",
                timeout_seconds=180,
            )
            self.assertIsNone(self.adapter.invocation_problem(invocation))
            findings = self.adapter.parse_findings(invocation.report_bytes)
            coverage = self.adapter.execution_coverage(invocation, self.prepared.source, ())
            self.assertTrue(coverage["verified"], coverage["notes"])
            self.assertEqual(coverage["history"]["commits"], 25)
            self.assertEqual(coverage["history"]["scope"], "selected-refs")
            self.assertEqual(coverage["unit_count"], 166)
            self.assertEqual(len(findings), 61)
            target = next(
                finding
                for finding in findings
                if finding.file == ".vscode/sftp.json"
                and finding.commit == "9f1468c79df2cf13c66041692ca7f044a27a874b"
            )
            self.assertEqual(target.line, 6)
            result = score_history(
                findings,
                self.oracle,
                self.prepared.source,
                scope=self.scope,
            )
            metrics = result.metrics
            self.assertEqual(metrics["expected_occurrences"], 65)
            self.assertEqual(metrics["matched_occurrences"], 21)
            self.assertEqual(metrics["unique_matched"], 19)
            self.assertEqual(metrics["duplicate_count"], 21)
            self.assertEqual(metrics["informative_match_count"], 7)
            self.assertEqual(metrics["verified_false_positive_count"], 12)
            self.assertEqual(metrics["unique_verified_nonsecret_exposure_count"], 4)
            self.assertEqual(metrics["unmatched_pending_review_count"], 0)
            self.assertEqual(metrics["unverified_evidence_count"], 0)
            self.assertEqual(metrics["accounted_observed_count"], 61)
            self.assertTrue(metrics["finding_accounting_reconciled"])
            self.assertIsNone(metrics["precision_percent"])
            self.assertEqual(
                metrics["precision_certification_status"],
                "BLOCKED_INCOMPLETE_NEGATIVE_ORACLE",
            )
            # The eight shifted-line observations are duplicates, not new TPs.
            self.assertTrue(
                {
                    (item.path, item.line, item.expected_id)
                    for item in result.evaluations
                    if item.classification == "DUPLICATE"
                }
                >= {
                    ("web/django/settings.py", 24, "LH-0137"),
                    ("web/var/www/.env", 14, "LH-0147"),
                    ("web/var/www/.env", 33, "LH-0152"),
                    ("web/var/www/public_html/config.php", 11, "LH-0157"),
                }
            )
            self.assertTrue(
                any(
                    item.classification == "FALSE_POSITIVE"
                    and item.expected_id == "LH-0124"
                    for item in result.evaluations
                )
            )
            self.assertFalse(
                any(
                    item.classification == "INFORMATIVE_MATCH"
                    and item.path == "web/js/salesforce.js"
                    for item in result.evaluations
                )
            )
            text = json.dumps(result.safe_dict()).lower()
            self.assertNotIn("secret_text", text)
            self.assertNotIn("source_sha256", text)


if __name__ == "__main__":
    unittest.main()
