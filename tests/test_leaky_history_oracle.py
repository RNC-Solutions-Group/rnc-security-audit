"""Owner-approved historical source-oracle integrity checks."""
import json
import tempfile
import unittest
from collections import Counter, defaultdict
from pathlib import Path

from harness import history_oracle
from harness.history_oracle import HistoryOracleError

CACHE = Path(
    "datasets/cache/leaky-repo/2e951359cac53addbee56437da3ffb546e3dfe24/source"
)


class ApprovedHistoryOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(Path("datasets/leaky-repo.history-oracle.json").read_text())
        cls.items = {i["id"]: i for i in cls.data["items"]}

    def test_complete(self):
        self.assertEqual(len(self.items), 184)
        self.assertEqual(
            Counter(i["disposition"] for i in self.items.values()),
            Counter({"POSITIVE": 65, "NEGATIVE": 89, "INFORMATIVE": 30, "LINEAGE_ONLY": 0}),
        )
        self.assertEqual(
            set(self.items),
            {f"LH-{i:04d}" for i in range(1, 182)}
            | {"PNM-001", "PNM-002", "PNJ-001"},
        )
        self.assertEqual(self.data["status"], "OWNER_APPROVED_FINAL")
        self.assertEqual(self.data["version"], "2026-11-12.3")
        for item_id in ("PNM-001", "PNM-002", "PNJ-001"):
            self.assertEqual(
                self.items[item_id]["review"]["status"], "OWNER_APPROVED_FINAL"
            )
            self.assertEqual(self.items[item_id]["disposition"], "NEGATIVE")
            self.assertTrue(self.items[item_id]["scoring"]["negative_reference"])

    def test_primary_recall(self):
        groups = defaultdict(list)
        for item in self.items.values():
            if item["disposition"] == "POSITIVE":
                self.assertTrue(item["scoring"]["expected_occurrence"])
                groups[item["identity"]["unique_group"]].append(item)
            else:
                self.assertFalse(item["scoring"]["expected_occurrence"])
        self.assertEqual(len(groups), 53)
        self.assertEqual(
            {g: len(a) for g, a in groups.items() if len(a) > 1},
            {"SG-001": 4, "SG-010": 4, "SG-013": 4, "SG-020": 3, "SG-042": 2},
        )

    def test_owner_exceptions(self):
        self.assertEqual(self.items["LH-0124"]["category"], "NON_SECRET_PLACEHOLDER")
        self.assertEqual(self.items["LH-0124"]["disposition"], "NEGATIVE")
        self.assertEqual(self.items["LH-0170"]["disposition"], "INFORMATIVE")
        self.assertEqual(self.items["LH-0170"]["category"], "RENAME_LINEAGE")
        self.assertTrue(self.items["LH-0170"]["scoring"]["lineage_only"])
        self.assertFalse(self.items["LH-0170"]["scoring"]["expected_occurrence"])
        for i in ("LH-0001", "LH-0079", "LH-0081", "LH-0083"):
            self.assertEqual(self.items[i]["category"], "CREDENTIAL_IDENTIFIER")
        self.assertEqual(self.items["LH-0128"]["source"]["line_start"], 4)
        self.assertEqual(self.items["LH-0129"]["source"]["line_start"], 11)
        for i in ("LH-0032", "LH-0091", "LH-0092", "LH-0103", "LH-0160"):
            self.assertTrue(self.items[i]["scoring"]["expected_occurrence"])
        self.assertFalse(self.data["policy"]["reviewed_negatives_exhaustive"])
        self.assertEqual(
            self.data["policy"]["unmatched_findings"],
            "MANDATORY_INVESTIGATION_NO_SILENT_DISCARD",
        )

    def test_loader_verifies_owner_counts_and_policy(self):
        loaded = history_oracle.load("datasets/leaky-repo.history-oracle.json")
        self.assertEqual(loaded.counts["POSITIVE"], 65)
        self.assertEqual(loaded.counts["positive_unique_groups"], 53)
        self.assertEqual(loaded.policy["precision_and_f1"], "NOT_CERTIFIED")
        self.assertTrue(loaded.policy["runtime_history_scoring_wired"])
        self.assertEqual(loaded.counts["total"], 184)
        self.assertEqual(loaded.counts["NEGATIVE"], 89)

    def test_loader_rejects_a_changed_owner_decision(self):
        text = Path("datasets/leaky-repo.history-oracle.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oracle.json"
            path.write_text(
                text.replace(
                    '"id": "LH-0124",\n      "disposition": "NEGATIVE"',
                    '"id": "LH-0124",\n      "disposition": "INFORMATIVE"',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(HistoryOracleError):
                history_oracle.load(path)

    def test_loader_rejects_exhaustive_negative_claim(self):
        text = Path("datasets/leaky-repo.history-oracle.json").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oracle.json"
            path.write_text(
                text.replace(
                    '"reviewed_negatives_exhaustive": false',
                    '"reviewed_negatives_exhaustive": true',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(HistoryOracleError):
                history_oracle.load(path)

    def test_loader_rejects_a_relaxed_total_count(self):
        document = json.loads(Path("datasets/leaky-repo.history-oracle.json").read_text())
        document["counts"]["total"] = 181
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oracle.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(HistoryOracleError):
                history_oracle.load(path)

    @unittest.skipUnless(CACHE.is_dir(), "pinned Leaky Repo cache is not prepared")
    def test_source_validation_matches_pinned_blobs(self):
        loaded = history_oracle.load(
            "datasets/leaky-repo.history-oracle.json",
            source_root=CACHE,
            scope_path="datasets/leaky-repo.history-scope.json",
        )
        validation = loaded.validation["source_validation"]
        self.assertEqual(validation["status"], "PASS")
        self.assertEqual(validation["checked_items"], 184)
        self.assertEqual(validation["checked_blobs"], 184)
        self.assertEqual(validation["commit_count"], 25)
        for item_id in ("PNM-001", "PNM-002", "PNJ-001"):
            self.assertIsNotNone(self.items[item_id]["identity"]["secret_sha256"])

    @unittest.skipUnless(CACHE.is_dir(), "pinned Leaky Repo cache is not prepared")
    def test_source_validation_detects_a_missing_scope(self):
        with self.assertRaises(HistoryOracleError):
            history_oracle.load(
                "datasets/leaky-repo.history-oracle.json",
                source_root=CACHE,
                scope_path="datasets/leaky-repo.truth-missing.json",
            )


if __name__ == "__main__":
    unittest.main()
