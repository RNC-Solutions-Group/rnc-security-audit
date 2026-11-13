"""Historical source-oracle matching tests.

These tests use a disposable synthetic Git repository.  They exercise commit
ancestry, later-snapshot attribution, exact value identity, rename lineage,
negative/informative references and complete finding accounting without needing
the external Leaky Repo cache.
"""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from harness import history_fixture
from harness.contracts import NormalizedFinding
from harness.history_matching import HistorySource, score_history
from harness.history_oracle import HistoryOracle


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def item(
    item_id: str,
    disposition: str,
    category: str,
    group: str | None,
    commit: str,
    path: str,
    line: int,
    *,
    value: str | None = None,
    current_path: str | None = None,
    observed_commit: str | None = None,
    change_event: str = "Added",
) -> dict:
    return {
        "id": item_id,
        "disposition": disposition,
        "category": category,
        "source": {
            "introduced_at": commit,
            "observed_commit": observed_commit or commit,
            "path": path,
            "current_path": current_path or path,
            "line_start": line,
            "line_end": line,
            "git_blob_sha": "0" * 40,
            "change_event": change_event,
            "current_presence": "Current",
            "evidence_url": f"https://example.invalid/{path}",
        },
        "identity": {
            "secret_sha256": digest(value) if value else None,
            "unique_group": group,
            "repetition": "FIRST" if group else "NOT_APPLICABLE",
        },
        "scoring": {
            "expected_occurrence": disposition == "POSITIVE",
            "unique_group_first": disposition == "POSITIVE",
            "informative_only": disposition == "INFORMATIVE",
            "lineage_only": False,
            "negative_reference": disposition == "NEGATIVE",
        },
        "review": {"status": "OWNER_APPROVED_FINAL"},
    }


def oracle(items: list[dict]) -> HistoryOracle:
    return HistoryOracle(
        path=Path("synthetic-oracle.json"),
        sha256="a" * 64,
        document={
            "id": "synthetic-history-oracle",
            "version": "1",
            "scope": {"head": "synthetic"},
            "counts": {},
            "policy": {},
        },
        items=tuple(items),
        validation={"status": "PASS"},
    )


class HistoryMatchingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.corpus = history_fixture.build(Path(cls._tmp.name) / "repo")
        root = cls.corpus.root
        # A later rename that preserves the beta credential without creating a
        # new source occurrence.
        renamed = root / "config" / "app-renamed.env"
        original = root / "config" / "app.env"
        renamed.write_text(original.read_text(encoding="utf-8"), encoding="utf-8")
        original.unlink()
        cls.rename_commit = history_fixture._commit(root, "rename app config", 6)
        info = root / "config" / "info.env"
        info.write_text("INFO=informative-value\n", encoding="utf-8")
        cls.info_commit = history_fixture._commit(root, "add informative line", 7)
        cls.source = HistorySource(root)
        cls.scope = {
            "renames": [
                {
                    "commit": cls.rename_commit,
                    "from": "config/app.env",
                    "to": "config/app-renamed.env",
                }
            ]
        }
        c = cls.corpus.commits
        cls.items = [
            item(
                "H1",
                "POSITIVE",
                "ENVIRONMENT_CREDENTIAL",
                "G1",
                c["c1"],
                "config/app.env",
                1,
                value=history_fixture.SECRETS["alpha"],
            ),
            item(
                "H2",
                "POSITIVE",
                "ENVIRONMENT_CREDENTIAL",
                "G1",
                c["c2"],
                "config/duplicate.env",
                1,
                value=history_fixture.SECRETS["alpha"],
            ),
            item(
                "H3",
                "POSITIVE",
                "DATABASE_PASSWORD",
                "G2",
                c["c3"],
                "config/app.env",
                1,
                value=history_fixture.SECRETS["beta"],
            ),
            item(
                "H4",
                "POSITIVE",
                "DATABASE_PASSWORD",
                "G2",
                c["c3"],
                "deploy/prod.env",
                1,
                value=history_fixture.SECRETS["beta"],
            ),
            item(
                "H5",
                "POSITIVE",
                "ENVIRONMENT_CREDENTIAL",
                "G3",
                c["c4"],
                "removed/legacy.env",
                1,
                value=history_fixture.SECRETS["gamma"],
            ),
            item(
                "N1",
                "NEGATIVE",
                "NON_SECRET_REFERENCE",
                None,
                c["c1"],
                "config/app.env",
                2,
            ),
            item(
                "I1",
                "INFORMATIVE",
                "CREDENTIAL_IDENTIFIER",
                None,
                cls.info_commit,
                "config/info.env",
                1,
            ),
        ]
        cls.oracle = oracle(cls.items)
        cls.findings = [
            NormalizedFinding("config/app.env", 1, "r", digest(history_fixture.SECRETS["alpha"]), commit=c["c1"]),
            NormalizedFinding("config/duplicate.env", 1, "r", digest(history_fixture.SECRETS["alpha"]), commit=c["c2"]),
            NormalizedFinding("config/app.env", 1, "r", digest(history_fixture.SECRETS["beta"]), commit=c["c3"]),
            NormalizedFinding("deploy/prod.env", 1, "r", digest(history_fixture.SECRETS["beta"]), commit=c["c3"]),
            NormalizedFinding("removed/legacy.env", 1, "r", digest(history_fixture.SECRETS["gamma"]), commit=c["c4"]),
            # Later observation of beta after the pure rename: duplicate, no new credit.
            NormalizedFinding("config/app-renamed.env", 1, "r", digest(history_fixture.SECRETS["beta"]), commit=cls.rename_commit),
            # Repeated observation at the introduction snapshot: duplicate.
            NormalizedFinding("config/app.env", 1, "r", digest(history_fixture.SECRETS["alpha"]), commit=c["c1"]),
            # Correct location, contradictory value: unverified, not TP/FP.
            NormalizedFinding("config/app.env", 1, "r", "f" * 64, commit=c["c1"]),
            # Reviewed negative line with its actual value: verified FP.
            NormalizedFinding("config/app.env", 2, "r", digest("example"), commit=c["c1"]),
            # Informative reference: separately visible.
            NormalizedFinding("config/info.env", 1, "r", digest("informative-value"), commit=cls.info_commit),
            # Existing location but stale value after modification.
            NormalizedFinding("config/app.env", 1, "r", digest(history_fixture.SECRETS["alpha"]), commit=c["c3"]),
            # Unknown path, bad commit, future-only path, and no line.
            NormalizedFinding("unknown/path.env", 1, "r", "e" * 64, commit=c["c1"]),
            NormalizedFinding("config/app.env", 1, "r", "d" * 64, commit="not-a-commit"),
            NormalizedFinding("deploy/prod.env", 1, "r", "c" * 64, commit=c["c1"]),
            NormalizedFinding("config/app.env", None, "r", "b" * 64, commit=c["c1"]),
            # Missing file identity.
            NormalizedFinding("", 1, "r", "a" * 64, commit=c["c1"]),
        ]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_complete_accounting_and_metrics(self):
        result = score_history(
            self.findings,
            self.oracle,
            self.source,
            scope=self.scope,
        )
        metrics = result.metrics
        self.assertEqual(metrics["expected_occurrences"], 5)
        self.assertEqual(metrics["matched_occurrences"], 5)
        self.assertEqual(metrics["missed_occurrences"], 0)
        self.assertEqual(metrics["unique_expected"], 3)
        self.assertEqual(metrics["unique_matched"], 3)
        self.assertEqual(metrics["observed_count"], len(self.findings))
        self.assertEqual(metrics["accounted_observed_count"], len(self.findings))
        self.assertTrue(metrics["finding_accounting_reconciled"])
        self.assertEqual(metrics["duplicate_count"], 2)
        self.assertEqual(metrics["verified_false_positive_count"], 1)
        self.assertEqual(metrics["informative_match_count"], 1)
        self.assertEqual(metrics["unverified_evidence_count"], 2)
        self.assertEqual(metrics["unmapped_count"], 1)
        self.assertIsNone(metrics["precision_percent"])
        self.assertIsNone(metrics["f1_percent"])
        self.assertEqual(
            metrics["precision_certification_status"],
            "BLOCKED_INCOMPLETE_NEGATIVE_ORACLE",
        )

    def test_duplicate_is_not_double_credited(self):
        result = score_history(self.findings, self.oracle, self.source, scope=self.scope)
        duplicates = [
            evaluation
            for evaluation in result.evaluations
            if evaluation.classification == "DUPLICATE"
        ]
        self.assertEqual(len(duplicates), 2)
        self.assertEqual(len({e.expected_id for e in duplicates}), 2)

    def test_rename_observation_maps_to_original_occurrence(self):
        result = score_history(self.findings, self.oracle, self.source, scope=self.scope)
        renamed = [
            evaluation
            for evaluation in result.evaluations
            if evaluation.path == "config/app-renamed.env"
        ]
        self.assertEqual(len(renamed), 1)
        self.assertEqual(renamed[0].classification, "DUPLICATE")
        self.assertEqual(renamed[0].expected_id, "H3")

    def test_unknown_and_unverified_are_not_false_positives(self):
        result = score_history(self.findings, self.oracle, self.source, scope=self.scope)
        unverified = [
            evaluation
            for evaluation in result.evaluations
            if evaluation.classification == "UNVERIFIED_EVIDENCE"
        ]
        self.assertEqual(len(unverified), 2)
        self.assertTrue(all(e.observed is not None for e in unverified))
        self.assertEqual(result.metrics["verified_false_positive_count"], 1)

    def test_ambiguous_source_occurrences_are_not_credited(self):
        ambiguous = oracle(
            [
                self.items[0],
                item(
                    "H9",
                    "POSITIVE",
                    "ENVIRONMENT_CREDENTIAL",
                    "G9",
                    self.corpus.commits["c1"],
                    "config/app.env",
                    1,
                    value=history_fixture.SECRETS["alpha"],
                ),
            ]
        )
        result = score_history(
            [
                NormalizedFinding(
                    "config/app.env",
                    1,
                    "r",
                    digest(history_fixture.SECRETS["alpha"]),
                    commit=self.corpus.commits["c1"],
                )
            ],
            ambiguous,
            self.source,
            scope=self.scope,
        )
        self.assertEqual(result.metrics["matched_occurrences"], 0)
        self.assertEqual(result.metrics["ambiguous_count"], 1)
        self.assertEqual(result.metrics["accounted_observed_count"], 1)
        self.assertIsNone(result.metrics["precision_percent"])

    def test_source_truth_is_not_scanner_specific(self):
        # A finding with no secret digest cannot earn primary credit.
        result = score_history(
            [NormalizedFinding("config/app.env", 1, "r", None, commit=self.corpus.commits["c1"])],
            self.oracle,
            self.source,
            scope=self.scope,
        )
        self.assertEqual(result.metrics["matched_occurrences"], 0)
        self.assertEqual(result.metrics["unverified_evidence_count"], 1)
        self.assertEqual(result.metrics["accounted_observed_count"], 1)


def init_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    history_fixture._git(root, "init", "-b", "main")
    history_fixture._git(root, "config", "user.name", "RNC Harness")
    history_fixture._git(root, "config", "user.email", "harness@example.invalid")


class AttributionRegressionTests(unittest.TestCase):
    def test_same_placement_line_shift_is_duplicate_not_new_tp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "app.env"
            path.write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            path.write_text("# comment\nKEY=alpha\n", encoding="utf-8")
            c2 = history_fixture._commit(root, "insert comment", 2)
            path.write_text("# comment\n# more\nKEY=alpha\n", encoding="utf-8")
            c3 = history_fixture._commit(root, "insert another comment", 3)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            findings = [
                NormalizedFinding("app.env", 1, "r", digest("alpha"), commit=c1),
                NormalizedFinding("app.env", 2, "r", digest("alpha"), commit=c2),
                NormalizedFinding("app.env", 3, "r", digest("alpha"), commit=c3),
            ]
            result = score_history(findings, manifest, HistorySource(root))
            self.assertEqual(result.metrics["matched_occurrences"], 1)
            self.assertEqual(result.metrics["duplicate_count"], 2)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 0)
            self.assertEqual(result.metrics["accounted_observed_count"], 3)
            self.assertEqual(
                sum(e.classification == "EXPECTED_DETECTION" for e in result.evaluations),
                1,
            )

    def test_same_value_different_placement_is_not_conflated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            (root / "app.env").write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            (root / "app.env").write_text("KEY=alpha\nCOPY=alpha\n", encoding="utf-8")
            (root / "other.env").write_text("KEY=alpha\n", encoding="utf-8")
            c2 = history_fixture._commit(root, "copy alpha", 2)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            findings = [
                NormalizedFinding("app.env", 2, "r", digest("alpha"), commit=c2),
                NormalizedFinding("other.env", 1, "r", digest("alpha"), commit=c2),
            ]
            result = score_history(findings, manifest, HistorySource(root))
            self.assertEqual(result.metrics["matched_occurrences"], 0)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 2)
            self.assertEqual(result.metrics["duplicate_count"], 0)

    def test_rename_preserves_original_credential_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            original = root / "app.env"
            renamed = root / "renamed.env"
            original.write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            renamed.write_text(original.read_text(encoding="utf-8"), encoding="utf-8")
            original.unlink()
            c2 = history_fixture._commit(root, "rename app config", 2)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            result = score_history(
                [NormalizedFinding("renamed.env", 1, "r", digest("alpha"), commit=c2)],
                manifest,
                HistorySource(root),
                scope={"renames": [{"commit": c2, "from": "app.env", "to": "renamed.env"}]},
            )
            self.assertEqual(result.metrics["matched_occurrences"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 0)

    def test_rename_with_line_movement_and_comment_is_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            original = root / "app.env"
            renamed = root / "renamed.env"
            original.write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            renamed.write_text("# moved comment\nKEY=alpha # annotation\n", encoding="utf-8")
            original.unlink()
            c2 = history_fixture._commit(root, "rename and annotate", 2)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            findings = [
                NormalizedFinding("app.env", 1, "r", digest("alpha"), commit=c1),
                NormalizedFinding("renamed.env", 2, "r", digest("alpha"), commit=c2),
            ]
            result = score_history(
                findings,
                manifest,
                HistorySource(root),
                scope={"renames": [{"commit": c2, "from": "app.env", "to": "renamed.env"}]},
            )
            self.assertEqual(result.metrics["matched_occurrences"], 1)
            self.assertEqual(result.metrics["duplicate_count"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 0)

    def test_rename_rotation_reintroduction_and_persistence_do_not_inherit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            original = root / "app.env"
            renamed = root / "renamed.env"
            original.write_text("PASSWORD=old-value\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "old value", 1)
            renamed.write_text("PASSWORD=new-value\n", encoding="utf-8")
            original.unlink()
            c2 = history_fixture._commit(root, "rename and rotate", 2)
            renamed.write_text("PASSWORD=old-value\n", encoding="utf-8")
            c3 = history_fixture._commit(root, "reintroduce old value", 3)
            (root / "marker.txt").write_text("persist\n", encoding="utf-8")
            c4 = history_fixture._commit(root, "persist reintroduced value", 4)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="old-value")]
            )
            findings = [
                NormalizedFinding("renamed.env", 1, "r", digest("new-value"), commit=c2),
                NormalizedFinding("renamed.env", 1, "r", digest("old-value"), commit=c3),
                NormalizedFinding("renamed.env", 1, "r", digest("old-value"), commit=c4),
            ]
            result = score_history(
                findings,
                manifest,
                HistorySource(root),
                scope={"renames": [{"commit": c2, "from": "app.env", "to": "renamed.env"}]},
            )
            self.assertEqual(result.metrics["matched_occurrences"], 0)
            self.assertEqual(result.metrics["duplicate_count"], 0)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 3)

    def test_rename_then_deletion_and_recreation_does_not_inherit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            original = root / "app.env"
            renamed = root / "renamed.env"
            original.write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            renamed.write_text(original.read_text(encoding="utf-8"), encoding="utf-8")
            original.unlink()
            c2 = history_fixture._commit(root, "rename app config", 2)
            renamed.unlink()
            history_fixture._commit(root, "delete renamed file", 3)
            renamed.write_text("KEY=alpha\n", encoding="utf-8")
            c4 = history_fixture._commit(root, "recreate renamed file", 4)
            (root / "marker.txt").write_text("persist\n", encoding="utf-8")
            c5 = history_fixture._commit(root, "persist recreated file", 5)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            result = score_history(
                [
                    NormalizedFinding("renamed.env", 1, "r", digest("alpha"), commit=c4),
                    NormalizedFinding("renamed.env", 1, "r", digest("alpha"), commit=c5),
                ],
                manifest,
                HistorySource(root),
                scope={"renames": [{"commit": c2, "from": "app.env", "to": "renamed.env"}]},
            )
            self.assertEqual(result.metrics["matched_occurrences"], 0)
            self.assertEqual(result.metrics["duplicate_count"], 0)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 2)

    def test_merge_rename_does_not_leak_to_unrelated_same_value_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            original = root / "app.env"
            original.write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            history_fixture._git(root, "checkout", "-b", "feature")
            renamed = root / "feature.env"
            renamed.write_text(original.read_text(encoding="utf-8"), encoding="utf-8")
            original.unlink()
            c2 = history_fixture._commit(root, "rename on feature", 2)
            history_fixture._git(root, "checkout", "main")
            (root / "unrelated.env").write_text("KEY=alpha\n", encoding="utf-8")
            history_fixture._commit(root, "add unrelated alpha", 3)
            history_fixture._git(root, "merge", "--no-ff", "feature", "-m", "merge feature")
            merge = history_fixture._git(root, "rev-parse", "HEAD")
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            result = score_history(
                [
                    NormalizedFinding("feature.env", 1, "r", digest("alpha"), commit=merge),
                    NormalizedFinding("unrelated.env", 1, "r", digest("alpha"), commit=merge),
                ],
                manifest,
                HistorySource(root),
                scope={"renames": [{"commit": c2, "from": "app.env", "to": "feature.env"}]},
            )
            self.assertEqual(result.metrics["matched_occurrences"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 1)
            self.assertEqual(result.metrics["duplicate_count"], 0)

    def test_same_line_comment_suffix_keeps_duplicate_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "app.env"
            path.write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            path.write_text("KEY=alpha # annotated\n", encoding="utf-8")
            c2 = history_fixture._commit(root, "annotate alpha", 2)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            findings = [
                NormalizedFinding("app.env", 1, "r", digest("alpha"), commit=c1),
                NormalizedFinding("app.env", 1, "r", digest("alpha"), commit=c2),
            ]
            result = score_history(findings, manifest, HistorySource(root))
            self.assertEqual(result.metrics["matched_occurrences"], 1)
            self.assertEqual(result.metrics["duplicate_count"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 0)

    def test_value_preserving_edit_that_changes_key_is_not_same_placement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "app.env"
            path.write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            path.write_text("OTHER=alpha\n", encoding="utf-8")
            c2 = history_fixture._commit(root, "change key", 2)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            result = score_history(
                [NormalizedFinding("app.env", 1, "r", digest("alpha"), commit=c2)],
                manifest,
                HistorySource(root),
            )
            self.assertEqual(result.metrics["matched_occurrences"], 0)
            self.assertEqual(result.metrics["duplicate_count"], 0)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 1)

    def test_trailing_comment_label_change_keeps_duplicate_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "app.env"
            path.write_text("KEY=alpha # Sensitive\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            path.write_text("KEY=alpha # Risk\n", encoding="utf-8")
            c2 = history_fixture._commit(root, "relabel alpha", 2)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            findings = [
                NormalizedFinding("app.env", 1, "r", digest("alpha"), commit=c1),
                NormalizedFinding("app.env", 1, "r", digest("alpha"), commit=c2),
            ]
            result = score_history(findings, manifest, HistorySource(root))
            self.assertEqual(result.metrics["matched_occurrences"], 1)
            self.assertEqual(result.metrics["duplicate_count"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 0)

    def test_rotation_and_reintroduction_do_not_reuse_old_occurrence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "app.env"
            path.write_text("PASSWORD=old-value\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "old value", 1)
            path.write_text("PASSWORD=new-value\n", encoding="utf-8")
            c2 = history_fixture._commit(root, "rotate value", 2)
            path.write_text("PASSWORD=old-value\n", encoding="utf-8")
            c3 = history_fixture._commit(root, "reintroduce old value", 3)
            (root / "marker.txt").write_text("persist\n", encoding="utf-8")
            c4 = history_fixture._commit(root, "persist reintroduced value", 4)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="old-value")]
            )
            findings = [
                NormalizedFinding("app.env", 1, "r", digest("old-value"), commit=c1),
                NormalizedFinding("app.env", 1, "r", digest("new-value"), commit=c2),
                NormalizedFinding("app.env", 1, "r", digest("old-value"), commit=c3),
                NormalizedFinding("app.env", 1, "r", digest("old-value"), commit=c4),
            ]
            result = score_history(findings, manifest, HistorySource(root))
            self.assertEqual(result.metrics["matched_occurrences"], 1)
            self.assertEqual(result.metrics["duplicate_count"], 0)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 3)

    def test_deleted_and_reintroduced_file_does_not_inherit_occurrence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "app.env"
            path.write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            path.unlink()
            history_fixture._commit(root, "delete file", 2)
            path.write_text("KEY=alpha\n", encoding="utf-8")
            c3 = history_fixture._commit(root, "recreate file", 3)
            (root / "marker.txt").write_text("persist\n", encoding="utf-8")
            c4 = history_fixture._commit(root, "persist recreated file", 4)
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            findings = [
                NormalizedFinding("app.env", 1, "r", digest("alpha"), commit=c3),
                NormalizedFinding("app.env", 1, "r", digest("alpha"), commit=c4),
            ]
            result = score_history(findings, manifest, HistorySource(root))
            self.assertEqual(result.metrics["matched_occurrences"], 0)
            self.assertEqual(result.metrics["duplicate_count"], 0)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 2)

    def test_branch_and_merge_line_shift_maps_to_introduction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "app.env"
            path.write_text("KEY=alpha\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "add alpha", 1)
            history_fixture._git(root, "checkout", "-b", "feature")
            path.write_text("# feature comment\nKEY=alpha\n", encoding="utf-8")
            history_fixture._commit(root, "shift on branch", 2)
            history_fixture._git(root, "checkout", "main")
            (root / "main.txt").write_text("main\n", encoding="utf-8")
            history_fixture._commit(root, "main change", 3)
            history_fixture._git(root, "merge", "--no-ff", "feature", "-m", "merge feature")
            merge = history_fixture._git(root, "rev-parse", "HEAD")
            manifest = oracle(
                [item("H", "POSITIVE", "ENVIRONMENT_CREDENTIAL", "G", c1, "app.env", 1, value="alpha")]
            )
            result = score_history(
                [NormalizedFinding("app.env", 2, "r", digest("alpha"), commit=merge)],
                manifest,
                HistorySource(root),
            )
            self.assertEqual(result.metrics["matched_occurrences"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 0)

    def test_removed_negative_matches_only_while_value_existed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "hub"
            path.write_text("oauth_token: oauth_token\n", encoding="utf-8")
            c1 = history_fixture._commit(root, "placeholder", 1)
            path.write_text('oauth_token: "real-token"\n', encoding="utf-8")
            c2 = history_fixture._commit(root, "replace placeholder", 2)
            manifest = oracle(
                [
                    item(
                        "N",
                        "NEGATIVE",
                        "NON_SECRET_PLACEHOLDER",
                        None,
                        c2,
                        "hub",
                        1,
                        observed_commit=c1,
                        change_event="Removed",
                    )
                ]
            )
            result = score_history(
                [
                    NormalizedFinding("hub", 1, "r", digest("oauth_token"), commit=c1),
                    NormalizedFinding("hub", 1, "r", digest("real-token"), commit=c2),
                ],
                manifest,
                HistorySource(root),
            )
            self.assertEqual(result.metrics["verified_false_positive_count"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 1)
            self.assertEqual(result.metrics["matched_occurrences"], 0)

    def test_informative_reference_requires_expected_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "login.js"
            path.write_text(
                "conn.login('user@example.com', 'examplepassword', function(err, res) {\n",
                encoding="utf-8",
            )
            c1 = history_fixture._commit(root, "add example", 1)
            manifest = oracle(
                [
                    item(
                        "I",
                        "INFORMATIVE",
                        "EXAMPLE_LOGIN_CREDENTIAL",
                        None,
                        c1,
                        "login.js",
                        1,
                        value="examplepassword",
                    )
                ]
            )
            result = score_history(
                [
                    NormalizedFinding("login.js", 1, "r", digest("function(err"), commit=c1),
                    NormalizedFinding("login.js", 1, "r", digest("examplepassword"), commit=c1),
                ],
                manifest,
                HistorySource(root),
            )
            self.assertEqual(result.metrics["informative_match_count"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 1)
            mentions = [
                evaluation
                for evaluation in result.evaluations
                if evaluation.observed is not None and evaluation.path == "login.js"
            ]
            self.assertEqual(
                sorted(evaluation.classification for evaluation in mentions),
                ["INFORMATIVE_MATCH", "UNMATCHED_PENDING_REVIEW"],
            )

    def test_exact_negative_on_informative_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "login.js"
            path.write_text(
                "conn.login('user@example.com', 'examplepassword', function(err, res) {\n",
                encoding="utf-8",
            )
            c1 = history_fixture._commit(root, "add example", 1)
            manifest = oracle(
                [
                    item(
                        "I",
                        "INFORMATIVE",
                        "EXAMPLE_LOGIN_CREDENTIAL",
                        None,
                        c1,
                        "login.js",
                        1,
                        value="examplepassword",
                    ),
                    item(
                        "N",
                        "NEGATIVE",
                        "NON_SECRET_REFERENCE",
                        None,
                        c1,
                        "login.js",
                        1,
                        value="function(err",
                    ),
                ]
            )
            result = score_history(
                [
                    NormalizedFinding("login.js", 1, "r", digest("function(err"), commit=c1),
                    NormalizedFinding("login.js", 1, "r", digest("examplepassword"), commit=c1),
                ],
                manifest,
                HistorySource(root),
            )
            self.assertEqual(result.metrics["verified_false_positive_count"], 1)
            self.assertEqual(result.metrics["unique_verified_nonsecret_exposure_count"], 1)
            self.assertEqual(result.metrics["informative_match_count"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 0)
            self.assertEqual(result.metrics["ambiguous_count"], 0)

    def test_repeated_negative_alerts_count_one_unique_exposure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            path = root / "login.js"
            path.write_text(
                "conn.login('user@example.com', 'examplepassword', function(err, res) {\n",
                encoding="utf-8",
            )
            c1 = history_fixture._commit(root, "add example", 1)
            (root / "marker.txt").write_text("persist\n", encoding="utf-8")
            c2 = history_fixture._commit(root, "persist example", 2)
            manifest = oracle(
                [
                    item(
                        "N",
                        "NEGATIVE",
                        "NON_SECRET_REFERENCE",
                        None,
                        c1,
                        "login.js",
                        1,
                        value="function(err",
                    )
                ]
            )
            result = score_history(
                [
                    NormalizedFinding("login.js", 1, "r", digest("function(err"), commit=c1),
                    NormalizedFinding("login.js", 1, "r", digest("function(err"), commit=c2),
                ],
                manifest,
                HistorySource(root),
            )
            self.assertEqual(result.metrics["verified_false_positive_count"], 2)
            self.assertEqual(result.metrics["unique_verified_nonsecret_exposure_count"], 1)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 0)

    def test_exact_negatives_do_not_match_other_tokens_on_the_same_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            init_repo(root)
            meta = root / ".leaky-meta"
            meta.mkdir()
            (meta / "secrets.csv").write_text(
                "# Risk: userPassword, sshPassphrase, sshUserPassword\n",
                encoding="utf-8",
            )
            (root / "login.js").write_text(
                "conn.login('user@example.com', 'examplepassword', function(err, res) {\n",
                encoding="utf-8",
            )
            c1 = history_fixture._commit(root, "add exact-negative lines", 1)
            manifest = oracle(
                [
                    item(
                        "PNM-001",
                        "NEGATIVE",
                        "NON_SECRET_REFERENCE",
                        None,
                        c1,
                        ".leaky-meta/secrets.csv",
                        1,
                        value="sshPassphrase",
                    ),
                    item(
                        "PNJ-001",
                        "NEGATIVE",
                        "NON_SECRET_REFERENCE",
                        None,
                        c1,
                        "login.js",
                        1,
                        value="function(err",
                    ),
                ]
            )
            result = score_history(
                [
                    NormalizedFinding(
                        ".leaky-meta/secrets.csv",
                        1,
                        "r",
                        digest("sshPassphrase"),
                        commit=c1,
                    ),
                    NormalizedFinding(
                        ".leaky-meta/secrets.csv",
                        1,
                        "r",
                        digest("userPassword"),
                        commit=c1,
                    ),
                    NormalizedFinding(
                        "login.js",
                        1,
                        "r",
                        digest("function(err"),
                        commit=c1,
                    ),
                    NormalizedFinding(
                        "login.js",
                        1,
                        "r",
                        digest("examplepassword"),
                        commit=c1,
                    ),
                ],
                manifest,
                HistorySource(root),
            )
            self.assertEqual(result.metrics["verified_false_positive_count"], 2)
            self.assertEqual(result.metrics["unique_verified_nonsecret_exposure_count"], 2)
            self.assertEqual(result.metrics["unmatched_pending_review_count"], 2)
            self.assertEqual(result.metrics["ambiguous_count"], 0)


if __name__ == "__main__":
    unittest.main()
