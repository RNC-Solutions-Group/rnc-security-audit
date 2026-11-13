"""End-to-end Leaky Repo history scoring through the suite boundary."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from harness import leaky_repo, rescore, status as statuses
from harness.adapters.base import BuildArtifact, PLATFORMS
from harness.contracts import NormalizedFinding
from harness.suites.leaky_repo import LeakyRepoSuite

CACHE = Path(
    "datasets/cache/leaky-repo/2e951359cac53addbee56437da3ffb546e3dfe24/source"
)
REPORT = Path(
    "reports/cp3/gitleaks-5f6ec56-native-5f6ec56cfa6f-default.json"
)


def retained_findings() -> list[NormalizedFinding]:
    document = json.loads(REPORT.read_text(encoding="utf-8"))
    lane = next(
        iter(document["suites"]["leaky-repo"]["details"]["history_lanes"].values())
    )
    return [
        NormalizedFinding(
            file=value["file"],
            line=value.get("line"),
            rule_id=value.get("rule_id") or "",
            secret_sha256=value.get("secret_sha256"),
            match_sha256=value.get("match_sha256"),
            secret_redacted=bool(value.get("secret_redacted")),
            commit=value.get("commit"),
            metadata=dict(value.get("metadata") or {}),
        )
        for value in lane["findings"]
    ]


@unittest.skipUnless(CACHE.is_dir() and REPORT.is_file(), "pinned history evidence is unavailable")
class HistorySuiteIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = leaky_repo.prepare(offline=True)
        cls.findings = retained_findings()

    def test_history_lane_is_scored_and_fully_accounted(self):
        artifact = BuildArtifact(
            platform=PLATFORMS["windows-amd64"],
            status=statuses.PASS,
            command=(),
            exit_code=0,
            duration_seconds=1.0,
            artifact_path="gitleaks.exe",
            artifact_sha256="a" * 64,
            image_id=None,
            image_tag=None,
            version="test",
            version_status=statuses.PASS,
            stdout_sha256="b" * 64,
            stderr_sha256="c" * 64,
            error=None,
        )

        class FakeAdapter:
            key = "gitleaks"
            supported_suites = ("leaky-repo",)

            def supports_mode(self, mode):
                return mode == "git"

            def can_execute(self, platform):
                return True

            def invoke_native(self, *args, **kwargs):
                return SimpleNamespace(
                    exit_code=1,
                    timed_out=False,
                    duration_seconds=1.0,
                    report_bytes=b"[]",
                    stdout=b"",
                    stderr=b"",
                )

            def invocation_problem(self, invocation):
                return None

            def parse_findings(self, data):
                return self.findings

        adapter = FakeAdapter()
        adapter.findings = self.findings
        cache = {}
        with tempfile.TemporaryDirectory() as tmp:
            context = SimpleNamespace(
                work_dir=Path(tmp),
                adapter=adapter,
                timeout=30,
                scanner_config=None,
                cached=lambda key, factory: cache.setdefault(key, factory()),
            )
            lane = LeakyRepoSuite()._run_history(context, artifact, self.prepared)
        self.assertEqual(lane["status"], statuses.PASS)
        self.assertEqual(lane["outcome"], statuses.COMPLETED_AND_SCORED)
        self.assertEqual(lane["truth_status"], "APPROVED_SOURCE_ORACLE")
        self.assertTrue(lane["scored"])
        metrics = lane["metrics"]
        self.assertEqual(metrics["expected_occurrences"], 65)
        self.assertEqual(metrics["matched_occurrences"], 21)
        self.assertEqual(metrics["unique_matched"], 15)
        self.assertEqual(metrics["duplicate_count"], 3)
        self.assertEqual(metrics["informative_match_count"], 2)
        self.assertEqual(metrics["verified_false_positive_count"], 0)
        self.assertEqual(metrics["accounted_observed_count"], 26)
        self.assertTrue(metrics["finding_accounting_reconciled"])
        self.assertIsNone(metrics["precision_percent"])
        self.assertEqual(
            metrics["precision_certification_status"],
            "BLOCKED_INCOMPLETE_NEGATIVE_ORACLE",
        )
        text = json.dumps(lane, sort_keys=True).lower()
        for raw_marker in ("raw_secret", "plaintext", "secret_text"):
            self.assertNotIn(raw_marker, text)

    def test_retained_report_rescores_without_a_scanner(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        document = rescore.rescore_report(
            report,
            platform="windows-amd64",
            cache_dir=leaky_repo.DEFAULT_CACHE,
        )
        self.assertEqual(document["status"], "PASS")
        self.assertEqual(document["input_report"]["observed_findings"], 26)
        self.assertEqual(document["metrics"]["matched_occurrences"], 21)
        self.assertEqual(document["metrics"]["unique_matched"], 15)

    def test_truncated_report_is_not_rescored_silently(self):
        report = {
            "suites": {
                "leaky-repo": {
                    "details": {
                        "history_lanes": {
                            "windows-amd64": {
                                "findings": [],
                                "finding_count": 26,
                            }
                        }
                    }
                }
            }
        }
        with self.assertRaises(rescore.RescoreError):
            rescore.extract_history_findings(report, platform="windows-amd64")

    def test_multiple_lanes_require_an_explicit_platform(self):
        report = {
            "suites": {
                "leaky-repo": {
                    "details": {
                        "history_lanes": {
                            "windows-amd64": {"findings": []},
                            "docker-linux-amd64": {"findings": []},
                        }
                    }
                }
            }
        }
        with self.assertRaises(rescore.RescoreError):
            rescore.extract_history_findings(report)


if __name__ == "__main__":
    unittest.main()
