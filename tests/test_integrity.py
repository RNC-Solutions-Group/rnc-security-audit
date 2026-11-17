"""Deterministic evidence selection and fail-closed publication tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.detection_gaps.inputs import (
    InputSelectionError,
    build_lock,
    select_report,
    write_lock,
)
from harness.detection_gaps.reporting import (
    DetectionGapError,
    _publication_guard,
    _publish_staged,
)


def _report(build_id: str = "rnc-cp4c", payload: str = "one") -> dict:
    return {
        "report_type": "rnc-scan-harness/experiment",
        "registered_build": {
            "id": build_id,
            "scanner": "rnc",
            "source_commit": "a" * 40,
            "executable_sha256": "b" * 64,
        },
        "summary": {"overall": "COMPLETE", "build_id": build_id},
        "profile": {"name": "default"},
        "report_options": {"scanner_extra_args": ["--workers", "auto"]},
        "payload": payload,
    }


class ReportSelectionTests(unittest.TestCase):
    def _workspace(self) -> tuple[Path, Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        report_dir = root / "reports"
        report_dir.mkdir()
        report = report_dir / "cp4c.json"
        report.write_text(json.dumps(_report()), encoding="utf-8")
        lock = root / "analysis-inputs.json"
        document = build_lock(
            {"cp4c": report},
            root=root,
            harness_version="test",
            harness_source_commit="f" * 40,
        )
        write_lock(lock, document)
        return root, report, lock

    def test_pinned_report_is_selected_regardless_of_newer_mtime(self) -> None:
        root, report, lock = self._workspace()
        newer = root / "reports" / "newer.json"
        newer.write_text(json.dumps(_report(payload="newer")), encoding="utf-8")
        selection = select_report("cp4c", lock_path=lock, root=root)
        self.assertEqual(selection.path, report)
        self.assertEqual(selection.source, "pinned-lock")
        self.assertFalse(selection.override)
        self.assertEqual(selection.sha256, selection.locked_sha256)

    def test_hash_mismatch_fails_closed(self) -> None:
        root, report, lock = self._workspace()
        report.write_text(json.dumps(_report(payload="changed")), encoding="utf-8")
        with self.assertRaises(InputSelectionError):
            select_report("cp4c", lock_path=lock, root=root)

    def test_missing_lock_does_not_fall_back_to_mtime(self) -> None:
        root, _report_path, _lock = self._workspace()
        with self.assertRaises(InputSelectionError) as raised:
            select_report("cp4c", lock_path=root / "missing.json", root=root)
        self.assertIn("no longer selects the newest report", str(raised.exception))

    def test_explicit_override_is_recorded_and_identity_checked(self) -> None:
        root, report, _lock = self._workspace()
        selection = select_report("cp4c", explicit=report, lock_path=None, root=root)
        self.assertTrue(selection.override)
        self.assertEqual(selection.source, "explicit-override")
        self.assertTrue(selection.warnings)

    def test_explicit_wrong_build_is_rejected(self) -> None:
        root, _report_path, _lock = self._workspace()
        wrong = root / "wrong.json"
        wrong.write_text(json.dumps(_report(build_id="rnc-cp3")), encoding="utf-8")
        with self.assertRaises(InputSelectionError):
            select_report("cp4c", explicit=wrong, root=root)


class PublicationTests(unittest.TestCase):
    def _workspace(self) -> tuple[Path, Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        staging = root / "staging"
        staging.mkdir()
        (staging / "README.md").write_text("# report\n", encoding="utf-8")
        (staging / "analysis-validation.json").write_text(
            json.dumps({"validation": {"all_missed_targets_have_evidence": True}}),
            encoding="utf-8",
        )
        return staging, root / "published"

    def test_publish_writes_complete_manifest(self) -> None:
        staging, out = self._workspace()
        _publish_staged(
            staging,
            out,
            replace=True,
            generated_at="2026-01-01T00:00:00Z",
            run_metadata={"test": True},
        )
        marker = json.loads((out / "publication.json").read_text(encoding="utf-8"))
        self.assertEqual(marker["status"], "COMPLETE")
        self.assertEqual({item["path"] for item in marker["files"]}, {"README.md", "analysis-validation.json"})
        self.assertTrue((out / "README.md").is_file())

    def test_failed_publish_leaves_in_progress_marker(self) -> None:
        staging, out = self._workspace()
        with patch(
            "harness.detection_gaps.reporting.atomic_write_bytes",
            side_effect=OSError("simulated disk failure"),
        ):
            with self.assertRaises(OSError):
                _publish_staged(
                    staging,
                    out,
                    replace=True,
                    generated_at="2026-01-01T00:00:00Z",
                    run_metadata={},
                )
        marker = json.loads((out / "publication.json").read_text(encoding="utf-8"))
        self.assertEqual(marker["status"], "IN_PROGRESS")

    def test_unknown_nonempty_directory_requires_replace(self) -> None:
        _staging, out = self._workspace()
        out.mkdir()
        (out / "historical.md").write_text("do not overwrite", encoding="utf-8")
        with self.assertRaises(DetectionGapError):
            _publication_guard(out, replace=False)


if __name__ == "__main__":
    unittest.main()
