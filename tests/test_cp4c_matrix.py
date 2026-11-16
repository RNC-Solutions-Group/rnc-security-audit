"""CP4C Matrix 0 contract and planning tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from harness import cp4c_matrix
from harness.profiler_contract import (
    ProfileError,
    load_profile,
    validate_profile,
    validate_profile_schema,
)


def _profile(**overrides):
    document = {
        "schema_version": "1",
        "engine_version": "0.1.0",
        "run_id": "matrix-test",
        "settings": {
            "requested": {
                "workers": "8",
                "mode": "auto",
                "strategy": "auto",
                "git_io": "process",
                "history_mode": "whole",
                "context_lines": "0",
            },
            "effective": {
                "workers": "8",
                "mode": "auto",
                "strategy": "regex",
                "git_io": "process",
                "history_mode": "whole",
                "context_lines": "0",
            },
        },
        "phases": {
            "execution": {"ns": 10, "exclusive_ns": 10, "count": 1, "bytes": 0},
        },
        "worker_phases": {
            "matching.regex": {"ns": 8, "exclusive_ns": 8, "count": 2, "bytes": 9},
        },
        "counters": {"workers_effective": 8},
    }
    document.update(overrides)
    return document


class ProfileContractTests(unittest.TestCase):
    def test_valid_profile_and_schema(self):
        validation = validate_profile(
            _profile(),
            expected_run_id="matrix-test",
            expected_requested={
                "workers": "8",
                "mode": "auto",
                "strategy": "auto",
                "git_io": "process",
                "history_mode": "whole",
                "context_lines": "0",
            },
        )
        self.assertEqual(validation["schema_version"], "1")
        self.assertEqual(validation["effective"]["strategy"], "regex")
        schema = validate_profile_schema(_profile())
        self.assertIn("performed", schema)

    def test_unknown_root_or_phase_field_is_rejected(self):
        with self.assertRaises(ProfileError):
            validate_profile({**_profile(), "extra": 1})
        bad = _profile()
        bad["phases"]["execution"]["private"] = 1
        with self.assertRaises(ProfileError):
            validate_profile(bad)

    def test_execution_phase_is_required(self):
        bad = _profile()
        bad["phases"].pop("execution")
        with self.assertRaises(ProfileError):
            validate_profile(bad)

    def test_effective_workers_must_match_requested(self):
        bad = _profile()
        bad["settings"]["effective"]["workers"] = "4"
        with self.assertRaises(ProfileError):
            validate_profile(bad)

    def test_expected_settings_must_match(self):
        with self.assertRaises(ProfileError):
            validate_profile(
                _profile(),
                expected_requested={"workers": "1", "mode": "auto"},
            )

    def test_duplicate_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.json"
            path.write_text(
                '{"schema_version":"1","schema_version":"1"}',
                encoding="utf-8",
            )
            with self.assertRaises(ProfileError):
                load_profile(path)

    def test_non_object_or_missing_profile_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "array.json").write_text("[]", encoding="utf-8")
            with self.assertRaises(ProfileError):
                load_profile(root / "array.json")
            with self.assertRaises(ProfileError):
                load_profile(root / "missing.json")

    def test_profile_is_loaded_with_duplicate_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.json"
            path.write_text(json.dumps(_profile()), encoding="utf-8")
            self.assertEqual(load_profile(path)["run_id"], "matrix-test")


class MatrixPlanningTests(unittest.TestCase):
    def _workload(self, *, mode="dir"):
        return cp4c_matrix.Workload(
            key="wl",
            title="workload",
            mode=mode,
            lane="filesystem" if mode == "dir" else "git",
            target=Path("target"),
            files=1,
            eligible_files=1,
            inspected_files=1,
            bytes=10,
            oracle_scored=True,
            multiplier=1,
            source="test",
            dataset={},
        )

    def test_config_keys_and_profile_states(self):
        self.assertEqual(
            cp4c_matrix.config_key("rnclab-git", 8, True),
            "rnclab-git-w8-profile-on",
        )
        self.assertEqual(cp4c_matrix.profile_state(False), "off")

    def test_filesystem_arguments_do_not_include_git_flags(self):
        workload = self._workload()
        args = cp4c_matrix.scan_arguments(
            workload, 4, profiler=False, profile_path=None
        )
        self.assertIn("--workers", args)
        self.assertIn("4", args)
        self.assertNotIn("--git-io", args)
        self.assertNotIn("--history-mode", args)
        self.assertNotIn("--profile-output", args)

    def test_git_and_profile_arguments(self):
        workload = self._workload(mode="git")
        args = cp4c_matrix.scan_arguments(
            workload,
            8,
            profiler=True,
            profile_path=Path("profile.json"),
        )
        self.assertIn("--git-io", args)
        self.assertEqual(args[args.index("--git-io") + 1], "process")
        self.assertEqual(args[args.index("--history-mode") + 1], "whole")
        self.assertEqual(args[args.index("--workers") + 1], "8")
        self.assertEqual(args[args.index("--profile-output") + 1], "profile.json")

    def test_expected_git_settings_include_default_context(self):
        settings = cp4c_matrix.expected_profile_settings(
            self._workload(mode="git"), 2
        )
        self.assertEqual(settings["workers"], "2")
        self.assertEqual(settings["context_lines"], "0")
        self.assertEqual(settings["git_io"], "process")

    def test_canonical_signature_is_order_invariant_and_byte_sensitive(self):
        first = SimpleNamespace(
            file="a.env",
            commit=None,
            line=1,
            rule_id="rule",
            secret_sha256="a" * 64,
            match_sha256="b" * 64,
            byte_start=1,
            byte_end=3,
            source_span_sha256="c" * 64,
            container_member=None,
        )
        second = SimpleNamespace(**{**vars(first), "file": "b.env"})
        forward = cp4c_matrix._canonical_signature([first, second])[0]
        reverse = cp4c_matrix._canonical_signature([second, first])[0]
        self.assertEqual(forward, reverse)
        changed = SimpleNamespace(**{**vars(first), "byte_end": 4})
        self.assertNotEqual(
            forward,
            cp4c_matrix._canonical_signature([changed, second])[0],
        )

    def test_stats_and_percentage(self):
        stats = cp4c_matrix._stats([1.0, 2.0, 3.0])
        self.assertEqual(stats["median"], 2.0)
        self.assertGreater(stats["coefficient_of_variation"], 0)
        self.assertEqual(cp4c_matrix._pct(2.0, 10.0), 20.0)
        self.assertIsNone(cp4c_matrix._pct(2.0, 0.0))
        self.assertEqual(cp4c_matrix._stats([])["count"], 0)

    def test_cli_exposes_matrix(self):
        from harness.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["matrix", "--experiment", "cp4c"])
        self.assertEqual(args.experiment, "cp4c")
        self.assertEqual(args.repetitions, 5)


if __name__ == "__main__":
    unittest.main()
