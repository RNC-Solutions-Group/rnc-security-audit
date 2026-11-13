"""Scanner adapter and platform catalog tests."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness import execution
from harness.adapters import (
    PLATFORM_CATALOG,
    adapter_keys,
    expand_platform_selection,
    get_adapter,
    host_platform,
)
from harness.adapters.gitleaks import _version_from_text
from harness.errors import ReportError


class BetterleaksAdapterTests(unittest.TestCase):
    def test_registry_and_capabilities(self):
        self.assertEqual(set(adapter_keys()), {"gitleaks", "betterleaks", "rnc"})
        adapter = get_adapter("betterleaks")
        self.assertEqual(adapter.key, "betterleaks")
        self.assertIn("synthetic-filesystem", adapter.supported_suites)
        self.assertIn("git-history", adapter.supported_suites)
        self.assertIn("leaky-repo", adapter.supported_suites)
        self.assertTrue(adapter.supports_mode("git"))
        self.assertFalse(adapter.supports_mode("stdin"))
        self.assertEqual(adapter.platforms, PLATFORM_CATALOG)

    def test_parser_normalizes_betterleaks_shape(self):
        adapter = get_adapter("betterleaks")
        raw = json.dumps(
            [
                {
                    "File": "a.env",
                    "StartLine": 3,
                    "RuleID": "rule",
                    "Secret": "synthetic-secret",
                    "Match": "KEY=synthetic-secret",
                    "Commit": "a" * 40,
                    "Fingerprint": "commit:a.env:rule:3",
                }
            ]
        ).encode()
        findings = adapter.parse_findings(raw)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file, "a.env")
        self.assertEqual(findings[0].line, 3)
        self.assertEqual(findings[0].commit, "a" * 40)
        self.assertNotIn("synthetic-secret", repr(findings[0]))
        self.assertNotIn("synthetic-secret", json.dumps(findings[0].safe_dict()))

    def test_betterleaks_has_no_release_artifact_dependency(self):
        import harness.adapters.betterleaks as module

        self.assertFalse(hasattr(module, "WINDOWS_URL"))
        self.assertFalse(hasattr(module, "DOCKER_AMD64"))
        self.assertFalse(hasattr(module, "WINDOWS_BINARY_SHA256"))
        self.assertIn("github.com/betterleaks/betterleaks", module.BetterleaksAdapter.default_repository)

    def test_empty_report_is_valid_zero_findings(self):
        for key in ("gitleaks", "betterleaks"):
            self.assertEqual(get_adapter(key).parse_findings(b"[]"), [])
        self.assertEqual(get_adapter("betterleaks").parse_findings(b"null"), [])

    def test_invalid_or_truncated_reports_are_errors(self):
        for key in ("gitleaks", "betterleaks"):
            adapter = get_adapter(key)
            for payload in (b"", b"not-json", b'[{"File":"a"'):
                with self.assertRaises((ReportError, ValueError), msg=(key, payload)):
                    adapter.parse_findings(payload)

    def test_default_profile_isolation_removes_config_environment(self):
        adapter = get_adapter("betterleaks")
        with patch.dict(
            os.environ,
            {"BETTERLEAKS_CONFIG": "hostile.toml", "GITLEAKS_CONFIG": "other.toml"},
            clear=False,
        ):
            environment = adapter.clean_environment()
        self.assertNotIn("BETTERLEAKS_CONFIG", environment)
        self.assertNotIn("GITLEAKS_CONFIG", environment)
        description = adapter.default_configuration()
        self.assertTrue(description["isolated_working_directory"])
        self.assertIn("BETTERLEAKS_CONFIG", description["removed_environment"])


class RNCAdapterTests(unittest.TestCase):
    _UNIT = "u-" + "a" * 64

    def _report(self, *, result_code=3, exit_code=10, finding=True):
        digest = "a" * 64
        document = {
            "format_version": "rnc-cp2-output-v1",
            "execution": {
                "state": "COMPLETED",
                "evidence_valid": True,
                "failure_codes": [],
                "fatal_errors": [],
                "source_adapter": {"id": "local-working-tree", "version": "0.1.0"},
                "ruleset_id": "rnc-providers-v1",
                "ruleset_digest": f"sha256:{digest}",
                "units": [
                    {
                        "unit_id": self._UNIT,
                        "source_id": "local-working-tree",
                        "source_kind": "working_tree_file",
                        "locator": "nested/app.env",
                        "required_scope": True,
                        "disposition": "INSPECTED",
                        "content_sha256": f"sha256:{'b' * 64}",
                        "byte_length": 32,
                        "line_count": 1,
                    }
                ],
            },
            "findings": [
                {
                    "schema_version": "0.2.0",
                    "unit_id": self._UNIT,
                    "finding_id": "f1",
                    "rule_id": "github-classic-pat",
                    "rule_version": "v1",
                    "category": "developer-platform-credential",
                    "start_byte": 8,
                    "end_byte": 28,
                    "line": 1,
                    "confidence": "high",
                    "validation": ["ASCII_ONLY"],
                    "evidence_digest": f"sha256:{digest}",
                }
            ]
            if finding
            else [],
            "result": {
                "result_code": result_code,
                "result": {1: "CLEAN", 2: "POLICY_APPLIED", 3: "ACTIONABLE", 4: "INCOMPLETE", 5: "FAILED"}[result_code],
                "coverage": "COMPLETE" if result_code in (1, 2, 3) else "INCOMPLETE",
                "evidence_valid": result_code in (1, 2, 3),
                "engine_version": "0.1.0",
                "ruleset_id": "rnc-providers-v1",
                "ruleset_digest": f"sha256:{digest}",
                "source_adapter": {"id": "local-working-tree", "version": "0.1.0"},
                "reason_codes": [],
                "counts": {
                    "discovered": 1,
                    "inspected": 1,
                    "required_discovered": 1,
                    "required_inspected": 1,
                    "required_verified_blocked": 0,
                    "required_uninspected": 0,
                    "uninspected": 0,
                    "verified_blocked": 0,
                },
            },
            "ci": {"process_exit_code": exit_code, "result_code": result_code},
        }
        return json.dumps(document).encode()

    def test_registry_capabilities_and_default_rules(self):
        self.assertEqual(set(adapter_keys()), {"gitleaks", "betterleaks", "rnc"})
        adapter = get_adapter("rnc")
        self.assertEqual(adapter.key, "rnc")
        self.assertEqual(
            set(adapter.supported_suites),
            {"synthetic-filesystem", "levain", "leaky-repo", "rnclab"},
        )
        self.assertTrue(adapter.supports_mode("dir"))
        self.assertTrue(adapter.supports_mode("git"))
        self.assertFalse(adapter.supports_mode("stdin"))
        self.assertEqual(adapter.default_configuration()["rules_path"], "rules/rnc-providers-v1.json")
        self.assertEqual(adapter.default_configuration()["history_mode"]["ref"], "HEAD")

    def test_private_report_normalizes_units_and_digest(self):
        adapter = get_adapter("rnc")
        findings = adapter.parse_findings(self._report())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file, "nested/app.env")
        self.assertEqual(findings[0].line, 1)
        self.assertEqual(findings[0].rule_id, "github-classic-pat")
        self.assertEqual(findings[0].secret_sha256, "a" * 64)
        self.assertTrue(findings[0].secret_redacted)
        self.assertNotIn("synthetic-secret", repr(findings[0]))

    def test_valid_empty_private_report_is_zero_findings(self):
        self.assertEqual(
            get_adapter("rnc").parse_findings(self._report(finding=False)), []
        )

    def test_exit_and_result_classification(self):
        adapter = get_adapter("rnc")
        for exit_code, result_code, expected in (
            (0, 1, None),
            (0, 2, None),
            (10, 3, None),
            (20, 4, "INCOMPLETE"),
            (30, 5, "FAILED"),
        ):
            invocation = execution.Invocation(
                binary_path="rnc",
                binary_sha256="b" * 64,
                argv=("rnc",),
                mode="dir",
                report_path="report.json",
                exit_code=exit_code,
                timed_out=False,
                duration_seconds=1.0,
                timeout_seconds=10,
                stdout=b"",
                stderr=b"",
                report_bytes=self._report(result_code=result_code, exit_code=exit_code),
            )
            self.assertEqual(adapter.invocation_problem(invocation), expected)

    def test_invalid_private_report_is_rejected(self):
        adapter = get_adapter("rnc")
        for payload in (
            b"",
            b"{}",
            json.dumps({"format_version": "rnc-cp2-output-v1", "findings": []}).encode(),
            self._report().replace(self._UNIT.encode(), b"u-" + b"b" * 64, 1),
        ):
            with self.assertRaises((ReportError, ValueError)):
                adapter.parse_findings(payload)

    def _coverage_report(
        self,
        path: Path,
        *,
        disposition: str = "INSPECTED",
        ruleset_id: str = "rnc-providers-v1",
        result_code: int = 1,
        unit: bool = True,
    ) -> bytes:
        content = b"KEY=value\n"
        path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        units = (
            [
                {
                    "unit_id": self._UNIT,
                    "locator": path.name,
                    "source_id": "local-working-tree",
                    "source_kind": "working_tree_file",
                    "required_scope": True,
                    "disposition": disposition,
                    "content_sha256": f"sha256:{digest}",
                    "byte_length": len(content),
                    "line_count": 1,
                }
            ]
            if unit
            else []
        )
        inspected = 1 if unit and disposition == "INSPECTED" else 0
        document = {
            "format_version": "rnc-cp2-output-v1",
            "execution": {
                "state": "COMPLETED" if result_code in (1, 2, 3) else "ERROR",
                "evidence_valid": result_code in (1, 2, 3),
                "failure_codes": [],
                "fatal_errors": [],
                "source_adapter": {"id": "local-working-tree", "version": "0.1.0"},
                "ruleset_id": ruleset_id,
                "ruleset_digest": f"sha256:{'a' * 64}",
                "units": units,
            },
            "findings": [],
            "result": {
                "result_code": result_code,
                "result": {1: "CLEAN", 2: "POLICY_APPLIED", 3: "ACTIONABLE", 4: "INCOMPLETE", 5: "FAILED"}[result_code],
                "coverage": "COMPLETE" if result_code in (1, 2, 3) else "INCOMPLETE",
                "evidence_valid": result_code in (1, 2, 3),
                "ruleset_id": ruleset_id,
                "ruleset_digest": f"sha256:{'a' * 64}",
                "source_adapter": {"id": "local-working-tree", "version": "0.1.0"},
                "reason_codes": [],
                "counts": {
                    "discovered": 1 if unit else 0,
                    "inspected": inspected,
                    "required_discovered": 1 if unit else 0,
                    "required_inspected": inspected,
                    "required_verified_blocked": 0,
                    "required_uninspected": 1 if unit and disposition != "INSPECTED" else 0,
                    "uninspected": 1 if unit and disposition != "INSPECTED" else 0,
                    "verified_blocked": 0,
                },
            },
            "ci": {"result_code": result_code, "process_exit_code": 0 if result_code in (1, 2) else 10},
        }
        return json.dumps(document).encode()

    def _coverage_invocation(self, report: bytes, exit_code: int = 0):
        return execution.Invocation(
            binary_path="rnc",
            binary_sha256="c" * 64,
            argv=("rnc",),
            mode="dir",
            report_path="report.json",
            exit_code=exit_code,
            timed_out=False,
            duration_seconds=1.0,
            timeout_seconds=10,
            stdout=b"",
            stderr=b"",
            report_bytes=report,
        )

    def test_execution_coverage_verifies_complete_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.env"
            report = self._coverage_report(path)
            adapter = get_adapter("rnc")
            adapter._active_ruleset = {
                "ruleset_id": "rnc-providers-v1",
                "ruleset_version": "2026.11.2",
                "digest": f"sha256:{'a' * 64}",
            }
            coverage = adapter.execution_coverage(
                self._coverage_invocation(report), tmp, ("app.env",)
            )
            self.assertTrue(coverage["verified"], coverage["notes"])
            self.assertEqual(coverage["counts"]["required_inspected"], 1)

    def test_execution_coverage_rejects_missing_and_uninspected_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.env"
            adapter = get_adapter("rnc")
            adapter._active_ruleset = {
                "ruleset_id": "rnc-providers-v1",
                "ruleset_version": "2026.11.2",
                "digest": f"sha256:{'a' * 64}",
            }
            for report in (
                self._coverage_report(path, unit=False),
                self._coverage_report(path, disposition="UNINSPECTED"),
                self._coverage_report(path, ruleset_id="wrong-ruleset"),
                self._coverage_report(path, result_code=4),
            ):
                coverage = adapter.execution_coverage(
                    self._coverage_invocation(report), tmp, ("app.env",)
                )
                self.assertFalse(coverage["verified"], coverage["notes"])

    def test_execution_coverage_rejects_missing_file_and_content_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.env"
            report = self._coverage_report(path)
            adapter = get_adapter("rnc")
            adapter._active_ruleset = {
                "ruleset_id": "rnc-providers-v1",
                "ruleset_version": "2026.11.2",
                "digest": f"sha256:{'a' * 64}",
            }
            self.assertFalse(
                adapter.execution_coverage(
                    self._coverage_invocation(report), tmp, ("missing.env",)
                )["verified"]
            )
            path.write_bytes(b"changed\n")
            self.assertFalse(
                adapter.execution_coverage(
                    self._coverage_invocation(report), tmp, ("app.env",)
                )["verified"]
            )

    def test_missing_and_malformed_reports_are_rejected(self):
        adapter = get_adapter("rnc")
        missing = self._coverage_invocation(report=None)
        self.assertEqual(adapter.invocation_problem(missing), "REPORT_MISSING")
        malformed = self._coverage_invocation(b"{not json")
        self.assertEqual(adapter.invocation_problem(malformed), "REPORT_INVALID")
        invalid_config = self._coverage_invocation(b"", exit_code=64)
        self.assertEqual(adapter.invocation_problem(invalid_config), "INVOCATION_FAILED")
        publication_failure = self._coverage_invocation(None, exit_code=30)
        self.assertEqual(adapter.invocation_problem(publication_failure), "REPORT_MISSING")

    def test_controlled_rules_are_rnc_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = get_adapter("rnc").write_control_config(Path(tmp) / "rules", "RNC_[A-Z0-9]{16}")
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["schema_version"], "0.1.0")
            self.assertEqual(document["rules"][0]["pattern"], "RNC_[A-Z0-9]{16}")
            self.assertEqual(document["rules"][0]["validators"], ["ASCII_ONLY"])

    def _history_report(
        self,
        *,
        finding_id: str = "f1",
        locator: str = "commit/" + "c" * 40 + "/nested/deep/config.env",
        unit_id: str | None = None,
        primary_digest: str = "a" * 64,
        components: list[dict] | None = None,
        result_code: int = 3,
        coverage: str = "COMPLETE",
        refs: list[str] | None = None,
        source_kind: str = "git_commit_blob",
    ) -> bytes:
        unit_id = unit_id or self._UNIT
        units = [
            {
                "unit_id": unit_id,
                "source_id": "local-git-history:0123456789abcdef",
                "source_kind": source_kind,
                "locator": locator,
                "required_scope": True,
                "disposition": "INSPECTED",
                "content_sha256": f"sha256:{'b' * 64}",
                "byte_length": 64,
                "line_count": 4,
            }
        ]
        document = {
            "format_version": "rnc-cp2-output-v1",
            "execution": {
                "state": "COMPLETED" if result_code in (1, 2, 3) else "ERROR",
                "evidence_valid": result_code in (1, 2, 3),
                "failure_codes": [],
                "fatal_errors": [],
                "source_adapter": {"id": "local-git-history", "version": "0.1.0"},
                "ruleset_id": "rnc-providers-v1",
                "ruleset_digest": f"sha256:{'a' * 64}",
                "units": units,
            },
            "findings": [
                {
                    "schema_version": "0.2.0",
                    "unit_id": unit_id,
                    "finding_id": finding_id,
                    "rule_id": "database-connection-credential",
                    "rule_version": "2026.11.1",
                    "category": "structured-credential",
                    "start_byte": 20,
                    "end_byte": 60,
                    "line": 4,
                    "confidence": "medium",
                    "validation": ["ASCII_ONLY", "DATABASE_URI"],
                    "evidence_digest": f"sha256:{primary_digest}",
                }
            ],
            "structured_evidence": {
                "version": "1",
                "components": components or [],
            },
            "history": {
                "commits": 25,
                "changed_paths": 172,
                "deleted_paths": 6,
                "units_seen": 1,
                "refs": refs if refs is not None else ["HEAD"],
                "scope": "selected-refs",
            },
            "result": {
                "result_code": result_code,
                "result": {1: "CLEAN", 2: "POLICY_APPLIED", 3: "ACTIONABLE", 4: "INCOMPLETE", 5: "FAILED"}[result_code],
                "coverage": coverage,
                "evidence_valid": result_code in (1, 2, 3),
                "engine_version": "0.1.0",
                "ruleset_id": "rnc-providers-v1",
                "ruleset_digest": f"sha256:{'a' * 64}",
                "source_adapter": {"id": "local-git-history", "version": "0.1.0"},
                "reason_codes": [],
                "counts": {
                    "discovered": 1,
                    "inspected": 1,
                    "required_discovered": 1,
                    "required_inspected": 1,
                    "required_verified_blocked": 0,
                    "required_uninspected": 0,
                    "uninspected": 0,
                    "verified_blocked": 0,
                },
            },
            "ci": {"process_exit_code": 0 if result_code in (1, 2) else 10, "result_code": result_code},
        }
        return json.dumps(document).encode()

    def test_history_locator_sets_commit_and_nested_repository_path(self):
        finding = get_adapter("rnc").parse_findings(self._history_report())[0]
        self.assertEqual(finding.commit, "c" * 40)
        self.assertEqual(finding.file, "nested/deep/config.env")
        self.assertEqual(finding.line, 4)
        self.assertEqual(finding.metadata["source_kind"], "git_commit_blob")
        self.assertEqual(finding.metadata["history_scope"], "selected-refs")

    def test_history_locator_rejects_malformed_commit_and_traversal(self):
        adapter = get_adapter("rnc")
        for locator in (
            "commit/abc/nested.env",
            "commit/" + "c" * 39 + "/nested.env",
            "commit/" + "c" * 40 + "/../outside.env",
            "commit/" + "c" * 40 + "/nested//empty.env",
            "commit/" + "c" * 40 + "\\nested.env",
        ):
            with self.assertRaises(ReportError, msg=locator):
                adapter.parse_findings(self._history_report(locator=locator))

    def test_unknown_unit_reference_is_rejected(self):
        payload = json.loads(self._history_report())
        payload["findings"][0]["unit_id"] = "u-" + "d" * 64
        with self.assertRaises(ReportError):
            get_adapter("rnc").parse_findings(json.dumps(payload).encode())

    def test_component_normalization_uses_password_digest_once(self):
        primary = "a" * 64
        source = "c" * 64
        normalized = "c" * 64
        payload = self._history_report(
            primary_digest=primary,
            components=[
                {
                    "finding_id": "f1",
                    "unit_id": self._UNIT,
                    "kind": "database-password",
                    "start_byte": 30,
                    "end_byte": 45,
                    "line": 4,
                    "line_end": 4,
                    "source_sha256": f"sha256:{source}",
                    "normalized_sha256": f"sha256:{normalized}",
                    "ansi": "NONE",
                }
            ],
        )
        findings = get_adapter("rnc").parse_findings(payload)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.secret_sha256, normalized)
        self.assertEqual(finding.match_sha256, primary)
        self.assertEqual(finding.metadata["contextual_secret_sha256"], primary)
        self.assertEqual(finding.metadata["structured_evidence"]["kind"], "database-password")
        projection = json.dumps(finding.safe_dict())
        self.assertNotIn("source_sha256", projection)
        self.assertNotIn("start_byte\": 30", projection)

    def test_ansi_component_preserves_source_and_normalized_identity(self):
        payload = self._history_report(
            primary_digest="a" * 64,
            components=[
                {
                    "finding_id": "f1",
                    "unit_id": self._UNIT,
                    "kind": "database-password",
                    "start_byte": 30,
                    "end_byte": 45,
                    "line": 4,
                    "source_sha256": f"sha256:{'d' * 64}",
                    "normalized_sha256": f"sha256:{'e' * 64}",
                    "normalization": "ansi-sgr-v1",
                    "ansi": "INTERNAL",
                }
            ],
        )
        finding = get_adapter("rnc").parse_findings(payload)[0]
        self.assertEqual(finding.secret_sha256, "e" * 64)
        self.assertEqual(finding.metadata["structured_evidence"]["ansi"], "INTERNAL")
        self.assertEqual(
            finding.metadata["structured_evidence"]["normalization"], "ansi-sgr-v1"
        )

    def test_missing_and_duplicate_components_fail_explicitly(self):
        adapter = get_adapter("rnc")
        self.assertEqual(
            adapter.parse_findings(self._history_report())[0].secret_sha256,
            "a" * 64,
        )
        component = {
            "finding_id": "f1",
            "unit_id": self._UNIT,
            "kind": "database-password",
            "start_byte": 30,
            "end_byte": 45,
            "line": 4,
            "source_sha256": f"sha256:{'b' * 64}",
            "normalized_sha256": f"sha256:{'c' * 64}",
            "ansi": "NONE",
        }
        with self.assertRaises(ReportError):
            adapter.parse_findings(
                self._history_report(components=[component, dict(component)])
            )

    def test_component_must_belong_to_database_finding_and_primary_unit(self):
        adapter = get_adapter("rnc")
        base = {
            "finding_id": "f1",
            "unit_id": self._UNIT,
            "kind": "database-password",
            "start_byte": 30,
            "end_byte": 45,
            "line": 4,
            "source_sha256": f"sha256:{'b' * 64}",
            "normalized_sha256": f"sha256:{'c' * 64}",
            "ansi": "NONE",
        }
        payload = json.loads(self._history_report(components=[base]))
        payload["findings"][0]["rule_id"] = "generic-secret-assignment"
        with self.assertRaises(ReportError):
            adapter.parse_findings(json.dumps(payload).encode())
        payload = json.loads(self._history_report(components=[base]))
        payload["structured_evidence"]["components"][0]["unit_id"] = "u-" + "f" * 64
        with self.assertRaises(ReportError):
            adapter.parse_findings(json.dumps(payload).encode())

    def test_history_coverage_requires_complete_selected_head_scope(self):
        adapter = get_adapter("rnc")
        adapter._active_ruleset = {
            "ruleset_id": "rnc-providers-v1",
            "digest": f"sha256:{'a' * 64}",
        }
        invocation = execution.Invocation(
            binary_path="rnc",
            binary_sha256="b" * 64,
            argv=("rnc",),
            mode="git",
            report_path="report.json",
            exit_code=10,
            timed_out=False,
            duration_seconds=1.0,
            timeout_seconds=10,
            stdout=b"",
            stderr=b"",
            report_bytes=self._history_report(),
        )
        coverage = adapter.execution_coverage(invocation, ".", ())
        self.assertTrue(coverage["verified"], coverage["notes"])
        self.assertEqual(coverage["mode"], "git")
        self.assertEqual(coverage["history"]["scope"], "selected-refs")

        incomplete = json.loads(self._history_report(result_code=4, coverage="PARTIAL"))
        incomplete["execution"]["state"] = "ERROR"
        incomplete["result"]["evidence_valid"] = False
        coverage = adapter.execution_coverage(
            execution.Invocation(**{**invocation.__dict__, "report_bytes": json.dumps(incomplete).encode()}),
            ".",
            (),
        )
        self.assertFalse(coverage["verified"], coverage["notes"])

        wrong_scope = adapter.execution_coverage(
            execution.Invocation(
                **{**invocation.__dict__, "report_bytes": self._history_report(refs=["--all"])}
            ),
            ".",
            (),
        )
        self.assertFalse(wrong_scope["verified"], wrong_scope["notes"])

    def test_native_and_container_history_arguments(self):
        adapter = get_adapter("rnc")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            out = Path(tmp) / "out"
            root.mkdir()
            out.mkdir()
            rules_path = out / "rules.json"
            rules_path.write_text(
                json.dumps(
                    {
                        "schema_version": "0.2.0",
                        "ruleset_id": "rnc-providers-v1",
                        "ruleset_version": "test",
                        "rules": [{"rule_id": "r"}],
                    }
                ),
                encoding="utf-8",
            )
            adapter._rules_path = rules_path
            adapter._history_supported = True
            fake = execution.Invocation(
                binary_path="rnc",
                binary_sha256="a" * 64,
                argv=("rnc",),
                mode="git",
                report_path=str(out / "report.json"),
                exit_code=10,
                timed_out=False,
                duration_seconds=1.0,
                timeout_seconds=10,
                stdout=b"",
                stderr=b"",
                report_bytes=self._history_report(),
            )
            with patch("harness.adapters.rnc.run_process", return_value=fake) as run:
                adapter.invoke_native(
                    Path(sys.executable),
                    root,
                    out / "native.json",
                    mode="git",
                )
                argv = list(run.call_args.args[0])
                self.assertIn("--history", argv)
                self.assertIn("--ref", argv)
                self.assertEqual(argv[argv.index("--ref") + 1], "HEAD")

            image = "rnc-test-image"
            with patch("harness.adapters.rnc.run_process", return_value=fake) as run:
                adapter.invoke_container(
                    image,
                    "sha256:" + "a" * 64,
                    root,
                    out,
                    mode="git",
                )
                argv = list(run.call_args.args[0])
                self.assertIn("--history", argv)
                self.assertIn("--network", argv)
                self.assertEqual(argv[argv.index("--network") + 1], "none")
                self.assertIn("target=/scan,readonly", " ".join(argv))
                self.assertIn("HOME=/tmp", argv)

    def test_dockerfile_installs_git_for_history(self):
        adapter = get_adapter("rnc")
        with tempfile.TemporaryDirectory() as tmp:
            text = adapter._dockerfile(Path(tmp)).read_text(encoding="utf-8")
        self.assertIn("git", text)
        self.assertIn("safe.directory", text)



class PlatformTests(unittest.TestCase):
    def test_required_platform_catalog(self):
        keys = {item.key for item in PLATFORM_CATALOG}
        self.assertEqual(
            keys,
            {
                "windows-amd64",
                "docker-linux-amd64",
                "docker-linux-arm64",
            },
        )

    def test_expand_aliases(self):
        self.assertEqual(len(expand_platform_selection("executable")), 1)
        self.assertEqual(len(expand_platform_selection("docker")), 2)
        self.assertEqual(len(expand_platform_selection("all")), 3)
        self.assertIn(host_platform(), expand_platform_selection("host"))

    def test_unknown_platform_is_rejected(self):
        with self.assertRaises(ValueError):
            expand_platform_selection("solaris-sparc")


class GitleaksAdapterTests(unittest.TestCase):
    def test_registry_and_capabilities(self):
        self.assertIn("gitleaks", adapter_keys())
        adapter = get_adapter("gitleaks")
        self.assertEqual(adapter.key, "gitleaks")
        self.assertEqual(
            set(adapter.supported_suites),
            {
                "gitleaks",
                "git-history",
                "levain",
                "leaky-repo",
                "rnclab",
                "synthetic-filesystem",
            },
        )

    def test_normalized_findings_do_not_expose_raw_values(self):
        adapter = get_adapter("gitleaks")
        report = json.dumps(
            [
                {
                    "RuleID": "test-rule",
                    "File": "C:\\scan\\dir\\secret.txt",
                    "StartLine": 4,
                    "Secret": "super-secret-value",
                    "Match": "password=super-secret-value",
                }
            ]
        ).encode("utf-8")
        findings = adapter.parse_findings(report)
        self.assertEqual(findings[0].file, "C:/scan/dir/secret.txt")
        self.assertEqual(findings[0].line, 4)
        self.assertIsNotNone(findings[0].secret_sha256)
        self.assertNotIn("super-secret-value", repr(findings[0]))

    def test_version_parser(self):
        self.assertEqual(_version_from_text("v8.1.2\n"), "v8.1.2")
        self.assertIsNone(_version_from_text("version is set by build process"))

    def test_config_hash(self):
        adapter = get_adapter("gitleaks")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text("title = 'test'\n", encoding="utf-8")
            resolved, digest = adapter.validate_config(path)
            self.assertEqual(resolved, path.resolve())
            self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
