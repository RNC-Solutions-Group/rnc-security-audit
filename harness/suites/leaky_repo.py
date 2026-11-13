"""Pinned Leaky Repo count-based filesystem benchmark suite."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .. import history_matching
from .. import history_oracle
from .. import leaky_repo as leaky_module
from .. import leaky_truth
from .. import scoring_engine
from .. import status as statuses
from ..contracts import ScoringPolicy
from .base import SuiteContext, TestingSuite, combine_targets


class LeakyRepoSuite(TestingSuite):
    key = "leaky-repo"
    title = "Leaky Repo filesystem benchmark"
    required_capabilities = ("executable_or_docker", "filesystem_detection")

    def _run_one(self, context: SuiteContext, artifact, prepared, truth_manifest) -> dict:
        platform_dir = context.work_dir / "leaky-repo" / artifact.platform.key
        scan_root = leaky_module.copy_scan_tree(prepared, platform_dir / "scan")
        if artifact.platform.is_executable:
            report_path = platform_dir / "report.json"
            invocation = context.adapter.invoke_native(
                artifact.artifact_path,
                scan_root,
                report_path,
                config=context.scanner_config,
                timeout_seconds=context.timeout,
                artifact=artifact,
                suite="leaky-repo",
                workload="leaky-repo-filesystem",
            )
        else:
            invocation = context.adapter.invoke_container(
                artifact.image_tag,
                artifact.image_id,
                scan_root,
                platform_dir / "out",
                config=context.scanner_config,
                timeout_seconds=context.timeout,
                artifact=artifact,
                suite="leaky-repo",
                workload="leaky-repo-filesystem",
            )
        problem = context.adapter.invocation_problem(invocation)
        if invocation.report_bytes is not None:
            context.raw_artifacts.append(
                {
                    "name": f"leaky-repo-{artifact.platform.key}-report.json",
                    "data": invocation.report_bytes,
                    "content_type": "application/json",
                }
            )
        if invocation.stdout:
            context.raw_artifacts.append(
                {
                    "name": f"leaky-repo-{artifact.platform.key}-stdout.txt",
                    "data": invocation.stdout,
                    "content_type": "text/plain",
                }
            )
        if invocation.stderr:
            context.raw_artifacts.append(
                {
                    "name": f"leaky-repo-{artifact.platform.key}-stderr.txt",
                    "data": invocation.stderr,
                    "content_type": "text/plain",
                }
            )
        if problem:
            return {
                "status": statuses.BLOCKED,
                "reason": f"scanner invocation problem: {problem}",
                "metrics": {},
            }
        findings = context.adapter.parse_findings(invocation.report_bytes)
        context.raw_artifacts.append(
            {
                "name": f"leaky-repo-{artifact.platform.key}-findings.json",
                "data": json.dumps(
                    [finding.safe_dict() for finding in findings],
                    indent=2,
                    sort_keys=True,
                ).encode("utf-8"),
                "content_type": "application/json",
            }
        )
        legacy = leaky_module.score(findings, prepared, scan_root)
        rich = None
        rich_error = None
        if truth_manifest is not None:
            try:
                rich_result = scoring_engine.score_findings(
                    findings,
                    truth_manifest,
                    execution_status="PASS",
                    policy=ScoringPolicy(
                        policy_id=str(truth_manifest.scoring_policy.get("id", "leaky-line-v1")),
                        policy_version=str(truth_manifest.scoring_policy.get("version", "1")),
                        allow_line_only=True,
                    ),
                )
                rich = rich_result.safe_dict()
            except Exception as exc:
                rich_error = str(exc)
        return {
            "status": statuses.PASS,
            "legacy": legacy,
            "rich": rich,
            "rich_status": rich.get("scoring_status") if rich else "NOT_READY",
            "rich_error": rich_error,
            "metrics": legacy,
            "findings": findings,
            "scan_root": str(scan_root),
        }

    def _run_history(self, context: SuiteContext, artifact, prepared) -> dict:
        if not context.adapter.supports_mode("git"):
            return {
                "status": statuses.NOT_APPLICABLE,
                "execution_status": statuses.NOT_APPLICABLE,
                "truth_status": "NOT_APPLICABLE",
                "scored": False,
                "outcome": statuses.NOT_APPLICABLE,
                "reason": "scanner adapter does not support Git-history mode",
                "capability": {
                    "mode": "git",
                    "supported": False,
                    "assessment": (
                        "adapter/source capability inspection: the pinned source "
                        "revision does not expose --history/--ref"
                    ),
                },
                "observed_findings": 0,
                "unique_secret_fingerprints": 0,
            }
        if not context.adapter.can_execute(artifact.platform):
            return {
                "status": statuses.NOT_APPLICABLE,
                "execution_status": statuses.NOT_APPLICABLE,
                "truth_status": "NOT_APPLICABLE",
                "scored": False,
                "outcome": statuses.NOT_APPLICABLE,
                "reason": context.adapter.execution_reason(artifact.platform),
                "observed_findings": 0,
                "unique_secret_fingerprints": 0,
            }
        oracle_path = prepared.spec.history_oracle_path
        scope_path = prepared.spec.history_scope_path
        if oracle_path is None or scope_path is None:
            return {
                "status": statuses.BLOCKED,
                "execution_status": statuses.NOT_RUN,
                "truth_status": "NOT_READY",
                "scored": False,
                "outcome": statuses.BLOCKED,
                "reason": "Leaky Repo history oracle/scope is not configured",
                "observed_findings": 0,
                "unique_secret_fingerprints": 0,
            }
        try:
            oracle = context.cached(
                "leaky_repo_history_oracle",
                lambda: history_oracle.load(
                    oracle_path,
                    expected_sha256=prepared.spec.history_oracle_sha256,
                    source_root=prepared.source,
                    scope_path=scope_path,
                ),
            )
            scope = json.loads(scope_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {
                "status": statuses.BLOCKED,
                "execution_status": statuses.NOT_RUN,
                "truth_status": "NOT_READY",
                "scored": False,
                "outcome": statuses.BLOCKED,
                "reason": f"history oracle/source validation failed: {exc}",
                "observed_findings": 0,
                "unique_secret_fingerprints": 0,
            }
        history_dir = context.work_dir / "leaky-history" / artifact.platform.key
        history_dir.mkdir(parents=True, exist_ok=True)
        try:
            if artifact.platform.is_executable:
                invocation = context.adapter.invoke_native(
                    artifact.artifact_path,
                    prepared.source,
                    history_dir / "report.json",
                    config=context.scanner_config,
                    mode="git",
                    timeout_seconds=context.timeout,
                    artifact=artifact,
                    suite="leaky-repo",
                    workload="leaky-repo-history",
                )
            else:
                invocation = context.adapter.invoke_container(
                    artifact.image_tag,
                    artifact.image_id,
                    prepared.source,
                    history_dir,
                    config=context.scanner_config,
                    mode="git",
                    timeout_seconds=context.timeout,
                    artifact=artifact,
                    suite="leaky-repo",
                    workload="leaky-repo-history",
                )
            problem = context.adapter.invocation_problem(invocation)
            if problem:
                raise RuntimeError(problem)
            findings = context.adapter.parse_findings(invocation.report_bytes or b"[]")
            commits = subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                cwd=prepared.source,
                capture_output=True,
                text=True,
                timeout=60,
            )
            commit_count = (
                int(commits.stdout.strip())
                if commits.returncode == 0 and commits.stdout.strip().isdigit()
                else None
            )
            coverage_method = getattr(context.adapter, "execution_coverage", None)
            coverage = (
                coverage_method(invocation, prepared.source, ())
                if callable(coverage_method)
                else None
            )
            expected_commits = (scope or {}).get("commit_count")
            scope_matches = (
                expected_commits is None or commit_count == expected_commits
            )
            if coverage and coverage.get("applicable") and not coverage.get("verified"):
                return {
                    "status": statuses.BLOCKED,
                    "execution_status": statuses.PASS,
                    "truth_status": "APPROVED_SOURCE_ORACLE",
                    "scored": False,
                    "outcome": statuses.BLOCKED,
                    "reason": "Git-history execution coverage was not verified; no score is certified",
                    "observed_findings": len(findings),
                    "unique_secret_fingerprints": len(
                        {finding.secret_sha256 for finding in findings if finding.secret_sha256}
                    ),
                    "commits_scanned": commit_count,
                    "expected_commits": expected_commits,
                    "scope_matches": scope_matches,
                    "coverage": coverage,
                    "findings": [finding.safe_dict() for finding in findings],
                    "finding_count": len(findings),
                    "findings_truncated": False,
                    "finding_samples": [finding.safe_dict() for finding in findings[:10]],
                    "finding_samples_truncated": len(findings) > 10,
                }
            if not scope_matches:
                return {
                    "status": statuses.BLOCKED,
                    "execution_status": statuses.PASS,
                    "truth_status": "APPROVED_SOURCE_ORACLE",
                    "scored": False,
                    "outcome": statuses.BLOCKED,
                    "reason": (
                        f"historical source scope mismatch: scanner scanned {commit_count} commits, "
                        f"approved scope is {expected_commits}"
                    ),
                    "observed_findings": len(findings),
                    "unique_secret_fingerprints": len(
                        {finding.secret_sha256 for finding in findings if finding.secret_sha256}
                    ),
                    "commits_scanned": commit_count,
                    "expected_commits": expected_commits,
                    "scope_matches": False,
                    "coverage": coverage,
                    "findings": [finding.safe_dict() for finding in findings],
                    "finding_count": len(findings),
                    "findings_truncated": False,
                    "finding_samples": [finding.safe_dict() for finding in findings[:10]],
                    "finding_samples_truncated": len(findings) > 10,
                }
            unique_fingerprints = len(
                {finding.secret_sha256 for finding in findings if finding.secret_sha256}
            )
            result = history_matching.score_history(
                findings,
                oracle,
                prepared.source,
                scope=scope,
            )
            scored = result.safe_dict()
            metrics = result.metrics
            if not metrics.get("finding_accounting_reconciled"):
                return {
                    "status": statuses.FAIL,
                    "execution_status": statuses.PASS,
                    "truth_status": "APPROVED_SOURCE_ORACLE",
                    "scored": False,
                    "outcome": statuses.FAILED,
                    "reason": "history finding accounting did not reconcile; no score is certified",
                    "observed_findings": len(findings),
                    "unique_secret_fingerprints": unique_fingerprints,
                    "commits_scanned": commit_count,
                    "expected_commits": expected_commits,
                    "scope_matches": scope_matches,
                    "coverage": coverage,
                    "findings": [finding.safe_dict() for finding in findings],
                    "finding_count": len(findings),
                    "findings_truncated": False,
                    "finding_samples": [finding.safe_dict() for finding in findings[:10]],
                    "finding_samples_truncated": len(findings) > 10,
                    "history": scored,
                }
            return {
                "status": statuses.PASS,
                "execution_status": statuses.PASS,
                "truth_status": "APPROVED_SOURCE_ORACLE",
                "scored": True,
                "outcome": statuses.COMPLETED_AND_SCORED,
                "reason": None,
                "observed_findings": len(findings),
                "unique_secret_fingerprints": unique_fingerprints,
                "commits_scanned": commit_count,
                "expected_commits": expected_commits,
                "scope_matches": scope_matches,
                "coverage": coverage,
                "duration_seconds": invocation.duration_seconds,
                "exit_code": invocation.exit_code,
                "metrics": metrics,
                "score_status": result.scoring_status,
                "history": scored,
                "findings": [finding.safe_dict() for finding in findings],
                "finding_count": len(findings),
                "findings_truncated": False,
                "finding_samples": [finding.safe_dict() for finding in findings[:10]],
                "finding_samples_truncated": len(findings) > 10,
            }
        except Exception as exc:
            return {
                "status": statuses.BLOCKED,
                "execution_status": statuses.BLOCKED,
                "truth_status": "APPROVED_SOURCE_ORACLE",
                "scored": False,
                "outcome": statuses.BLOCKED,
                "reason": f"Git-history execution/scoring failed: {exc}",
                "observed_findings": 0,
                "unique_secret_fingerprints": 0,
            }

    def _register_performance(self, context: SuiteContext, prepared) -> None:
        if not hasattr(context, "performance_workloads"):
            return
        source_path = Path(prepared.source).resolve()
        # Unit-test stubs use Path(".") as a synthetic prepared source.  Never
        # recursively copy the harness checkout as a performance workload.
        if "leaky-repo" not in source_path.parts or not source_path.is_dir():
            return
        source_tree = leaky_module.copy_scan_tree(
            prepared, context.work_dir / "performance" / "leaky-source"
        )
        copies = max(1, int(getattr(context, "performance_copies", 10)))
        target_root = context.work_dir / "performance" / "leaky-target"
        if target_root.exists():
            shutil.rmtree(target_root)
        target_root.mkdir(parents=True)
        if copies == 1:
            shutil.copytree(source_tree, target_root / "scan")
        else:
            for index in range(copies):
                shutil.copytree(source_tree, target_root / f"replica-{index:02d}")
        files = sum(1 for path in target_root.rglob("*") if path.is_file())
        bytes_total = sum(
            path.stat().st_size for path in target_root.rglob("*") if path.is_file()
        )
        context.performance_workloads.append(
            {
                "suite": self.key,
                "key": "leaky-repo-filesystem",
                "title": "Leaky Repo replicated filesystem workload",
                "target": str(target_root),
                "mode": "dir",
                "dataset": {
                    "dataset_id": "leaky-repo",
                    "dataset_version": prepared.spec.revision,
                    "inventory_sha256": prepared.inventory_sha256,
                    "truth_manifest_version": prepared.spec.truth_manifest_version,
                    "lane": "filesystem",
                },
                "workload": {
                    "dataset": "leaky-repo",
                    "lane": "filesystem",
                    "replicas": copies,
                    "files": files,
                    "eligible_files": files,
                    "bytes": bytes_total,
                },
                "multiplier": copies,
            }
        )
        if context.adapter.supports_mode("git"):
            context.performance_workloads.append(
                {
                    "suite": self.key,
                    "key": "leaky-repo-git",
                    "title": "Leaky Repo owner-approved Git history",
                    "target": str(prepared.source),
                    "mode": "git",
                    "dataset": {
                        "dataset_id": "leaky-repo",
                        "dataset_version": prepared.spec.revision,
                        "history_oracle_version": prepared.spec.history_oracle_version,
                        "history_oracle_sha256": prepared.spec.history_oracle_sha256,
                        "lane": "git",
                    },
                    "workload": {
                        "dataset": "leaky-repo",
                        "lane": "git",
                        "commits": 25,
                        "files": None,
                        "bytes": None,
                    },
                    "multiplier": 1,
                }
            )

    def run(self, context: SuiteContext) -> dict:
        try:
            prepared = context.cached(
                "leaky_repo",
                lambda: leaky_module.prepare(
                    cache_dir=context.config.cache_dir,
                    offline=context.offline,
                ),
            )
        except Exception as exc:
            return self.result(
                status=statuses.BLOCKED,
                reason=f"Leaky Repo preparation failed: {exc}",
            )
        truth_manifest = None
        truth_error = None
        history_scope = None
        if prepared.spec.history_scope_path is not None and prepared.spec.history_scope_path.is_file():
            try:
                history_scope = json.loads(
                    prepared.spec.history_scope_path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                history_scope = None
        try:
            truth_manifest = leaky_truth.load_validated(
                prepared.spec.truth_manifest_path, prepared.source
            )
        except Exception as exc:
            truth_error = str(exc)
        try:
            self._register_performance(context, prepared)
        except Exception as exc:
            context.performance_workloads.append(
                {
                    "suite": self.key,
                    "key": "leaky-repo-filesystem",
                    "status": statuses.BLOCKED,
                    "reason": f"performance workload preparation failed: {exc}",
                    "target": None,
                    "mode": "dir",
                    "dataset": {},
                    "workload": {},
                    "multiplier": 1,
                }
            )
        targets: dict[str, dict] = {}
        lanes: dict[str, dict] = {}
        history_selected = context.adapter.supports_mode("git")
        for key, artifact in context.builds.items():
            if artifact.status != statuses.PASS:
                targets[key] = {"status": statuses.BLOCKED, "reason": "target build failed"}
                continue
            if not context.adapter.can_execute(artifact.platform):
                targets[key] = {
                    "status": statuses.NOT_APPLICABLE,
                    "reason": context.adapter.execution_reason(artifact.platform),
                }
                continue
            try:
                lane = self._run_one(context, artifact, prepared, truth_manifest)
            except Exception as exc:
                lane = {
                    "status": statuses.BLOCKED,
                    "reason": str(exc),
                    "metrics": {},
                }
            lanes[key] = lane
            target_status = lane["status"]
            target_reason = lane.get("reason")
            target_outcome = statuses.outcome(target_status, scored=True)
            if lane.get("rich_status") in ("NOT_READY", "BLOCKED"):
                target_status = statuses.PASS
                target_reason = (
                    "legacy count score completed; rich scoring is UNSCORED because "
                    "a defensible line-level oracle was unavailable"
                )
                target_outcome = statuses.COMPLETED_UNSCORED
            targets[key] = {
                "status": target_status,
                "outcome": target_outcome,
                "reason": target_reason,
                "metrics": lane.get("metrics", {}),
                "legacy_score_status": "COMPLETED" if lane.get("legacy") else "NOT_READY",
                "rich_score_status": lane.get("rich_status", "NOT_READY"),
            }
        history_lanes: dict[str, dict] = {}
        if history_selected:
            for key, artifact in context.builds.items():
                if artifact.status != statuses.PASS:
                    history_lanes[key] = {
                        "status": statuses.BLOCKED,
                        "execution_status": statuses.BLOCKED,
                        "truth_status": "BLOCKED",
                        "reason": "target build failed",
                    }
                    continue
                history_lanes[key] = self._run_history(context, artifact, prepared)
                if history_lanes[key].get("status") in (statuses.FAIL, statuses.BLOCKED):
                    targets[key] = {
                        "status": history_lanes[key].get("status"),
                        "reason": history_lanes[key].get("reason"),
                    }
                elif history_lanes[key].get("execution_status") == statuses.BLOCKED:
                    targets[key] = {
                        "status": statuses.FAIL,
                        "reason": history_lanes[key].get("reason"),
                    }
                elif history_lanes[key].get("execution_status") == statuses.NOT_RUN:
                    targets[key] = {
                        "status": statuses.BLOCKED,
                        "reason": history_lanes[key].get("reason"),
                    }
        comparisons: dict[str, dict] = {}
        executable_keys = [
            key for key in lanes if context.builds[key].platform.is_executable
        ]
        docker_keys = [key for key in lanes if context.builds[key].platform.is_docker]
        comparable = executable_keys + docker_keys
        for index, left_key in enumerate(comparable):
            for right_key in comparable[index + 1 :]:
                left = lanes[left_key]
                right = lanes[right_key]
                legacy_left = left.get("legacy", {})
                legacy_right = right.get("legacy", {})
                legacy_keys = (
                    "observed_findings",
                    "covered_count",
                    "files_covered",
                    "excess_findings",
                    "unlisted_findings",
                )
                legacy_differences = [
                    {
                        "metric": name,
                        "left": legacy_left.get(name),
                        "right": legacy_right.get(name),
                    }
                    for name in legacy_keys
                    if legacy_left.get(name) != legacy_right.get(name)
                ]
                left_files = {
                    item.get("path"): item.get("observed_findings")
                    for item in legacy_left.get("per_file", [])
                }
                right_files = {
                    item.get("path"): item.get("observed_findings")
                    for item in legacy_right.get("per_file", [])
                }
                per_file_differences = [
                    {
                        "path": path,
                        "left": left_files.get(path),
                        "right": right_files.get(path),
                    }
                    for path in sorted(set(left_files) | set(right_files))
                    if left_files.get(path) != right_files.get(path)
                ]
                rich_differences: list[dict] = []
                rich_left = left.get("rich")
                rich_right = right.get("rich")
                if rich_left is None or rich_right is None:
                    rich_status = "NOT_READY"
                    rich_differences.append(
                        {
                            "finding_id": "<rich-score>",
                            "left": "READY" if rich_left is not None else "NOT_READY",
                            "right": "READY" if rich_right is not None else "NOT_READY",
                        }
                    )
                else:
                    def evaluation_map(rich):
                        return {
                            item.get("expected_id")
                            or f"observed:{item.get('path')}:{item.get('line')}:"
                            f"{(item.get('observed') or {}).get('secret_sha256')}:{index}": item.get(
                                "classification"
                            )
                            for index, item in enumerate(rich.get("evaluations", []))
                        }

                    left_map = evaluation_map(rich_left)
                    right_map = evaluation_map(rich_right)
                    for finding_id in sorted(set(left_map) | set(right_map)):
                        if left_map.get(finding_id) != right_map.get(finding_id):
                            rich_differences.append(
                                {
                                    "finding_id": finding_id,
                                    "left": left_map.get(finding_id),
                                    "right": right_map.get(finding_id),
                                }
                            )
                    rich_status = statuses.PASS if not rich_differences else statuses.FAIL
                differences = (
                    len(legacy_differences)
                    + len(per_file_differences)
                    + len(rich_differences)
                )
                comparisons[f"{left_key}_vs_{right_key}"] = {
                    "status": statuses.FAIL if differences else statuses.PASS,
                    "legacy_differences": legacy_differences,
                    "per_file_differences": per_file_differences,
                    "rich_differences": rich_differences,
                    "rich_status": rich_status,
                    "summary": (
                        f"{len(legacy_differences)} legacy metric differences; "
                        f"{len(per_file_differences)} per-file differences; "
                        f"{len(rich_differences)} rich finding differences"
                    ),
                }
        metrics: dict = {}
        if lanes:
            first = next(iter(lanes.values()))
            legacy = first.get("legacy", {})
            for name in (
                "expected_count",
                "expected_files",
                "observed_findings",
                "covered_count",
                "files_covered",
                "files_covered_percent",
                "excess_findings",
                "unlisted_findings",
            ):
                metrics[name] = legacy.get(name)
            metrics["legacy_count_coverage_percent"] = legacy.get(
                "count_coverage_percent"
            )
            rich = first.get("rich") or {}
            rich_metrics = rich.get("metrics") or {}
            metrics["rich_score_status"] = rich.get("scoring_status", "NOT_READY")
            metrics["rich_expected_count"] = rich_metrics.get("expected_count")
            metrics["rich_matched_count"] = rich_metrics.get("matched_count")
            metrics["rich_missed_count"] = rich_metrics.get("missed_count")
            metrics["rich_unexpected_count"] = rich_metrics.get("unexpected_count")
            metrics["rich_duplicate_count"] = rich_metrics.get("duplicate_count")
            metrics["rich_detection_recall_percent"] = rich_metrics.get(
                "detection_recall_percent"
            )
            metrics["rich_precision_percent"] = rich_metrics.get("precision_percent")
            metrics["rich_f1_percent"] = rich_metrics.get("f1_percent")
            metrics["rich_category_conflict_items"] = rich_metrics.get(
                "category_conflict_items"
            )
            metrics["value_verified_count"] = rich_metrics.get("value_verified_count")
            metrics["line_only_count"] = rich_metrics.get("line_only_count")
        history_first = next(iter(history_lanes.values()), {})
        history_metrics = history_first.get("metrics") or {}
        if history_selected:
            metrics["history_execution_status"] = history_first.get("execution_status")
            metrics["history_truth_status"] = history_first.get("truth_status")
            metrics["history_score_status"] = (
                history_first.get("score_status")
                or ("COMPLETED" if history_first.get("scored") else "NOT_READY")
            )
        else:
            metrics["history_execution_status"] = "NOT_APPLICABLE"
            metrics["history_truth_status"] = "NOT_APPLICABLE"
            metrics["history_score_status"] = "NOT_APPLICABLE"
        metrics["history_observed_findings"] = history_first.get("observed_findings")
        metrics["history_scored"] = bool(history_first.get("scored"))
        metrics["history_unique_secret_fingerprints"] = history_first.get(
            "unique_secret_fingerprints"
        )
        metrics["history_commits_scanned"] = history_first.get("commits_scanned")
        metrics["history_expected_commits"] = history_first.get("expected_commits")
        metrics["history_scope_matches"] = history_first.get("scope_matches")
        history_coverage = history_first.get("coverage") or {}
        metrics["history_coverage_verified"] = (
            history_coverage.get("verified")
            if history_coverage.get("applicable")
            else None
        )
        for name in (
            "expected_occurrences",
            "matched_occurrences",
            "missed_occurrences",
            "unique_expected",
            "unique_matched",
            "unique_recall_percent",
            "occurrence_recall_percent",
            "verified_false_positive_count",
            "informative_match_count",
            "duplicate_count",
            "unmatched_pending_review_count",
            "unverified_evidence_count",
            "ambiguous_count",
            "observed_count",
            "accounted_observed_count",
            "finding_accounting_reconciled",
        ):
            metrics[f"history_{name}"] = history_metrics.get(name)
        metrics["history_precision_percent"] = None
        metrics["history_f1_percent"] = None
        metrics["history_precision_certification_status"] = history_metrics.get(
            "precision_certification_status"
        )
        status = combine_targets(targets)
        if any(item.get("status") == statuses.FAIL for item in comparisons.values()):
            status = statuses.FAIL
        limitations = [
            "Legacy Leaky Repo score preserves the upstream line-count methodology.",
            "RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.",
            "Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.",
        ]
        if not history_selected:
            limitations.append(
                "Leaky Repo Git-history capability is NOT_APPLICABLE for this scanner."
            )
        elif not history_first.get("scored"):
            limitations.append(
                "Leaky Repo Git-history execution completed but could not be scored: "
                f"{history_first.get('reason') or history_first.get('truth_status')}."
            )
        else:
            limitations.extend(
                [
                    "Leaky Repo history uses the owner-approved 65-occurrence / 53-group source oracle; "
                    "the filesystem 175-item denominator is not applied.",
                    "Reviewed negative references are not exhaustive; history precision and F1 are NOT CERTIFIED.",
                    "Informative history references are excluded from primary recall.",
                    "Every observed history finding is retained; unmatched and unverified findings require review.",
                ]
            )
            if history_metrics.get("unmatched_pending_review_count"):
                limitations.append(
                    f"History has {history_metrics.get('unmatched_pending_review_count')} unmatched "
                    "finding(s) awaiting source review."
                )
            if history_metrics.get("unverified_evidence_count"):
                limitations.append(
                    f"History has {history_metrics.get('unverified_evidence_count')} unverified "
                    "evidence finding(s) awaiting review."
                )
        if truth_manifest is None:
            limitations.append(f"RNC rich score is NOT_READY: {truth_error}")
        exceptions = []
        for lane_key, lane in lanes.items():
            rich = lane.get("rich") or {}
            for item in rich.get("exceptions", []):
                exceptions.append({"platform": lane_key, "dimension": "filesystem", **item})
        for lane_key, lane in history_lanes.items():
            history = lane.get("history") or {}
            for item in history.get("exceptions", []):
                exceptions.append({"platform": lane_key, "dimension": "history", **item})
        rich_ready = bool(lanes) and all(
            lane.get("rich_status") == "COMPLETED" for lane in lanes.values()
        )
        history_ready = bool(history_lanes) and any(
            lane.get("status") != statuses.NOT_APPLICABLE for lane in history_lanes.values()
        ) and all(
            lane.get("scored") is True
            and (lane.get("metrics") or {}).get("finding_accounting_reconciled", True)
            for lane in history_lanes.values()
            if lane.get("status") != statuses.NOT_APPLICABLE
        )
        baseline_metric = getattr(context, "profile_name", "default") == "default"
        profile_name = getattr(context, "profile_name", "default")
        suite_outcome = statuses.outcome(
            status,
            scored=rich_ready and (history_ready if history_selected else True),
        )
        result_rows: list[dict] = []
        for key, lane in lanes.items():
            result_rows.append(
                {
                    "dimension": "filesystem",
                    "outcome": statuses.outcome(
                        lane["status"], scored=lane.get("rich_status") == "COMPLETED"
                    ),
                    "status": lane["status"],
                    "platform": key,
                    "legacy_count_coverage_percent": (
                        lane.get("legacy") or {}
                    ).get("count_coverage_percent"),
                    "rich_score_status": lane.get("rich_status"),
                    "configuration_profile": profile_name,
                    "baseline_metric": baseline_metric,
                }
            )
        for key, lane in history_lanes.items():
            result_rows.append(
                {
                    "dimension": "history",
                    "outcome": lane.get("outcome")
                    or statuses.outcome(
                        lane.get("status", statuses.BLOCKED), scored=False
                    ),
                    "status": lane.get("status"),
                    "platform": key,
                    "execution_status": lane.get("execution_status"),
                    "truth_status": lane.get("truth_status"),
                    "score_status": (lane.get("metrics") or {}).get("history_score_status")
                    or lane.get("score_status"),
                    "observed_findings": lane.get("observed_findings"),
                    "unique_recall_percent": (lane.get("metrics") or {}).get(
                        "unique_recall_percent"
                    ),
                    "occurrence_recall_percent": (lane.get("metrics") or {}).get(
                        "occurrence_recall_percent"
                    ),
                    "configuration_profile": profile_name,
                    "baseline_metric": False,
                }
            )
        if not history_selected:
            result_rows.append(
                {
                    "dimension": "history",
                    "outcome": statuses.NOT_APPLICABLE,
                    "status": statuses.NOT_APPLICABLE,
                    "reason": "scanner adapter does not support Git-history mode",
                    "configuration_profile": profile_name,
                    "baseline_metric": False,
                }
            )
        return self.result(
            status=status,
            targets=targets,
            metrics=metrics,
            comparisons=comparisons if comparisons else {},
            baseline_metric=baseline_metric,
            scored=True,
            outcome=suite_outcome,
            results=result_rows,
            limitations=limitations,
            summary={
                "methodology": "dual: upstream-count legacy + RNC line-level rich",
                "platforms_executed": len(lanes),
                "configuration_profile": profile_name,
                "baseline_metric": baseline_metric,
                "filesystem_scored": rich_ready,
                "expected_count": prepared.spec.expected_count,
                "expected_files": prepared.spec.expected_files,
                "legacy_score_status": "COMPLETED" if lanes else "NOT_READY",
                "rich_score_status": (
                    "NOT_READY" if not rich_ready else "READY_WITH_CATEGORY_CAVEAT"
                ),
                "truth_manifest_version": prepared.spec.truth_manifest_version,
                "category_reconciliation": (
                    truth_manifest.category_reconciliation.get("status")
                    if truth_manifest is not None
                    else "UNKNOWN"
                ),
                "capabilities_auto": ["filesystem", "history"] if history_selected else ["filesystem"],
                "filesystem_selected": True,
                "history_selected": history_selected,
                "history_execution_status": (
                    history_first.get("execution_status")
                    if history_selected
                    else "NOT_APPLICABLE"
                ),
                "history_truth_status": (
                    history_first.get("truth_status")
                    if history_selected
                    else "NOT_APPLICABLE"
                ),
                "history_score_status": (
                    history_first.get("score_status")
                    if history_selected and history_first.get("scored")
                    else "NOT_READY"
                ),
                "history_scored": bool(history_first.get("scored")),
                "history_ready": history_ready,
                "history_observed_findings": history_first.get("observed_findings"),
                "history_commits_scanned": history_first.get("commits_scanned"),
                "history_expected_commits": history_first.get("expected_commits"),
                "history_scope_matches": history_first.get("scope_matches"),
                "history_coverage_verified": metrics.get("history_coverage_verified"),
                "history_expected_occurrences": history_metrics.get("expected_occurrences"),
                "history_matched_occurrences": history_metrics.get("matched_occurrences"),
                "history_missed_occurrences": history_metrics.get("missed_occurrences"),
                "history_unique_expected": history_metrics.get("unique_expected"),
                "history_unique_matched": history_metrics.get("unique_matched"),
                "history_unique_recall_percent": history_metrics.get(
                    "unique_recall_percent"
                ),
                "history_occurrence_recall_percent": history_metrics.get(
                    "occurrence_recall_percent"
                ),
                "history_unmatched_pending_review": history_metrics.get(
                    "unmatched_pending_review_count"
                ),
                "history_unverified_evidence": history_metrics.get(
                    "unverified_evidence_count"
                ),
                "history_scope_commit_count": (history_scope or {}).get("commit_count"),
                "history_scope_historical_only_paths": (history_scope or {}).get(
                    "historical_only_path_count"
                ),
            },
            details={
                "configuration": {
                    "profile": profile_name,
                    "config_path": (
                        str(getattr(context, "scanner_config", None))
                        if getattr(context, "scanner_config", None)
                        else None
                    ),
                    "config_sha256": getattr(context, "scanner_config_sha256", None),
                    "baseline_metric": baseline_metric,
                },
                "lanes": {
                    key: {
                        k: v
                        for k, v in lane.items()
                        if k not in ("findings",)
                    }
                    for key, lane in lanes.items()
                },
                "history_lanes": history_lanes,
                "exceptions": exceptions,
                "reconciliation": (
                    leaky_truth.reconciliation_report(truth_manifest, prepared.inventory)
                    if truth_manifest is not None
                    else None
                ),
                "truth": (
                    truth_manifest.category_reconciliation
                    | {
                        "manifest_version": truth_manifest.manifest_version,
                        "integrity": truth_manifest.integrity,
                    }
                    if truth_manifest is not None
                    else {"status": "NOT_READY", "reason": truth_error}
                ),
                "datasets": {
                    "leaky-repo": {
                        "name": prepared.spec.name,
                        "revision": prepared.spec.revision,
                        "inventory_sha256": prepared.inventory_sha256,
                        "license_sha256": prepared.spec.license_sha256,
                        "truth_manifest_sha256": prepared.spec.truth_manifest_sha256,
                        "truth_manifest_version": prepared.spec.truth_manifest_version,
                        "expected_count": prepared.spec.expected_count,
                        "expected_files": prepared.spec.expected_files,
                    }
                },
                "history_truth": {
                    "status": (
                        "APPROVED_SOURCE_ORACLE"
                        if history_selected and history_first.get("scored")
                        else "NOT_APPLICABLE"
                        if not history_selected
                        else history_first.get("truth_status") or "NOT_READY"
                    ),
                    "reason": history_first.get("reason")
                    or (
                        "Owner-approved 65-occurrence / 53-group source oracle; informative "
                        "references are separate and reviewed negatives are not exhaustive."
                    )
                    if history_selected
                    else "Scanner does not support Git-history scanning.",
                    "denominator": "65 source occurrences / 53 unique groups",
                    "capability": {
                        "mode": "git",
                        "supported": bool(history_selected),
                        "assessment": (
                            "adapter/source supports --history/--ref; execution scored"
                            if history_selected
                            else "adapter/source capability inspection: the pinned "
                            "source revision does not expose --history/--ref"
                        ),
                    },
                    "unit_model": "changed commit/path revisions (not full snapshots)",
                    "history_coverage_verified": metrics.get("history_coverage_verified"),
                    "history_scope_matches": metrics.get("history_scope_matches"),
                    "history_expected_commits": metrics.get("history_expected_commits"),
                    "precision_and_f1": "NOT_CERTIFIED",
                    "reviewed_negatives_exhaustive": False,
                    "scope": history_scope,
                    "scope_sha256": prepared.spec.history_scope_sha256,
                    "scope_version": prepared.spec.history_scope_version,
                    "oracle_path": str(prepared.spec.history_oracle_path)
                    if getattr(prepared.spec, "history_oracle_path", None)
                    else None,
                    "oracle_sha256": getattr(prepared.spec, "history_oracle_sha256", None),
                    "oracle_version": getattr(
                        prepared.spec, "history_oracle_version", None
                    ),
                },
            },
        )
