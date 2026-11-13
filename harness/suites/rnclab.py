"""Certified RNC Synthetic Secrets Lab v3 suite.

Filesystem and Git-history are independent scoring lanes.  The suite scans only
``corpus/filesystem`` for the filesystem lane and only ``corpus/history`` for the
Git lane; it never points a scanner at the combined corpus root.  Canonical
performance and run-owned legacy-5x/legacy-10x load targets are registered for
the experiment performance runner.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .. import rnclab
from .. import status as statuses
from .base import SuiteContext, TestingSuite, combine_targets


class RncLabSuite(TestingSuite):
    key = "rnclab"
    title = "RNC Synthetic Secrets Lab v3"
    required_capabilities = ("executable_or_docker", "filesystem_detection")

    def _scan(
        self,
        context: SuiteContext,
        artifact,
        target: Path,
        work: Path,
        *,
        mode: str,
    ) -> tuple[object, list, str | None, dict | None]:
        work.mkdir(parents=True, exist_ok=True)
        if artifact.platform.is_executable:
            invocation = context.adapter.invoke_native(
                artifact.artifact_path,
                target,
                work / "report.json",
                config=context.scanner_config,
                mode=mode,
                timeout_seconds=context.timeout,
                artifact=artifact,
                suite="rnclab",
                workload=f"rnclab-{'history' if mode == 'git' else 'filesystem'}",
            )
        else:
            invocation = context.adapter.invoke_container(
                artifact.image_tag,
                artifact.image_id,
                target,
                work,
                config=context.scanner_config,
                mode=mode,
                timeout_seconds=context.timeout,
                artifact=artifact,
                suite="rnclab",
                workload=f"rnclab-{'history' if mode == 'git' else 'filesystem'}",
            )
        if invocation.report_bytes is not None:
            context.raw_artifacts.append(
                {
                    "name": f"rnclab-{artifact.platform.key}-{mode}-report.json",
                    "data": invocation.report_bytes,
                    "content_type": "application/json",
                }
            )
        if invocation.stdout:
            context.raw_artifacts.append(
                {
                    "name": f"rnclab-{artifact.platform.key}-{mode}-stdout.txt",
                    "data": invocation.stdout,
                    "content_type": "text/plain",
                }
            )
        if invocation.stderr:
            context.raw_artifacts.append(
                {
                    "name": f"rnclab-{artifact.platform.key}-{mode}-stderr.txt",
                    "data": invocation.stderr,
                    "content_type": "text/plain",
                }
            )
        problem = context.adapter.invocation_problem(invocation)
        partial = None
        if problem:
            partial_method = getattr(context.adapter, "partial_execution_evidence", None)
            if callable(partial_method):
                partial = partial_method(invocation)
            if not partial:
                return invocation, [], problem, None
        try:
            findings = context.adapter.parse_findings(invocation.report_bytes or b"[]")
        except Exception as exc:
            return invocation, [], f"REPORT_PARSE_FAILED: {exc}", partial
        return invocation, findings, None, partial

    def _lane(
        self,
        context: SuiteContext,
        artifact,
        dataset: rnclab.LabDataset,
        lane: str,
    ) -> dict:
        root = (
            dataset.filesystem_root if lane == "filesystem" else dataset.history_root
        )
        work = context.work_dir / "rnclab" / artifact.platform.key / lane
        if lane == "git":
            if not context.adapter.supports_mode("git"):
                return {
                    "status": statuses.NOT_APPLICABLE,
                    "outcome": statuses.NOT_APPLICABLE,
                    "reason": (
                        "the pinned scanner source revision does not expose "
                        "Git-history scanning"
                    ),
                    "capability": {
                        "mode": "git",
                        "supported": False,
                        "assessment": "adapter/source capability inspection",
                    },
                    "metrics": {},
                    "findings": [],
                }
        invocation, findings, problem, partial = self._scan(
            context, artifact, root, work, mode="dir" if lane == "filesystem" else "git"
        )
        if problem:
            return {
                "status": statuses.BLOCKED,
                "outcome": statuses.BLOCKED,
                "reason": f"scanner invocation problem: {problem}",
                "metrics": {},
                "findings": [],
            }
        try:
            scored = rnclab.score_findings(dataset, lane, findings)
        except Exception as exc:
            return {
                "status": statuses.FAIL,
                "outcome": statuses.FAILED,
                "reason": f"lab scoring failed: {exc}",
                "metrics": {},
                "findings": [],
            }
        metrics = scored["metrics"]
        metrics["invocation"] = {
            "exit_code": invocation.exit_code,
            "timed_out": invocation.timed_out,
            "duration_seconds": invocation.duration_seconds,
            "mode": lane,
        }
        if partial:
            metrics["coverage_caveat"] = partial
            metrics["unsupported_capability_count"] = int(
                partial.get("unsupported_capability_count") or 0
            )
        return {
            "status": statuses.PASS,
            "outcome": statuses.outcome(statuses.PASS, scored=True),
            "reason": None,
            "metrics": metrics,
            "categories": scored["categories"],
            "representations": scored["representations"],
            "exceptions": scored["exceptions"],
            "exception_count": scored["exception_count"],
            "findings": scored["findings"],
            "matched_positive_ids": scored["matched_positive_ids"],
            "missed_positive_ids": scored["missed_positive_ids"],
            "accounted": scored["accounted"],
            "source_root": scored["source_root"],
            "coverage_caveat": partial,
            "capability": {
                "mode": lane,
                "supported": True,
                "assessment": (
                    "executed and source-scored with explicit symlink-alias "
                    "coverage caveat"
                    if partial
                    else "executed and source-scored"
                ),
            },
        }

    def _register_performance(
        self,
        context: SuiteContext,
        dataset: rnclab.LabDataset,
        git_supported: bool,
    ) -> None:
        files = dataset.manifest.get("corpus", {}).get("files") or []
        byte_count = sum(int(item.get("bytes") or 0) for item in files)
        symlink_count = int(
            (dataset.manifest.get("topology", {}).get("symlinks") or {}).get(
                "symlink_count"
            )
            or 0
        )
        filesystem_workload = {
            "suite": self.key,
            "key": "rnclab-filesystem",
            "title": "RNC Lab v3 canonical filesystem",
            "target": str(dataset.filesystem_root),
            "mode": "dir",
            "dataset": {
                "dataset_id": "rnc-synthetic-secrets-lab",
                "dataset_version": rnclab.LAB_VERSION,
                "build_id": rnclab.BUILD_ID,
                "manifest_sha256": dataset.manifest_sha256,
                "oracle_sha256": dataset.oracle_sha256,
                "lane": "filesystem",
            },
            "workload": {
                "dataset": "rnc-synthetic-secrets-lab",
                "lane": "filesystem",
                "files": len(files) + symlink_count,
                "eligible_files": len(files) + symlink_count,
                "inspected_files": len(files),
                "bytes": byte_count,
                "symlink_aliases": symlink_count,
                "oracle_items": dataset.counts("filesystem")["TOTAL"],
                "positives": dataset.counts("filesystem")["POSITIVE"],
            },
            "multiplier": 1,
            "allow_partial": True,
        }
        context.performance_workloads.append(filesystem_workload)
        if git_supported:
            tracked = subprocess.run(
                ["git", "-C", str(dataset.history_root), "ls-tree", "-r", "-l", "HEAD"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            git_files = git_bytes = None
            if tracked.returncode == 0:
                lines = [line for line in tracked.stdout.splitlines() if line]
                git_files = len(lines)
                try:
                    git_bytes = sum(
                        int(line.split()[3]) for line in lines if len(line.split()) >= 4
                    )
                except (ValueError, IndexError):
                    git_bytes = None
            context.performance_workloads.append(
                {
                    "suite": self.key,
                    "key": "rnclab-git",
                    "title": "RNC Lab v3 canonical Git history",
                    "target": str(dataset.history_root),
                    "mode": "git",
                    "dataset": {
                        "dataset_id": "rnc-synthetic-secrets-lab",
                        "dataset_version": rnclab.LAB_VERSION,
                        "build_id": rnclab.BUILD_ID,
                        "manifest_sha256": dataset.manifest_sha256,
                        "oracle_sha256": dataset.oracle_sha256,
                        "lane": "git",
                        "git_head": dataset.git_head,
                        "commit_count": dataset.git_commit_count,
                    },
                    "workload": {
                        "dataset": "rnc-synthetic-secrets-lab",
                        "lane": "git",
                        "files": git_files,
                        "eligible_files": git_files,
                        "bytes": git_bytes,
                        "commits": dataset.git_commit_count,
                        "oracle_items": dataset.counts("git")["TOTAL"],
                        "positives": dataset.counts("git")["POSITIVE"],
                    },
                    "multiplier": 1,
                }
            )
        context.performance_loads.append(
            {
                "suite": self.key,
                "lab_root": str(dataset.root),
                "profiles": ["legacy-5x", "legacy-10x"],
            }
        )

    def run(self, context: SuiteContext) -> dict:
        try:
            dataset = context.cached(
                "rnclab_dataset",
                lambda: rnclab.load(context.config.cache_dir / "rnc-synth-lab"),
            )
        except Exception as exc:
            return self.result(
                status=statuses.BLOCKED,
                outcome=statuses.BLOCKED,
                reason=f"certified RNC Lab loading failed: {exc}",
                scored=False,
                baseline_metric=False,
            )
        targets: dict[str, dict] = {}
        lanes: dict[str, dict] = {}
        target_metrics: dict[str, dict] = {}
        git_supported = context.adapter.supports_mode("git")
        for key, artifact in context.builds.items():
            if artifact.status != statuses.PASS:
                targets[key] = {
                    "status": statuses.BLOCKED,
                    "outcome": statuses.BLOCKED,
                    "reason": "target build failed",
                    "lanes": {},
                }
                continue
            if not context.adapter.can_execute(artifact.platform):
                targets[key] = {
                    "status": statuses.NOT_APPLICABLE,
                    "outcome": statuses.NOT_APPLICABLE,
                    "reason": context.adapter.execution_reason(artifact.platform),
                    "lanes": {},
                }
                continue
            platform_lanes: dict[str, dict] = {}
            try:
                platform_lanes["filesystem"] = self._lane(
                    context, artifact, dataset, "filesystem"
                )
                platform_lanes["git"] = self._lane(context, artifact, dataset, "git")
            except Exception as exc:
                platform_lanes["error"] = {
                    "status": statuses.BLOCKED,
                    "outcome": statuses.BLOCKED,
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            lanes[key] = platform_lanes
            lane_status = combine_targets(platform_lanes)
            filesystem = platform_lanes.get("filesystem") or {}
            target_metrics[key] = filesystem.get("metrics") or {}
            targets[key] = {
                "status": lane_status,
                "outcome": statuses.outcome(
                    lane_status, scored=bool(filesystem.get("metrics"))
                ),
                "reason": (
                    filesystem.get("reason")
                    or (platform_lanes.get("git") or {}).get("reason")
                ),
                "metrics": filesystem.get("metrics") or {},
                "lanes": {
                    name: {
                        "status": lane.get("status"),
                        "outcome": lane.get("outcome"),
                        "reason": lane.get("reason"),
                        "metrics": lane.get("metrics") or {},
                        "capability": lane.get("capability"),
                    }
                    for name, lane in platform_lanes.items()
                },
            }
        try:
            frozen = rnclab.verify_frozen(dataset)
        except Exception as exc:
            frozen = {"status": "FAIL", "reason": str(exc)}
        if frozen.get("status") != "PASS":
            return self.result(
                status=statuses.FAIL,
                outcome=statuses.FAILED,
                reason=f"frozen lab integrity failed after scanning: {frozen.get('reason')}",
                targets=targets,
                metrics={},
                baseline_metric=context.profile_name == "default",
                scored=False,
                details={"frozen": frozen},
            )
        self._register_performance(context, dataset, git_supported)
        status = combine_targets(targets)
        filesystem_metrics = [
            item.get("metrics") or {}
            for item in targets.values()
            if item.get("status") in (statuses.PASS, statuses.FAIL)
        ]
        primary = filesystem_metrics[0] if filesystem_metrics else {}
        aggregate = {
            "expected_positives": dataset.counts("filesystem")["POSITIVE"],
            "expected_unique_groups": len(
                {item.group_id for item in dataset.positives("filesystem") if item.group_id}
            ),
            "products": len(filesystem_metrics),
            "true_positive_occurrences": int(
                primary.get("true_positive_occurrences") or 0
            ),
            "false_negative_occurrences": int(
                primary.get("false_negative_occurrences") or 0
            ),
            "duplicate_count": int(primary.get("duplicate_count") or 0),
            "informative_match_count": int(
                primary.get("informative_match_count") or 0
            ),
            "verified_false_positive_alert_count": int(
                primary.get("verified_false_positive_alert_count") or 0
            ),
            "unique_verified_nonsecret_exposures": int(
                primary.get("unique_verified_nonsecret_exposures") or 0
            ),
            "unmatched_pending_review_count": int(
                primary.get("unmatched_pending_review_count") or 0
            ),
            "unverified_evidence_count": int(
                primary.get("unverified_evidence_count") or 0
            ),
            "unsupported_capability_count": int(
                primary.get("unsupported_capability_count") or 0
            ),
            "observed_findings": int(primary.get("observed_findings") or 0),
            "unique_groups_matched": int(primary.get("unique_groups_matched") or 0),
            "precision_percent": None,
            "f1_percent": None,
            "precision_certification_status": "BLOCKED_INCOMPLETE_NEGATIVE_ORACLE",
        }
        if aggregate["expected_positives"]:
            aggregate["occurrence_recall_percent"] = round(
                100.0
                * aggregate["true_positive_occurrences"]
                / aggregate["expected_positives"],
                2,
            )
        else:
            aggregate["occurrence_recall_percent"] = None
        if aggregate["expected_unique_groups"]:
            aggregate["unique_recall_percent"] = round(
                100.0
                * aggregate["unique_groups_matched"]
                / aggregate["expected_unique_groups"],
                2,
            )
        else:
            aggregate["unique_recall_percent"] = None
        exceptions = []
        for key, platform_lanes in lanes.items():
            for lane_name, lane in platform_lanes.items():
                for exception in lane.get("exceptions") or []:
                    exceptions.append(
                        {
                            "dimension": f"{lane_name}:{key}",
                            **exception,
                        }
                    )
        limitations = [
            "RNC Lab negative references are source-adjudicated within the frozen "
            "corpus; findings not present in the oracle remain pending review and "
            "precision/F1 are not certified.",
            "Filesystem (1,282) and Git-history (320) denominators are separate and "
            "are never combined.",
            "Private-key credit requires private-key material; public-key-only, "
            "SPKI-only, filename-only and encrypted-container-only evidence is not "
            "a true positive.",
            "The frozen lab is verified before and after scanning; a hash change "
            "blocks the run.",
        ]
        if not git_supported:
            limitations.append(
                "Git-history mode is NOT_APPLICABLE for this pinned scanner source "
                "revision; no zero score or fabricated occurrences were emitted."
            )
        return self.result(
            status=status,
            targets=targets,
            metrics=aggregate,
            baseline_metric=context.profile_name == "default",
            scored=bool(filesystem_metrics),
            limitations=limitations,
            summary={
                "lab": rnclab.LAB_VERSION,
                "build": rnclab.BUILD_ID,
                "platforms_executed": len(filesystem_metrics),
                "git_mode_supported": git_supported,
                "filesystem_items": dataset.counts("filesystem")["TOTAL"],
                "git_items": dataset.counts("git")["TOTAL"],
                "positive_unique_groups": rnclab.EXPECTED_UNIQUE_POSITIVES,
            },
            details={
                "datasets": {
                    "rnclab": {
                        "name": "RNC Synthetic Secrets Lab",
                        "version": rnclab.LAB_VERSION,
                        "build_id": rnclab.BUILD_ID,
                        "manifest_sha256": dataset.manifest_sha256,
                        "oracle_sha256": dataset.oracle_sha256,
                        "corpus_sha256": dataset.corpus_sha256,
                        "counts": {
                            "total": len(dataset.items),
                            "filesystem": dataset.counts("filesystem"),
                            "git": dataset.counts("git"),
                        },
                        "unique_positive_groups": rnclab.EXPECTED_UNIQUE_POSITIVES,
                        "source_validation": dataset.source_validation,
                        "frozen_verification": frozen,
                    }
                },
                "lanes": lanes,
                "capability": {
                    "git": {
                        "supported": git_supported,
                        "assessment": (
                            "adapter reports Git mode and the pinned source CLI "
                            "contains the history entry point"
                            if git_supported
                            else "pinned source does not expose --history/--ref"
                        ),
                    }
                },
                "exceptions": exceptions[:500],
                "load_profiles": ["legacy-5x", "legacy-10x"],
            },
        )
