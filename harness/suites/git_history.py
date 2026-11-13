"""Controlled Git-history evaluation suite.

The suite builds a deterministic synthetic repository, executes the scanner's
native/container product in Git mode, parses normalized findings, and scores
occurrences and unique credentials separately. It never uses the filesystem
Leaky Repo denominator.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .. import history_fixture
from .. import scoring_engine
from .. import status as statuses
from ..contracts import EXPECTED_DETECTION, ScoringPolicy
from ..suites.base import TestingSuite, combine_targets
from ..util import sha256_file


class GitHistorySuite(TestingSuite):
    key = "git-history"
    title = "Synthetic Git History"

    def run(self, context) -> dict:
        work = Path(context.work_dir) / "synthetic-history"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True, exist_ok=True)
        corpus = history_fixture.build(work / "repo")
        config = history_fixture.write_config(work / "gitleaks.toml")
        config_sha256 = sha256_file(config)
        targets: dict[str, dict] = {}
        lanes: dict[str, dict] = {}
        for key, artifact in context.builds.items():
            if not artifact.status == statuses.PASS:
                targets[key] = {"status": statuses.BLOCKED, "reason": "target build failed"}
                continue
            if not context.adapter.supports_mode("git"):
                targets[key] = {
                    "status": statuses.NOT_APPLICABLE,
                    "reason": "scanner adapter does not support Git-history mode",
                }
                continue
            if not context.adapter.can_execute(artifact.platform):
                targets[key] = {
                    "status": statuses.NOT_APPLICABLE,
                    "reason": context.adapter.execution_reason(artifact.platform),
                }
                continue
            lane_dir = work / "lanes" / key
            lane_dir.mkdir(parents=True, exist_ok=True)
            try:
                if artifact.platform.is_executable:
                    invocation = context.adapter.invoke_native(
                        artifact.artifact_path,
                        corpus.root,
                        lane_dir / "report.json",
                        config=config,
                        mode="git",
                        timeout_seconds=context.timeout,
                        artifact=artifact,
                        suite="git-history",
                        workload="git-history",
                    )
                else:
                    invocation = context.adapter.invoke_container(
                        artifact.image_tag,
                        artifact.image_id,
                        corpus.root,
                        lane_dir,
                        config=config,
                        mode="git",
                        timeout_seconds=context.timeout,
                        artifact=artifact,
                        suite="git-history",
                        workload="git-history",
                    )
                problem = context.adapter.invocation_problem(invocation)
                if problem:
                    raise RuntimeError(problem)
                findings = context.adapter.parse_findings(invocation.report_bytes or b"[]")
                result = scoring_engine.score_findings(
                    findings,
                    corpus.manifest,
                    policy=ScoringPolicy(
                        policy_id="git-history-occurrence-v1",
                        policy_version="1",
                        allow_partial=False,
                    ),
                )
                unique_expected = {
                    item.metadata.get("unique_secret_id")
                    for item in corpus.manifest.items
                }
                unique_matched = {
                    item.metadata.get("unique_secret_id")
                    for item in corpus.manifest.items
                    if item.finding_id
                    in {
                        evaluation.expected_id
                        for evaluation in result.evaluations
                        if evaluation.classification == EXPECTED_DETECTION
                    }
                }
                unique_recall = round(
                    100.0 * len(unique_matched) / len(unique_expected), 2
                ) if unique_expected else 0.0
                occurrences = {
                    "expected": result.metrics["expected_count"],
                    "matched": result.metrics["matched_count"],
                    "missed": result.metrics["missed_count"],
                    "unexpected": result.metrics["unexpected_count"],
                    "duplicates": result.metrics["duplicate_count"],
                    "value_verified": result.metrics["value_verified_count"],
                    "line_only": result.metrics["line_only_count"],
                }
                lane = {
                    "status": statuses.PASS,
                    "scoring_status": result.scoring_status,
                    "execution_status": result.execution_status,
                    "duration_seconds": invocation.duration_seconds,
                    "exit_code": invocation.exit_code,
                    "commits_scanned": corpus.commits,
                    "occurrences": occurrences,
                    "unique": {
                        "expected": len(unique_expected),
                        "matched": len(unique_matched),
                        "recall_percent": unique_recall,
                        "ids": sorted(unique_matched),
                    },
                    "evaluations": [
                        evaluation.safe_dict() for evaluation in result.evaluations
                    ],
                    "findings": [finding.safe_dict() for finding in findings],
                    "report": str(getattr(invocation, "report_path", "")),
                }
            except Exception as exc:
                lane = {
                    "status": statuses.BLOCKED,
                    "reason": str(exc),
                    "scoring_status": "BLOCKED",
                    "occurrences": {},
                    "unique": {},
                    "evaluations": [],
                }
            lanes[key] = lane
            targets[key] = {
                "status": lane["status"],
                "reason": lane.get("reason"),
                "scoring_status": lane.get("scoring_status"),
                "occurrences": lane.get("occurrences", {}),
                "unique": lane.get("unique", {}),
            }
        comparisons: dict[str, dict] = {}
        keys = list(lanes)
        for index, left_key in enumerate(keys):
            for right_key in keys[index + 1 :]:
                left = lanes[left_key]
                right = lanes[right_key]
                differences = []
                left_map = {
                    (
                        item.get("expected_id")
                        or f"observed:{item.get('path')}:{item.get('line')}:"
                        f"{(item.get('observed') or {}).get('commit')}:"
                        f"{(item.get('observed') or {}).get('secret_sha256')}:{index}"
                    ): item.get("classification")
                    for index, item in enumerate(left.get("evaluations", []))
                }
                right_map = {
                    (
                        item.get("expected_id")
                        or f"observed:{item.get('path')}:{item.get('line')}:"
                        f"{(item.get('observed') or {}).get('commit')}:"
                        f"{(item.get('observed') or {}).get('secret_sha256')}:{index}"
                    ): item.get("classification")
                    for index, item in enumerate(right.get("evaluations", []))
                }
                for finding_id in sorted(set(left_map) | set(right_map)):
                    if left_map.get(finding_id) != right_map.get(finding_id):
                        differences.append(
                            {
                                "finding_id": finding_id,
                                "left": left_map.get(finding_id),
                                "right": right_map.get(finding_id),
                            }
                        )
                comparisons[f"{left_key}_vs_{right_key}"] = {
                    "status": statuses.PASS if not differences else statuses.FAIL,
                    "differences": differences,
                    "summary": f"{len(differences)} finding-classification differences",
                }
        status = combine_targets(targets)
        if any(item.get("status") == statuses.FAIL for item in comparisons.values()):
            status = statuses.FAIL
        first = next(iter(lanes.values()), {})
        metrics = {
            **{f"occurrence_{key}": value for key, value in (first.get("occurrences") or {}).items()},
            "unique_expected": (first.get("unique") or {}).get("expected"),
            "unique_matched": (first.get("unique") or {}).get("matched"),
            "unique_recall_percent": (first.get("unique") or {}).get("recall_percent"),
        }
        return self.result(
            status=status,
            targets=targets,
            metrics=metrics,
            comparisons=comparisons,
            baseline_metric=False,
            scored=True,
            results=[
                {
                    "dimension": "controlled-history",
                    "outcome": statuses.outcome(lane["status"], scored=True),
                    "status": lane["status"],
                    "platform": key,
                    "scoring_status": lane.get("scoring_status"),
                    "configuration_profile": "CONTROLLED_FIXTURE",
                    "baseline_metric": False,
                }
                for key, lane in lanes.items()
            ],
            summary={
                "history_scope": corpus.scope,
                "unique_expected_secrets": corpus.scope["unique_secret_count"],
                "expected_occurrences": corpus.scope["occurrence_count"],
                "configuration_profile": "CONTROLLED_FIXTURE",
                "baseline_metric": False,
                "history_status": (
                    "COMPLETE"
                    if all(
                        lane.get("scoring_status") == "COMPLETED"
                        for lane in lanes.values()
                    )
                    else "BLOCKED"
                ),
            },
            details={
                "configuration": {
                    "profile": "CONTROLLED_FIXTURE",
                    "config_source": "harness/history_fixture.py",
                    "config_sha256": config_sha256,
                    "baseline_metric": False,
                    "note": "The controlled history rule is a fixture rule, not a scanner default.",
                },
                "truth": {
                    "manifest_id": corpus.manifest.manifest_id,
                    "manifest_version": corpus.manifest.manifest_version,
                    "dataset_id": corpus.manifest.dataset_id,
                    "dataset_version": corpus.manifest.dataset_version,
                    "verification_status": "VERIFIED_CONTROLLED_CORPUS",
                    "unique_secret_ids": corpus.manifest.metadata.get(
                        "unique_secret_ids", []
                    ),
                    "items": [
                        item.safe_dict() for item in corpus.manifest.items
                    ],
                },
                "lanes": lanes,
            },
        )
