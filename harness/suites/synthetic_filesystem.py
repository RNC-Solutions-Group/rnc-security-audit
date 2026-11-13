"""Controlled filesystem end-to-end suite.

Actual scanner output is normalized by the adapter and scored against an
independent synthetic truth manifest. Detection accuracy is separate from the
scoring engine's own control tests.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .. import filesystem_fixture
from .. import scoring_engine
from .. import status as statuses
from ..contracts import EXPECTED_DETECTION, ScoringPolicy
from ..suites.base import TestingSuite, combine_targets
from ..util import sha256_file


class SyntheticFilesystemSuite(TestingSuite):
    key = "synthetic-filesystem"
    title = "Synthetic Filesystem Controls"
    required_capabilities = ("executable_or_docker", "filesystem_detection")

    def run(self, context) -> dict:
        work = Path(context.work_dir) / "synthetic-filesystem"
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True, exist_ok=True)
        corpus = filesystem_fixture.build(work / "target")
        config = context.adapter.write_control_config(
            work / "scanner-config", "RNC_[A-Z0-9]{16}"
        )
        config_sha256 = sha256_file(config)
        targets: dict[str, dict] = {}
        lanes: dict[str, dict] = {}
        for key, artifact in context.builds.items():
            if artifact.status != statuses.PASS:
                targets[key] = {"status": statuses.BLOCKED, "reason": "target build failed"}
                continue
            if not context.adapter.supports_mode("dir"):
                targets[key] = {
                    "status": statuses.NOT_APPLICABLE,
                    "reason": "scanner does not support filesystem scanning",
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
                        mode="dir",
                        timeout_seconds=context.timeout,
                    )
                else:
                    invocation = context.adapter.invoke_container(
                        artifact.image_tag,
                        artifact.image_id,
                        corpus.root,
                        lane_dir,
                        config=config,
                        mode="dir",
                        timeout_seconds=context.timeout,
                    )
                problem = context.adapter.invocation_problem(invocation)
                if problem:
                    raise RuntimeError(problem)
                findings = context.adapter.parse_findings(
                    invocation.report_bytes or b"[]"
                )
                result = scoring_engine.score_findings(
                    findings,
                    corpus.manifest,
                    policy=ScoringPolicy(
                        policy_id="filesystem-controlled-v1",
                        policy_version="1",
                        negative_oracle=True,
                    ),
                )
                lane = {
                    "status": statuses.PASS,
                    "scoring_status": result.scoring_status,
                    "execution_status": result.execution_status,
                    "duration_seconds": invocation.duration_seconds,
                    "exit_code": invocation.exit_code,
                    "metrics": result.metrics,
                    "evaluations": [
                        evaluation.safe_dict() for evaluation in result.evaluations
                    ],
                    "findings": [finding.safe_dict() for finding in findings],
                }
            except Exception as exc:
                lane = {
                    "status": statuses.BLOCKED,
                    "reason": str(exc),
                    "scoring_status": "BLOCKED",
                    "metrics": {},
                    "evaluations": [],
                }
            lanes[key] = lane
            targets[key] = {
                "status": lane["status"],
                "reason": lane.get("reason"),
                "scoring_status": lane.get("scoring_status"),
                "metrics": lane.get("metrics", {}),
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
                        f"{(item.get('observed') or {}).get('secret_sha256')}:{index}"
                    ): item.get("classification")
                    for index, item in enumerate(left.get("evaluations", []))
                }
                right_map = {
                    (
                        item.get("expected_id")
                        or f"observed:{item.get('path')}:{item.get('line')}:"
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
        metrics = dict(first.get("metrics") or {})
        return self.result(
            status=status,
            targets=targets,
            metrics=metrics,
            comparisons=comparisons,
            baseline_metric=False,
            scored=True,
            results=[
                {
                    "dimension": "controlled-filesystem",
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
                "expected": 4,
                "negative_oracle": True,
                "engine_status": "VALID",
                "configuration_profile": "CONTROLLED_FIXTURE",
                "baseline_metric": False,
                "note": "Synthetic fixtures test scanner/adapter/scorer integration; they are not real-world prevalence.",
            },
            details={
                "configuration": {
                    "profile": "CONTROLLED_FIXTURE",
                    "config_source": "harness/filesystem_fixture.py",
                    "config_sha256": config_sha256,
                    "baseline_metric": False,
                    "note": "The controlled RNC-token rule is a fixture rule, not a scanner default and not a real-world benchmark configuration.",
                },
                "truth": {
                    "manifest_id": corpus.manifest.manifest_id,
                    "manifest_version": corpus.manifest.manifest_version,
                    "dataset_id": corpus.manifest.dataset_id,
                    "dataset_version": corpus.manifest.dataset_version,
                    "items": [item.safe_dict() for item in corpus.manifest.items],
                },
                "lanes": {
                    key: {
                        k: v
                        for k, v in lane.items()
                        if k not in ("findings",)
                    }
                    for key, lane in lanes.items()
                },
            },
        )
