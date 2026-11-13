"""Pinned Gitleaks functional fixture suite."""

from __future__ import annotations

from .. import fixtures as fixtures_module
from .. import status as statuses
from ..comparisons import compare_fixtures
from .base import SuiteContext, TestingSuite, combine_targets


class GitleaksFixtureSuite(TestingSuite):
    key = "gitleaks"
    title = "Gitleaks functional fixtures"
    required_capabilities = ("fixtures", "executable_or_docker")

    def run(self, context: SuiteContext) -> dict:
        try:
            prepared = context.cached(
                "gitleaks_fixtures",
                lambda: fixtures_module.prepare(
                    cache_dir=context.config.cache_dir,
                    offline=context.offline,
                ),
            )
        except Exception as exc:
            return self.result(
                status=statuses.BLOCKED,
                reason=f"pinned Gitleaks fixture preparation failed: {exc}",
                limitations=["Fixture suite could not run without the pinned fixture cache."],
            )

        targets: dict[str, dict] = {}
        lane_results: dict[str, dict] = {}
        for key, artifact in context.builds.items():
            if artifact.status != statuses.PASS:
                targets[key] = {
                    "status": statuses.BLOCKED,
                    "reason": f"target build {artifact.status}",
                }
                continue
            if not context.adapter.can_execute(artifact.platform):
                targets[key] = {
                    "status": statuses.NOT_APPLICABLE,
                    "reason": context.adapter.execution_reason(artifact.platform),
                }
                continue
            if artifact.platform.is_executable:
                lane = context.adapter.run_fixture_suite_native(
                    prepared,
                    artifact,
                    context.work_dir / "gitleaks-fixtures" / key,
                    context.timeout,
                )
            else:
                lane = context.adapter.run_fixture_suite_docker(
                    prepared,
                    artifact,
                    context.work_dir / "gitleaks-fixtures" / key,
                    context.timeout,
                )
            lane_results[key] = lane
            targets[key] = {
                "status": lane.get("status", statuses.BLOCKED),
                "reason": lane.get("reason"),
                "summary": lane.get("summary", {}),
                "parity": lane.get("parity"),
                "adapter": lane.get("adapter"),
            }

        comparisons: dict[str, dict] = {}
        comparable = list(lane_results)
        for index, left_key in enumerate(comparable):
            for right_key in comparable[index + 1 :]:
                comparisons[f"{left_key}_vs_{right_key}"] = compare_fixtures(
                    lane_results[left_key], lane_results[right_key]
                )

        exceptions = []
        for platform, lane in lane_results.items():
            for test in lane.get("tests", []):
                if test.get("status") == statuses.PASS:
                    continue
                classification = (
                    statuses.NOT_APPLICABLE
                    if test.get("status") == statuses.NOT_APPLICABLE
                    else statuses.FAIL
                )
                exceptions.append(
                    {
                        "classification": classification,
                        "platform": platform,
                        "path": test.get("fixture"),
                        "line": None,
                        "reason": test.get("diagnostic")
                        or f"scenario status {test.get('status')}",
                    }
                )

        metrics: dict = {}
        for lane in lane_results.values():
            summary = lane.get("summary") or {}
            for name in (
                "scenario_total",
                "scenario_passed",
                "assertion_total",
                "assertion_passed",
                "assertion_failed",
            ):
                if name in summary:
                    metrics[name] = metrics.get(name, 0) + int(summary[name] or 0)
            if lane.get("parity"):
                metrics["docker_parity"] = lane["parity"].get("matches")
        status = combine_targets(targets)
        if any(item.get("status") == statuses.FAIL for item in comparisons.values()):
            status = statuses.FAIL
        limitations = [
            "One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.",
            "The legacy fixture lane retains hashed reports rather than raw scanner report bytes.",
        ]
        return self.result(
            status=status,
            metrics=metrics,
            targets=targets,
            comparisons=comparisons,
            baseline_metric=False,
            scored=True,
            results=[
                {
                    "dimension": "functional-fixtures",
                    "outcome": statuses.outcome(lane.get("status", statuses.BLOCKED)),
                    "status": lane.get("status"),
                    "platform": key,
                    "configuration_profile": "FIXTURE_CONTROLLED",
                    "baseline_metric": False,
                }
                for key, lane in lane_results.items()
            ],
            limitations=limitations,
            summary={
                "platforms_executed": len(lane_results),
                "configuration_profile": "FIXTURE_CONTROLLED",
                "baseline_metric": False,
                "coverage_incomplete": any(
                    not lane.get("coverage_complete", False) for lane in lane_results.values()
                ),
            },
            details={
                "configuration": {
                    "profile": "FIXTURE_CONTROLLED",
                    "config_source": "pinned Gitleaks fixture scenarios",
                    "baseline_metric": False,
                },
                "lane_statuses": {
                    key: lane.get("status") for key, lane in lane_results.items()
                },
                "exceptions": exceptions,
                "datasets": {
                    "gitleaks-fixtures": {
                        "name": prepared.spec.name,
                        "revision": prepared.revision,
                        "manifest_sha256": prepared.spec.manifest_sha256,
                        "inventory_digest": prepared.spec.inventory_digest,
                    }
                },
            },
        )
