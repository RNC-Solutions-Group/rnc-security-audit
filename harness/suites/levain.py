"""Pinned Levain corpus suite using the scanner adapter for invocation."""

from __future__ import annotations

import hashlib
from dataclasses import asdict

from .. import dataset as dataset_module
from .. import status as statuses
from ..comparisons import compare_levain
from ..control import CONTROL_FILE, CONTROL_SECRETS
from ..model import Finding
from ..report import build_report, write_reports
from ..scoring import RunResult, assess_findings, materialize
from ..util import basename
from .base import SuiteContext, TestingSuite, combine_targets

PASSING = {
    "COMPLETED",
    "COMPLETED_WITH_WARNINGS",
    "COMPLETED_CONTROL_WARNING",
    "COMPLETED_COVERAGE_VERIFIED",
}


def _status(raw: str | None) -> str:
    if raw in PASSING:
        return statuses.PASS
    if raw in ("NOT_RUN", "NOT_RUN_UNSCORABLE"):
        return statuses.NOT_RUN
    if raw:
        return statuses.FAIL
    return statuses.BLOCKED


def _assess_invocation(context: SuiteContext, invocation, target, sections) -> RunResult:
    problem = context.adapter.invocation_problem(invocation)
    if problem:
        return RunResult(
            corpus=target.corpus,
            status=problem,
            invocation=invocation,
            control=None,
            results=None,
            unattributed=(),
            notes=(),
        )
    normalized = context.adapter.parse_findings(invocation.report_bytes)
    expected_by_file: dict[str, dict[str, str]] = {}
    for section in sections:
        name = basename(section.filename)
        for secret in section.secrets:
            expected_by_file.setdefault(name, {})[
                hashlib.sha256(secret.text.encode("utf-8")).hexdigest()
            ] = secret.text
    # The control file is not part of the scored corpus, but its expected values
    # must be available to the digest-based adapter bridge so structured control
    # detections are not reduced to empty findings.
    for _kind, value in CONTROL_SECRETS:
        expected_by_file.setdefault(CONTROL_FILE, {})[
            hashlib.sha256(value.encode("utf-8")).hexdigest()
        ] = value
    findings = []
    for item in normalized:
        name = basename(item.file)
        text = item.secret_text
        if not text and item.secret_sha256:
            text = expected_by_file.get(name, {}).get(item.secret_sha256)
        findings.append(
            Finding(
                file=name,
                line=item.line,
                rule_id=item.rule_id,
                secret=text or "",
                match=text or "",
            )
        )
    expected_files = tuple(
        sorted(
            path.relative_to(target.directory).as_posix()
            for path in target.directory.rglob("*")
            if path.is_file()
        )
    )
    coverage = context.adapter.execution_coverage(
        invocation, target.directory, expected_files
    )
    return assess_findings(
        invocation, findings, target, sections, coverage=coverage
    )


class LevainSuite(TestingSuite):
    key = "levain"
    title = "Levain credential corpus"
    required_capabilities = ("executable_or_docker", "detection")

    def _register_performance(self, context: SuiteContext, prepared, corpora) -> None:
        if not hasattr(context, "performance_workloads"):
            return
        root = context.work_dir / "performance" / "levain"
        positive = materialize(
            corpora.positive,
            root / "positive",
            corpus="positive",
            include_control=True,
        )
        negative = materialize(
            corpora.negative,
            root / "negative",
            corpus="negative",
            include_control=True,
        )
        files = sum(1 for path in root.rglob("*") if path.is_file())
        byte_count = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
        context.performance_workloads.append(
            {
                "suite": self.key,
                "key": "levain-filesystem",
                "title": "Levain positive and negative credential corpus",
                "target": str(root),
                "mode": "dir",
                "dataset": {
                    "dataset_id": "levain",
                    "dataset_version": prepared.spec.revision,
                    "manifest_sha256": prepared.manifest_sha256,
                },
                "workload": {
                    "dataset": "levain",
                    "lane": "filesystem",
                    "files": files,
                    "eligible_files": files,
                    "bytes": byte_count,
                    "positive_sections": len(positive.index),
                    "negative_sections": len(negative.index),
                },
                "multiplier": 1,
            }
        )

    def _run_one(self, context: SuiteContext, artifact, prepared, corpora) -> dict:
        work = context.work_dir / "levain" / artifact.platform.key
        work.mkdir(parents=True, exist_ok=True)
        runs = []
        for corpus in ("negative", "positive"):
            sections = corpora.negative if corpus == "negative" else corpora.positive
            target = materialize(
                sections,
                work / corpus,
                corpus=corpus,
                include_control=True,
            )
            if artifact.platform.is_executable:
                report_path = work / f"{corpus}-report.json"
                invocation = context.adapter.invoke_native(
                    artifact.artifact_path,
                    target.directory,
                    report_path,
                    config=context.scanner_config,
                    timeout_seconds=context.timeout,
                )
            else:
                out = work / f"{corpus}-out"
                invocation = context.adapter.invoke_container(
                    artifact.image_tag,
                    artifact.image_id,
                    target.directory,
                    out,
                    config=context.scanner_config,
                    timeout_seconds=context.timeout,
                )
            runs.append(
                _assess_invocation(context, invocation, target, sections)
            )
            if invocation.report_bytes is not None:
                context.raw_artifacts.append(
                    {
                        "name": f"levain-{artifact.platform.key}-{corpus}-report.json",
                        "data": invocation.report_bytes,
                        "content_type": "application/json",
                    }
                )
            if invocation.stdout:
                context.raw_artifacts.append(
                    {
                        "name": f"levain-{artifact.platform.key}-{corpus}-stdout.txt",
                        "data": invocation.stdout,
                        "content_type": "text/plain",
                    }
                )
            if invocation.stderr:
                context.raw_artifacts.append(
                    {
                        "name": f"levain-{artifact.platform.key}-{corpus}-stderr.txt",
                        "data": invocation.stderr,
                        "content_type": "text/plain",
                    }
                )
        report = build_report(
            prepared,
            corpora,
            runs,
            scanner_kind=context.adapter.key,
            source_revision=context.source.commit,
            config_path=context.scanner_config,
            config_sha256=context.scanner_config_sha256,
            extra_limitations=(
                f"Levain was invoked through {artifact.platform.key}.",
            ),
        )
        report_dir = context.work_dir / "levain-reports" / artifact.platform.key
        write_reports(report, report_dir, "levain")
        raw = report["summary"]["overall_status"]
        positive = next((run for run in runs if run.corpus == "positive"), None)
        negative = next((run for run in runs if run.corpus == "negative"), None)
        positive_status = _status(positive.status if positive else None)
        negative_status = _status(negative.status if negative else None)
        negative_results = (negative.results or {}) if negative else {}
        negative_scored = isinstance(negative_results.get("false_positives"), int)
        if positive_status == statuses.FAIL or negative_status == statuses.FAIL:
            lane_status = statuses.FAIL
            reason = "one or more Levain corpora failed"
        elif positive_status == statuses.PASS:
            lane_status = statuses.PASS
            reason = (
                None
                if negative_scored
                else "positive corpus completed; negative-corpus control was not detected, so precision and false positives are UNSCORED"
            )
        else:
            lane_status = positive_status
            reason = "positive corpus did not complete"
        return {
            "status": lane_status,
            "report_status": raw,
            "reason": reason,
            "negative_scored": negative_scored,
            "report": str(report_dir / "levain.md"),
            "adapter": "executable" if artifact.platform.is_executable else "docker",
            "runs": [
                {
                    "corpus": run.corpus,
                    "status": run.status,
                    "results": run.results,
                    "control": asdict(run.control) if run.control else None,
                    "coverage": run.coverage,
                }
                for run in runs
            ],
            "metrics": {
                "true_positives": (positive.results or {}).get("true_positives") if positive else None,
                "expected_secrets": (positive.results or {}).get("expected_secrets") if positive else None,
                "partial_matches": (positive.results or {}).get("partial_matches") if positive else None,
                "duplicates": (positive.results or {}).get("duplicates") if positive else None,
                "unexpected_findings": (
                    (positive.results or {}).get("unexpected_findings") if positive else None
                ),
                "false_positives": (
                    negative_results.get("false_positives") if negative_scored else None
                ),
                "negative_corpus_findings": negative_results.get("unexpected_findings"),
                "negative_control_status": negative.status if negative else None,
                "control_reported": bool(negative.control and negative.control.reported),
                "coverage_verified": bool(
                    negative.coverage and negative.coverage.get("verified")
                ),
            },
        }

    def run(self, context: SuiteContext) -> dict:
        try:
            prepared = context.cached(
                "levain",
                lambda: dataset_module.prepare(
                    cache_dir=context.config.cache_dir,
                    offline=context.offline,
                ),
            )
            corpora = dataset_module.load_corpora(prepared)
            self._register_performance(context, prepared, corpora)
        except Exception as exc:
            return self.result(
                status=statuses.BLOCKED,
                reason=f"Levain dataset preparation failed: {exc}",
            )
        targets: dict[str, dict] = {}
        lanes: dict[str, dict] = {}
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
                lane = self._run_one(context, artifact, prepared, corpora)
            except Exception as exc:
                lane = {
                    "status": statuses.BLOCKED,
                    "reason": str(exc),
                    "metrics": {},
                    "runs": [],
                }
            lanes[key] = lane
            targets[key] = {
                "status": lane["status"],
                "outcome": statuses.outcome(
                    lane["status"], scored=lane.get("negative_scored", True)
                ),
                "reason": lane.get("reason"),
                "metrics": lane.get("metrics", {}),
                "negative_scored": lane.get("negative_scored", True),
            }
        comparisons: dict[str, dict] = {}
        comparable = list(lanes)
        for index, left_key in enumerate(comparable):
            for right_key in comparable[index + 1 :]:
                comparisons[f"{left_key}_vs_{right_key}"] = compare_levain(
                    lanes[left_key], lanes[right_key]
                )
        exceptions = []
        for lane_key, lane in lanes.items():
            for run in lane.get("runs", []):
                results = run.get("results") or {}
                if run.get("corpus") == "positive":
                    for missed in results.get("missed_secrets", []):
                        exceptions.append(
                            {
                                "classification": "MISSED_EXPECTATION",
                                "platform": lane_key,
                                "path": missed.get("section"),
                                "line": None,
                                "reason": f"credential kind {missed.get('kind')} not detected",
                            }
                        )
                    for partial in results.get("partial_match_details", []):
                        exceptions.append(
                            {
                                "classification": "PARTIAL_MATCH",
                                "platform": lane_key,
                                "path": partial.get("section"),
                                "line": partial.get("line"),
                                "reason": f"partial evidence for {', '.join(partial.get('candidate_kinds', []))}",
                            }
                        )
                else:
                    for example in results.get("examples", []):
                        exceptions.append(
                            {
                                "classification": "UNEXPECTED_FINDING",
                                "platform": lane_key,
                                "path": example.get("section"),
                                "line": example.get("line"),
                                "reason": f"negative corpus finding rule {example.get('rule_id')}",
                            }
                        )
        metrics: dict = {}
        for lane in lanes.values():
            for name, value in (lane.get("metrics") or {}).items():
                if isinstance(value, int):
                    metrics[name] = value
        true_positives = metrics.get("true_positives")
        expected = metrics.get("expected_secrets")
        false_positives = metrics.get("false_positives")
        if isinstance(true_positives, int) and isinstance(false_positives, int):
            denominator = true_positives + false_positives
            metrics["precision_percent"] = (
                round(100.0 * true_positives / denominator, 2)
                if denominator
                else None
            )
        else:
            metrics["precision_percent"] = None
        metrics["recall_percent"] = (
            round(100.0 * true_positives / expected, 2)
            if isinstance(true_positives, int) and isinstance(expected, int) and expected
            else None
        )
        if metrics["precision_percent"] is not None and metrics["recall_percent"]:
            metrics["f1_percent"] = round(
                2
                * metrics["precision_percent"]
                * metrics["recall_percent"]
                / (metrics["precision_percent"] + metrics["recall_percent"]),
                2,
            )
        else:
            metrics["f1_percent"] = None
        metrics["negative_oracle"] = bool(lanes) and all(
            lane.get("negative_scored", True) for lane in lanes.values()
        )
        status = combine_targets(targets)
        if any(item.get("status") == statuses.FAIL for item in comparisons.values()):
            status = statuses.FAIL
        baseline_metric = getattr(context, "profile_name", "default") == "default"
        profile_name = getattr(context, "profile_name", "default")
        scored = bool(lanes) and all(
            lane.get("negative_scored", True) for lane in lanes.values()
        )
        limitations = [
            "Levain is a synthetic corpus; counts are not real-world prevalence.",
            *(
                []
                if baseline_metric
                else [
                    "CUSTOM profile results are excluded from DEFAULT baseline metrics."
                ]
            ),
        ]
        if not scored:
            limitations.append(
                "The Levain negative-corpus control was not detected, so precision, "
                "false-positive counts and F1 are UNSCORED; positive-corpus recall remains observable."
            )
        return self.result(
            status=status,
            targets=targets,
            metrics=metrics,
            comparisons=comparisons,
            baseline_metric=baseline_metric,
            scored=scored,
            outcome=statuses.outcome(status, scored=scored),
            results=[
                {
                    "dimension": "levain",
                    "outcome": statuses.outcome(
                        lane["status"], scored=lane.get("negative_scored", True)
                    ),
                    "status": lane["status"],
                    "platform": key,
                    "metrics": lane.get("metrics") or {},
                    "configuration_profile": profile_name,
                    "baseline_metric": baseline_metric,
                }
                for key, lane in lanes.items()
            ],
            limitations=limitations,
            summary={
                "platforms_executed": len(lanes),
                "configuration_profile": profile_name,
                "baseline_metric": baseline_metric,
                "negative_oracle": metrics["negative_oracle"],
                "coverage_incomplete": not scored,
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
                "lanes": lanes,
                "exceptions": exceptions,
                "datasets": {
                    "levain": {
                        "name": prepared.spec.name,
                        "revision": prepared.spec.revision,
                        "manifest_sha256": prepared.manifest_sha256,
                        "license_sha256": prepared.spec.license_sha256,
                    }
                },
            },
        )
