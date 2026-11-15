"""One-scanner, one-registered-artifact experiment orchestrator."""

from __future__ import annotations

import traceback
from pathlib import Path

from . import __version__
from . import performance
from . import rnclab
from . import status as statuses
from .adapters import BuildArtifact, expand_platform_selection, get_adapter
from .artifacts import RegisteredBuild, load_manifest, toolchain_metadata
from .config import HarnessConfig, load_config, validate_raw_destination
from .errors import HarnessError
from .profile import load_profile
from .reporting import compact_document, render_console, write_experiment_reports
from .suites import resolve_suites
from .suites.base import SuiteContext
from .telemetry import host_metadata
from .util import utc_now
from .workspace import RunWorkspace, new_run_id

ROOT = Path(__file__).resolve().parents[1]


def _blocked_build(platform, error: str, *, build: RegisteredBuild | None = None) -> BuildArtifact:
    return BuildArtifact(
        platform=platform,
        status=statuses.BLOCKED,
        command=(),
        exit_code=None,
        duration_seconds=0.0,
        artifact_path=None,
        artifact_sha256=None,
        image_id=None,
        image_tag=None,
        version=(build.version if build is not None else None),
        version_status=(
            statuses.PASS
            if build is not None and build.version
            else statuses.NOT_APPLICABLE
        ),
        stdout_sha256="",
        stderr_sha256="",
        error=error,
        metadata={
            "artifact_origin": "operator-provided-local-artifact",
            "build_id": build.id if build is not None else None,
            "scanner": build.scanner if build is not None else None,
            "source_commit": build.source_commit if build is not None else None,
            "source_identity": "manifest-metadata",
            "source_commit_verified": False,
            "manifest": (
                {
                    "path": str(build.manifest_path),
                    "sha256": build.manifest_sha256,
                }
                if build is not None
                else {}
            ),
            "artifact_verification_error": error,
        },
    )


def _artifact_summary(artifact: BuildArtifact) -> dict:
    metadata = artifact.metadata or {}
    return {
        "build_id": metadata.get("build_id"),
        "scanner": metadata.get("scanner"),
        "status": artifact.status,
        "platform": artifact.platform.key,
        "kind": "docker" if artifact.platform.is_docker else "executable",
        "execution_method": "docker" if artifact.platform.is_docker else "native",
        "executable": artifact.artifact_path,
        "executable_sha256": artifact.artifact_sha256,
        "docker_image": artifact.image_tag,
        "docker_image_id": artifact.image_id,
        "source_commit": metadata.get("source_commit"),
        "manifest_sha256": (metadata.get("manifest") or {}).get("sha256"),
        "rules_file": metadata.get("rules_file"),
        "rules_sha256": metadata.get("rules_sha256"),
        "error": artifact.error,
    }


def _blocked_build(platform, error: str) -> BuildArtifact:
    return BuildArtifact(
        platform=platform,
        status=statuses.BLOCKED,
        command=(),
        exit_code=None,
        duration_seconds=0.0,
        artifact_path=None,
        artifact_sha256=None,
        image_id=None,
        image_tag=None,
        version=None,
        version_status=statuses.NOT_APPLICABLE,
        stdout_sha256="",
        stderr_sha256="",
        error=error,
    )


def _blocked_suite(key: str, reason: str, *, applicable: bool = True) -> dict:
    return {
        "key": key,
        "title": key,
        "status": statuses.BLOCKED if applicable else statuses.NOT_APPLICABLE,
        "outcome": statuses.BLOCKED if applicable else statuses.NOT_APPLICABLE,
        "applicable": applicable,
        "baseline_metric": False,
        "reason": reason,
        "summary": {},
        "metrics": {},
        "targets": {},
        "results": [],
        "comparisons": {},
        "limitations": [],
        "details": {},
    }


def _not_applicable_suite(key: str, reason: str) -> dict:
    return _blocked_suite(key, reason, applicable=False)


def _requested_suites(value, config: HarnessConfig) -> list[str]:
    if value is None:
        return list(config.suites)
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(item).strip() for item in value if str(item).strip()]


def _coverage_limitations(suites: dict[str, dict]) -> tuple[bool, list[str]]:
    limitations: list[str] = []
    leaky = suites.get("leaky-repo")
    if leaky:
        metrics = leaky.get("metrics") or {}
        coverage = metrics.get("legacy_count_coverage_percent")
        if coverage is not None and coverage < 100:
            limitations.append(
                f"LEGACY COUNT COVERAGE for Leaky Repo is {coverage}% "
                f"({metrics.get('files_covered', 0)}/{metrics.get('expected_files', 0)} files); "
                "this is an upstream count metric, not verified detection recall."
            )
    for key, item in suites.items():
        if (item.get("summary") or {}).get("coverage_incomplete"):
            limitations.append(f"Suite {key} reports incomplete coverage.")
    return not limitations, limitations


def _detection_summary(suites: dict[str, dict]) -> dict:
    leaky = suites.get("leaky-repo") or {}
    metrics = leaky.get("metrics") or {}
    lab = suites.get("rnclab") or {}
    lab_metrics = lab.get("metrics") or {}
    return {
        "synthetic_filesystem": (suites.get("synthetic-filesystem") or {}).get("metrics")
        or {},
        "synthetic_history": (suites.get("git-history") or {}).get("metrics") or {},
        "levain": (suites.get("levain") or {}).get("metrics") or {},
        "leaky_filesystem": {
            "methodology": "legacy_count_plus_rich_line_truth",
            "legacy_count_coverage": {
                "expected_count": metrics.get("expected_count"),
                "covered_count": metrics.get("covered_count"),
                "coverage_percent": metrics.get("legacy_count_coverage_percent"),
                "files_covered": metrics.get("files_covered"),
                "expected_files": metrics.get("expected_files"),
                "excess_findings": metrics.get("excess_findings"),
                "unlisted_findings": metrics.get("unlisted_findings"),
                "label": "LEGACY COUNT COVERAGE",
            },
            "rich_line_truth": {
                "expected_count": metrics.get("rich_expected_count"),
                "matched_count": metrics.get("rich_matched_count"),
                "missed_count": metrics.get("rich_missed_count"),
                "unexpected_count": metrics.get("rich_unexpected_count"),
                "duplicate_count": metrics.get("rich_duplicate_count"),
                "detection_recall_percent": metrics.get("rich_detection_recall_percent"),
                "precision_percent": None,
                "f1_percent": None,
                "negative_oracle": False,
                "value_verified_count": metrics.get("value_verified_count"),
                "line_only_count": metrics.get("line_only_count"),
                "category_conflict_items": metrics.get("rich_category_conflict_items"),
            },
        },
        "rnclab": {
            "lab": lab.get("summary", {}).get("lab"),
            "build": lab.get("summary", {}).get("build"),
            "filesystem": {
                "expected_positives": lab_metrics.get("expected_positives"),
                "true_positive_occurrences": lab_metrics.get(
                    "true_positive_occurrences"
                ),
                "false_negative_occurrences": lab_metrics.get(
                    "false_negative_occurrences"
                ),
                "occurrence_recall_percent": lab_metrics.get(
                    "occurrence_recall_percent"
                ),
                "expected_unique_groups": lab_metrics.get("expected_unique_groups"),
                "unique_groups_matched": lab_metrics.get("unique_groups_matched"),
                "unique_recall_percent": lab_metrics.get("unique_recall_percent"),
                "duplicate_count": lab_metrics.get("duplicate_count"),
                "informative_match_count": lab_metrics.get("informative_match_count"),
                "verified_false_positive_alert_count": lab_metrics.get(
                    "verified_false_positive_alert_count"
                ),
                "near_miss_count": lab_metrics.get("near_miss_count"),
                "near_miss_target_count": lab_metrics.get("near_miss_target_count"),
                "near_miss_reason_counts": lab_metrics.get("near_miss_reason_counts"),
                "near_miss_targets": lab_metrics.get("near_miss_targets"),
                "unmatched_pending_review_count": lab_metrics.get(
                    "unmatched_pending_review_count"
                ),
                "unverified_evidence_count": lab_metrics.get(
                    "unverified_evidence_count"
                ),
                "ambiguous_count": lab_metrics.get("ambiguous_count"),
                "target_accounting_reconciled": lab_metrics.get(
                    "target_accounting_reconciled"
                ),
                "finding_accounting_reconciled": lab_metrics.get(
                    "finding_accounting_reconciled"
                ),
                "unsupported_capability_count": lab_metrics.get(
                    "unsupported_capability_count"
                ),
                "precision_percent": None,
                "f1_percent": None,
                "precision_certification_status": lab_metrics.get(
                    "precision_certification_status"
                ),
            },
            "git": {
                "supported": lab.get("summary", {}).get("git_mode_supported"),
                "lanes": {
                    key: ((value.get("lanes") or {}).get("git") or {})
                    for key, value in (lab.get("targets") or {}).items()
                },
            },
            "denominators": {
                "filesystem_total_items": 1282,
                "git_total_items": 320,
                "positive_occurrences": 800,
                "unique_credential_identities": 496,
            },
        },
        "leaky_history": {
            "scored": bool(metrics.get("history_scored")),
            "truth_status": metrics.get("history_truth_status"),
            "execution_status": metrics.get("history_execution_status"),
            "score_status": metrics.get("history_score_status"),
            "observed_findings": metrics.get("history_observed_findings"),
            "unique_secret_fingerprints": metrics.get(
                "history_unique_secret_fingerprints"
            ),
            "commits_scanned": metrics.get("history_commits_scanned"),
            "expected_commits": metrics.get("history_expected_commits"),
            "scope_matches": metrics.get("history_scope_matches"),
            "coverage_verified": metrics.get("history_coverage_verified"),
            "expected_occurrences": metrics.get("history_expected_occurrences"),
            "matched_occurrences": metrics.get("history_matched_occurrences"),
            "missed_occurrences": metrics.get("history_missed_occurrences"),
            "unique_expected": metrics.get("history_unique_expected"),
            "unique_matched": metrics.get("history_unique_matched"),
            "unique_recall_percent": metrics.get("history_unique_recall_percent"),
            "occurrence_recall_percent": metrics.get(
                "history_occurrence_recall_percent"
            ),
            "duplicate_count": metrics.get("history_duplicate_count"),
            "informative_match_count": metrics.get("history_informative_match_count"),
            "verified_false_positive_count": metrics.get(
                "history_verified_false_positive_count"
            ),
            "unmatched_pending_review_count": metrics.get(
                "history_unmatched_pending_review_count"
            ),
            "unverified_evidence_count": metrics.get(
                "history_unverified_evidence_count"
            ),
            "precision_percent": None,
            "f1_percent": None,
            "precision_certification_status": metrics.get(
                "history_precision_certification_status"
            ),
            "denominator": "65 source occurrences / 53 unique groups",
        },
    }


def _detection_by_product(suites: dict[str, dict], builds: dict[str, BuildArtifact]) -> dict:
    product: dict[str, dict] = {}
    for platform in builds:
        row: dict = {}
        for key, suite in suites.items():
            target = (suite.get("targets") or {}).get(platform) or {}
            if target:
                row[key] = {
                    "status": target.get("status"),
                    "outcome": target.get("outcome"),
                    "metrics": target.get("metrics") or {},
                    "reason": target.get("reason"),
                }
        history_lanes = ((suites.get("leaky-repo") or {}).get("details") or {}).get(
            "history_lanes"
        ) or {}
        if platform in history_lanes:
            row["leaky-history"] = history_lanes[platform]
        product[platform] = row
    return product


def _performance_unavailable(reason: str, status: str = statuses.BLOCKED) -> dict:
    return {
        "status": status,
        "reason": reason,
        "products": [],
        "workloads": [],
        "workload": {},
        "methodology": {
            "sequential": True,
            "build_time_separate": True,
            "detection_and_performance_separate": True,
        },
        "limitations": [],
    }


def _apply_coverage_caveats(result: dict) -> None:
    """Make scanner-declared unit exclusions visible in performance coverage."""
    summary = result.get("summary") or {}
    caveats = summary.get("coverage_caveats") or []
    if not caveats:
        return
    maximum = max(
        int((item or {}).get("unsupported_capability_count") or 0)
        for item in caveats
    )
    eligible = summary.get("files_eligible")
    current = summary.get("files_inspected")
    if (
        isinstance(eligible, int)
        and eligible >= maximum
        and (current is None or current >= eligible)
    ):
        summary["files_inspected"] = eligible - maximum
        summary["file_coverage_percent"] = round(
            100.0 * (eligible - maximum) / eligible, 2
        )
    result["coverage_caveat"] = {
        "unsupported_capability_count": maximum,
        "details": caveats[0] if caveats else None,
    }


def _performance_plan(
    *,
    warmups: int,
    runs: int,
    timeout: int,
    mode: str,
    benchmark_environment: str,
    stress_profile: str,
) -> performance.BenchmarkPlan:
    return performance.BenchmarkPlan(
        warmups=warmups,
        measured_runs=runs,
        timeout_seconds=timeout,
        mode=mode,
        environment=benchmark_environment,
        stress_profile=stress_profile,
    )


def _run_performance(
    adapter,
    context: SuiteContext,
    *,
    config: HarnessConfig,
    copies: int,
    warmups: int,
    runs: int,
    timeout: int,
    offline: bool,
    benchmark_environment: str = "DEV",
    stress_profile: str = "none",
) -> dict:
    successes = [
        (key, artifact)
        for key, artifact in context.builds.items()
        if artifact.status == statuses.PASS and adapter.can_execute(artifact.platform)
    ]
    if not successes:
        return _performance_unavailable("no executable product built")
    workloads = [
        item
        for item in context.performance_workloads
        if item.get("status") != statuses.BLOCKED
    ]
    if not workloads:
        return _performance_unavailable(
            "the selected suites do not define a performance workload "
            "(the scanner-specific fixture lane is functional-only)",
            statuses.NOT_APPLICABLE,
        )
    products: list[dict] = []
    product_order: list[str] = []
    sequence_index = 0
    for key, artifact in successes:
        product_order.append(key)
        for workload in workloads:
            target = workload.get("target")
            if not target:
                products.append(
                    {
                        "status": statuses.BLOCKED,
                        "product": {"platform": key},
                        "suite": workload.get("suite"),
                        "workload_key": workload.get("key"),
                        "reason": workload.get("reason") or "performance target unavailable",
                    }
                )
                continue
            try:
                plan = _performance_plan(
                    warmups=warmups,
                    runs=runs,
                    timeout=timeout,
                    mode=str(workload.get("mode") or "dir"),
                    benchmark_environment=benchmark_environment,
                    stress_profile=stress_profile,
                )
                result = performance.benchmark_product(
                    adapter,
                    artifact,
                    target,
                    context.work_dir / "performance" / key / str(workload["key"]),
                    plan=plan,
                    workload=workload.get("workload") or {},
                    scanner_version=artifact.version,
                    dataset=workload.get("dataset") or {},
                    scanner_config=context.scanner_config,
                    sequence_index=sequence_index,
                    cache_state="warm_after_warmup" if warmups else "cold_target",
                    allow_partial=bool(workload.get("allow_partial")),
                    suite=str(workload.get("suite") or ""),
                    workload_key=str(workload.get("key") or ""),
                )
                result["suite"] = workload.get("suite")
                result["workload_key"] = workload.get("key")
                result["workload_title"] = workload.get("title")
                result["requested_multiplier"] = workload.get("multiplier", 1)
                result["load_profile"] = None
                _apply_coverage_caveats(result)
                result["artifact"] = _artifact_summary(artifact)
                result["build"] = {
                    "status": artifact.status,
                    "build_id": (artifact.metadata or {}).get("build_id"),
                    "artifact_sha256": artifact.artifact_sha256,
                    "image_id": artifact.image_id,
                    "source_commit": (artifact.metadata or {}).get("source_commit"),
                }
                products.append(result)
            except Exception as exc:
                products.append(
                    {
                        "status": statuses.BLOCKED,
                        "product": {"platform": key},
                        "suite": workload.get("suite"),
                        "workload_key": workload.get("key"),
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
                )
            sequence_index += 1

        # Follow-on load profiles run only after the canonical rnclab
        # measurements for this product, and only one profile at a time.
        for load in context.performance_loads:
            if load.get("suite") != "rnclab":
                continue
            canonical = next(
                (
                    item
                    for item in products
                    if item.get("suite") == "rnclab"
                    and item.get("workload_key") == "rnclab-filesystem"
                    and (item.get("product") or {}).get("platform") == key
                ),
                None,
            )
            try:
                dataset = context.cached(
                    "rnclab_dataset",
                    lambda: rnclab.load(config.cache_dir / "rnc-synth-lab"),
                )
            except Exception as exc:
                products.append(
                    {
                        "status": statuses.BLOCKED,
                        "product": {"platform": key},
                        "suite": "rnclab",
                        "workload_key": "rnclab-load",
                        "reason": f"lab dataset unavailable for load testing: {exc}",
                    }
                )
                continue
            for profile in load.get("profiles") or []:
                generated: dict | None = None
                try:
                    generated = rnclab.generate_stress(
                        dataset,
                        context.work_dir / "performance" / key / "loads" / profile,
                        profile,
                        timeout=max(timeout, 900),
                    )
                    load_workload = {
                        "dataset": "rnc-synthetic-secrets-lab",
                        "lane": "filesystem",
                        "load_profile": profile,
                        "requested_multiplier": generated["multiplier"],
                        "files": generated["files"],
                        "eligible_files": generated["files"],
                        "bytes": generated["bytes"],
                        "oracle_scored": False,
                        "stress_manifest": generated["manifest"],
                    }
                    plan = _performance_plan(
                        warmups=1,
                        runs=3,
                        timeout=timeout,
                        mode="dir",
                        benchmark_environment=benchmark_environment,
                        stress_profile=stress_profile,
                    )
                    result = performance.benchmark_product(
                        adapter,
                        artifact,
                        generated["target"],
                        context.work_dir
                        / "performance"
                        / key
                        / "load-measure"
                        / profile,
                        plan=plan,
                        workload=load_workload,
                        scanner_version=artifact.version,
                        dataset={
                            "dataset_id": "rnc-synthetic-secrets-lab",
                            "dataset_version": rnclab.LAB_VERSION,
                            "build_id": rnclab.BUILD_ID,
                            "manifest_sha256": dataset.manifest_sha256,
                            "load_profile": profile,
                            "generated_corpus": True,
                        },
                        scanner_config=context.scanner_config,
                        sequence_index=sequence_index,
                        cache_state="warm_after_warmup",
                        allow_partial=True,
                        suite="rnclab",
                        workload_key=f"rnclab-{profile}",
                    )
                    result["suite"] = "rnclab"
                    result["workload_key"] = f"rnclab-{profile}"
                    result["workload_title"] = f"RNC Lab {profile} load"
                    result["requested_multiplier"] = generated["multiplier"]
                    result["load_profile"] = profile
                    result["accuracy_scored"] = False
                    result["load_generation"] = {
                        "manifest": generated["manifest"],
                        "files": generated["files"],
                        "bytes": generated["bytes"],
                        "command": generated["command"],
                    }
                    _apply_coverage_caveats(result)
                    if canonical:
                        canonical_median = (
                            (canonical.get("summary") or {})
                            .get("runtime_seconds", {})
                            .get("median")
                        )
                        load_median = (
                            (result.get("summary") or {})
                            .get("runtime_seconds", {})
                            .get("median")
                        )
                        canonical_memory = (
                            (canonical.get("summary") or {})
                            .get("peak_memory_bytes", {})
                            .get("max")
                        )
                        load_memory = (
                            (result.get("summary") or {})
                            .get("peak_memory_bytes", {})
                            .get("max")
                        )
                        canonical_files = (
                            (canonical.get("summary") or {}).get("files_eligible")
                        )
                        result["scaling"] = {
                            "canonical_median_seconds": canonical_median,
                            "load_median_seconds": load_median,
                            "runtime_scaling": round(load_median / canonical_median, 6)
                            if canonical_median and load_median
                            else None,
                            "canonical_peak_memory_bytes": canonical_memory,
                            "load_peak_memory_bytes": load_memory,
                            "memory_scaling": round(load_memory / canonical_memory, 6)
                            if canonical_memory and load_memory
                            else None,
                            "canonical_throughput_bytes_per_second": (
                                (canonical.get("summary") or {}).get(
                                    "throughput_bytes_per_second"
                                )
                            ),
                            "load_throughput_bytes_per_second": (
                                (result.get("summary") or {}).get(
                                    "throughput_bytes_per_second"
                                )
                            ),
                            "actual_file_multiplier": round(
                                generated["files"] / canonical_files, 3
                            )
                            if canonical_files
                            else None,
                        }
                    result["build"] = {
                        "status": artifact.status,
                        "build_id": (artifact.metadata or {}).get("build_id"),
                        "artifact_sha256": artifact.artifact_sha256,
                        "image_id": artifact.image_id,
                        "source_commit": (artifact.metadata or {}).get("source_commit"),
                    }
                    result["artifact"] = _artifact_summary(artifact)
                    products.append(result)
                except Exception as exc:
                    products.append(
                        {
                            "status": statuses.BLOCKED,
                            "product": {"platform": key},
                            "suite": "rnclab",
                            "workload_key": f"rnclab-{profile}",
                            "load_profile": profile,
                            "reason": f"{type(exc).__name__}: {exc}",
                        }
                    )
                finally:
                    if generated is not None:
                        rnclab.cleanup_stress(generated)
                sequence_index += 1

    product_status = (
        statuses.PASS
        if products
        and all(item.get("status") != statuses.BLOCKED for item in products)
        else statuses.BLOCKED
    )
    return {
        "status": product_status,
        "methodology": {
            "version": performance.PERFORMANCE_VERSION,
            "warmups": warmups,
            "measured_runs": runs,
            "load_warmups": 1,
            "load_measured_runs": 3,
            "copies": copies,
            "sequential": True,
            "single_active_execution": True,
            "build_time_separate": True,
            "detection_and_performance_separate": True,
            "environment_mode": benchmark_environment,
            "stress_profile": stress_profile,
            "scanner_order": product_order,
            "cache_state": "warm_after_warmup" if warmups else "cold_target",
            "workloads": [item.get("key") for item in workloads],
            "load_profiles": [
                profile
                for load in context.performance_loads
                for profile in (load.get("profiles") or [])
            ],
        },
        "workload": {
            "count": len(workloads),
            "files": sum(
                int((item.get("workload") or {}).get("files") or 0)
                for item in workloads
            ),
            "bytes": sum(
                int((item.get("workload") or {}).get("bytes") or 0)
                for item in workloads
            ),
            "items": [
                {
                    "key": item.get("key"),
                    "suite": item.get("suite"),
                    "mode": item.get("mode"),
                    "files": (item.get("workload") or {}).get("files"),
                    "bytes": (item.get("workload") or {}).get("bytes"),
                    "multiplier": item.get("multiplier", 1),
                }
                for item in workloads
            ],
        },
        "products": products,
        "limitations": [
            "Performance is reported separately from detection accuracy; no weighted combined score exists.",
            "Native, container, and emulated-architecture products are not directly comparable.",
            "Unavailable CPU or memory telemetry is null, never zero.",
            "DEV measurements are contended and not publishable as release evidence.",
            "Levain, Leaky filesystem, Leaky Git and RNC Lab filesystem/Git are separate workloads.",
            "RNC Lab legacy-5x/legacy-10x loads are performance-only and are never scored against the canonical oracle.",
            "Archive extraction and inspected-file coverage are recorded from the declared workload; scanner-internal traversal is not inferred from timing.",
            *(
                [f"Only {runs} measured run(s) were requested; variability and drift are preliminary."]
                if runs < 3
                else []
            ),
        ],
    }


def run(
    *,
    build: str | None = None,
    artifact_manifest: Path | str | None = None,
    scanner: str | None = None,
    platforms: str | list[str] | tuple[str, ...] | None = None,
    suites: str | list[str] | tuple[str, ...] | None = None,
    profile_name: str = "default",
    scanner_config: Path | str | None = None,
    config: HarnessConfig | None = None,
    config_path: Path | str | None = None,
    warmups: int | None = None,
    runs: int | None = None,
    copies: int = 10,
    retain_work: bool = False,
    timeout: int | None = None,
    offline: bool = False,
    compact: bool = False,
    benchmark_environment: str | None = None,
    stress_profile: str | None = None,
) -> dict:
    config = config or load_config(config_path)
    manifest = load_manifest(artifact_manifest or config.artifact.manifest)
    selected = manifest.select(build if build is not None else config.artifact.build)
    if scanner and scanner != selected.scanner:
        raise HarnessError(
            f"registered build {selected.id!r} belongs to scanner {selected.scanner!r}, "
            f"not {scanner!r}"
        )
    adapter = get_adapter(selected.scanner)
    profile = load_profile(adapter, profile_name, scanner_config)
    benchmark_environment_record = performance.environment_for(
        benchmark_environment or config.benchmark_environment,
        stress_profile=stress_profile or config.stress_profile,
    )
    selected_platforms = expand_platform_selection(
        platforms if platforms is not None else config.platforms
    )
    if not selected_platforms:
        raise ValueError("no target platforms were selected")
    requested_suites = _requested_suites(suites, config)
    run_id = new_run_id()
    workspace = RunWorkspace.create(run_id, retain=retain_work)
    workspace.prepare()
    adapter.bind_run(run_id)
    work_dir = workspace.evidence
    started_at = utc_now()
    builds: dict[str, BuildArtifact] = {}
    suite_results: dict[str, dict] = {}
    context: SuiteContext | None = None
    performance_document: dict = _performance_unavailable("not reached")
    fatal_error: str | None = None
    fatal_traceback: str | None = None
    try:
        for platform in selected_platforms:
            verification_dir = work_dir / "artifact-verification" / platform.key
            verification_dir.mkdir(parents=True, exist_ok=True)
            try:
                builds[platform.key] = adapter.resolve_artifact(
                    selected, platform, verification_dir
                )
            except Exception as exc:
                builds[platform.key] = _blocked_build(
                    platform,
                    f"{type(exc).__name__}: {exc}",
                    build=selected,
                )
        context = SuiteContext(
            adapter=adapter,
            build=selected,
            config=config,
            builds=builds,
            work_dir=work_dir,
            report_dir=config.reports.output_dir,
            run_id=run_id,
            offline=offline,
            timeout=timeout or config.timeout,
            profile=profile,
            scanner_config=profile.scanner_config,
            scanner_config_sha256=profile.config_sha256,
            performance_copies=max(1, int(copies)),
        )
        for key, suite, reason in resolve_suites(requested_suites, adapter):
            if suite is None:
                suite_results[key] = _not_applicable_suite(
                    key, reason or "unsupported suite"
                )
                continue
            try:
                suite_results[key] = suite.run(context)
            except Exception as exc:
                suite_results[key] = _blocked_suite(
                    key, f"{type(exc).__name__}: {exc}"
                )
                suite_results[key]["details"]["traceback"] = traceback.format_exc(limit=8)
        if any(item.status == statuses.PASS for item in builds.values()):
            try:
                performance_document = _run_performance(
                    adapter,
                    context,
                    config=config,
                    copies=copies,
                    warmups=warmups if warmups is not None else config.benchmark_warmups,
                    runs=runs if runs is not None else config.benchmark_runs,
                    timeout=timeout or config.timeout,
                    offline=offline,
                    benchmark_environment=benchmark_environment_record.mode,
                    stress_profile=benchmark_environment_record.stress_profile,
                )
            except Exception as exc:
                performance_document = _performance_unavailable(
                    f"{type(exc).__name__}: {exc}"
                )
    except KeyboardInterrupt:
        fatal_error = "KeyboardInterrupt: cancelled by operator"
        fatal_traceback = traceback.format_exc(limit=8)
        if not suite_results:
            for key in requested_suites:
                if key in adapter.supported_suites:
                    suite_results[key] = _blocked_suite(
                        key, "experiment cancelled before completion"
                    )
                else:
                    suite_results[key] = _not_applicable_suite(
                        key, f"scanner adapter {adapter.key!r} does not support suite {key!r}"
                    )
    except Exception as exc:
        fatal_error = f"{type(exc).__name__}: {exc}"
        fatal_traceback = traceback.format_exc(limit=8)
        if not suite_results:
            for key in requested_suites:
                if key in adapter.supported_suites:
                    suite_results[key] = _blocked_suite(key, f"experiment failed: {fatal_error}")
                else:
                    suite_results[key] = _not_applicable_suite(
                        key, f"scanner adapter {adapter.key!r} does not support suite {key!r}"
                    )
    cleanup = workspace.cleanup(
        inspect_docker=any(item.platform.is_docker for item in builds.values()),
    )

    build_statuses = [item.status for item in builds.values()]
    suite_statuses = [item["status"] for item in suite_results.values()]
    matrix_status = statuses.combine([*build_statuses, *suite_statuses])
    coverage_ok, coverage_limits = _coverage_limitations(suite_results)
    overall = statuses.overall(
        [*build_statuses, *suite_statuses], coverage_complete=coverage_ok
    )
    if fatal_error:
        matrix_status = statuses.FAIL
        overall = "FAIL"
    elif not any(
        status in (statuses.PASS, statuses.FAIL, statuses.BLOCKED)
        for status in suite_statuses
    ):
        overall = "INCOMPLETE"
    elif overall == "COMPLETE" and cleanup.get("status") != statuses.PASS:
        overall = "COMPLETE_WITH_LIMITATIONS"
    elif (
        overall == "COMPLETE"
        and performance_document.get("status") != statuses.PASS
    ):
        overall = "COMPLETE_WITH_LIMITATIONS"
    scoring_failures = [
        key
        for key, item in suite_results.items()
        if any(
            row.get("rich_score_status") == "NOT_READY"
            for row in (item.get("targets") or {}).values()
            if isinstance(row, dict)
        )
    ]
    if scoring_failures:
        limitations_note = (
            "Scoring oracle unavailable (findings may still be reported): "
            + ", ".join(sorted(scoring_failures))
        )
        coverage_limits.append(limitations_note)
    counts = {
        "pass": sum(item == statuses.PASS for item in suite_statuses),
        "fail": sum(item == statuses.FAIL for item in suite_statuses),
        "blocked": sum(item == statuses.BLOCKED for item in suite_statuses),
        "not_run": sum(item == statuses.NOT_RUN for item in suite_statuses),
        "not_applicable": sum(item == statuses.NOT_APPLICABLE for item in suite_statuses),
    }
    limitations = [
        "Source commit is operator-supplied manifest metadata; the harness did not clone, check out, or compile scanner source.",
        "The registered executable SHA-256 and Docker image ID are the executed artifact identities; they are verified before every run.",
        "A verified artifact is not counted as tested unless an applicable suite executed it.",
        "Registered Docker images and run/ executables are never deleted or modified by the harness.",
        *coverage_limits,
    ]
    for item in suite_results.values():
        limitations.extend(item.get("limitations", []))
    if profile.limitations:
        limitations.extend(profile.limitations)
    if fatal_error:
        limitations.append(f"Experiment failed before completion: {fatal_error}")
    if cleanup.get("status") != statuses.PASS:
        limitations.append("Run-owned cleanup was incomplete; see cleanup report.")
    if performance_document.get("status") not in (
        statuses.PASS,
        statuses.NOT_APPLICABLE,
    ):
        limitations.append(
            f"Performance section status is {performance_document.get('status')}; "
            "see its reason and limitations."
        )
    if (
        benchmark_environment_record.mode == "DEV"
        and performance_document.get("status") != statuses.NOT_APPLICABLE
    ):
        limitations.append(
            "Performance measurements used the DEV environment profile; the host was "
            "contended/uncontrolled and these timings are not release evidence."
        )
    if benchmark_environment_record.stress_profile != "none":
        limitations.append(
            f"Performance measurements used the {benchmark_environment_record.stress_profile} "
            "stress profile; results are reported separately from the default baseline."
        )
    seen: set[str] = set()
    unique_limitations = []
    for item in limitations:
        if item not in seen:
            seen.add(item)
            unique_limitations.append(item)
    datasets: dict[str, dict] = {}
    for item in suite_results.values():
        datasets.update((item.get("details") or {}).get("datasets") or {})
    scanner_ruleset = next(
        (
            item.metadata.get("ruleset")
            for item in builds.values()
            if item.metadata and item.metadata.get("ruleset")
        ),
        None,
    )
    profile_document = profile.to_dict()
    if scanner_ruleset:
        profile_document["ruleset"] = scanner_ruleset
        profile_document.setdefault("applied_settings", {})["rules_sha256"] = (
            scanner_ruleset.get("sha256")
        )
    source_document = {
        "repository": selected.source_repository,
        "commit": selected.source_commit,
        "requested_commit": selected.source_commit,
        "head": None,
        "head_verified": False,
        "identity": "manifest-metadata",
        "metadata_only": True,
        "verified": False,
        "note": (
            "Source commit is operator-supplied metadata. No scanner source was "
            "cloned, checked out, or compiled."
        ),
        "build_id": selected.id,
        "manifest": {
            "path": manifest.to_dict()["path"],
            "sha256": manifest.sha256,
        },
    }
    document = {
        "schema_version": 2,
        "report_type": "rnc-scan-harness/experiment",
        "harness_version": __version__,
        "generated_at": utc_now(),
        "started_at": started_at,
        "run_id": run_id,
        "scanner": {
            "key": adapter.key,
            "name": adapter.display_name,
            "version": selected.version,
            "identity": "operator-provided-artifact",
            "ruleset": scanner_ruleset,
        },
        "adapter": {
            "key": adapter.key,
            "name": adapter.display_name,
            "supported_suites": list(adapter.supported_suites),
        },
        "source": source_document,
        "registered_build": selected.to_dict(),
        "artifact_manifest": {
            "path": manifest.to_dict()["path"],
            "sha256": manifest.sha256,
            "schema_version": manifest.to_dict()["schema_version"],
            "registered_builds": [item.id for item in manifest.builds],
        },
        "profile": profile_document,
        "host": {
            **host_metadata(),
            "toolchain": toolchain_metadata(),
        },
        "benchmark_environment": benchmark_environment_record.to_dict(),
        "platforms": [item.to_dict() for item in selected_platforms],
        "builds": {key: item.to_dict() for key, item in builds.items()},
        "datasets": datasets,
        "suites": suite_results,
        "detection": _detection_summary(suite_results),
        "detection_by_product": _detection_by_product(suite_results, builds),
        "performance": performance_document,
        "cleanup": cleanup,
        "invocations": list(adapter.invocations),
        "summary": {
            "overall": overall,
            "matrix_status": matrix_status,
            "experiment_status": overall,
            "source_commit": selected.source_commit,
            "source_head_verified": False,
            "source_commit_metadata_only": True,
            "build_id": selected.id,
            "artifact_manifest_sha256": manifest.sha256,
            "invocation_count": len(adapter.invocations),
            "profile": profile.name,
            "baseline_metrics_included": profile.is_default,
            "suites": {key: item["status"] for key, item in suite_results.items()},
            "outcomes": {key: item["outcome"] for key, item in suite_results.items()},
            "builds": {key: item.status for key, item in builds.items()},
            "counts": counts,
            "coverage_complete": coverage_ok,
            "performance_status": performance_document.get("status"),
            "benchmark_environment": benchmark_environment_record.mode,
            "stress_profile": benchmark_environment_record.stress_profile,
            "baseline_metrics_executed": any(
                item.get("baseline_metric") is True
                and item.get("status") in (statuses.PASS, statuses.FAIL)
                for item in suite_results.values()
            ),
            "scoring_oracle_unavailable": scoring_failures,
            "tested_platforms": sorted(
                {
                    platform
                    for item in suite_results.values()
                    for platform, target in (item.get("targets") or {}).items()
                    if target.get("status") in (statuses.PASS, statuses.FAIL)
                }
            ),
            "fatal_error": fatal_error,
            "cleanup_status": cleanup.get("status"),
        },
        "limitations": unique_limitations,
        "reports": {"sanitized": [], "raw": None},
        "report_options": {
            "exceptions_enabled": config.reports.exceptions_enabled,
            "exception_mode": config.reports.exception_mode,
            "include_coverage_gaps": config.reports.include_coverage_gaps,
            "include_skipped": config.reports.include_skipped,
            "include_not_applicable": config.reports.include_not_applicable,
            "include_baseline_deltas": config.reports.include_baseline_deltas,
        },
    }
    if fatal_traceback:
        document["diagnostics"] = {"traceback": fatal_traceback}
    if config.reports.raw:
        validate_raw_destination(config)
    document["raw_policy"] = "exported" if config.reports.raw else "discarded"
    report_document = compact_document(document) if compact else document
    paths = write_experiment_reports(
        report_document,
        config,
        run_id=run_id,
        scanner=adapter.key,
        commit=selected.source_commit,
        profile=profile.name,
        suites=list(suite_results),
        raw_artifacts=context.raw_artifacts if context else [],
    )
    document["reports"] = paths
    document["_paths"] = {
        **paths,
        "work": str(workspace.root),
        "console": render_console(document),
        "raw_policy": "exported" if paths.get("raw") else "discarded",
        "retained": bool(retain_work),
    }
    return document


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="One-scanner registered-artifact experiment."
    )
    parser.add_argument("--build", default=None, help="registered build id")
    parser.add_argument(
        "--artifact-manifest",
        default=None,
        help="local artifact manifest (default: run/manifest.toml)",
    )
    parser.add_argument("--scanner", default=None)
    parser.add_argument("--platforms", default=None)
    parser.add_argument("--suites", default=None)
    parser.add_argument("--profile", choices=("default", "custom"), default="default")
    parser.add_argument("--scanner-config", default=None)
    parser.add_argument("--config", default=None)
    parser.add_argument("--warmups", type=int, default=None)
    parser.add_argument("--runs", type=int, default=None)
    parser.add_argument("--copies", type=int, default=10)
    parser.add_argument(
        "--retain-work",
        action="store_true",
        help="retain the run-owned benchmark workspace and Docker containers",
    )
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument(
        "--benchmark-environment",
        choices=("DEV", "CONTROLLED", "RELEASE"),
        default=None,
    )
    parser.add_argument(
        "--stress-profile",
        choices=("none", "cpu", "memory", "io", "network"),
        default="none",
    )
    args = parser.parse_args(argv)
    document = run(
        build=args.build,
        artifact_manifest=args.artifact_manifest,
        scanner=args.scanner,
        platforms=args.platforms,
        suites=args.suites,
        profile_name=args.profile,
        scanner_config=args.scanner_config,
        config_path=args.config,
        warmups=args.warmups,
        runs=args.runs,
        copies=args.copies,
        retain_work=args.retain_work,
        offline=args.offline,
        compact=args.compact,
        timeout=args.timeout,
        benchmark_environment=args.benchmark_environment,
        stress_profile=args.stress_profile,
    )
    print(document["_paths"]["console"])
    if document["summary"]["overall"] == "FAIL":
        return 1
    return 0 if document["summary"]["overall"] == "COMPLETE" else 3
