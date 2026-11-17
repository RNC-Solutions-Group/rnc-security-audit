"""Experiment report generation: compact Markdown and machine-readable JSON."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from .config import HarnessConfig, validate_raw_destination
from .safe_text import markdown_cell, markdown_code
from .util import atomic_write_bytes, atomic_write_text, sha256_bytes, utc_now

_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def report_stem(
    config: HarnessConfig,
    *,
    run_id: str,
    scanner: str,
    commit: str = "",
    profile: str = "",
    suites: list[str] | None = None,
) -> str:
    try:
        rendered = config.reports.naming.format(
            timestamp=run_id,
            scanner=scanner,
            commit=commit[:12],
            profile=profile,
            suites="-".join(suites or []),
            run_id=run_id,
        )
    except KeyError as exc:
        raise ValueError(f"unknown report naming placeholder: {exc}") from exc
    stem = _SAFE.sub("-", rendered).strip("-.")
    if not stem:
        raise ValueError("report naming convention produced an empty filename")
    return stem


def _unique_stem(directory: Path, stem: str) -> str:
    candidate = stem
    counter = 1
    while any((directory / f"{candidate}{suffix}").exists() for suffix in (".json", ".md")):
        counter += 1
        candidate = f"{stem}-{counter}"
    return candidate


def _metric_rows(suite: dict) -> list[tuple[str, str]]:
    labels = {
        "legacy_count_coverage_percent": "LEGACY COUNT COVERAGE %",
        "rich_detection_recall_percent": "rich line-truth recall %",
        "rich_precision_percent": "rich precision % (not claimed)",
        "rich_f1_percent": "rich F1 % (not claimed)",
        "true_positives": "true positives",
        "expected_secrets": "expected credentials",
        "false_positives": "false positives",
        "partial_matches": "partial matches",
        "duplicates": "duplicates",
        "precision_percent": "precision %",
        "recall_percent": "recall %",
        "f1_percent": "F1 %",
        "expected_count": "expected",
        "covered_count": "covered",
        "files_covered": "files covered",
        "rich_matched_count": "rich matched",
        "rich_missed_count": "rich missed",
        "rich_unexpected_count": "rich unexpected",
        "rich_duplicate_count": "rich duplicates",
        "value_verified_count": "value-verified",
        "line_only_count": "line-only",
        "scenario_passed": "scenarios passed",
        "scenario_total": "scenarios",
        "assertion_passed": "assertions passed",
        "assertion_total": "assertions",
        "unique_matched": "unique matched",
        "unique_expected": "unique expected",
        "occurrence_matched": "occurrences matched",
        "occurrence_expected": "occurrences expected",
        "history_score_status": "history score status",
        "history_expected_occurrences": "history expected occurrences",
        "history_matched_occurrences": "history matched occurrences",
        "history_missed_occurrences": "history missed occurrences",
        "history_unique_expected": "history unique expected",
        "history_unique_matched": "history unique matched",
        "history_unique_recall_percent": "history unique recall %",
        "history_occurrence_recall_percent": "history occurrence recall %",
        "history_unmatched_pending_review_count": "history unmatched pending",
        "history_unverified_evidence_count": "history unverified evidence",
        "history_informative_match_count": "history informative matches",
        "history_verified_false_positive_count": "history verified false positives",
    }
    metrics = suite.get("metrics") or {}
    rows: list[tuple[str, str]] = []
    for key in labels:
        value = metrics.get(key)
        if value is not None:
            rows.append((labels[key], str(value)))
    return rows


def compact_document(document: dict, *, exception_limit: int = 20) -> dict:
    """Trim bulky diagnostic dumps without dropping benchmark outcomes."""
    compact = copy.deepcopy(document)
    compact["compact"] = True
    compact["compaction"] = {
        "exception_limit": exception_limit,
        "omitted": [
            "full fixture test/assertion dumps",
            "full rich evaluation dumps",
            "large per-finding history dumps",
        ],
    }
    for suite in (compact.get("suites") or {}).values():
        details = suite.get("details") or {}
        exceptions = details.get("exceptions")
        if isinstance(exceptions, list):
            details["exception_count"] = len(exceptions)
            details["exceptions"] = exceptions[:exception_limit]
            details["exceptions_truncated"] = len(exceptions) > exception_limit
        for lane in (details.get("lanes") or {}).values():
            if not isinstance(lane, dict):
                continue
            rich = lane.get("rich")
            if isinstance(rich, dict):
                evaluations = rich.get("evaluations")
                if isinstance(evaluations, list):
                    rich["evaluation_count"] = len(evaluations)
                    rich.pop("evaluations", None)
            for key in ("findings", "tests", "assertions"):
                if isinstance(lane.get(key), list):
                    lane[f"{key}_count"] = len(lane[key])
                    lane[key] = lane[key][:exception_limit]
                    lane[f"{key}_truncated"] = (
                        lane[f"{key}_count"] > exception_limit
                    )
        for lane in (details.get("history_lanes") or {}).values():
            if not isinstance(lane, dict):
                continue
            history_score = lane.get("history")
            if isinstance(history_score, dict):
                evaluations = history_score.get("evaluations")
                if isinstance(evaluations, list):
                    history_score["evaluation_count"] = len(evaluations)
                    history_score["evaluations"] = evaluations[:exception_limit]
                    history_score["evaluations_truncated"] = (
                        len(evaluations) > exception_limit
                    )
                exceptions = history_score.get("exceptions")
                if isinstance(exceptions, list):
                    history_score["exception_count"] = len(exceptions)
                    history_score["exceptions"] = exceptions[:exception_limit]
                    history_score["exceptions_truncated"] = (
                        len(exceptions) > exception_limit
                    )
            if isinstance(lane.get("findings"), list):
                lane["finding_count"] = len(lane["findings"])
                lane["findings"] = lane["findings"][:exception_limit]
                lane["findings_truncated"] = lane["finding_count"] > exception_limit
    return compact


def _status_line(label: str, value) -> str:
    return f"| {label} | {value if value is not None else '—'} |"


def _code(value) -> str:
    return markdown_code(value if value is not None else "—")


def _md(value) -> str:
    return markdown_cell(value)


def _execution_section(document: dict) -> list[str]:
    provenance = document.get("execution_provenance") or {}
    policy = provenance.get("argument_policy") or (document.get("profile") or {}).get(
        "argument_policy"
    ) or {}
    invocations = provenance.get("scanner_invocations") or document.get("invocations") or []
    auxiliary = provenance.get("auxiliary_commands") or []
    if not provenance and not invocations:
        return []
    lines = [
        "## Scanner invocations: execution commands and effective configuration",
        "",
        "This section separates the command used to invoke the harness, the "
        "commands the harness executed against the scanner, and auxiliary "
        "operations.  The per-run command is the sanitized argument vector that "
        "was actually passed to the process; the normalized template is derived "
        "for display only.",
        "",
        "### Configuration comparability",
        "",
        "| Dimension | Value |",
        "| --- | --- |",
        f"| Detection configuration | {_md(policy.get('detection_configuration', 'UNKNOWN'))} |",
        f"| Execution/performance configuration | {_md(policy.get('execution_configuration', 'UNKNOWN'))} |",
        f"| Source scope | {_md(policy.get('source_scope_configuration', 'UNKNOWN'))} |",
        f"| Reporting configuration | {_md(policy.get('reporting_configuration', 'UNKNOWN'))} |",
        f"| Comparability | **{_md(policy.get('comparability', 'UNKNOWN'))}** |",
        f"| Baseline metrics included | {_md(policy.get('baseline_metrics_included'))} |",
        f"| Argument origin | {_md(policy.get('argument_origin', 'none'))} |",
    ]
    if policy.get("reasons"):
        lines.extend(["", "Comparability limitations:"])
        for reason in policy["reasons"]:
            lines.append(f"- {reason}")
    arguments = policy.get("arguments") or []
    lines.extend(
        [
            "",
            "### Explicit scanner overrides",
            "",
        ]
    )
    if arguments:
        lines.extend(
            [
                "| Flag | Category | Origin | Requested | Effective | Accepted | Baseline effect |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in arguments:
            per_run = [
                argument
                for invocation in invocations
                for argument in (invocation.get("supplied_arguments") or [])
                if argument.get("flag") == item.get("flag")
            ]
            effective = item.get("effective")
            if effective is None:
                effective = next(
                    (
                        argument.get("effective")
                        for argument in per_run
                        if argument.get("effective") is not None
                    ),
                    None,
                )
            effective_text = (
                effective
                if effective is not None
                else "not independently observable from retained artifact"
            )
            accepted_values = {argument.get("accepted") for argument in per_run}
            if accepted_values == {True}:
                accepted_text = f"yes ({len(per_run)} process completion(s))"
            elif False in accepted_values:
                accepted_text = "no (at least one process was not accepted)"
            else:
                accepted_text = "unverified"
            lines.append(
                f"| {_code(item.get('flag'))} | {_md(item.get('category'))} | "
                f"{_md(item.get('origin'))} | {_code(item.get('value') if item.get('value') is not None else '(switch)')} | "
                f"{_md(effective_text)} | {_md(accepted_text)} | "
                f"{'neutral to detection' if item.get('baseline_neutral') else 'may limit baseline comparability'} |"
            )
    else:
        lines.append(
            "No experiment-owned `--scanner-args` were supplied.  The scanner "
            "received only harness/adapter-generated arguments and its registered "
            "rules/configuration."
        )

    lines.extend(
        [
            "",
            "### Command templates by workload and phase",
            "",
            "Templates replace volatile target/report/workspace paths and run IDs. "
            "They are labels for grouping, not literal executed commands.",
            "",
            "| Suite | Workload | Phase | Runs | Invocation IDs | Normalized template |",
            "| --- | --- | --- | ---: | --- | --- |",
        ]
    )
    groups: dict[tuple[str, str, str, str], list[dict]] = {}
    for item in invocations:
        key = (
            str(item.get("suite") or ""),
            str(item.get("workload") or ""),
            str(item.get("phase") or item.get("invocation_type") or ""),
            str(item.get("command_template") or ""),
        )
        groups.setdefault(key, []).append(item)
    for (suite, workload, phase, template), items in groups.items():
        ids = ", ".join(str(item.get("invocation_id") or item.get("sequence")) for item in items)
        suite_label = suite or (
            "artifact-verification" if phase == "verification" else "none"
        )
        workload_label = workload or "none"
        lines.append(
            f"| {_code(suite_label)} | {_code(workload_label)} | {_md(phase)} | "
            f"{len(items)} | {_md(ids)} | {_code(template or 'not recorded')} |"
        )
    if not groups:
        lines.append("| — | — | — | 0 | — | no scanner invocation was launched |")

    lines.extend(
        [
            "",
            "### Per-run sanitized argv and evidence",
            "",
            "| Invocation | Phase | Status | Exit | Duration (s) | Report SHA-256 | Sanitized actual command |",
            "| --- | --- | --- | ---: | ---: | --- | --- |",
        ]
    )
    for item in invocations:
        rendered = (item.get("command_rendered") or {}).get("powershell")
        if not rendered:
            rendered = " ".join(str(token) for token in item.get("command") or [])
        lines.append(
            f"| {_code(item.get('invocation_id') or item.get('sequence'))} | "
            f"{_md(item.get('phase') or item.get('invocation_type'))} | "
            f"{_md(item.get('status'))} | {item.get('exit_code')} | "
            f"{item.get('duration_seconds')} | "
            f"{_code(item.get('report_sha256') or '—')} | {_code(rendered)} |"
        )
    if not invocations:
        lines.append("| — | — | NOT RUN | — | — | — | no scanner process was launched |")

    failures = [
        item
        for item in invocations
        if item.get("status") != "PASS" or item.get("timed_out") or item.get("error_code")
    ]
    lines.extend(["", "### Failed, skipped and blocked invocations", ""])
    if failures:
        lines.extend(
            [
                "| Invocation | Phase | Launched? | Status | Error |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in failures:
            lines.append(
                f"| {_code(item.get('invocation_id') or item.get('sequence'))} | "
                f"{_md(item.get('phase') or item.get('invocation_type'))} | "
                f"{'yes' if item.get('process_started') else 'no'} | "
                f"{_md(item.get('status'))} | {_md(item.get('error_code') or item.get('error_message') or '—')} |"
            )
    else:
        lines.append("No failed, skipped, or blocked scanner invocation was recorded.")
    if auxiliary:
        lines.extend(
            [
                "",
                "### Auxiliary harness operations (not scanner invocations)",
                "",
                "| Operation | Status | Exit | Command |",
                "| --- | --- | ---: | --- |",
            ]
        )
        for item in auxiliary:
            lines.append(
                f"| {_md(item.get('operation'))} | {_md(item.get('status'))} | "
                f"{item.get('exit_code')} | {_code(item.get('command_rendered') or ' '.join(item.get('command') or []))} |"
            )
    harness_command = provenance.get("harness_command") or {}
    if harness_command:
        lines.extend(
            [
                "",
                "Harness invocation (not a scanner command): "
                + _code(harness_command.get("rendered") or " ".join(harness_command.get("argv") or [])),
            ]
        )
    lines.append("")
    return lines


def render_markdown(document: dict) -> str:
    scanner = document.get("scanner") or {}
    source = document.get("source") or {}
    adapter = document.get("adapter") or {"key": scanner.get("key")}
    profile = document.get("profile") or {}
    summary = document.get("summary") or {}
    cleanup = document.get("cleanup") or {}
    registered = document.get("registered_build") or {}
    manifest = document.get("artifact_manifest") or {}
    lines = [
        "# Scanner Experiment Report",
        "",
        f"> **Outcome: {summary.get('overall', 'UNKNOWN')}**",
        "",
        "## Identity",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Scanner | {scanner.get('name') or scanner.get('key')} (`{scanner.get('key')}`) |",
        f"| Registered build | `{registered.get('id') or summary.get('build_id') or '—'}` |",
        f"| Scanner version | {scanner.get('version') or 'unavailable'} |",
        f"| Artifact manifest | `{manifest.get('path') or '—'}` |",
        f"| Artifact manifest SHA-256 | `{manifest.get('sha256') or '—'}` |",
        f"| Source commit (manifest metadata) | `{source.get('commit') or '—'}` |",
        f"| Source commit verification | NOT VERIFIED — operator-supplied metadata; no source checkout or build |",
        f"| Registered executable | `{registered.get('executable') or '—'}` |",
        f"| Registered executable SHA-256 | `{registered.get('executable_sha256') or '—'}` |",
        f"| Registered Docker image | `{registered.get('docker_image') or '—'}` |",
        f"| Registered Docker image ID | `{registered.get('docker_image_id') or '—'}` |",
        f"| Rules/configuration file | `{registered.get('rules_file') or '—'}` |",
        f"| Rules/configuration SHA-256 | `{registered.get('rules_sha256') or '—'}` |",
        f"| Adapter | `{adapter.get('key')}` / {adapter.get('name') or '—'} |",
        f"| Configuration profile | **{profile.get('name') or '—'}** |",
        f"| Configuration source | {profile.get('config_source') or '—'} |",
        f"| Configuration SHA-256 | `{profile.get('config_sha256') or '—'}` |",
        f"| Run ID | `{document.get('run_id')}` |",
        f"| Harness version | {document.get('harness_version')} |",
        f"| Generated (UTC) | {document.get('generated_at')} |",
        "",
        "The executed scanner identity is the operator-provided executable SHA-256 or "
        "Docker image ID above. The source commit is retained as operator metadata "
        "only; it is never acquired or compiled by this harness.",
        "",
        "## Configuration profile",
        "",
        "| Setting | Value |",
        "| --- | --- |",
    ]
    for key, value in (profile.get("applied_settings") or {}).items():
        lines.append(f"| {key} | {value} |")
    if profile.get("default_isolation"):
        lines.append(
            f"| default isolation | {json.dumps(profile['default_isolation'], sort_keys=True)} |"
        )
    if profile.get("limitations"):
        for item in profile["limitations"]:
            lines.append(f"- Limitation: {item}")
    lines.extend(["", "## Registered artifacts and products", "", "| Product | Kind | Status | Build ID | Version | Artifact identity | Verified |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for key, build in (document.get("builds") or {}).items():
        metadata = build.get("metadata") or {}
        identity = build.get("artifact_sha256") or build.get("image_id") or "—"
        verified = (
            metadata.get("executable_hash_verified")
            if build.get("platform", {}).get("kind") == "executable"
            else metadata.get("docker_image_id_verified")
        )
        lines.append(
            f"| `{key}` | {build.get('platform', {}).get('kind')} | "
            f"{build.get('status')} | `{metadata.get('build_id') or '—'}` | "
            f"{build.get('version') or 'unavailable'} | `{identity}` | {verified} |"
        )
    errors = [
        (key, build.get("error"))
        for key, build in (document.get("builds") or {}).items()
        if build.get("error")
    ]
    if errors:
        lines.append("")
        for key, error in errors:
            lines.append(f"- Artifact `{key}` problem: {error}")
    tools = (document.get("host") or {}).get("toolchain") or {}
    lines.extend(
        [
            "",
            f"Toolchain: Docker `{tools.get('docker') or 'unavailable'}`, Git `{tools.get('git') or 'unavailable'}`, Python `{tools.get('python') or 'unavailable'}`.",
            "",
            "## Benchmark outcomes",
            "",
            "| Suite | Outcome | Status | Baseline? | Metrics |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for key, suite in (document.get("suites") or {}).items():
        rows = _metric_rows(suite)
        rendered = "; ".join(f"{name}={value}" for name, value in rows[:7]) or "—"
        lines.append(
            f"| `{key}` | **{suite.get('outcome')}** | {suite.get('status')} | "
            f"{suite.get('baseline_metric')} | {rendered} |"
        )
    lines.extend(["", "### Product-level results", ""])
    for key, suite in (document.get("suites") or {}).items():
        lines.append(f"#### {key}")
        lines.append("")
        if suite.get("reason"):
            lines.append(f"- Reason: {suite['reason']}")
        for result in suite.get("results") or []:
            lines.append(
                f"- {result.get('dimension')} / `{result.get('platform')}`: "
                f"**{result.get('outcome')}** ({result.get('status')})"
                + (f" — {result.get('reason')}" if result.get("reason") else "")
            )
        for platform, target in (suite.get("targets") or {}).items():
            lines.append(
                f"- target `{platform}`: **{target.get('status')}**"
                + (f" — {target.get('reason')}" if target.get("reason") else "")
            )
        for limitation in suite.get("limitations", []):
            lines.append(f"- Limitation: {limitation}")
        lines.append("")
    detection = document.get("detection") or {}
    if detection:
        levain = detection.get("levain") or {}
        leaky = detection.get("leaky_filesystem") or {}
        legacy = leaky.get("legacy_count_coverage") or {}
        rich = leaky.get("rich_line_truth") or {}
        history = detection.get("leaky_history") or {}
        lab = ((detection.get("rnclab") or {}).get("filesystem") or {})
        lines.extend(
            [
                "## Detection summary",
                "",
                "| Benchmark | Result |",
                "| --- | --- |",
                f"| Synthetic filesystem | matched={detection.get('synthetic_filesystem', {}).get('matched_count')}/{detection.get('synthetic_filesystem', {}).get('expected_count')} |",
                f"| Synthetic history | unique={detection.get('synthetic_history', {}).get('unique_matched')}/{detection.get('synthetic_history', {}).get('unique_expected')}, occurrences={detection.get('synthetic_history', {}).get('occurrence_matched')}/{detection.get('synthetic_history', {}).get('occurrence_expected')} |",
                f"| Levain | TP={levain.get('true_positives')}, FP={levain.get('false_positives')}, precision={levain.get('precision_percent')}, recall={levain.get('recall_percent')}, F1={levain.get('f1_percent')} |",
                f"| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** {legacy.get('covered_count')}/{legacy.get('expected_count')} ({legacy.get('coverage_percent')}%), rich line-truth matched={rich.get('matched_count')}/{rich.get('expected_count')} |",
                f"| Leaky Repo history | {'**SCORED**' if history.get('scored') else '**UNSCORED**'} — truth={history.get('truth_status')}, execution={history.get('execution_status')}, occurrences={history.get('matched_occurrences')}/{history.get('expected_occurrences')}, unique={history.get('unique_matched')}/{history.get('unique_expected')}, recall={history.get('occurrence_recall_percent')}%, pending={history.get('unmatched_pending_review_count')}, unverified={history.get('unverified_evidence_count')} |",
                f"| RNC Lab v3 filesystem | TP={lab.get('true_positive_occurrences')}/{lab.get('expected_positives')}, unique={lab.get('unique_groups_matched')}/{lab.get('expected_unique_groups')}, recall={lab.get('occurrence_recall_percent')}%, duplicates={lab.get('duplicate_count')}, near-misses={lab.get('near_miss_count')} ({lab.get('near_miss_target_count')} targets), unverified={lab.get('unverified_evidence_count')}, pending={lab.get('unmatched_pending_review_count')}, FP alerts={lab.get('verified_false_positive_alert_count')}, precision=NOT CERTIFIED |",
                f"| RNC Lab v3 Git | {'supported' if (detection.get('rnclab', {}).get('git', {}) or {}).get('supported') else 'NOT_APPLICABLE'}; lane details in JSON |",
                "",
                "Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth "
                "reports detection only; precision/F1 remain unavailable without a negative oracle. "
                "Leaky history is scored only against the owner-approved source oracle; its reviewed "
                "negatives are not exhaustive, so precision/F1 are not certified. Unmatched and "
                "unverified findings remain in the investigation ledger.",
                "",
            ]
        )
    perf = document.get("performance") or {}
    lines.extend(["## Performance (separate from detection)", ""])
    if perf.get("products"):
        methodology = perf.get("methodology") or {}
        workloads = (perf.get("workload") or {}).get("items") or []
        lines.extend(
            [
                "Canonical plan: "
                f"{methodology.get('warmups')} warm-up(s), "
                f"{methodology.get('measured_runs')} measured run(s); "
                f"load plan: 1 warm-up, 3 measured runs; "
                f"environment={methodology.get('environment_mode')}, "
                f"stress={methodology.get('stress_profile')}.",
                "",
                "Workloads: "
                + ", ".join(
                    f"`{item.get('key')}` ({item.get('files')} files / "
                    f"{item.get('bytes')} bytes)"
                    for item in workloads
                ),
                "",
                "| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability | Measured invocation IDs |",
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
            ]
        )
        for item in perf["products"]:
            platform = item.get("product", {}).get("platform")
            workload_key = item.get("workload_key") or "leaky-repo-filesystem"
            if item.get("status") == "BLOCKED":
                lines.append(
                    f"| `{platform}` | `{workload_key}` | BLOCKED | — | — | — | — | — | — | — |"
                )
                continue
            total = item.get("summary") or {}
            runtime = total.get("runtime_seconds") or {}
            cpu = (total.get("cpu_total_seconds") or {}).get("median")
            memory = (total.get("peak_memory_bytes") or {}).get("max")
            invocation_ids = [
                str(run.get("invocation_id"))
                for run in (item.get("runs") or [])
                if run.get("phase") == "measured" and run.get("invocation_id")
            ]
            lines.append(
                f"| `{platform}` | `{workload_key}` | {runtime.get('median')} | "
                f"{runtime.get('minimum')}/{runtime.get('maximum')} | "
                f"{runtime.get('coefficient_of_variation')} | "
                f"{cpu if cpu is not None else 'unavailable'} | "
                f"{round(memory / 1048576, 2) if memory else 'unavailable'} | "
                f"{total.get('files_inspected')}/{total.get('files_eligible')} | "
                f"{total.get('stability')} | "
                f"{_md(', '.join(invocation_ids) or 'not recorded')} |"
            )
        lines.append("")
        scaling = [
            item
            for item in perf["products"]
            if item.get("load_profile") and item.get("scaling")
        ]
        if scaling:
            lines.extend(
                [
                    "### RNC Lab load scaling",
                    "",
                    "| Product | Profile | Files | Bytes | Runtime scaling | Memory scaling | Accuracy scored |",
                    "| --- | --- | ---: | ---: | ---: | ---: | --- |",
                ]
            )
            for item in scaling:
                workload = item.get("workload") or {}
                scale = item.get("scaling") or {}
                lines.append(
                    f"| `{item['product']['platform']}` | `{item.get('load_profile')}` | "
                    f"{workload.get('files')} | {workload.get('bytes')} | "
                    f"{scale.get('runtime_scaling')} | {scale.get('memory_scaling')} | "
                    f"false (performance only) |"
                )
        lines.append("")
        for item in perf["products"]:
            for run in item.get("runs") or []:
                if run.get("phase") == "measured":
                    lines.append(
                        f"- `{item['product']['platform']}` "
                        f"`{item.get('workload_key') or 'workload'}` run "
                        f"{run.get('run_index')} "
                        f"(invocation `{run.get('invocation_id') or 'not recorded'}`): "
                        f"{run.get('duration_seconds')} s, "
                        f"exit={run.get('exit_code')}, telemetry={run.get('telemetry_method')}"
                    )
    else:
        lines.append(
            f"Not available: {perf.get('reason') or 'no performance measurement'}"
        )
    lines.extend(_execution_section(document))
    lines.extend(["", "## Cleanup", ""])
    lines.append(f"- Status: **{cleanup.get('status', 'UNKNOWN')}**")
    lines.append(f"- Retained by request: {cleanup.get('retained', False)}")
    for action in cleanup.get("actions") or []:
        lines.append(f"- {action}")
    for failure in cleanup.get("failures") or []:
        lines.append(f"- Failure: {failure}")
    errors = []
    for key, suite in (document.get("suites") or {}).items():
        for exception in (suite.get("details") or {}).get("exceptions") or []:
            errors.append((key, exception))
    if errors:
        lines.extend(
            [
                "",
                "## Exceptions",
                "",
                "| Suite | Dimension | Classification | Path | Reason |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for key, exception in errors[:100]:
            lines.append(
                f"| `{key}` | {exception.get('dimension') or 'filesystem'} | "
                f"{exception.get('classification')} | "
                f"{exception.get('path') or '—'} | {exception.get('reason') or ''} |"
            )
    if document.get("diagnostics"):
        lines.extend(["", "## Diagnostics", "", "```", str(document["diagnostics"].get("traceback", ""))[-4000:], "```"])
    lines.extend(["", "## Limitations", ""])
    for limitation in document.get("limitations") or []:
        lines.append(f"- {limitation}")
    lines.extend(
        [
            "",
            "Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.",
            "Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.",
            "",
        ]
    )
    return "\n".join(lines)


def render_console(document: dict) -> str:
    scanner = document.get("scanner") or {}
    source = document.get("source") or {}
    summary = document.get("summary") or {}
    profile = document.get("profile") or {}
    registered = document.get("registered_build") or {}
    lines = [
        f"Scanner: {scanner.get('key')} {scanner.get('version') or '(version unavailable)'}",
        f"Build:   {registered.get('id') or summary.get('build_id') or 'unknown'}",
        f"Source:  {source.get('commit')} (manifest metadata; not checked out)",
        (
            "Artifact:"
            + (
                f" exe {registered.get('executable')} sha256={registered.get('executable_sha256')}"
                if registered.get("executable")
                else ""
            )
            + (
                f" image {registered.get('docker_image')} id={registered.get('docker_image_id')}"
                if registered.get("docker_image")
                else ""
            )
        ),
        f"Profile: {profile.get('name') or 'unknown'}  config={profile.get('config_sha256') or 'registered default'}",
        "Artifacts:  "
        + ", ".join(
            f"{key}={value['status']}" for key, value in (document.get("builds") or {}).items()
        ),
        "Suites:",
    ]
    for key, suite in (document.get("suites") or {}).items():
        rows = _metric_rows(suite)
        rendered = ", ".join(f"{name}={value}" for name, value in rows[:5])
        lines.append(
            f"  {key:16} {suite.get('status'):14} "
            f"{(suite.get('outcome') or 'UNKNOWN'):22} {rendered}"
        )
    performance = document.get("performance") or {}
    for item in performance.get("products") or []:
        label = (
            f"{item.get('product', {}).get('platform')}/"
            f"{item.get('workload_key') or 'workload'}"
        )
        if item.get("status") == "BLOCKED":
            lines.append(f"  perf {label}: BLOCKED")
        else:
            runtime = (item.get("summary") or {}).get("runtime_seconds") or {}
            lines.append(
                f"  perf {label}: median={runtime.get('median')}s "
                f"stability={(item.get('summary') or {}).get('stability')}"
            )
    cleanup = document.get("cleanup") or {}
    counts = summary.get("counts") or {}
    lines.append(
        "Totals:  "
        + ", ".join(
            f"{name}={counts.get(name, 0)}"
            for name in ("pass", "fail", "blocked", "not_run", "not_applicable")
        )
    )
    lines.append(f"Cleanup: {cleanup.get('status')} retained={cleanup.get('retained')}")
    lines.append(f"Invocations: {summary.get('invocation_count', len(document.get('invocations') or []))}")
    lines.append(f"Overall: {summary.get('overall')}")
    reports = document.get("reports") or {}
    if reports.get("sanitized"):
        lines.append("Report:  " + ", ".join(reports["sanitized"]))
    return "\n".join(lines)


def write_experiment_reports(
    document: dict,
    config: HarnessConfig,
    *,
    run_id: str,
    scanner: str,
    commit: str,
    profile: str,
    suites: list[str],
    raw_artifacts: list[dict] | None = None,
) -> dict:
    raw_artifacts = raw_artifacts or []
    sanitized_paths: list[str] = []
    output_dir = config.reports.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = report_stem(
        config,
        run_id=run_id,
        scanner=scanner,
        commit=commit,
        profile=profile,
        suites=suites,
    )
    stem = _unique_stem(output_dir, stem)
    if config.reports.sanitized:
        if "json" in config.reports.formats:
            sanitized_paths.append(str(output_dir / f"{stem}.json"))
        if "markdown" in config.reports.formats:
            sanitized_paths.append(str(output_dir / f"{stem}.md"))
    raw_path = (
        str(config.reports.raw_output_dir / stem)
        if config.reports.raw and raw_artifacts
        else None
    )
    document["reports"] = {"sanitized": list(sanitized_paths), "raw": raw_path}
    if config.reports.sanitized:
        if "json" in config.reports.formats:
            atomic_write_text(
                output_dir / f"{stem}.json",
                json.dumps(document, indent=2, sort_keys=True) + "\n",
            )
        if "markdown" in config.reports.formats:
            atomic_write_text(output_dir / f"{stem}.md", render_markdown(document))
    if config.reports.raw and raw_artifacts:
        validate_raw_destination(config)
        raw_dir = config.reports.raw_output_dir / stem
        raw_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "run_id": run_id,
            "generated_at": utc_now(),
            "scanner": document.get("scanner"),
            "source": document.get("source"),
            "warning": "Raw scanner output may contain synthetic secret-shaped values. It is not printed to the console.",
            "artifacts": [],
        }
        for index, artifact in enumerate(raw_artifacts, 1):
            data = artifact.get("data")
            if not isinstance(data, (bytes, bytearray)):
                continue
            name = _SAFE.sub("-", str(artifact.get("name") or f"artifact-{index}")).strip("-.")
            if not name:
                name = f"artifact-{index}"
            path = raw_dir / name
            atomic_write_bytes(path, bytes(data))
            manifest["artifacts"].append(
                {
                    "name": name,
                    "sha256": sha256_bytes(bytes(data)),
                    "bytes": len(data),
                    "content_type": artifact.get("content_type", "application/octet-stream"),
                }
            )
        atomic_write_text(
            raw_dir / "manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        )
    return {"sanitized": sanitized_paths, "raw": raw_path}


def write_matrix_reports(
    document: dict,
    config: HarnessConfig,
    *,
    run_id: str,
    suites: list[str],
    raw_artifacts: list[dict] | None = None,
) -> dict:
    """Compatibility writer for the synthetic-validation report document."""
    source = document.get("source") or {}
    return write_experiment_reports(
        document,
        config,
        run_id=run_id,
        scanner=(document.get("scanner") or {}).get("key", "synthetic"),
        commit=source.get("commit") or "0" * 40,
        profile=(document.get("profile") or {}).get("name", "synthetic"),
        suites=suites,
        raw_artifacts=raw_artifacts,
    )
