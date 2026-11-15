"""Redacted human- and machine-readable reports.

No report contains a matched credential, an expected secret value, or a raw
scanner report. Only locations, rule identifiers, hashes, and counts are kept.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from . import SCENARIO_VERSION, __version__
from . import scope as scope_module
from .dataset import CorpusBundle, PreparedDataset
from .scoring import RunResult, overall_status
from .util import (
    atomic_write_text,
    display_path,
    platform_summary,
    utc_now,
)

_FAILURE_STATUSES = {
    "INVOCATION_FAILED",
    "TIMEOUT",
    "REPORT_MISSING",
    "REPORT_INVALID",
    "BINARY_NOT_FOUND",
    "NOT_RUN_UNSCORABLE",
    "NOT_RUN",
    "COVERAGE_UNVERIFIED",
}


def _run_document(
    result: RunResult,
    target_dir: Path,
    report_path: Path,
) -> dict:
    invocation = result.invocation
    binary_display = display_path(invocation.binary_path)
    display = [
        argument.replace(str(report_path), "<report>")
        .replace(str(target_dir), "<corpus-dir>")
        .replace(invocation.binary_path, binary_display)
        for argument in invocation.argv
    ]
    return {
        "corpus": result.corpus,
        "status": result.status,
        "scored": result.results is not None,
        "notes": list(result.notes),
        "control": asdict(result.control) if result.control else None,
        "coverage": result.coverage,
        "unattributed_files": list(result.unattributed),
        "invocation": {
            "argv": display,
            "mode": invocation.mode,
            "exit_code": invocation.exit_code,
            "timed_out": invocation.timed_out,
            "timeout_seconds": invocation.timeout_seconds,
            "duration_seconds": invocation.duration_seconds,
            "stdout_sha256": invocation.stdout_sha256,
            "stdout_bytes": len(invocation.stdout),
            "stderr_sha256": invocation.stderr_sha256,
            "stderr_bytes": len(invocation.stderr),
            "stderr_summary": "[stderr present; raw content withheld]" if invocation.stderr else "",
            "report_sha256": invocation.report_sha256,
            "report_bytes": len(invocation.report_bytes) if invocation.report_bytes is not None else None,
            "error_code": invocation.error_code,
            "error_message": invocation.error_message,
        },
        "control": asdict(result.control) if result.control else None,
        "results": result.results,
    }


def build_report(
    prepared: PreparedDataset,
    corpora: CorpusBundle,
    runs: list[RunResult],
    *,
    scanner_kind: str,
    source_revision: str | None,
    config_path: Path | None,
    config_sha256: str | None,
    extra_limitations: tuple[str, ...] = (),
    raw_artifacts_retained: bool = False,
) -> dict:
    overall = overall_status(runs)
    if scanner_kind == "stub":
        integration = "STUB_VALIDATION_ONLY"
        detection = "NOT_A_GITLEAKS_MEASUREMENT"
    elif overall in _FAILURE_STATUSES:
        integration = "BLOCKED"
        detection = "NOT_MEASURED"
    else:
        integration = "EXECUTED"
        detection = "MEASURED"

    limitations = [
        "Only the CP1 detection lane is implemented; functional conformance, "
        "performance, and Go race testing are not part of this report.",
        "The corpus is synthetic and finite; it does not measure real-world "
        "repository or credential prevalence.",
        "Negative-corpus true negatives are not inferred from line counts; the "
        "oracle is 'expected secrets are zero'.",
        "Three hard-tier credentials are reported separately and are not included in "
        "the core recall percentage.",
        "Partial, ambiguous, and line-only findings are not credited as true "
        "positives; they are reported separately.",
    ]
    if scanner_kind == "stub":
        limitations.insert(
            0,
            "The scanner used for this report is a controlled test double, not "
            "Gitleaks. The counts below validate the harness and must not be read "
            "as Gitleaks detection accuracy.",
        )
    else:
        limitations.append(
            "The real Gitleaks CLI and JSON parser were exercised at the pinned "
            "source revision; other versions and configurations are untested."
        )
    limitations.append(
        "Detection-scope annotation is a conservative manual mapping to the pinned "
        "default rule IDs, not a scanner result; it does not alter TP/FN counts."
    )
    if source_revision is None:
        limitations.append("No target Gitleaks source revision was supplied.")
    limitations.extend(extra_limitations)

    documents = []
    for run in runs:
        report_path = Path(run.invocation.report_path)
        target_dir = Path(
            run.invocation.argv[2] if run.invocation.mode == "dir" else run.invocation.argv[3]
        )
        documents.append(_run_document(run, target_dir, report_path))

    summary = {
        "overall_status": overall,
        "gitleaks_integration": integration,
        "gitleaks_execution": "BLOCKED" if scanner_kind == "stub" or integration == "BLOCKED" else "EXECUTED",
        "detection_accuracy": detection,
        "scanner_kind": scanner_kind,
        "runs": len(runs),
        "scored_runs": sum(1 for run in runs if run.results is not None),
        "failed_or_unscored_runs": sum(1 for run in runs if run.results is None),
    }

    config_mode = "builtin-default" if config_path is None else "file"
    positive = next(
        (run for run in runs if run.corpus == "positive" and run.results is not None),
        None,
    )
    if scanner_kind != "gitleaks":
        detection_scope = {
            "available": False,
            "config_mode": config_mode,
            "reason": "scope annotation applies only to real Gitleaks runs",
            "out_of_scope": [],
            "unknown": [],
            "in_scope_misses": [],
            "counts": {"out_of_scope": 0, "unknown": 0, "in_scope": 0},
        }
    elif positive is not None:
        detection_scope = scope_module.summarize(
            positive.results["missed_secrets"], config_mode
        )
    else:
        detection_scope = {
            "available": False,
            "config_mode": config_mode,
            "reason": "positive corpus was not scored",
            "out_of_scope": [],
            "unknown": [],
            "in_scope_misses": [],
            "counts": {"out_of_scope": 0, "unknown": 0, "in_scope": 0},
        }

    return {
        "schema_version": 1,
        "report_type": "gitleaks-scan-harness/detection",
        "harness_version": __version__,
        "scenario_version": SCENARIO_VERSION,
        "generated_at": utc_now(),
        "scope": {
            "lane": "detection_accuracy",
            "functional_conformance": "NOT_RUN",
            "performance": "NOT_RUN",
            "race_stability": "NOT_TESTED",
        },
        "summary": summary,
        "environment": platform_summary(),
        "dataset": {
            "name": prepared.spec.name,
            "source_repository": prepared.spec.source_repository,
            "author_reference": prepared.spec.author_reference,
            "license": prepared.spec.license,
            "license_url": prepared.spec.license_url,
            "license_sha256": prepared.spec.license_sha256,
            "license_notice": prepared.spec.license_notice,
            "revision": prepared.spec.revision,
            "tag": prepared.spec.revision_tag,
            "revision_date": prepared.spec.revision_date,
            "manifest_sha256": prepared.manifest_sha256,
            "artifact_sha256": prepared.artifact_hashes,
            "derived_sha256": prepared.derived_hashes,
            "negative_counts": corpora.negative_counts,
            "positive_counts": corpora.positive_counts,
            "counting_unit": prepared.spec.counting_unit,
        },
        "target": {
            "scanner_kind": scanner_kind,
            "binary_path": display_path(runs[0].invocation.binary_path) if runs else None,
            "binary_sha256": runs[0].invocation.binary_sha256 if runs else None,
            "source_revision": source_revision,
            "mode": runs[0].invocation.mode if runs else None,
            "integration_status": integration,
            "gitleaks_execution": "BLOCKED" if scanner_kind == "stub" or integration == "BLOCKED" else "EXECUTED",
        },
        "config": {
            "path": display_path(config_path) if config_path else None,
            "sha256": config_sha256,
            "mode": config_mode,
        },
        "detection_scope": detection_scope,
        "redaction": {
            "raw_matches_omitted": True,
            "raw_scanner_report_retained": raw_artifacts_retained,
            "expected_secret_values_omitted": True,
        },
        "runs": documents,
        "limitations": limitations,
    }


def _status_badge(status: str) -> str:
    return "**%s**" % status


def _results_negative(results: dict) -> list[str]:
    lines = [
        "| Metric | Value |",
        "| --- | --- |",
        f"| Sections scanned | {results['sections_scanned']} |",
        f"| Expected credentials | {results['expected_secrets']} |",
        f"| Findings parsed | {results['findings_total']} |",
        f"| False positives | {results['false_positives']} |",
        f"| Duplicate findings | {results['duplicates']} |",
        f"| Personal-data matches (not counted) | {results['personal_data_matches']} |",
        f"| Findings without extracted evidence | {results['findings_without_evidence']} |",
        f"| Sections tripped | {results['sections_tripped']} |",
        f"| Clean | {'yes' if results['clean'] else 'no'} |",
        "",
        "True negatives are **not** inferred from line counts; this corpus has no "
        "per-line oracle. A clean run means no unexpected finding was reported.",
    ]
    if results["worst_sections"]:
        lines.extend(["", "| Section | Findings |", "| --- | --- |"])
        for item in results["worst_sections"]:
            lines.append(f"| {item['section']} | {item['findings']} |")
    return lines


def _results_positive(results: dict) -> list[str]:
    lines = [
        "| Metric | Value |",
        "| --- | --- |",
        f"| Sections scanned | {results['sections_scanned']} |",
        f"| Expected credentials | {results['expected_secrets']} "
        f"({results['expected_core']} core, {results['expected_hard']} hard) |",
        f"| True positives | {results['true_positives']} |",
        f"| False negatives | {results['false_negatives']} |",
        f"| Core recall | {results['core_recall_percent']}% |",
        f"| Hard recall | {results['hard_recall_percent']}% |",
        f"| Overall recall | {results['overall_recall_percent']}% |",
        f"| Unexpected findings | {results['unexpected_findings']} |",
        f"| Partial matches (not credited) | {results['partial_matches']} |",
        f"| Ambiguous findings (not credited) | {results['ambiguous_findings']} |",
        f"| False positives | {results['false_positives']} |",
        f"| Duplicate findings | {results['duplicates']} |",
        f"| Personal-data matches (not counted) | {results['personal_data_matches']} |",
        f"| Findings without extracted evidence | {results['findings_without_evidence']} |",
    ]
    classification = results.get("match_classification", {})
    if classification:
        lines.extend(
            [
                "",
                "| Match classification | Count |",
                "| --- | --- |",
                f"| Complete | {classification['complete']} |",
                f"| Normalized | {classification['normalized']} |",
                f"| Partial (uncredited, included in FN) | {classification['partial']} |",
                f"| Ambiguous findings (not target buckets) | {classification['ambiguous']} |",
                f"| Ordinary miss | {classification['miss']} |",
            ]
        )
        accounting = results.get("target_accounting") or {}
        if accounting:
            lines.extend(
                [
                    "",
                    f"Target accounting: expected={accounting.get('expected')}, "
                    f"TP={accounting.get('true_positives')}, "
                    f"FN={accounting.get('false_negatives')} "
                    f"(ordinary={accounting.get('ordinary_misses')}, "
                    f"partial={accounting.get('partial_uncredited')}); "
                    f"reconciled={accounting.get('reconciled')}.",
                ]
            )
    if results["missed_secrets"]:
        lines.extend(
            [
                "",
                "Missed credentials (kind only; values omitted):",
                "",
                "| Section | Kind | Tier | Classification | Partial evidence |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in results["missed_secrets"][:30]:
            lines.append(
                f"| {item['section']} | {item['kind']} | {'hard' if item['hard'] else 'core'} | "
                f"{item.get('classification', 'miss')} | {item.get('partial_evidence', 0)} |"
            )
        if len(results["missed_secrets"]) > 30:
            lines.append(f"| ... | {len(results['missed_secrets']) - 30} more | ... | ... | ... |")
    if results.get("partial_match_details"):
        lines.extend(
            [
                "",
                "Partial matches (locations only; not credited):",
                "",
                "| Section | Line | Rule | Candidate kinds | Relation |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for item in results["partial_match_details"][:20]:
            lines.append(
                f"| {item['section']} | {item['line'] if item['line'] is not None else '?'} | "
                f"{item['rule_id'] or '?'} | {', '.join(item['candidate_kinds'])} | "
                f"{', '.join(item['relations'])} |"
            )
    if results.get("ambiguous_match_details"):
        lines.extend(
            [
                "",
                "Ambiguous findings (multiple candidate credentials; not credited):",
                "",
                "| Section | Line | Rule | Candidate kinds |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in results["ambiguous_match_details"][:20]:
            lines.append(
                f"| {item['section']} | {item['line'] if item['line'] is not None else '?'} | "
                f"{item['rule_id'] or '?'} | {', '.join(item['candidate_kinds'])} |"
            )
    if results["examples"]:
        lines.extend(["", "Unexpected findings (locations only):", "", "| Section | Line | Rule |", "| --- | --- | --- |"])
        for item in results["examples"]:
            lines.append(
                f"| {item['section']} | {item['line'] if item['line'] is not None else '?'} | {item['rule_id'] or '?'} |"
            )
    return lines


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    stub = summary["scanner_kind"] == "stub"
    lines: list[str] = [
        "# Gitleaks Scan Harness — Detection Report",
        "",
        "> **HARNESS VALIDATION REPORT.**" if stub else "> **DETECTION REPORT.**",
        "",
        "This file contains no raw matched values, no expected secret text, and no raw scanner report.",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Overall status | {_status_badge(summary['overall_status'])} |",
        f"| Gitleaks integration | {summary['gitleaks_integration']} |",
        f"| Gitleaks execution | {summary.get('gitleaks_execution', 'UNKNOWN')} |",
        f"| Detection accuracy | {summary['detection_accuracy']} |",
        f"| Scanner kind | {summary['scanner_kind']} |",
        f"| Harness / scenario | {report['harness_version']} / {report['scenario_version']} |",
        f"| Generated (UTC) | {report['generated_at']} |",
        "",
    ]
    if stub:
        lines.extend(
            [
                "## Scope warning",
                "",
                "The scanner used here is a **controlled test double**, not Gitleaks. "
                "The numbers demonstrate the harness's acquisition, execution, scoring, "
                "failure detection, and reporting paths. **They are not Gitleaks "
                "benchmark results.**",
                "",
            ]
        )
    lines.extend(["## Dataset", "", "| Field | Value |", "| --- | --- |"])
    dataset = report["dataset"]
    for label, key in [
        ("Name", "name"),
        ("Source", "source_repository"),
        ("Revision", "revision"),
        ("Tag", "tag"),
        ("License", "license"),
        ("Manifest SHA-256", "manifest_sha256"),
        ("Counting unit", "counting_unit"),
    ]:
        lines.append(f"| {label} | {dataset[key]} |")
    lines.extend(
        [
            "",
            "| Corpus | Sections | Lines | Credentials | Hard sections |",
            "| --- | --- | --- | --- | --- |",
            f"| Negative | {dataset['negative_counts']['sections']} | "
            f"{dataset['negative_counts']['lines']} | 0 | 0 |",
            f"| Positive | {dataset['positive_counts']['sections']} | "
            f"{dataset['positive_counts']['lines']} | {dataset['positive_counts']['secrets']} | "
            f"{dataset['positive_counts']['hard_sections']} |",
            "",
        ]
    )

    target = report["target"]
    lines.extend(
        [
            "## Target",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Scanner kind | {target['scanner_kind']} |",
            f"| Binary path | `{target['binary_path']}` |",
            f"| Binary SHA-256 | `{target['binary_sha256']}` |",
            f"| Gitleaks source revision | {target['source_revision'] or 'not supplied'} |",
            f"| Integration status | {target['integration_status']} |",
            f"| Scan mode | {target['mode']} |",
            f"| Configuration mode | {report['config']['mode']} |",
            f"| Configuration path | {report['config']['path'] or 'built-in default'} |",
            f"| Configuration SHA-256 | {report['config']['sha256'] or 'not applicable'} |",
            "",
        ]
    )

    lines.extend(["## Execution", ""])
    for run in report["runs"]:
        invocation = run["invocation"]
        control = run["control"]
        lines.extend(
            [
                f"### {run['corpus'].capitalize()} corpus",
                "",
                "| Field | Value |",
                "| --- | --- |",
                f"| Status | {_status_badge(run['status'])} |",
                f"| Command | `{' '.join(invocation['argv'])}` |",
                f"| Exit code | {invocation['exit_code']} |",
                f"| Timed out | {'yes' if invocation['timed_out'] else 'no'} |",
                f"| Timeout limit (s) | {invocation['timeout_seconds']} |",
                f"| Duration (s) | {invocation['duration_seconds']} |",
                f"| Positive control reported | "
                f"{'yes' if control and control['reported'] else 'no'} |",
                f"| Control file encountered | "
                f"{'yes' if control and control['file_encountered'] else 'no'} |",
                f"| Control findings on file | {control['findings_on_file'] if control else 0} |",
                f"| Control credential findings | {control['credential_findings'] if control else 0} |",
                f"| Control kinds detected | "
                f"{', '.join(control['kinds_detected']) if control and control['kinds_detected'] else 'none'} |",
                f"| Control kinds echoed in raw output | "
                f"{', '.join(control['kinds_echoed']) if control and control['kinds_echoed'] else 'none'} |",
                f"| Unmatched control-file findings | {control['unmatched_findings'] if control else 0} |",
                f"| Scanner report SHA-256 | `{invocation['report_sha256']}` |",
                f"| Stderr (redacted) | {invocation['stderr_summary'] or '(empty)'} |",
                "",
            ]
        )
        if run["notes"]:
            lines.extend([f"- {note}" for note in run["notes"]])
            lines.append("")
        results = run["results"]
        if results is None:
            lines.extend(["**Not scored.** The run did not produce a trustworthy report.", ""])
            continue
        if run["corpus"] == "negative":
            lines.extend(_results_negative(results))
        else:
            lines.extend(_results_positive(results))
        lines.append("")

    scope = report.get("detection_scope", {})
    if scope.get("available"):
        lines.extend(
            [
                "## Detection scope",
                "",
                "Scope annotation is separate from TP/FN scoring and applies only to the "
                "pinned default configuration. It is a conservative manual mapping to the "
                "default rule IDs, not a scanner result.",
                "",
                "| Scope class | Missed cases |",
                "| --- | --- |",
                f"| Out of scope | {scope['counts']['out_of_scope']} |",
                f"| Unknown | {scope['counts']['unknown']} |",
                f"| In scope but missed | {scope['counts']['in_scope']} |",
            ]
        )
        if scope["out_of_scope"]:
            lines.extend(
                [
                    "",
                    "Out-of-scope cases:",
                    "",
                    "| Section | Kind | Basis |",
                    "| --- | --- | --- |",
                ]
            )
            for item in scope["out_of_scope"]:
                lines.append(f"| {item['section']} | {item['kind']} | {item['basis']} |")
        if scope["unknown"]:
            lines.extend(
                [
                    "",
                    "Unknown-scope cases:",
                    "",
                    "| Section | Kind | Basis |",
                    "| --- | --- | --- |",
                ]
            )
            for item in scope["unknown"]:
                lines.append(f"| {item['section']} | {item['kind']} | {item['basis']} |")
        if scope["in_scope_misses"]:
            lines.extend(
                [
                    "",
                    "In-scope cases still missed:",
                    "",
                    "| Section | Kind | Tier |",
                    "| --- | --- | --- |",
                ]
            )
            for item in scope["in_scope_misses"]:
                lines.append(
                    f"| {item['section']} | {item['kind']} | {'hard' if item['hard'] else 'core'} |"
                )
        lines.append("")

    lines.extend(["## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            "```sh",
            "python -m harness prepare",
            "python -m harness run --gitleaks <path-to-gitleaks> --corpus both \\",
            "  --gitleaks-source-revision <40-char-sha> --out-dir reports --name <name>",
            "```",
            "",
            "The scan target directory and raw report are temporary. See "
            "`docs/checkpoints/CP1A-report.md` for the CP1A checkpoint record.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(report: dict, out_dir: Path, name: str) -> tuple[Path, Path]:
    out_dir = Path(out_dir)
    json_path = out_dir / f"{name}.json"
    markdown_path = out_dir / f"{name}.md"
    atomic_write_text(json_path, json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    atomic_write_text(markdown_path, render_markdown(report))
    return json_path, markdown_path
