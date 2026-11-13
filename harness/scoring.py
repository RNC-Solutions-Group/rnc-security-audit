"""Deterministic scoring of scanner findings against a frozen answer key.

Counting units are explicit per corpus:

* negative corpus: one section is one format; the expected secret count is zero.
  Every finding that does not match a listed personal-data span is a false
  positive. `true_negatives` is not derived from line counts and is `null`.
* positive corpus: one planted credential is one case. A credential is credited
  only by a complete or supported normalized match of extracted evidence. A
  partial match, a line-only finding, or an ambiguous finding satisfies no case.
  Each finding can satisfy at most one planted credential.

Raw matched strings never leave this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import control as control_module
from .errors import DatasetError
from .matching import COMPLETE, NORMALIZED, PARTIAL, best_match
from .model import ControlResult, Finding, Section
from .util import basename


@dataclass(frozen=True)
class ScanTarget:
    directory: Path
    corpus: str
    index: dict[str, Section]
    control: bool


@dataclass(frozen=True)
class RunResult:
    corpus: str
    status: str
    invocation: Any
    control: ControlResult | None
    results: dict | None
    unattributed: tuple[str, ...]
    notes: tuple[str, ...]
    coverage: dict | None = None


def materialize(
    sections: tuple[Section, ...],
    directory: Path,
    *,
    corpus: str,
    include_control: bool,
) -> ScanTarget:
    directory.mkdir(parents=True, exist_ok=True)
    index: dict[str, Section] = {}
    for section in sections:
        if section.filename in index:
            raise DatasetError(f"duplicate generated corpus filename: {section.filename}")
        text = section.text if section.text.endswith("\n") else section.text + "\n"
        (directory / section.filename).write_text(text, encoding="utf-8", newline="\n")
        index[section.filename] = section
    if include_control:
        (directory / control_module.CONTROL_FILE).write_text(
            control_module.control_text(), encoding="utf-8", newline="\n"
        )
    return ScanTarget(directory=directory, corpus=corpus, index=index, control=include_control)


def _signature(finding: Finding) -> tuple[str, int | None, str, str]:
    return (finding.file, finding.line, finding.rule_id, finding.secret)


def _findings_by_file(sections: tuple[Section, ...]) -> dict[str, Section]:
    return {section.filename: section for section in sections}


def _split(findings: list[Finding], index: dict[str, Section], control_on: bool):
    known: list[Finding] = []
    control: list[Finding] = []
    unattributed: list[Finding] = []
    for finding in findings:
        if control_on and basename(finding.file) == control_module.CONTROL_FILE:
            control.append(finding)
        elif finding.file in index:
            known.append(finding)
        else:
            unattributed.append(finding)
    return known, control, unattributed


def _duplicates(findings: list[Finding]) -> int:
    seen: set[tuple[str, int | None, str, str]] = set()
    duplicates = 0
    for finding in findings:
        signature = _signature(finding)
        if signature in seen:
            duplicates += 1
        else:
            seen.add(signature)
    return duplicates


def _public_finding(finding: Finding, section: Section) -> dict:
    return {
        "section": section.name,
        "line": finding.line,
        "rule_id": finding.rule_id or None,
    }


def _has_evidence(finding: Finding) -> bool:
    return bool(finding.secret or finding.match)


def score_negative(sections: tuple[Section, ...], findings: list[Finding]) -> dict:
    index = _findings_by_file(sections)
    unexpected: list[Finding] = []
    personal: list[Finding] = []
    no_evidence = 0
    by_section: dict[str, int] = {}
    for finding in findings:
        section = index[finding.file]
        if any(best_match(text, finding).eligible for text in section.personal_data):
            personal.append(finding)
            continue
        unexpected.append(finding)
        if not _has_evidence(finding):
            no_evidence += 1
        by_section[section.name] = by_section.get(section.name, 0) + 1
    examples = [_public_finding(finding, index[finding.file]) for finding in unexpected[:10]]
    ranked = sorted(by_section.items(), key=lambda item: (-item[1], item[0]))
    return {
        "counting_unit": "section/format; expected credentials are zero",
        "sections_scanned": len(sections),
        "lines_scanned": sum(section.lines for section in sections),
        "expected_secrets": 0,
        "findings_total": len(findings),
        "false_positives": len(unexpected),
        "duplicates": _duplicates(findings),
        "personal_data_matches": len(personal),
        "findings_without_evidence": no_evidence,
        "sections_tripped": len(by_section),
        "clean": not unexpected,
        "true_negatives": None,
        "true_negatives_note": "not inferred from lines; this corpus has no per-line oracle",
        "worst_sections": [{"section": name, "findings": count} for name, count in ranked[:10]],
        "examples": examples,
    }


def score_positive(sections: tuple[Section, ...], findings: list[Finding]) -> dict:
    index = _findings_by_file(sections)
    cases: list[tuple[int, Section, object]] = []
    cases_by_section: dict[str, list[tuple[int, Section, object]]] = {}
    for section in sections:
        for secret in section.secrets:
            case_index = len(cases)
            cases.append((case_index, section, secret))
            cases_by_section.setdefault(section.filename, []).append(
                (case_index, section, secret)
            )

    case_candidates: dict[int, list[tuple[int, object]]] = {}
    ambiguous: dict[int, list[int]] = {}
    partial: dict[int, list[tuple[int, object]]] = {}
    eligible_positions: set[int] = set()
    for position, finding in enumerate(findings):
        candidates = []
        for case_index, _section, secret in cases_by_section.get(finding.file, ()):
            match = best_match(secret.text, finding)
            if match.eligible:
                candidates.append((case_index, match))
        if len(candidates) > 1:
            ambiguous[position] = [case_index for case_index, _ in candidates]
            continue
        if len(candidates) == 1:
            case_index, match = candidates[0]
            case_candidates.setdefault(case_index, []).append((position, match))
            eligible_positions.add(position)
            continue
        partial_for_finding = []
        for case_index, _section, secret in cases_by_section.get(finding.file, ()):
            match = best_match(secret.text, finding)
            if match.classification == PARTIAL:
                partial_for_finding.append((case_index, match))
        if partial_for_finding:
            partial[position] = partial_for_finding

    assigned_positions: set[int] = set()
    assignments: dict[int, tuple[int, object]] = {}
    duplicates = 0
    for case_index, _section, _secret in cases:
        candidates = case_candidates.get(case_index, [])
        available = [(position, match) for position, match in candidates if position not in assigned_positions]
        if available:
            position, match = available[0]
            assignments[case_index] = (position, match)
            assigned_positions.add(position)
        duplicates += max(0, len(candidates) - 1)

    matched_secrets: list[dict] = []
    missed_secrets: list[dict] = []
    complete_count = 0
    normalized_count = 0
    for case_index, section, secret in cases:
        if case_index in assignments:
            position, match = assignments[case_index]
            kind = COMPLETE if match.classification == COMPLETE else NORMALIZED
            if kind == COMPLETE:
                complete_count += 1
            else:
                normalized_count += 1
            matched_secrets.append(
                {
                    "section": section.name,
                    "kind": secret.kind,
                    "hard": section.hard,
                    "match_type": kind,
                    "match_field": match.field,
                    "line": findings[position].line,
                    "rule_id": findings[position].rule_id or None,
                }
            )
        else:
            partial_count = sum(
                1
                for position, _finding in enumerate(findings)
                if any(case == case_index for case, _m in partial.get(position, ()))
            )
            missed_secrets.append(
                {
                    "section": section.name,
                    "kind": secret.kind,
                    "hard": section.hard,
                    "classification": "partial" if partial_count else "miss",
                    "partial_evidence": partial_count,
                }
            )

    unexpected: list[Finding] = []
    personal: list[Finding] = []
    partial_entries: list[dict] = []
    ambiguous_entries: list[dict] = []
    no_evidence = 0
    by_section: dict[str, int] = {}
    false_positive_positions: list[int] = []
    for position, finding in enumerate(findings):
        section = index[finding.file]
        if position in ambiguous:
            ambiguous_entries.append(
                {
                    "section": section.name,
                    "line": finding.line,
                    "rule_id": finding.rule_id or None,
                    "candidate_count": len(ambiguous[position]),
                    "candidate_kinds": sorted(
                        {
                            cases[case_index][2].kind
                            for case_index in ambiguous[position]
                        }
                    ),
                }
            )
            by_section[section.name] = by_section.get(section.name, 0) + 1
            false_positive_positions.append(position)
            continue
        if position in eligible_positions:
            continue
        if position in partial:
            candidates = partial[position]
            partial_entries.append(
                {
                    "section": section.name,
                    "line": finding.line,
                    "rule_id": finding.rule_id or None,
                    "candidate_kinds": sorted({cases[case_index][2].kind for case_index, _m in candidates}),
                    "relations": sorted({match.relation for _case, match in candidates}),
                    "match_fields": sorted({match.field for _case, match in candidates}),
                }
            )
            by_section[section.name] = by_section.get(section.name, 0) + 1
            false_positive_positions.append(position)
            continue
        if any(best_match(text, finding).eligible for text in section.personal_data):
            personal.append(finding)
            continue
        if not _has_evidence(finding):
            no_evidence += 1
        unexpected.append(finding)
        by_section[section.name] = by_section.get(section.name, 0) + 1
        false_positive_positions.append(position)

    core_expected = sum(1 for _case, section, _secret in cases if not section.hard)
    hard_expected = sum(1 for _case, section, _secret in cases if section.hard)
    core_found = sum(1 for item in matched_secrets if not item["hard"])
    hard_found = sum(1 for item in matched_secrets if item["hard"])
    ranked = sorted(by_section.items(), key=lambda item: (-item[1], item[0]))
    false_positives = len(unexpected) + len(partial_entries) + len(ambiguous_entries)
    duplicates += _duplicates([findings[position] for position in false_positive_positions])

    return {
        "counting_unit": "planted credential; one expected secret is one case",
        "sections_scanned": len(sections),
        "lines_scanned": sum(section.lines for section in sections),
        "expected_secrets": len(cases),
        "expected_core": core_expected,
        "expected_hard": hard_expected,
        "true_positives": len(matched_secrets),
        "core_true_positives": core_found,
        "hard_true_positives": hard_found,
        "false_negatives": len(missed_secrets),
        "core_false_negatives": core_expected - core_found,
        "hard_false_negatives": hard_expected - hard_found,
        "core_recall_percent": round(100.0 * core_found / core_expected, 2) if core_expected else None,
        "hard_recall_percent": round(100.0 * hard_found / hard_expected, 2) if hard_expected else None,
        "overall_recall_percent": round(100.0 * len(matched_secrets) / len(cases), 2) if cases else None,
        "findings_total": len(findings),
        "unexpected_findings": len(unexpected),
        "partial_matches": len(partial_entries),
        "ambiguous_findings": len(ambiguous_entries),
        "false_positives": false_positives,
        "duplicates": duplicates,
        "personal_data_matches": len(personal),
        "findings_without_evidence": no_evidence,
        "sections_tripped": len(by_section),
        "match_classification": {
            "complete": complete_count,
            "normalized": normalized_count,
            "partial": len(partial_entries),
            "ambiguous": len(ambiguous_entries),
            "miss": len(missed_secrets),
        },
        "matched_secrets": matched_secrets,
        "missed_secrets": missed_secrets,
        "partial_match_details": partial_entries,
        "ambiguous_match_details": ambiguous_entries,
        "worst_sections": [{"section": name, "findings": count} for name, count in ranked[:10]],
        "examples": [_public_finding(finding, index[finding.file]) for finding in unexpected[:10]],
    }


def assess_findings(
    invocation: Any,
    findings: list[Finding],
    target: ScanTarget,
    sections: tuple[Section, ...],
    *,
    raw_texts: tuple[str, ...] | None = None,
    coverage: dict | None = None,
) -> RunResult:
    """Score already-normalized findings without invoking a scanner parser."""
    if raw_texts is None:
        raw_texts = (
            invocation.report_bytes.decode("utf-8", "replace")
            if invocation.report_bytes is not None
            else "",
            invocation.stdout.decode("utf-8", "replace"),
            invocation.stderr.decode("utf-8", "replace"),
        )
    coverage = coverage or {}
    coverage_applicable = bool(coverage.get("applicable"))
    coverage_verified = bool(coverage.get("verified"))
    coverage_notes = tuple(coverage.get("notes") or ())
    control = (
        control_module.control_result(findings, tuple(raw_texts)) if target.control else None
    )
    known, _control_findings, unattributed = _split(findings, target.index, target.control)
    unknown_names = tuple(sorted({basename(item.file) for item in unattributed}))
    notes: list[str] = list(coverage_notes)
    if unknown_names:
        notes.append("findings named files outside the generated corpus: " + ", ".join(unknown_names[:5]))
    if control is not None:
        notes.extend(control.notes)

    if coverage_applicable and not coverage_verified:
        notes.append(
            "scanner-native coverage evidence did not prove complete required inspection; "
            "the run is not scoreable"
        )
        return RunResult(
            corpus=target.corpus,
            status="COVERAGE_UNVERIFIED",
            invocation=invocation,
            control=control,
            results=None,
            unattributed=unknown_names,
            notes=tuple(notes),
            coverage=coverage,
        )

    if not known and not coverage_verified and not (control and control.reported):
        notes.append(
            "no finding on the corpus and no verified control credential: "
            "a silent or unverified scan is not a zero result"
        )
        return RunResult(
            corpus=target.corpus,
            status="NOT_RUN_UNSCORABLE",
            invocation=invocation,
            control=control,
            results=None,
            unattributed=unknown_names,
            notes=tuple(notes),
            coverage=coverage,
        )

    if target.corpus == "negative":
        results = score_negative(sections, known)
    elif target.corpus == "positive":
        results = score_positive(sections, known)
    else:
        raise DatasetError(f"unknown corpus kind: {target.corpus}")

    if control is None:
        status = "COMPLETED_WITH_WARNINGS"
        notes.append("positive control was disabled; a zero result is not independently witnessed")
    elif not control.reported and not coverage_verified:
        status = "COMPLETED_CONTROL_WARNING"
        notes.append(
            "scanner produced corpus findings but did not extract an expected control "
            "credential; the scan may have read only part of the target"
        )
    elif not control.reported and coverage_verified:
        status = "COMPLETED_COVERAGE_VERIFIED"
        notes.append(
            "the scanner-native execution records prove complete required inspection; "
            "the synthetic control credential was not detected"
        )
    else:
        status = "COMPLETED"
    return RunResult(
        corpus=target.corpus,
        status=status,
        invocation=invocation,
        control=control,
        results=results,
        unattributed=unknown_names,
        notes=tuple(notes),
        coverage=coverage,
    )


def assess_run(
    invocation: Any,
    target: ScanTarget,
    sections: tuple[Section, ...],
) -> RunResult:
    from .errors import ReportError
    from .errors import ReportError
    from .execution import invocation_problem, report_findings

    problem = invocation_problem(invocation)
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

    try:
        findings = report_findings(invocation)
    except ReportError as exc:  # defensive; invocation_problem already parsed it
        return RunResult(
            corpus=target.corpus,
            status="REPORT_INVALID",
            invocation=invocation,
            control=None,
            results=None,
            unattributed=(),
            notes=(str(exc),),
        )

    raw_texts = (
        invocation.report_bytes.decode("utf-8", "replace")
        if invocation.report_bytes is not None
        else "",
        invocation.stdout.decode("utf-8", "replace"),
        invocation.stderr.decode("utf-8", "replace"),
    )
    return assess_findings(
        invocation, findings, target, sections, raw_texts=raw_texts
    )


def overall_status(results: list[RunResult]) -> str:
    statuses = {result.status for result in results}
    failure = {
        "INVOCATION_FAILED",
        "TIMEOUT",
        "REPORT_MISSING",
        "REPORT_INVALID",
        "BINARY_NOT_FOUND",
        "COVERAGE_UNVERIFIED",
    }
    if statuses & failure:
        return "INVOCATION_FAILED" if "INVOCATION_FAILED" in statuses else sorted(statuses & failure)[0]
    if "NOT_RUN_UNSCORABLE" in statuses:
        return "NOT_RUN"
    if "COMPLETED_WITH_WARNINGS" in statuses or "COMPLETED_CONTROL_WARNING" in statuses:
        return "COMPLETED_WITH_WARNINGS"
    return "COMPLETED"
