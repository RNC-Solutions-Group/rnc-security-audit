"""Independent byte-addressed provider-corpus scorer.

This module is test infrastructure. It reads scanner output and an independently
authored truth manifest, verifies the truth manifest against source bytes, and
classifies findings by exact byte span and credential family. It is never called
by the detector.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CLASSIFICATIONS = (
    "EXPECTED_DETECTION",
    "MISSED_EXPECTATION",
    "FALSE_POSITIVE",
    "MISALIGNED_MATCH",
    "WRONG_RULE",
    "WRONG_FAMILY",
    "DUPLICATE",
    "AMBIGUOUS_MATCH",
    "UNMAPPED",
)


def normalized_path(value: str) -> str:
    result = str(value).replace("\\", "/")
    while result.startswith("./"):
        result = result[2:]
    return result


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def line_for(data: bytes, offset: int) -> int:
    line = 1
    index = 0
    while index < offset:
        if data[index] == 13:
            if index + 1 < offset and data[index + 1] == 10:
                index += 2
            else:
                index += 1
            line += 1
        elif data[index] == 10:
            index += 1
            line += 1
        else:
            index += 1
    return line


def line_end_for(data: bytes, start: int, end: int) -> int:
    last = end - 1
    while last > start and data[last] in (10, 13):
        last -= 1
    return line_for(data, last)


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(100.0 * numerator / denominator, 2)


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None:
        return None
    denominator = precision + recall
    if denominator == 0:
        return 0.0
    return round(2 * precision * recall / denominator, 2)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int | None
    rule_id: str
    family: str
    start_byte: int
    end_byte: int
    confidence: str
    finding_id: str
    validation: tuple[str, ...]


@dataclass(frozen=True)
class Truth:
    path: str
    finding_id: str
    expected_rule_id: str
    family: str
    credential_type: str
    start_byte: int
    end_byte: int
    line_start: int
    line_end: int
    secret_sha256: str


class ScoringError(ValueError):
    pass


def load_rules(path: Path) -> tuple[dict[str, dict], dict]:
    document = json.loads(path.read_text(encoding="utf-8"))
    mapping = {}
    for rule in document.get("rules", []):
        rule_id = rule.get("rule_id")
        if not rule_id:
            raise ScoringError("rules bundle has a rule without rule_id")
        mapping[rule_id] = {
            "family": rule.get("family") or "unclassified",
            "provider": rule.get("provider") or "unclassified",
            "credential_type": rule.get("credential_type") or "unclassified",
            "confidence": rule.get("confidence") or "unknown",
        }
    return mapping, document


def load_truth(path: Path, source_root: Path, *, verify: bool = True) -> tuple[dict, list[Truth], dict[str, bytes]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1:
        raise ScoringError("unsupported provider truth schema_version")
    files = {normalized_path(item["path"]): item for item in document.get("files", [])}
    contents: dict[str, bytes] = {}
    integrity: dict[str, Any] = {"status": "PASS", "files": {}, "errors": []}
    for path, record in files.items():
        source = source_root / path
        if not source.is_file():
            integrity["status"] = "FAIL"
            integrity["errors"].append(f"missing source file: {path}")
            continue
        data = source.read_bytes()
        contents[path] = data
        digest = sha256_hex(data)
        if digest != record.get("sha256"):
            integrity["status"] = "FAIL"
            integrity["errors"].append(f"source hash mismatch: {path}")
        if len(data) != record.get("byte_length"):
            integrity["status"] = "FAIL"
            integrity["errors"].append(f"source length mismatch: {path}")
        integrity["files"][path] = {"sha256": digest, "bytes": len(data)}
    truths: list[Truth] = []
    identities: set[str] = set()
    for item in document.get("items", []):
        path = normalized_path(item["path"])
        if path not in contents:
            integrity["status"] = "FAIL"
            integrity["errors"].append(f"truth item references missing file: {path}")
            continue
        data = contents[path]
        start = int(item["start_byte"])
        end = int(item["end_byte"])
        if not (0 <= start < end <= len(data)):
            integrity["status"] = "FAIL"
            integrity["errors"].append(f"truth item has invalid byte range: {item.get('finding_id')}")
            continue
        digest = sha256_hex(data[start:end])
        if digest != item.get("secret_sha256"):
            integrity["status"] = "FAIL"
            integrity["errors"].append(f"truth item hash mismatch: {item.get('finding_id')}")
        expected_start_line = line_for(data, start)
        expected_end_line = line_end_for(data, start, end)
        if expected_start_line != item.get("line_start") or expected_end_line != item.get("line_end"):
            integrity["status"] = "FAIL"
            integrity["errors"].append(f"truth item line mismatch: {item.get('finding_id')}")
        if item["finding_id"] in identities:
            integrity["status"] = "FAIL"
            integrity["errors"].append(f"duplicate truth identity: {item['finding_id']}")
        identities.add(item["finding_id"])
        metadata = item.get("metadata") or {}
        truths.append(
            Truth(
                path=path,
                finding_id=item["finding_id"],
                expected_rule_id=item.get("expected_rule_id", ""),
                family=metadata.get("provider_family") or item.get("category", ""),
                credential_type=metadata.get("credential_type", ""),
                start_byte=start,
                end_byte=end,
                line_start=expected_start_line,
                line_end=expected_end_line,
                secret_sha256=digest,
            )
        )
    if verify and integrity["status"] != "PASS":
        raise ScoringError("truth integrity failed: " + "; ".join(integrity["errors"][:5]))
    truths.sort(key=lambda item: (item.path, item.start_byte, item.end_byte, item.expected_rule_id))
    return document, truths, contents


def load_findings(path: Path) -> tuple[dict, list[Finding]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    units = {unit["unit_id"]: unit for unit in document.get("execution", {}).get("units", [])}
    findings: list[Finding] = []
    for item in document.get("findings", []):
        unit = units.get(item.get("unit_id"))
        if unit is None:
            raise ScoringError("finding references an unknown unit")
        if unit.get("disposition") != "INSPECTED":
            raise ScoringError("finding references a non-inspected unit")
        findings.append(
            Finding(
                path=normalized_path(unit["locator"]),
                line=item.get("line"),
                rule_id=item["rule_id"],
                family="unclassified",
                start_byte=int(item["start_byte"]),
                end_byte=int(item["end_byte"]),
                confidence=item.get("confidence", "unknown"),
                finding_id=item["finding_id"],
                validation=tuple(item.get("validation", [])),
            )
        )
    return document, findings


def _overlap(left: Truth | Finding, right: Truth | Finding) -> bool:
    return left.path == right.path and left.start_byte < right.end_byte and right.start_byte < left.end_byte


def _execution_gate(document: dict, truth_paths: set[str], units_by_locator: dict[str, dict]) -> dict:
    execution = document.get("execution", {})
    result = document.get("result", {})
    required_uninspected = sum(
        1
        for unit in execution.get("units", [])
        if unit.get("disposition") == "UNINSPECTED" and unit.get("required_scope")
    )
    inspected_paths = {
        normalized_path(unit["locator"])
        for unit in execution.get("units", [])
        if unit.get("disposition") == "INSPECTED"
    }
    missing_paths = sorted(truth_paths - inspected_paths)
    state = execution.get("state")
    result_code = result.get("result_code")
    status = "PASS"
    reasons = []
    if result_code == 5 or state == "ERROR":
        status = "FAILED"
        reasons.append("execution failed")
    elif result_code == 4 or state == "INTERRUPTED":
        status = "INCOMPLETE"
        reasons.append("execution interrupted or incomplete")
    if required_uninspected:
        status = "INCOMPLETE"
        reasons.append(f"{required_uninspected} required unit(s) uninspected")
    if missing_paths:
        status = "INCOMPLETE"
        reasons.append(f"{len(missing_paths)} truth file(s) were not inspected")
    if result_code not in (1, 2, 3):
        status = "INCOMPLETE" if status == "PASS" else status
        reasons.append(f"result_code {result_code} is not scorable")
    if not execution.get("evidence_valid", False):
        status = "INCOMPLETE" if status == "PASS" else status
        reasons.append("execution evidence is not valid")
    return {
        "status": status,
        "reasons": reasons,
        "required_uninspected": required_uninspected,
        "expected_files": len(truth_paths),
        "inspected_expected_files": len(truth_paths & inspected_paths),
        "missing_paths": missing_paths[:50],
        "execution_state": state,
        "evidence_valid": execution.get("evidence_valid"),
        "result_code": result_code,
    }


def score(
    private_document: dict,
    truth_document: dict,
    truths: list[Truth],
    findings: list[Finding],
    rule_map: dict[str, dict],
    *,
    source_root: Path | None = None,
    backend: str = "unknown",
    mode: str = "unknown",
    platform: str = "unknown",
) -> dict:
    resolved_findings: list[Finding] = []
    for finding in findings:
        metadata = rule_map.get(finding.rule_id, {})
        resolved_findings.append(
            Finding(
                path=finding.path,
                line=finding.line,
                rule_id=finding.rule_id,
                family=metadata.get("family", "unclassified"),
                start_byte=finding.start_byte,
                end_byte=finding.end_byte,
                confidence=finding.confidence,
                finding_id=finding.finding_id,
                validation=finding.validation,
            )
        )
    findings = resolved_findings
    units_by_locator = {
        normalized_path(unit["locator"]): unit
        for unit in private_document.get("execution", {}).get("units", [])
    }
    truth_paths = {item.path for item in truths}
    gate = _execution_gate(private_document, truth_paths, units_by_locator)
    if gate["status"] != "PASS":
        return {
            "scoring_status": gate["status"],
            "execution_gate": gate,
            "backend": backend,
            "mode": mode,
            "platform": platform,
            "metrics": {
                "expected_count": len(truths),
                "observed_count": len(findings),
                "precision_percent": None,
                "recall_percent": None,
                "f1_percent": None,
            },
            "classifications": [],
            "warnings": ["Accuracy is not scored when required coverage or execution evidence is incomplete."],
        }

    by_path: dict[str, list[Truth]] = {}
    for item in truths:
        by_path.setdefault(item.path, []).append(item)
    claimed: set[str] = set()
    ambiguous_truth: set[str] = set()
    classifications: list[dict] = []
    counts = {name: 0 for name in CLASSIFICATIONS}

    def record(classification: str, finding: Finding | None, truth: Truth | None, reason: str) -> None:
        counts[classification] += 1
        entry: dict[str, Any] = {
            "classification": classification,
            "path": finding.path if finding else (truth.path if truth else None),
            "start_byte": finding.start_byte if finding else (truth.start_byte if truth else None),
            "end_byte": finding.end_byte if finding else (truth.end_byte if truth else None),
            "rule_id": finding.rule_id if finding else (truth.expected_rule_id if truth else None),
            "family": finding.family if finding else (truth.family if truth else None),
            "finding_id": finding.finding_id if finding else None,
            "expected_id": truth.finding_id if truth else None,
            "reason": reason,
        }
        classifications.append(entry)

    ordered = sorted(findings, key=lambda item: (item.path, item.start_byte, item.end_byte, item.rule_id, item.finding_id))
    for finding in ordered:
        path_truth = by_path.get(finding.path, [])
        exact = [item for item in path_truth if item.start_byte == finding.start_byte and item.end_byte == finding.end_byte]
        if exact:
            if len(exact) > 1:
                for item in exact:
                    ambiguous_truth.add(item.finding_id)
                record("AMBIGUOUS_MATCH", finding, None, f"{len(exact)} truth items share this byte span")
                continue
            truth = exact[0]
            if truth.expected_rule_id and truth.expected_rule_id != finding.rule_id:
                if truth.family == finding.family:
                    record("WRONG_RULE", finding, truth, "byte span and family match, rule identity differs")
                else:
                    record("WRONG_FAMILY", finding, truth, "byte span matches, credential family differs")
                continue
            if truth.finding_id in claimed:
                record("DUPLICATE", finding, truth, "expected occurrence was already matched")
                continue
            claimed.add(truth.finding_id)
            record("EXPECTED_DETECTION", finding, truth, "exact byte span and rule match")
            continue
        overlapping = [item for item in path_truth if _overlap(item, finding)]
        if len(overlapping) > 1:
            for item in overlapping:
                ambiguous_truth.add(item.finding_id)
            record("AMBIGUOUS_MATCH", finding, None, f"finding overlaps {len(overlapping)} truth items")
        elif len(overlapping) == 1:
            record("MISALIGNED_MATCH", finding, overlapping[0], "byte range overlaps but does not match exactly")
        elif finding.path in by_path:
            record("FALSE_POSITIVE", finding, None, "no truth item at this path/span")
        else:
            record("UNMAPPED", finding, None, "finding path is outside the truth manifest")

    for truth in truths:
        if truth.finding_id in claimed or truth.finding_id in ambiguous_truth:
            continue
        counts["MISSED_EXPECTATION"] += 1
        classifications.append(
            {
                "classification": "MISSED_EXPECTATION",
                "path": truth.path,
                "start_byte": truth.start_byte,
                "end_byte": truth.end_byte,
                "rule_id": truth.expected_rule_id,
                "family": truth.family,
                "finding_id": None,
                "expected_id": truth.finding_id,
                "reason": "no observed finding matched this exact byte span",
            }
        )

    tp = counts["EXPECTED_DETECTION"]
    false_positive_classes = {
        "FALSE_POSITIVE",
        "MISALIGNED_MATCH",
        "WRONG_RULE",
        "WRONG_FAMILY",
        "UNMAPPED",
    }
    fp = sum(counts[name] for name in false_positive_classes)
    fn = counts["MISSED_EXPECTATION"]
    ambiguous = counts["AMBIGUOUS_MATCH"]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _f1(precision, recall)

    def metrics_for_family(values: list[str]) -> dict:
        result = {}
        class_by_finding = {
            entry["finding_id"]: entry["classification"]
            for entry in classifications
            if entry.get("finding_id")
        }
        family_fp_classes = {"FALSE_POSITIVE", "MISALIGNED_MATCH", "WRONG_FAMILY", "UNMAPPED"}
        for value in sorted(values):
            expected_ids = {item.finding_id for item in truths if item.family == value}
            family_tp_ids = {
                finding.finding_id
                for finding in findings
                if finding.family == value
                and any(
                    truth.finding_id in claimed
                    and truth.path == finding.path
                    and truth.start_byte == finding.start_byte
                    and truth.end_byte == finding.end_byte
                    and truth.family == value
                    for truth in truths
                )
            }
            fp = sum(
                1
                for finding in findings
                if finding.family == value
                and class_by_finding.get(finding.finding_id) in family_fp_classes
            )
            result[value] = {
                "expected": len(expected_ids),
                "tp": len(family_tp_ids),
                "fn": len(expected_ids) - len(family_tp_ids),
                "observed": sum(1 for finding in findings if finding.family == value),
                "fp": fp,
                "precision_percent": _ratio(len(family_tp_ids), len(family_tp_ids) + fp),
                "recall_percent": _ratio(len(family_tp_ids), len(expected_ids)),
            }
        return result

    def metrics_for_rule(values: list[str]) -> dict:
        result = {}
        class_by_finding = {
            entry["finding_id"]: entry["classification"]
            for entry in classifications
            if entry.get("finding_id")
        }
        fp_classes = {
            "FALSE_POSITIVE",
            "MISALIGNED_MATCH",
            "WRONG_RULE",
            "WRONG_FAMILY",
            "UNMAPPED",
        }
        for value in sorted(values):
            expected_ids = {item.finding_id for item in truths if item.expected_rule_id == value}
            tp = sum(
                1
                for entry in classifications
                if entry["classification"] == "EXPECTED_DETECTION"
                and entry.get("rule_id") == value
            )
            fp = sum(
                1
                for finding in findings
                if finding.rule_id == value
                and class_by_finding.get(finding.finding_id) in fp_classes
            )
            result[value] = {
                "expected": len(expected_ids),
                "tp": tp,
                "fn": len(expected_ids) - tp,
                "observed": sum(1 for finding in findings if finding.rule_id == value),
                "fp": fp,
                "precision_percent": _ratio(tp, tp + fp),
                "recall_percent": _ratio(tp, len(expected_ids)),
            }
        return result

    family_values = {item.family for item in truths} | {item.family for item in findings}
    rule_values = {item.expected_rule_id for item in truths} | {item.rule_id for item in findings}
    exact_span_family_tp = sum(
        1
        for finding in findings
        if any(
            truth.finding_id in claimed
            and truth.path == finding.path
            and truth.start_byte == finding.start_byte
            and truth.end_byte == finding.end_byte
            and truth.family == finding.family
            for truth in truths
        )
    )
    return {
        "scoring_status": "COMPLETED",
        "execution_gate": gate,
        "backend": backend,
        "mode": mode,
        "platform": platform,
        "scanner": "rnc",
        "ruleset_id": private_document.get("execution", {}).get("ruleset_id"),
        "ruleset_digest": private_document.get("execution", {}).get("ruleset_digest"),
        "metrics": {
            "expected_count": len(truths),
            "observed_count": len(findings),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision_percent": precision,
            "recall_percent": recall,
            "f1_percent": f1,
            "precision_denominator": tp + fp,
            "recall_denominator": tp + fn,
            "duplicates": counts["DUPLICATE"],
            "ambiguous": ambiguous,
            "wrong_rule": counts["WRONG_RULE"],
            "wrong_family": counts["WRONG_FAMILY"],
            "misaligned": counts["MISALIGNED_MATCH"],
            "unmapped": counts["UNMAPPED"],
            "false_positive": counts["FALSE_POSITIVE"],
            "missed": counts["MISSED_EXPECTATION"],
            "family_tp": exact_span_family_tp,
            "expected_files": gate["expected_files"],
            "required_coverage_percent": _ratio(
                gate["inspected_expected_files"], gate["expected_files"]
            ),
            "coverage_complete": gate["inspected_expected_files"] == gate["expected_files"],
        },
        "classifications": classifications,
        "by_family": metrics_for_family(family_values),
        "by_rule": metrics_for_rule(rule_values),
        "warnings": [
            "Ambiguous and unmapped observations are reported separately and are not silently folded into TP/FP.",
            "A parseable provider-format value is a detection of format, not proof that a credential is active.",
        ],
    }


def score_files(
    findings_path: Path,
    truth_path: Path,
    rules_path: Path,
    source_root: Path,
    *,
    backend: str = "unknown",
    mode: str = "unknown",
    platform: str = "unknown",
) -> dict:
    rule_map, _rules_document = load_rules(rules_path)
    truth_document, truths, _contents = load_truth(truth_path, source_root)
    private_document, findings = load_findings(findings_path)
    return score(
        private_document,
        truth_document,
        truths,
        findings,
        rule_map,
        source_root=source_root,
        backend=backend,
        mode=mode,
        platform=platform,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--backend", default="unknown")
    parser.add_argument("--mode", default="unknown")
    parser.add_argument("--platform", default="unknown")
    parser.add_argument("--require-perfect", action="store_true")
    args = parser.parse_args()
    report = score_files(
        args.findings,
        args.truth,
        args.rules,
        args.source_root,
        backend=args.backend,
        mode=args.mode,
        platform=args.platform,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8", newline="\n")
    print(payload, end="")
    metrics = report["metrics"]
    if args.require_perfect:
        perfect = (
            report["scoring_status"] == "COMPLETED"
            and metrics["tp"] == metrics["expected_count"]
            and metrics["fp"] == 0
            and metrics["fn"] == 0
            and metrics["duplicates"] == 0
            and metrics["ambiguous"] == 0
        )
        return 0 if perfect else 1
    return 0 if report["scoring_status"] == "COMPLETED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
