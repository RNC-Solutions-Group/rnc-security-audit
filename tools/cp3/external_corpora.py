"""Authorized, isolated external-corpus scans and transparent accounting.

Levain's MIT corpus has a credential-level positive/negative oracle. Leaky Repo's
oracle is count-based and does not support credential-level TP/FP. The two are
reported separately; no combined score is manufactured.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "rules/rnc-providers-v1.json"

LEVAIN_KIND_RULES = {
    "aws_access_key_id": "aws-access-key-id",
    "aws_sts_service_bearer_token": "aws-sts-service-bearer-token-id",
    "aws_context_specific_credential": "aws-context-specific-credential-id",
    "aws_secret_access_key": "aws-secret-access-key",
    "github_app_installation_token": "github-app-installation-token",
    "stripe_secret_key": "stripe-secret-api-key",
    "github_pat_classic": "github-classic-pat",
    "github_pat_fine_grained": "github-fine-grained-pat",
    "github_oauth_token": "github-oauth-app-token",
    "gitlab_pat": "gitlab-personal-access-token",
    "google_api_key": "google-api-key",
    "npm_token": "npm-auth-token",
    "sendgrid_api_key": "sendgrid-api-key",
    "slack_bot_token": "slack-token",
    "slack_app_level_token": "slack-token",
    "private_key_pem": "pem-private-key",
    "generic_assignment": "generic-secret-assignment",
}
ALTERNATE_RULES = {
    "aws-secret-access-key-terraform": "aws-secret-access-key",
}


def _slug(value: str, index: int) -> str:
    safe = "".join(character if character.isalnum() else "-" for character in value.lower())
    safe = "-".join(part for part in safe.split("-") if part)[:60]
    return f"{index:03d}-{safe or 'section'}"


def _line_for(data: bytes, offset: int) -> int:
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


def _run_scan(binary: Path, source_root: Path, output: Path, run_id: str) -> dict:
    command = [
        str(binary),
        "scan",
        "--root",
        str(source_root),
        "--rules",
        str(RULES),
        "--format",
        "json",
        "--output",
        str(output),
        "--run-id",
        run_id,
        "--mode",
        "whole",
        "--strategy",
        "regex",
        "--accept-result",
        "1",
        "--accept-result",
        "2",
        "--accept-result",
        "3",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    if completed.returncode not in (0, 10, 20):
        raise RuntimeError(f"external scan failed ({completed.returncode}): {completed.stderr[:400]}")
    return json.loads(output.read_text(encoding="utf-8"))


def _unit_paths(document: dict) -> dict[str, str]:
    return {unit["unit_id"]: unit["locator"] for unit in document["execution"]["units"]}


def _safe_findings(document: dict) -> list[dict]:
    paths = _unit_paths(document)
    return [
        {
            "path": paths[finding["unit_id"]],
            "rule_id": finding["rule_id"],
            "start_byte": finding["start_byte"],
            "end_byte": finding["end_byte"],
            "line": finding["line"],
            "confidence": finding["confidence"],
        }
        for finding in document["findings"]
    ]


def _materialize_levain(cache_root: Path, destination: Path) -> tuple[Path, Path, dict]:
    source = cache_root / "source"
    derived = cache_root / "derived"
    negative = json.loads((source / "fp-corpus.json").read_text(encoding="utf-8"))
    positive = json.loads((derived / "tp-corpus.json").read_text(encoding="utf-8"))
    neg_root = destination / "levain-negative"
    pos_root = destination / "levain-positive"
    neg_root.mkdir(parents=True)
    pos_root.mkdir(parents=True)
    for index, section in enumerate(negative["sections"]):
        (neg_root / f"{_slug(section['name'], index)}.txt").write_bytes(
            section["text"].encode("utf-8")
        )
    truth_items = []
    unsupported_items = []
    skipped = []
    for index, section in enumerate(positive["sections"]):
        path = f"{_slug(section['name'], index)}.txt"
        data = section["text"].encode("utf-8")
        (pos_root / path).write_bytes(data)
        for secret in section["secrets"]:
            kind = secret["kind"]
            rule_id = LEVAIN_KIND_RULES.get(kind)
            token = secret["text"].encode("utf-8")
            start = data.find(token)
            if start < 0:
                skipped.append({"kind": kind, "reason": "secret text not found in section"})
                continue
            end = start + len(token)
            if rule_id is None or (kind == "jwt" and "Bearer " not in section["text"]):
                unsupported_items.append(
                    {
                        "path": path,
                        "kind": kind,
                        "start_byte": start,
                        "end_byte": end,
                        "reason": "family or context not implemented",
                    }
                )
                skipped.append({"kind": kind, "reason": "family not implemented"})
                continue
            truth_items.append(
                {
                    "finding_id": "levain-" + hashlib.sha256(
                        f"{path}\0{rule_id}\0{start}\0{end}".encode()
                    ).hexdigest(),
                    "path": path,
                    "rule_id": rule_id,
                    "family": kind,
                    "start_byte": start,
                    "end_byte": end,
                    "line": _line_for(data, start),
                    "secret_sha256": hashlib.sha256(token).hexdigest(),
                }
            )
    truth = {
        "dataset": "levain-tp-corpus",
        "revision": cache_root.name,
        "license": "MIT",
        "items": truth_items,
        "unsupported_items": unsupported_items,
        "skipped_kinds": skipped,
        "mapped_kinds": sorted(set(LEVAIN_KIND_RULES) & {
            secret["kind"] for section in positive["sections"] for secret in section["secrets"]
        }),
    }
    return neg_root, pos_root, truth


def score_levain_positive(document: dict, truth: dict, _rules_document: dict) -> dict:
    allowed = set(LEVAIN_KIND_RULES.values()) | set(ALTERNATE_RULES)
    actual = _safe_findings(document)
    truth_by_key = {}
    for item in truth["items"]:
        truth_by_key[(item["path"], item["start_byte"], item["end_byte"], item["rule_id"])] = item
    claimed = set()
    tp = 0
    fp = 0
    duplicate = 0
    out_of_scope = 0
    wrong_rule = 0
    alternate_observations = 0
    findings_out = []
    for finding in actual:
        if finding["rule_id"] not in allowed:
            out_of_scope += 1
            continue
        canonical_rule = ALTERNATE_RULES.get(finding["rule_id"], finding["rule_id"])
        if canonical_rule != finding["rule_id"]:
            alternate_observations += 1
        key = (
            finding["path"],
            finding["start_byte"],
            finding["end_byte"],
            canonical_rule,
        )
        if key in truth_by_key and key not in claimed:
            claimed.add(key)
            tp += 1
            classification = "EXPECTED_DETECTION"
        elif key in truth_by_key:
            duplicate += 1
            classification = "DUPLICATE"
        else:
            unsupported = any(
                item["path"] == finding["path"]
                and item["start_byte"] == finding["start_byte"]
                and item["end_byte"] == finding["end_byte"]
                for item in truth.get("unsupported_items", [])
            )
            if unsupported:
                out_of_scope += 1
                findings_out.append({**finding, "classification": "OUT_OF_SCOPE_UNSUPPORTED_FAMILY"})
                continue
            fp += 1
            classification = "FALSE_POSITIVE"
            overlapping = [
                item
                for item in truth["items"]
                if item["path"] == finding["path"]
                and item["start_byte"] < finding["end_byte"]
                and finding["start_byte"] < item["end_byte"]
            ]
            if overlapping:
                wrong_rule += 1
                classification = "WRONG_RULE_OR_SPAN"
        findings_out.append({**finding, "classification": classification})
    fn = sum(1 for item in truth["items"] if (item["path"], item["start_byte"], item["end_byte"], item["rule_id"]) not in claimed)
    missed = [
        {
            "path": item["path"],
            "line": item["line"],
            "kind": item["family"],
            "rule_id": item["rule_id"],
        }
        for item in truth["items"]
        if (item["path"], item["start_byte"], item["end_byte"], item["rule_id"]) not in claimed
    ]
    precision = round(100.0 * tp / (tp + fp), 2) if tp + fp else None
    recall = round(100.0 * tp / (tp + fn), 2) if tp + fn else None
    f1 = (
        round(2 * precision * recall / (precision + recall), 2)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    by_rule = {}
    for rule_id in sorted(allowed):
        expected = sum(1 for item in truth["items"] if item["rule_id"] == rule_id)
        if not expected:
            continue
        matched = sum(
            1
            for item in truth["items"]
            if item["rule_id"] == rule_id
            and (item["path"], item["start_byte"], item["end_byte"], item["rule_id"]) in claimed
        )
        observed = sum(1 for finding in actual if finding["rule_id"] == rule_id)
        by_rule[rule_id] = {
            "expected": expected,
            "tp": matched,
            "fn": expected - matched,
            "observed": observed,
            "precision_scope": "mapped family only",
        }
    return {
        "dataset": truth["dataset"],
        "revision": truth["revision"],
        "license": truth["license"],
        "scope": "only credential families declared by the RNC catalog",
        "expected_mapped": len(truth["items"]),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "duplicates": duplicate,
        "wrong_rule_or_span": wrong_rule,
        "out_of_scope_findings": out_of_scope,
        "alternate_rule_observations": alternate_observations,
        "precision_percent": precision,
        "recall_percent": recall,
        "f1_percent": f1,
        "observed_total": len(actual),
        "by_rule": by_rule,
        "findings": findings_out,
        "missed": missed,
        "skipped_kinds": truth["skipped_kinds"],
        "notes": [
            "Levain kinds that RNC does not implement are excluded from the denominator.",
            "The corpus says every positive is synthetic and no positive has been live.",
            "JWT entries without a Bearer context are outside the declared RNC JWT rule.",
        ],
    }


def score_negative(document: dict, corpus: str) -> dict:
    findings = _safe_findings(document)
    per_rule = Counter(finding["rule_id"] for finding in findings)
    per_path = Counter(finding["path"] for finding in findings)
    return {
        "dataset": corpus,
        "claims": "No section contains a credential; every reported value is a false positive.",
        "observed_findings": len(findings),
        "false_positive_findings": len(findings),
        "per_rule": dict(sorted(per_rule.items())),
        "per_path": dict(sorted(per_path.items())),
        "findings": findings,
        "notes": [
            "This is a precision stress corpus, not a positive-recall corpus.",
            "Raw values are not included; the report contains paths, rules and offsets.",
        ],
    }


def score_leaky(document: dict, inventory: dict) -> dict:
    rows = {str(row["path"]): row for row in inventory["rows"]}
    observed = Counter(finding["path"] for finding in _safe_findings(document))
    unlisted = sorted(path for path in observed if path not in rows)
    per_file = []
    for path, row in rows.items():
        expected = int(row["total"])
        count = observed.get(path, 0)
        per_file.append(
            {
                "path": path,
                "expected_count": expected,
                "risk_count": int(row["risk"]),
                "informative_count": int(row["informative"]),
                "observed_findings": count,
                "covered_count": min(count, expected),
                "excess_findings": max(0, count - expected),
            }
        )
    expected_total = sum(item["expected_count"] for item in per_file)
    covered = sum(item["covered_count"] for item in per_file)
    return {
        "dataset": "leaky-repo",
        "methodology": "count-based filesystem benchmark; not credential-level TP/FP",
        "expected_count": expected_total,
        "observed_findings": sum(observed.values()),
        "covered_count": covered,
        "count_coverage_percent": round(100.0 * covered / expected_total, 2)
        if expected_total
        else 0.0,
        "files_covered": sum(1 for item in per_file if item["observed_findings"] > 0),
        "expected_files": len(per_file),
        "excess_findings": sum(item["excess_findings"] for item in per_file),
        "unlisted_findings": len(unlisted),
        "unlisted_paths": unlisted[:50],
        "per_file": per_file,
        "notes": [
            "Observed findings are not converted into TP/FP; the oracle is count-based.",
            "Excess findings are not automatically false positives.",
            "The scanner inspected the copied worktree without .git.",
        ],
    }


def run(
    binary: Path,
    *,
    levain_cache: Path | None,
    leaky_source: Path | None,
    leaky_inventory: Path | None,
) -> dict:
    rules_document = json.loads(RULES.read_text(encoding="utf-8"))
    result = {
        "external_corpora_executed": True,
        "levain": None,
        "leaky_repo": None,
        "scanner_accuracy_claim": "Scoped external evidence; see each corpus's methodology.",
    }
    with tempfile.TemporaryDirectory(prefix="rnc-cp3-external-") as temp:
        workspace = Path(temp)
        if levain_cache is not None:
            neg_root, pos_root, truth = _materialize_levain(levain_cache, workspace)
            negative_document = _run_scan(
                binary, neg_root, workspace / "levain-negative.json", "cp3-levain-negative"
            )
            positive_document = _run_scan(
                binary, pos_root, workspace / "levain-positive.json", "cp3-levain-positive"
            )
            result["levain"] = {
                "negative": score_negative(negative_document, "levain-fp-corpus"),
                "positive": score_levain_positive(positive_document, truth, rules_document),
                "cache_revision": levain_cache.name,
            }
        if leaky_source is not None and leaky_inventory is not None:
            scan_root = workspace / "leaky-repo"
            shutil.copytree(
                leaky_source,
                scan_root,
                ignore=shutil.ignore_patterns(".git"),
            )
            inventory = json.loads(leaky_inventory.read_text(encoding="utf-8"))
            leaky_document = _run_scan(
                binary, scan_root, workspace / "leaky-repo.json", "cp3-leaky-repo"
            )
            result["leaky_repo"] = score_leaky(leaky_document, inventory)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--levain-cache", type=Path)
    parser.add_argument("--leaky-source", type=Path)
    parser.add_argument("--leaky-inventory", type=Path)
    args = parser.parse_args()
    document = run(
        args.binary,
        levain_cache=args.levain_cache,
        leaky_source=args.leaky_source,
        leaky_inventory=args.leaky_inventory,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
