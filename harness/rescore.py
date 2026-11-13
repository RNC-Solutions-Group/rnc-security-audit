"""Offline rescoring of retained normalized history findings.

This path never invokes a scanner.  It exists so approved truth or matcher
changes can be applied to already-captured evidence without manufacturing new
scanner observations.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import history_matching
from . import history_oracle
from . import leaky_repo
from .errors import HarnessError


class RescoreError(HarnessError):
    pass


def extract_history_findings(report: dict, platform: str | None = None) -> tuple[str, list[dict]]:
    details = ((report.get("suites") or {}).get("leaky-repo") or {}).get("details") or {}
    lanes = details.get("history_lanes") or {}
    if not isinstance(lanes, dict) or not lanes:
        raise RescoreError("report contains no Leaky Repo history lanes")
    if platform is not None:
        if platform not in lanes:
            raise RescoreError(f"report has no history lane for platform {platform!r}")
        lanes = {platform: lanes[platform]}
    elif len(lanes) != 1:
        raise RescoreError(
            "report has multiple history lanes; specify one platform explicitly"
        )
    selected = next(iter(lanes.items()))
    key, lane = selected
    findings = lane.get("findings")
    if not isinstance(findings, list):
        raise RescoreError(f"history lane {key!r} has no retained finding list")
    count = lane.get("finding_count")
    if isinstance(count, int) and count != len(findings):
        raise RescoreError(
            f"history lane {key!r} is truncated: retained {len(findings)} of {count}; "
            "rescore the un-compacted report"
        )
    return key, findings


def rescore_report(
    report: dict,
    *,
    platform: str | None = None,
    cache_dir: Path | str = leaky_repo.DEFAULT_CACHE,
) -> dict:
    prepared = leaky_repo.prepare(cache_dir=cache_dir, offline=True)
    spec = prepared.spec
    if spec.history_oracle_path is None or spec.history_scope_path is None:
        raise RescoreError("the pinned Leaky Repo manifest has no history oracle/scope")
    oracle = history_oracle.load(
        spec.history_oracle_path,
        expected_sha256=spec.history_oracle_sha256,
        source_root=prepared.source,
        scope_path=spec.history_scope_path,
    )
    scope = json.loads(spec.history_scope_path.read_text(encoding="utf-8"))
    lane_key, findings = extract_history_findings(report, platform=platform)
    result = history_matching.score_history(
        findings,
        oracle,
        prepared.source,
        scope=scope,
    )
    source = report.get("source") or {}
    return {
        "report_type": "rnc-scan-harness/history-rescore",
        "schema_version": 1,
        "status": "PASS" if result.metrics.get("finding_accounting_reconciled") else "FAIL",
        "input_report": {
            "scan": report.get("scanner") or {},
            "source": {
                "repository": source.get("repository"),
                "commit": source.get("commit"),
                "head_verified": source.get("head_verified"),
            },
            "platform": lane_key,
            "observed_findings": len(findings),
        },
        "oracle": {
            "id": oracle.oracle_id,
            "version": oracle.version,
            "sha256": oracle.sha256,
            "scope_head": oracle.scope.get("head"),
            "counts": oracle.counts,
            "source_validation": oracle.validation.get("source_validation"),
        },
        "score": result.safe_dict(),
        "metrics": result.metrics,
        "warnings": list(result.warnings),
    }


def write(document: dict, path: Path | str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return target
