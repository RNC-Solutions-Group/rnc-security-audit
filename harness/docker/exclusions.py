#!/usr/bin/env python3
"""Print every unvalidated fixture from an execution or aggregate report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def exclusions_from(report: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(report.get("fixture_exclusions"), list):
        return report["fixture_exclusions"]
    if isinstance(report.get("unvalidated_fixtures"), list):
        return report["unvalidated_fixtures"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect fixture exclusions in a Phase 2 execution or aggregate JSON report.")
    parser.add_argument("report", type=Path, help="execution.json or aggregate JSON path")
    args = parser.parse_args()
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        parser.error(f"cannot read report: {exc}")

    exclusions = exclusions_from(report)
    print(f"Applicable fixtures: {report.get('summary', {}).get('applicable_fixtures', report.get('required_fixture_count', 'unknown'))}")
    print(f"Validated: {report.get('summary', {}).get('validated_fixtures', report.get('validated_fixture_count', 'unknown'))}")
    print(f"Not validated: {len(exclusions)}")
    for fixture in exclusions:
        print(
            f"{fixture.get('path', fixture.get('fixture_id', 'unknown'))} | "
            f"{fixture.get('coverage_status', fixture.get('classification', 'UNKNOWN'))} | "
            f"{fixture.get('exclusion_reason', fixture.get('aggregate_exclusion_reason', ''))} | "
            f"scenarios: {', '.join(fixture.get('scenarios', []))} | "
            f"next: {fixture.get('next_action', 'see aggregate report')}"
        )
    if not exclusions:
        print("UNVALIDATED FIXTURES: NONE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())