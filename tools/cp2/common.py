"""Shared CP2 integration helpers."""

from __future__ import annotations


def stable_findings(execution: dict, findings: list[dict]) -> list[dict]:
    units = {unit["unit_id"]: unit["locator"] for unit in execution["units"]}
    return sorted(
        [
            {**{key: value for key, value in finding.items() if key != "run_id"}, "locator": units[finding["unit_id"]]}
            for finding in findings
        ],
        key=lambda item: (item["locator"], item["start_byte"], item["end_byte"], item["rule_id"], item["finding_id"]),
    )


def units_without_private_plan(execution: dict) -> list[dict]:
    return sorted(
        [{key: value for key, value in unit.items() if key != "run_id"} for unit in execution["units"]],
        key=lambda unit: unit["unit_id"],
    )
