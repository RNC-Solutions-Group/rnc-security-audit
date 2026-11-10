"""Strict CP0 contract primitives and cross-record validation.

This module is reference infrastructure, not a production scanner or reporter.
Every identity is derived from a documented canonical input, and the validator
rejects schema-valid records that contradict each other.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "docs/contracts/schemas"
SCHEMA_VERSION = "0.2.0"

RESULT_NAMES = {
    1: "CLEAN",
    2: "POLICY_APPLIED",
    3: "ACTIONABLE",
    4: "INCOMPLETE",
    5: "FAILED",
}
RESULT_CODES = {name: code for code, name in RESULT_NAMES.items()}
DEFAULT_ACCEPTED = frozenset({1, 2})
PROCESS_EXITS = {4: 20, 5: 30}
REJECTED_COMPLETED_EXIT = 10

PUBLIC_FORBIDDEN_KEYS = frozenset({
    "locator",
    "secret",
    "secret_text",
    "match",
    "match_text",
    "raw",
    "raw_bytes",
    "line_text",
    "path",
})
SECRET_SHAPED = (
    re.compile(r"RNC_SYNTH_KEY_[A-Z0-9_]+"),
    re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}"),
)
DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
ABS_PATH_FRAGMENT = re.compile(r"(?:^|[\s\"'])(?:/(?:home|Users|tmp|var|etc|opt|workspace)/)")


class ContractViolation(ValueError):
    """Raised when records are schema-valid but mutually impossible."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_locator(locator: str) -> str:
    if not isinstance(locator, str) or not locator:
        raise ContractViolation("LOCATOR_INVALID", "locator must be a non-empty string")
    value = locator.replace("\\", "/")
    while value.startswith("./"):
        value = value[2:]
    while "//" in value:
        value = value.replace("//", "/")
    if value.startswith("/") or DRIVE_PATH.match(value) or value.startswith("~"):
        raise ContractViolation("LOCATOR_INVALID", "locator must be relative to the source root")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ContractViolation("LOCATOR_INVALID", "locator contains an empty, dot or traversal segment")
    return value


def make_unit_id(source_id: str, locator: str) -> str:
    if not source_id:
        raise ContractViolation("UNIT_ID_INVALID", "source_id is required")
    canonical = canonical_locator(locator)
    material = f"{source_id}\0{canonical}".encode("utf-8")
    return "u-" + hashlib.sha256(material).hexdigest()


def make_finding_id(
    unit_id: str,
    rule_id: str,
    rule_version: str,
    start_byte: int,
    end_byte: int,
    evidence_digest: str,
) -> str:
    material = "\0".join(
        [unit_id, rule_id, rule_version, str(start_byte), str(end_byte), evidence_digest]
    ).encode("utf-8")
    return "f-" + hashlib.sha256(material).hexdigest()


def make_request_id(policy_id: str, kind: str, selector: str) -> str:
    material = "\0".join([policy_id, kind, selector]).encode("utf-8")
    return "r-" + hashlib.sha256(material).hexdigest()


def line_for_offset(data: bytes, offset: int) -> int:
    if offset < 0 or offset > len(data):
        raise ContractViolation("OFFSET_INVALID", "byte offset is outside the content")
    line = 1
    index = 0
    while index < offset:
        byte = data[index]
        if byte == 13:
            if index + 1 < offset and data[index + 1] == 10:
                index += 2
            else:
                index += 1
            line += 1
        elif byte == 10:
            index += 1
            line += 1
        else:
            index += 1
    return line


def line_count(data: bytes) -> int:
    if not data:
        return 0
    count = 0
    index = 0
    while index < len(data):
        if data[index] == 13:
            if index + 1 < len(data) and data[index + 1] == 10:
                index += 2
            else:
                index += 1
            count += 1
        elif data[index] == 10:
            index += 1
            count += 1
        else:
            index += 1
    if data[-1] not in (10, 13):
        count += 1
    return count


def schema_registry() -> tuple[dict[str, dict], Registry]:
    schemas = {path.name: json.loads(path.read_text(encoding="utf-8")) for path in SCHEMAS.glob("*.schema.json")}
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()]
    )
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    return schemas, registry


def _validator(name: str, schemas: Mapping[str, dict], registry: Registry) -> Draft202012Validator:
    try:
        schema = schemas[name]
    except KeyError as exc:
        raise ContractViolation("SCHEMA_MISSING", f"unknown schema {name}") from exc
    return Draft202012Validator(schema, registry=registry)


def schema_check(
    value: dict,
    name: str,
    schemas: Mapping[str, dict],
    registry: Registry,
    *,
    code: str = "SCHEMA_INVALID",
) -> None:
    try:
        _validator(name, schemas, registry).validate(value)
    except ValidationError as exc:
        location = "/".join(str(part) for part in exc.absolute_path) or "<root>"
        raise ContractViolation(code, f"{name} at {location}: {exc.message}") from exc


def _expect(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise ContractViolation(code, message)


def _canonical_order(name: str, values: list[dict], key) -> None:
    if values != sorted(values, key=key):
        raise ContractViolation("ORDER_NON_DETERMINISTIC", f"{name} are not in canonical order")


def _validate_unit(unit: dict, contents: Mapping[str, bytes] | None) -> None:
    source_id = unit["source_id"]
    locator = unit["locator"]
    _expect(
        unit["unit_id"] == make_unit_id(source_id, locator),
        "UNIT_ID_MISMATCH",
        f"unit {unit.get('unit_id')} does not match source identity",
    )
    if unit["disposition"] == "INSPECTED":
        data = contents.get(unit["unit_id"]) if contents is not None else None
        if data is not None:
            _expect(unit["byte_length"] == len(data), "UNIT_LENGTH_MISMATCH", f"byte_length for {unit['unit_id']}")
            _expect(
                unit["content_sha256"] == sha256_bytes(data),
                "UNIT_DIGEST_MISMATCH",
                f"content digest for {unit['unit_id']}",
            )
            _expect(
                unit["line_count"] == line_count(data),
                "UNIT_LINE_COUNT_MISMATCH",
                f"line count for {unit['unit_id']}",
            )
    else:
        _expect(bool(unit.get("reason_codes")), "UNIT_REASON_MISSING", f"{unit['unit_id']} lacks a reason code")
        for forbidden in ("byte_length", "line_count", "content_sha256"):
            _expect(forbidden not in unit, "UNIT_CONTENT_LEAK", f"{unit['unit_id']} records {forbidden} despite non-inspection")


def _validate_finding(finding: dict, units: Mapping[str, dict], contents: Mapping[str, bytes] | None) -> None:
    unit = units.get(finding["unit_id"])
    _expect(unit is not None, "FINDING_UNIT_UNKNOWN", f"finding {finding['finding_id']} refers to an unknown unit")
    _expect(
        unit["disposition"] == "INSPECTED",
        "FINDING_OUTSIDE_INSPECTION",
        f"finding {finding['finding_id']} is attached to a non-inspected unit",
    )
    start, end = finding["start_byte"], finding["end_byte"]
    _expect(start < end, "FINDING_RANGE_INVALID", f"finding {finding['finding_id']} has an empty/reversed range")
    _expect(end <= unit["byte_length"], "FINDING_RANGE_OUTSIDE_UNIT", f"finding {finding['finding_id']} exceeds unit bytes")
    _expect(finding["line"] <= unit["line_count"], "FINDING_LINE_OUTSIDE_UNIT", f"finding {finding['finding_id']} line exceeds unit")
    if "line_end" in finding:
        _expect(
            finding["line"] <= finding["line_end"] <= unit["line_count"],
            "FINDING_LINE_RANGE_INVALID",
            f"finding {finding['finding_id']} has an invalid line range",
        )
    expected_id = make_finding_id(
        finding["unit_id"],
        finding["rule_id"],
        finding["rule_version"],
        start,
        end,
        finding["evidence_digest"],
    )
    _expect(
        finding["finding_id"] == expected_id,
        "FINDING_ID_MISMATCH",
        f"finding {finding['finding_id']} does not match its canonical identity",
    )
    data = contents.get(unit["unit_id"]) if contents is not None else None
    if data is not None:
        _expect(
            finding["line"] == line_for_offset(data, start),
            "FINDING_LINE_MISMATCH",
            f"finding {finding['finding_id']} line does not match its byte offset",
        )
        if "line_end" in finding:
            last = end - 1
            while last > start and data[last] in (10, 13):
                last -= 1
            _expect(
                finding["line_end"] == line_for_offset(data, last),
                "FINDING_LINE_MISMATCH",
                f"finding {finding['finding_id']} line_end does not match its byte range",
            )
        _expect(
            finding["evidence_digest"] == sha256_bytes(data[start:end]),
            "FINDING_EVIDENCE_MISMATCH",
            f"finding {finding['finding_id']} evidence digest does not match content",
        )


def _validate_policy(
    policy: dict,
    units: Mapping[str, dict],
    findings: Mapping[str, dict],
) -> None:
    policies = policy["effective_policies"]
    _expect(
        policy["effective_policy_digest"] == record_digest(policies),
        "POLICY_DIGEST_MISMATCH",
        "effective_policy_digest does not cover the effective_policies array",
    )
    by_policy: dict[str, dict] = {}
    for entry in policies:
        policy_id = entry["policy_id"]
        _expect(policy_id not in by_policy, "POLICY_DUPLICATE", f"duplicate effective policy {policy_id}")
        _expect(
            not entry["mandatory"] or entry["origin"] == "global",
            "POLICY_MANDATORY_ORIGIN",
            f"mandatory policy {policy_id} must originate globally",
        )
        by_policy[policy_id] = entry

    requests = policy["requests"]
    by_request: dict[str, dict] = {}
    for request in requests:
        request_id = request["request_id"]
        _expect(request_id not in by_request, "REQUEST_DUPLICATE", f"duplicate request {request_id}")
        effective = by_policy.get(request["policy_id"])
        _expect(effective is not None, "REQUEST_POLICY_UNKNOWN", f"request {request_id} uses an unknown policy")
        _expect(
            effective["origin"] == request["origin"],
            "REQUEST_ORIGIN_MISMATCH",
            f"request {request_id} origin disagrees with the effective policy",
        )
        if request["status"] == "APPLIED":
            _expect(
                len(request.get("matched_unit_ids", [])) + len(request.get("matched_finding_ids", [])) > 0,
                "REQUEST_APPLIED_EMPTY",
                f"applied request {request_id} matched nothing",
            )
            if request["kind"] == "BLOCK":
                _expect(
                    not request.get("matched_finding_ids"),
                    "REQUEST_KIND_MISMATCH",
                    f"block request {request_id} carries finding matches",
                )
                for unit_id in request["matched_unit_ids"]:
                    _expect(
                        units.get(unit_id, {}).get("disposition") == "VERIFIED_BLOCKED",
                        "REQUEST_BLOCK_NOT_BLOCKED",
                        f"request {request_id} claims a block on a non-blocked unit",
                    )
            else:
                _expect(
                    not request.get("matched_unit_ids"),
                    "REQUEST_KIND_MISMATCH",
                    f"exemption request {request_id} carries unit matches",
                )
                for finding_id in request["matched_finding_ids"]:
                    _expect(finding_id in findings, "REQUEST_EXEMPTION_FINDING_UNKNOWN", f"request {request_id} refers to an unknown finding")
        by_request[request_id] = request

    blocked = {unit_id: unit for unit_id, unit in units.items() if unit["disposition"] == "VERIFIED_BLOCKED"}
    applied_blocks = policy["applied_blocks"]
    applied_ids = [entry["unit_id"] for entry in applied_blocks]
    _expect(len(set(applied_ids)) == len(applied_ids), "BLOCK_DUPLICATE", "a unit has more than one applied block")
    _expect(set(applied_ids) == set(blocked), "BLOCK_RECONCILIATION", "blocked units and applied block events differ")
    for event in applied_blocks:
        request = by_request.get(event["request_id"])
        _expect(request is not None, "BLOCK_REQUEST_UNKNOWN", f"block event {event['unit_id']} has no request")
        _expect(request["kind"] == "BLOCK" and request["status"] == "APPLIED", "BLOCK_REQUEST_NOT_APPLIED", "block event does not reference an applied block request")
        _expect(event["unit_id"] in request.get("matched_unit_ids", []), "BLOCK_REQUEST_MISMATCH", "block event is not listed by its request")
        _expect(event["policy_id"] == request["policy_id"], "BLOCK_POLICY_MISMATCH", "block event policy differs from its request")
        _expect(event["origin"] == request["origin"], "BLOCK_ORIGIN_MISMATCH", "block event origin differs from its request")
        _expect(event["reason"] == request["reason"], "BLOCK_REASON_MISMATCH", "block event reason differs from its request")
        _expect(event["verified_non_access"] is True, "BLOCK_UNVERIFIED", "block event lacks verified non-access")

    for request in requests:
        if request["kind"] == "BLOCK" and request["status"] == "APPLIED":
            expected = {event["unit_id"] for event in applied_blocks if event["request_id"] == request["request_id"]}
            _expect(
                expected == set(request["matched_unit_ids"]),
                "BLOCK_REQUEST_EVIDENCE_MISMATCH",
                f"block request {request['request_id']} and applied blocks differ",
            )

    dispositions = policy["dispositions"]
    disposition_ids = [entry["finding_id"] for entry in dispositions]
    _expect(len(set(disposition_ids)) == len(disposition_ids), "DISPOSITION_DUPLICATE", "a finding has more than one disposition")
    _expect(set(disposition_ids) == set(findings), "DISPOSITION_RECONCILIATION", "findings and dispositions differ")
    exempted_requests: dict[str, set[str]] = {}
    for entry in dispositions:
        if entry["status"] == "ACTIONABLE":
            _expect(
                not any(key in entry for key in ("policy_id", "origin", "reason", "request_id")),
                "ACTIONABLE_POLICY_FIELDS",
                "an ACTIONABLE disposition must not claim an applied policy",
            )
            continue
        request = by_request.get(entry["request_id"])
        _expect(request is not None, "EXEMPTION_REQUEST_UNKNOWN", "exempted finding has no exemption request")
        _expect(request["kind"] == "EXEMPTION" and request["status"] == "APPLIED", "EXEMPTION_REQUEST_NOT_APPLIED", "exemption does not reference an applied exemption request")
        _expect(entry["finding_id"] in request.get("matched_finding_ids", []), "EXEMPTION_REQUEST_MISMATCH", "exemption is not listed by its request")
        _expect(entry["policy_id"] == request["policy_id"], "EXEMPTION_POLICY_MISMATCH", "exemption policy differs from its request")
        _expect(entry["origin"] == request["origin"], "EXEMPTION_ORIGIN_MISMATCH", "exemption origin differs from its request")
        exempted_requests.setdefault(request["request_id"], set()).add(entry["finding_id"])
    for request in requests:
        if request["kind"] == "EXEMPTION" and request["status"] == "APPLIED":
            _expect(
                exempted_requests.get(request["request_id"], set()) == set(request["matched_finding_ids"]),
                "EXEMPTION_REQUEST_EVIDENCE_MISMATCH",
                f"exemption request {request['request_id']} and dispositions differ",
            )


def compute_counts(
    units: Iterable[dict],
    findings: Iterable[dict],
    dispositions: Iterable[dict],
) -> dict[str, int]:
    unit_list = list(units)
    finding_list = list(findings)
    disposition_list = list(dispositions)
    required = [unit for unit in unit_list if unit["required_scope"]]
    return {
        "discovered": len(unit_list),
        "inspected": sum(unit["disposition"] == "INSPECTED" for unit in unit_list),
        "verified_blocked": sum(unit["disposition"] == "VERIFIED_BLOCKED" for unit in unit_list),
        "uninspected": sum(unit["disposition"] == "UNINSPECTED" for unit in unit_list),
        "required_discovered": len(required),
        "required_inspected": sum(unit["disposition"] == "INSPECTED" for unit in required),
        "required_verified_blocked": sum(unit["disposition"] == "VERIFIED_BLOCKED" for unit in required),
        "required_uninspected": sum(unit["disposition"] == "UNINSPECTED" for unit in required),
        "detected": len(finding_list),
        "actionable": sum(entry["status"] == "ACTIONABLE" for entry in disposition_list),
        "exempted": sum(entry["status"] == "EXEMPTED" for entry in disposition_list),
    }


def classify(execution: dict, policy: dict, counts: Mapping[str, int]) -> int:
    if (
        not policy["policy_valid"]
        or execution["state"] != "COMPLETED"
        or bool(execution["fatal_errors"])
    ):
        return 5
    if counts["required_discovered"] == 0:
        return 4
    if counts["required_uninspected"] > 0 or not execution["evidence_valid"]:
        return 4
    if counts["actionable"] > 0:
        return 3
    if counts["verified_blocked"] > 0 or counts["exempted"] > 0:
        return 2
    return 1


def coverage_for(code: int, counts: Mapping[str, int]) -> str:
    if code == 5:
        return "UNVERIFIED"
    if code == 4:
        return "NONE" if counts["required_inspected"] + counts["required_verified_blocked"] == 0 else "PARTIAL"
    if counts["verified_blocked"] > 0 or counts["exempted"] > 0:
        return "COMPLETE_POLICY_ADJUSTED"
    return "COMPLETE"


def reason_codes_for(execution: dict, policy: dict, counts: Mapping[str, int], code: int) -> list[str]:
    if code == 5:
        return sorted(set(execution["failure_codes"] or policy.get("errors") or ["EXECUTION_FAILURE"]))
    if code == 4:
        if counts["required_discovered"] == 0:
            return ["NO_REQUIRED_SCOPE"]
        if counts["required_uninspected"] > 0:
            return ["REQUIRED_COVERAGE_INCOMPLETE"]
        return ["EVIDENCE_UNVERIFIED"]
    return []


def ci_decision(
    result_code: int,
    accepted: set[int] | frozenset[int] = DEFAULT_ACCEPTED,
    *,
    run_id: str = "cp0-run",
    result_digest: str = "sha256:" + "0" * 64,
) -> dict:
    _expect(result_code in RESULT_NAMES, "RESULT_CODE_INVALID", f"unknown result code {result_code}")
    _expect(accepted.issubset({1, 2, 3}), "CI_ACCEPTANCE_INVALID", "only completed result codes 1-3 may be accepted")
    if result_code == 4:
        exit_code = 20
    elif result_code == 5:
        exit_code = 30
    else:
        exit_code = 0 if result_code in accepted else REJECTED_COMPLETED_EXIT
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "result_code": result_code,
        "result_digest": result_digest,
        "accepted_result_codes": sorted(accepted),
        "accepted": exit_code == 0,
        "process_exit_code": exit_code,
    }


def validate_records(
    execution: dict,
    findings: list[dict],
    policy: dict,
    result: dict | None = None,
    ci: dict | None = None,
    *,
    contents: Mapping[str, bytes] | None = None,
    check_order: bool = True,
) -> dict:
    """Validate schemas and all cross-record invariants.

    ``contents`` is keyed by ``unit_id`` and lets a reporting/harness validator
    prove byte ranges, line numbers, line counts and evidence digests against
    the actual inspected bytes. It is optional for reporters that only hold
    derived records.
    """
    schemas, registry = schema_registry()
    schema_check(execution, "execution.schema.json", schemas, registry)
    schema_check(policy, "policy.schema.json", schemas, registry)
    for finding in findings:
        schema_check(finding, "finding.schema.json", schemas, registry)
    if result is not None:
        schema_check(result, "result.schema.json", schemas, registry)
    if ci is not None:
        schema_check(ci, "ci-decision.schema.json", schemas, registry)

    run_id = execution["run_id"]
    _expect(policy["run_id"] == run_id, "RUN_ID_MISMATCH", "policy run_id differs")
    _expect(all(finding["run_id"] == run_id for finding in findings), "RUN_ID_MISMATCH", "finding run_id differs")
    if result is not None:
        _expect(result["run_id"] == run_id, "RUN_ID_MISMATCH", "result run_id differs")
    if ci is not None:
        _expect(ci["run_id"] == run_id, "RUN_ID_MISMATCH", "CI decision run_id differs")

    if check_order:
        _canonical_order("units", execution["units"], key=lambda unit: unit["unit_id"])
        _canonical_order(
            "findings",
            findings,
            key=lambda finding: (
                finding["unit_id"],
                finding["start_byte"],
                finding["end_byte"],
                finding["rule_id"],
                finding["rule_version"],
                finding["finding_id"],
            ),
        )
        _canonical_order("effective policies", policy["effective_policies"], key=lambda entry: entry["policy_id"])
        _canonical_order("policy requests", policy["requests"], key=lambda entry: entry["request_id"])
        _canonical_order("applied blocks", policy["applied_blocks"], key=lambda entry: (entry["unit_id"], entry["request_id"]))
        _canonical_order("dispositions", policy["dispositions"], key=lambda entry: entry["finding_id"])

    _expect(
        not execution["fatal_errors"] or execution["state"] != "COMPLETED",
        "EXECUTION_STATE_CONTRADICTION",
        "fatal errors cannot coexist with a COMPLETED state",
    )
    if execution["state"] == "COMPLETED":
        _expect(not execution["failure_codes"], "EXECUTION_FAILURE_CODES", "completed execution carries failure codes")
    _expect(
        policy["policy_valid"] != bool(policy.get("errors")),
        "POLICY_ERROR_STATE",
        "policy_valid and policy errors contradict each other",
    )

    units = {unit["unit_id"]: unit for unit in execution["units"]}
    _expect(len(units) == len(execution["units"]), "UNIT_DUPLICATE", "duplicate unit_id")
    _expect(
        all(unit["run_id"] == run_id for unit in execution["units"]),
        "RUN_ID_MISMATCH",
        "source unit run_id differs",
    )
    _expect(
        all(finding["schema_version"] == SCHEMA_VERSION for finding in findings),
        "SCHEMA_VERSION_MISMATCH",
        "finding schema version differs",
    )
    _expect(
        all(unit["schema_version"] == SCHEMA_VERSION for unit in execution["units"]),
        "SCHEMA_VERSION_MISMATCH",
        "unit schema version differs",
    )
    locator_keys = {(unit["source_id"], unit["locator"].replace("\\", "/")) for unit in execution["units"]}
    _expect(len(locator_keys) == len(execution["units"]), "UNIT_SOURCE_DUPLICATE", "duplicate source identity")
    for unit in execution["units"]:
        _validate_unit(unit, contents)

    finding_map = {finding["finding_id"]: finding for finding in findings}
    _expect(len(finding_map) == len(findings), "FINDING_DUPLICATE", "duplicate finding_id")
    for finding in findings:
        _validate_finding(finding, units, contents)

    _validate_policy(policy, units, finding_map)

    counts = compute_counts(execution["units"], findings, policy["dispositions"])
    code = classify(execution, policy, counts)
    coverage = coverage_for(code, counts)
    reasons = reason_codes_for(execution, policy, counts, code)
    expected_records = {
        "execution_digest": record_digest(execution),
        "findings_digest": record_digest(findings),
        "policy_digest": record_digest(policy),
    }

    if result is not None:
        _expect(result["counts"] == counts, "RESULT_COUNT_MISMATCH", "result counts do not reconcile to the records")
        _expect(result["result_code"] == code, "RESULT_PRECEDENCE_MISMATCH", f"expected result code {code}, found {result['result_code']}")
        _expect(result["result"] == RESULT_NAMES[code], "RESULT_NAME_MISMATCH", "result name does not match result code")
        _expect(result["coverage"] == coverage, "RESULT_COVERAGE_MISMATCH", f"expected coverage {coverage}")
        _expect(result["evidence_valid"] == execution["evidence_valid"], "RESULT_EVIDENCE_MISMATCH", "result evidence flag differs")
        _expect(result["engine_version"] == execution["engine_version"], "RESULT_ENGINE_MISMATCH", "engine version differs")
        _expect(result["ruleset_id"] == execution["ruleset_id"], "RESULT_RULESET_MISMATCH", "ruleset ID differs")
        _expect(result["ruleset_digest"] == execution["ruleset_digest"], "RESULT_RULESET_MISMATCH", "ruleset digest differs")
        _expect(result["source_adapter"] == execution["source_adapter"], "RESULT_ADAPTER_MISMATCH", "source adapter differs")
        _expect(result["records"] == expected_records, "RESULT_RECORD_DIGEST_MISMATCH", "result does not commit to the exact records")
        _expect(result["reason_codes"] == sorted(result["reason_codes"]), "ORDER_NON_DETERMINISTIC", "reason codes are not sorted")
        if code in (4, 5):
            _expect(bool(result["reason_codes"]), "RESULT_REASON_MISSING", "incomplete/failed result lacks a reason")
        else:
            _expect(result["reason_codes"] == reasons, "RESULT_REASON_UNEXPECTED", "completed result carries a failure reason")

    if ci is not None:
        _expect(result is not None, "CI_WITHOUT_RESULT", "CI decision requires the immutable result")
        _expect(ci["result_code"] == result["result_code"], "CI_RESULT_MISMATCH", "CI result code differs from the finalized result")
        _expect(ci["result_digest"] == record_digest(result), "CI_RESULT_DIGEST_MISMATCH", "CI decision does not reference the exact result")
        _expect(ci["accepted_result_codes"] == sorted(ci["accepted_result_codes"]), "ORDER_NON_DETERMINISTIC", "accepted result codes are not sorted")
        expected_accepted = result["result_code"] in ci["accepted_result_codes"] and result["result_code"] <= 3
        _expect(ci["accepted"] == expected_accepted, "CI_ACCEPTANCE_MISMATCH", "accepted flag disagrees with the accepted set")
        expected_exit = PROCESS_EXITS.get(result["result_code"], 0 if expected_accepted else REJECTED_COMPLETED_EXIT)
        _expect(ci["process_exit_code"] == expected_exit, "CI_EXIT_MISMATCH", "process exit code disagrees with acceptance semantics")
        if result["result_code"] in (4, 5):
            _expect(not ci["accepted"], "CI_ACCEPTED_INCOMPLETE", "incomplete/failed results cannot be accepted")

    return {
        "run_id": run_id,
        "counts": counts,
        "result_code": code,
        "result": RESULT_NAMES[code],
        "coverage": coverage,
        "reason_codes": reasons,
        "records": expected_records,
    }


def assert_public_safe(value: Any, *, path: str = "$") -> None:
    """Reject likely secret bytes, private keys and locators in public documents."""
    if isinstance(value, dict):
        for key, child in value.items():
            _expect(key.lower() not in PUBLIC_FORBIDDEN_KEYS, "PUBLIC_PRIVATE_KEY", f"forbidden public key {key!r} at {path}")
            assert_public_safe(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_public_safe(child, path=f"{path}[{index}]")
    elif isinstance(value, str):
        for pattern in SECRET_SHAPED:
            _expect(not pattern.search(value), "PUBLIC_SECRET_SHAPED", f"secret-shaped value at {path}")
        _expect(not DRIVE_PATH.search(value), "PUBLIC_ABSOLUTE_PATH", f"absolute Windows path at {path}")
        _expect(not ABS_PATH_FRAGMENT.search(value), "PUBLIC_ABSOLUTE_PATH", f"absolute POSIX path at {path}")


def sorted_findings(findings: Iterable[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda finding: (
            finding["unit_id"],
            finding["start_byte"],
            finding["end_byte"],
            finding["rule_id"],
            finding["rule_version"],
            finding["finding_id"],
        ),
    )
