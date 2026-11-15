"""CP4C profile schema-v1 ingestion and validation.

The profile is an opt-in scanner performance artifact.  It contains phase names,
integer durations/counts, settings and run identity only.  This module validates
the complete schema-v1 shape before any profile value is used in analysis.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROFILE_SCHEMA_VERSION = "1"
DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "docs" / "contracts" / "profiler.schema.json"
)
_ALLOWED_STRATEGIES = {"regex", "regexset", "prefilter"}
_ALLOWED_MODES = {"auto", "whole", "stream"}
_ALLOWED_HISTORY_MODES = {"whole", "diff"}
_ALLOWED_GIT_IO = {"process", "batch"}


class ProfileError(ValueError):
    """A CP4C profile is missing, malformed, private, or inconsistent."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError(f"profile contains duplicate key {key!r}")
        result[key] = value
    return result


def load_profile(path: Path | str) -> dict[str, Any]:
    target = Path(path)
    try:
        text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(f"profile is unreadable: {exc}") from exc
    try:
        document = json.loads(text, object_pairs_hook=_pairs)
    except json.JSONDecodeError as exc:
        raise ProfileError(f"profile is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ProfileError("profile root is not an object")
    return document


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileError(message)


def _string_map(value: Any, label: str) -> dict[str, str]:
    _require(isinstance(value, dict), f"{label} is not an object")
    result: dict[str, str] = {}
    for key, item in value.items():
        _require(isinstance(key, str) and key, f"{label} has an invalid key")
        _require(
            isinstance(item, str) and len(item) <= 256,
            f"{label}.{key} is not a string of at most 256 characters",
        )
        result[key] = item
    return result


def _phase_stats(value: Any, label: str) -> None:
    _require(isinstance(value, dict), f"{label} is not an object")
    _require(
        set(value) == {"ns", "exclusive_ns", "count", "bytes"},
        f"{label} has unexpected or missing fields",
    )
    for field, item in value.items():
        _require(
            isinstance(item, int)
            and not isinstance(item, bool)
            and item >= 0,
            f"{label}.{field} is not a non-negative integer",
        )


def validate_profile(
    document: dict[str, Any],
    *,
    expected_run_id: str | None = None,
    expected_requested: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Validate schema-v1 and optional invocation identity/settings.

    Returns a compact validation record suitable for experiment JSON.
    """
    _require(isinstance(document, dict), "profile root is not an object")
    allowed_root = {
        "schema_version",
        "engine_version",
        "run_id",
        "settings",
        "phases",
        "worker_phases",
        "counters",
    }
    _require(
        set(document) == allowed_root,
        "profile root fields do not match schema version 1",
    )
    _require(
        document.get("schema_version") == PROFILE_SCHEMA_VERSION,
        "profile schema_version is not 1",
    )
    engine = document.get("engine_version")
    _require(
        isinstance(engine, str) and 1 <= len(engine) <= 64,
        "profile engine_version is invalid",
    )
    run_id = document.get("run_id")
    _require(
        isinstance(run_id, str) and 1 <= len(run_id) <= 4096,
        "profile run_id is invalid",
    )
    if expected_run_id is not None:
        _require(run_id == expected_run_id, "profile run_id does not match the invocation")

    settings = document.get("settings")
    _require(isinstance(settings, dict), "profile settings is not an object")
    _require(
        set(settings) == {"requested", "effective"},
        "profile settings fields do not match schema version 1",
    )
    requested = _string_map(settings["requested"], "settings.requested")
    effective = _string_map(settings["effective"], "settings.effective")
    _require(
        "workers" in requested and "workers" in effective,
        "profile settings do not record workers",
    )
    _require(
        effective["workers"] == requested["workers"],
        "effective worker count does not match requested worker count",
    )
    _require(
        effective.get("strategy") in _ALLOWED_STRATEGIES,
        "profile effective strategy is unsupported",
    )
    _require(
        effective.get("mode") in _ALLOWED_MODES,
        "profile effective mode is unsupported",
    )
    if "history_mode" in requested:
        _require(
            requested["history_mode"] in _ALLOWED_HISTORY_MODES,
            "profile history_mode is unsupported",
        )
    if "git_io" in requested:
        _require(
            requested["git_io"] in _ALLOWED_GIT_IO,
            "profile git_io is unsupported",
        )
    if expected_requested:
        for key, value in expected_requested.items():
            _require(
                requested.get(key) == value,
                f"profile requested {key} is {requested.get(key)!r}, expected {value!r}",
            )

    phases = document.get("phases")
    _require(isinstance(phases, dict), "profile phases is not an object")
    for name, stats in phases.items():
        _require(isinstance(name, str) and name, "profile has an invalid phase name")
        _phase_stats(stats, f"phases.{name}")
    _require("execution" in phases, "profile phases.execution is missing")

    worker_phases = document.get("worker_phases")
    _require(isinstance(worker_phases, dict), "profile worker_phases is not an object")
    for name, stats in worker_phases.items():
        _require(
            isinstance(name, str) and name,
            "profile has an invalid worker phase name",
        )
        _phase_stats(stats, f"worker_phases.{name}")

    counters = document.get("counters")
    _require(isinstance(counters, dict), "profile counters is not an object")
    for name, value in counters.items():
        _require(isinstance(name, str) and name, "profile has an invalid counter name")
        _require(
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0,
            f"counters.{name} is not a non-negative integer",
        )

    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "engine_version": engine,
        "run_id": run_id,
        "requested": requested,
        "effective": effective,
        "wall_phase_count": len(phases),
        "worker_phase_count": len(worker_phases),
        "counter_count": len(counters),
    }


def validate_profile_schema(
    document: dict[str, Any],
    *,
    schema_path: Path | str | None = None,
) -> dict[str, Any]:
    """Validate against the checked-in JSON Schema when jsonschema is present.

    The structural validator above remains authoritative for ingestion so the
    harness has no mandatory third-party dependency.  This is an additional
    schema-conformance check recorded in the experiment evidence.
    """
    target = Path(schema_path) if schema_path is not None else DEFAULT_SCHEMA_PATH
    try:
        import jsonschema
    except ImportError:
        return {
            "performed": False,
            "reason": "jsonschema is not installed",
            "schema_path": str(target),
        }
    try:
        schema = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {
            "performed": False,
            "reason": f"schema unavailable: {exc}",
            "schema_path": str(target),
        }
    try:
        jsonschema.Draft202012Validator(schema).validate(document)
    except jsonschema.ValidationError as exc:
        raise ProfileError(f"profile fails JSON Schema validation: {exc.message}") from exc
    try:
        from importlib.metadata import version

        jsonschema_version = version("jsonschema")
    except Exception:
        jsonschema_version = None
    return {
        "performed": True,
        "schema_path": str(target),
        "validator": "Draft202012",
        "jsonschema_version": jsonschema_version,
    }
