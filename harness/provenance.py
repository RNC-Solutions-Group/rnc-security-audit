"""Exact execution provenance and scanner-argument comparability policy.

The harness records argument vectors that were actually passed to the process.
This module owns the reusable pieces of that contract:

* a Windows/POSIX-safe splitter for the experiment-owned ``--scanner-args`` text;
* a scanner-neutral argument classification and reserved-flag policy;
* credential-safe argv rendering for JSON and human-readable reports;
* normalized command templates, clearly separate from the literal argv.

Detection configuration, execution/performance configuration, source scope and
reporting configuration are intentionally separate.  A performance-only
override does not silently change detection comparability; a scope, detection or
unknown override does.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from .safe_text import redact_text, safe_path, text

CATEGORY_PERFORMANCE = "PERFORMANCE"
CATEGORY_DETECTION = "DETECTION"
CATEGORY_SCOPE = "SCOPE"
CATEGORY_OUTPUT = "OUTPUT"
CATEGORY_SECURITY = "SECURITY"
CATEGORY_UNKNOWN = "UNKNOWN"

CATEGORIES = (
    CATEGORY_PERFORMANCE,
    CATEGORY_DETECTION,
    CATEGORY_SCOPE,
    CATEGORY_OUTPUT,
    CATEGORY_SECURITY,
    CATEGORY_UNKNOWN,
)

ORIGIN_CLI = "cli"
ORIGIN_MATRIX = "matrix"
ORIGIN_CONFIGURATION = "configuration"
ORIGIN_MANIFEST = "manifest"
ORIGIN_HARNESS = "harness-generated"
ORIGIN_ADAPTER = "adapter-generated"
ORIGIN_SCANNER_DEFAULT = "scanner-default"

COMPARABILITY_BASELINE = "BASELINE_COMPARABLE"
COMPARABILITY_PERFORMANCE = "PERFORMANCE_TUNED_BASELINE_DETECTION"
COMPARABILITY_OUTPUT = "DEFAULT_DETECTION_WITH_REPORTING_OVERRIDE"
COMPARABILITY_NOT_BASELINE = "NOT_BASELINE_COMPARABLE"
COMPARABILITY_EXPERIMENTAL = "EXPERIMENTAL_UNVERIFIED"

# Explicit credential-bearing switches.  Values are redacted, not removed: the
# report must preserve that the switch was supplied while withholding its value.
SENSITIVE_FLAGS = {
    "--secret",
    "--token",
    "--password",
    "--passphrase",
    "--api-key",
    "--apikey",
    "--access-key",
    "--access-token",
    "--client-secret",
    "--credential",
    "--credentials",
    "--auth",
    "--auth-token",
    "--bearer",
    "--header",
    "--headers",
    "--private-key",
    "--key",
}
_SENSITIVE_PREFIX = tuple(flag + "=" for flag in SENSITIVE_FLAGS)


@dataclass(frozen=True)
class _ArgumentSpec:
    category: str
    effect: str
    baseline_neutral: bool
    repeatable: bool = False


def _spec(category: str, effect: str, *, baseline_neutral: bool = False, repeatable: bool = False) -> _ArgumentSpec:
    return _ArgumentSpec(category, effect, baseline_neutral, repeatable)


_COMMON_SPECS: dict[str, _ArgumentSpec] = {
    "--workers": _spec(CATEGORY_PERFORMANCE, "worker fan-out", baseline_neutral=True),
    "--threads": _spec(CATEGORY_PERFORMANCE, "worker fan-out", baseline_neutral=True),
    "--concurrency": _spec(CATEGORY_PERFORMANCE, "worker fan-out", baseline_neutral=True),
    "--parallelism": _spec(CATEGORY_PERFORMANCE, "worker fan-out", baseline_neutral=True),
    "-j": _spec(CATEGORY_PERFORMANCE, "worker fan-out", baseline_neutral=True),
    "--profile": _spec(CATEGORY_PERFORMANCE, "profiling", baseline_neutral=True),
    "--profiler": _spec(CATEGORY_PERFORMANCE, "profiling", baseline_neutral=True),
    "--profile-output": _spec(CATEGORY_PERFORMANCE, "profiling output", baseline_neutral=True),
    "--cpu-profile": _spec(CATEGORY_PERFORMANCE, "profiling", baseline_neutral=True),
    "--mem-profile": _spec(CATEGORY_PERFORMANCE, "profiling", baseline_neutral=True),
    "--mode": _spec(CATEGORY_PERFORMANCE, "scan execution mode", baseline_neutral=True),
    "--strategy": _spec(CATEGORY_PERFORMANCE, "matching engine strategy", baseline_neutral=True),
    "--git-io": _spec(CATEGORY_PERFORMANCE, "Git acquisition backend", baseline_neutral=True),
    "--history-mode": _spec(CATEGORY_SCOPE, "Git history traversal mode"),
    "--timeout": _spec(CATEGORY_SECURITY, "execution time bound"),
    "--max-file-size": _spec(CATEGORY_SECURITY, "source size limit"),
    "--max-target-megabytes": _spec(CATEGORY_SECURITY, "source size limit"),
    "--max-archive-depth": _spec(CATEGORY_SECURITY, "archive acquisition bound"),
    "--max-decode-depth": _spec(CATEGORY_SECURITY, "encoding decode bound"),
    "--config": _spec(CATEGORY_DETECTION, "detection configuration"),
    "--rules": _spec(CATEGORY_DETECTION, "detection rule bundle"),
    "--rule": _spec(CATEGORY_DETECTION, "detection rule selection"),
    "--enable-rule": _spec(CATEGORY_DETECTION, "detection rule selection"),
    "--disable-rule": _spec(CATEGORY_DETECTION, "detection rule selection"),
    "--baseline-path": _spec(CATEGORY_DETECTION, "finding baseline"),
    "--source": _spec(CATEGORY_SCOPE, "source path"),
    "--no-git": _spec(CATEGORY_SCOPE, "Git history exclusion"),
    "--log-opts": _spec(CATEGORY_SCOPE, "Git history range"),
    "--include": _spec(CATEGORY_SCOPE, "source inclusion", repeatable=True),
    "--exclude": _spec(CATEGORY_SCOPE, "source exclusion", repeatable=True),
    "--platform": _spec(CATEGORY_SCOPE, "scanner platform scope"),
    "--history": _spec(CATEGORY_SCOPE, "Git history selection"),
    "--ref": _spec(CATEGORY_SCOPE, "Git ref selection"),
    "--report-format": _spec(CATEGORY_OUTPUT, "report format"),
    "--report-path": _spec(CATEGORY_OUTPUT, "report destination"),
    "--verbose": _spec(CATEGORY_OUTPUT, "verbose scanner output", baseline_neutral=True),
    "--redact": _spec(CATEGORY_OUTPUT, "report value redaction"),
    "--log-level": _spec(CATEGORY_OUTPUT, "scanner logging", baseline_neutral=True),
    "--no-banner": _spec(CATEGORY_OUTPUT, "banner suppression", baseline_neutral=True),
    "--exit-code": _spec(CATEGORY_OUTPUT, "scanner exit code"),
    "--network": _spec(CATEGORY_SECURITY, "container networking"),
    "--read-only": _spec(CATEGORY_SECURITY, "container filesystem mode"),
}

_SCANNER_SPECS: dict[str, dict[str, _ArgumentSpec]] = {
    "gitleaks": {
        **_COMMON_SPECS,
        "--no-git": _spec(CATEGORY_SCOPE, "filesystem-only scan"),
        "--log-opts": _spec(CATEGORY_SCOPE, "Git history range"),
        "--platform": _spec(CATEGORY_SCOPE, "scan platform"),
        "--max-archive-depth": _spec(CATEGORY_SECURITY, "archive acquisition bound"),
        "--max-decode-depth": _spec(CATEGORY_SECURITY, "encoding decode bound"),
    },
    "betterleaks": {
        **_COMMON_SPECS,
        "--no-git": _spec(CATEGORY_SCOPE, "filesystem-only scan"),
        "--log-opts": _spec(CATEGORY_SCOPE, "Git history range"),
        "--platform": _spec(CATEGORY_SCOPE, "scan platform"),
    },
    "rnc": {
        **_COMMON_SPECS,
        "--root": _spec(CATEGORY_SCOPE, "source root"),
        "--output": _spec(CATEGORY_OUTPUT, "report destination"),
        "--format": _spec(CATEGORY_OUTPUT, "report format"),
        "--run-id": _spec(CATEGORY_OUTPUT, "scanner run identity"),
        "--profile-output": _spec(CATEGORY_PERFORMANCE, "profiling output", baseline_neutral=True),
    },
}

_RESERVED: dict[str, set[str]] = {
    "gitleaks": {
        "--config",
        "--source",
        "--report-format",
        "--report-path",
        "--exit-code",
        "--no-banner",
        "--redact",
    },
    "betterleaks": {
        "--config",
        "--source",
        "--report-format",
        "--report-path",
        "--exit-code",
        "--no-banner",
        "--redact",
    },
    "rnc": {
        "--config",
        "--rules",
        "--root",
        "--output",
        "--format",
        "--run-id",
        "--history",
        "--ref",
    },
}

_BOOLEAN_FLAGS = {
    "--no-git",
    "--history",
    "--verbose",
    "--redact",
    "--no-banner",
    "--read-only",
    "--profiler",
}

_EFFECT_LIMITS = {
    CATEGORY_DETECTION: "detection configuration",
    CATEGORY_SCOPE: "source scope",
    CATEGORY_UNKNOWN: "unverified scanner behaviour",
    CATEGORY_SECURITY: "source/security limits",
}


class ArgumentPolicyError(ValueError):
    """An experiment-owned scanner argument vector is unsafe or inconsistent."""


@dataclass
class ArgumentRecord:
    index: int
    token: str
    flag: str
    value: str | None
    category: str
    effect: str
    origin: str
    accepted: bool | None = True
    effective: str | None = None
    effective_source: str = "not observable from retained artifact"
    baseline_neutral: bool = False
    redacted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "token": self.token,
            "flag": self.flag,
            "value": self.value,
            "category": self.category,
            "effect": self.effect,
            "origin": self.origin,
            "accepted": self.accepted,
            "effective": self.effective,
            "effective_source": self.effective_source,
            "baseline_neutral": self.baseline_neutral,
            "redacted": self.redacted,
        }


@dataclass
class ArgumentPolicy:
    adapter: str
    profile: str
    origin: str
    arguments: list[ArgumentRecord] = field(default_factory=list)
    categories: dict[str, int] = field(default_factory=dict)
    detection_configuration: str = "DEFAULT"
    execution_configuration: str = "DEFAULT"
    source_scope_configuration: str = "DEFAULT"
    reporting_configuration: str = "HARNESS_CONTROLLED"
    comparability: str = COMPARABILITY_BASELINE
    baseline_metrics_included: bool = True
    baseline_detection_comparable: bool = True
    reasons: list[str] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "adapter": self.adapter,
            "profile": self.profile,
            "argument_origin": self.origin,
            "detection_configuration": self.detection_configuration,
            "execution_configuration": self.execution_configuration,
            "source_scope_configuration": self.source_scope_configuration,
            "reporting_configuration": self.reporting_configuration,
            "comparability": self.comparability,
            "baseline_metrics_included": self.baseline_metrics_included,
            "baseline_detection_comparable": self.baseline_detection_comparable,
            "categories": dict(self.categories),
            "arguments": [item.to_dict() for item in self.arguments],
            "reasons": list(self.reasons),
            "rejected": list(self.rejected),
        }


def split_arguments(value: str | None) -> tuple[str, ...]:
    """Split a shell-like argument string without corrupting Windows paths.

    POSIX ``shlex.split`` treats every backslash as an escape, which turns an
    unquoted ``C:\\temp`` into ``C:temp``.  This splitter treats backslashes as
    literal unless they escape whitespace, a quote, or another backslash.
    Single quotes are literal, double quotes group whitespace, and an unterminated
    quote is an error rather than a silently truncated vector.
    """
    if value is None or not value.strip():
        return ()
    result: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    length = len(value)
    started = False
    while index < length:
        char = value[index]
        if quote == "'":
            if char == "'":
                quote = None
            else:
                current.append(char)
            index += 1
            continue
        if quote == '"':
            if char == '"':
                quote = None
                index += 1
                continue
            if char == "\\" and index + 1 < length and value[index + 1] in ('"', "\\", " "):
                current.append(value[index + 1])
                index += 2
                continue
            current.append(char)
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            started = True
            index += 1
            continue
        if char.isspace():
            if current or started:
                result.append("".join(current))
                current = []
                started = False
            index += 1
            continue
        if char == "\\" and index + 1 < length and value[index + 1].isspace():
            current.append(value[index + 1])
            started = True
            index += 2
            continue
        current.append(char)
        started = True
        index += 1
    if quote is not None:
        raise ArgumentPolicyError("unterminated quote in --scanner-args")
    if current or started:
        result.append("".join(current))
    return tuple(result)


def _option_parts(token: str) -> tuple[str, str | None]:
    if token.startswith("--") and "=" in token:
        name, value = token.split("=", 1)
        return name, value
    return token, None


def _parse_arguments(
    adapter: str,
    arguments: Sequence[str],
) -> list[tuple[int, str, str | None]]:
    """Return ``(argv index, flag, value)`` for supplied scanner arguments."""
    specs = _SCANNER_SPECS.get(adapter, _COMMON_SPECS)
    reserved = _RESERVED.get(adapter, set())
    parsed: list[tuple[int, str, str | None]] = []
    seen: dict[str, int] = {}
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            raise ArgumentPolicyError(
                "positional scanner arguments after '--' are not supported; use explicit flags"
            )
        if not token.startswith("-"):
            raise ArgumentPolicyError(
                f"positional scanner argument {token!r} is not supported; "
                "use explicit flags so scope and precedence remain auditable"
            )
        name, inline = _option_parts(token)
        if name in reserved:
            raise ArgumentPolicyError(
                f"scanner argument {name!r} is harness-controlled and cannot be "
                "overridden through --scanner-args"
            )
        if name != token:
            if inline is None or inline == "":
                raise ArgumentPolicyError(f"scanner argument {name!r} has an empty value")
            value: str | None = inline
            consumed = 1
        elif name in _BOOLEAN_FLAGS:
            value = None
            consumed = 1
        elif index + 1 < len(arguments) and not arguments[index + 1].startswith("-"):
            value = arguments[index + 1]
            consumed = 2
        else:
            value = None
            consumed = 1
        if name in seen and not specs.get(name, _spec(CATEGORY_UNKNOWN, "unknown")).repeatable:
            raise ArgumentPolicyError(
                f"scanner argument {name!r} is repeated; conflicting or duplicate "
                "values are rejected rather than silently resolved"
            )
        seen[name] = index
        parsed.append((index, name, value))
        index += consumed
    return parsed


def _redact_value(flag: str, value: str | None) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    if flag.lower() in SENSITIVE_FLAGS:
        return "<redacted>", True
    redacted = redact_text(value)
    if redacted != value:
        return redacted, True
    return value, False


def redact_argv(argv: Sequence[str]) -> tuple[list[str], list[int]]:
    """Redact explicit credential-bearing argument values and URL userinfo.

    The returned indexes identify values that were changed.  A separate digest of
    the unredacted vector is retained by the invocation record.
    """
    rendered: list[str] = []
    redactions: list[int] = []
    redact_next = False
    for index, argument in enumerate(argv):
        if redact_next:
            rendered.append("<redacted>")
            redactions.append(index)
            redact_next = False
            continue
        lowered = argument.lower()
        if lowered in SENSITIVE_FLAGS:
            rendered.append(argument)
            redact_next = True
            continue
        prefix = next((flag for flag in _SENSITIVE_PREFIX if lowered.startswith(flag)), None)
        if prefix is not None:
            rendered.append(argument[: argument.index("=") + 1] + "<redacted>")
            redactions.append(index)
            continue
        if lowered.startswith("--scanner-args="):
            embedded = argument.split("=", 1)[1]
            try:
                nested = split_arguments(embedded)
            except ArgumentPolicyError:
                nested = ()
            nested_redacted, nested_indexes = redact_argv(nested)
            if nested_indexes:
                rendered.append(
                    "--scanner-args=" + shlex.join(nested_redacted)
                )
                redactions.append(index)
                continue
        sanitized = redact_text(argument)
        if sanitized != argument:
            rendered.append(sanitized)
            redactions.append(index)
            continue
        rendered.append(argument)
    return rendered, redactions


def build_argument_policy(
    adapter: str,
    arguments: Sequence[str],
    *,
    profile: str = "default",
    origin: str = ORIGIN_CLI,
) -> ArgumentPolicy:
    """Classify supplied arguments and decide baseline comparability.

    Reserved flags raise :class:`ArgumentPolicyError` before any scanner process
    is launched.  Unknown flags are recorded but cannot inherit baseline
    comparability.
    """
    parsed = _parse_arguments(adapter, arguments)
    specs = _SCANNER_SPECS.get(adapter, _COMMON_SPECS)
    records: list[ArgumentRecord] = []
    categories: dict[str, int] = {}
    for index, flag, value in parsed:
        spec = specs.get(flag, _spec(CATEGORY_UNKNOWN, "unregistered scanner argument"))
        redacted_value, was_redacted = _redact_value(flag, value)
        token = flag if redacted_value is None else f"{flag} {redacted_value}"
        record = ArgumentRecord(
            index=index,
            token=token,
            flag=flag,
            value=redacted_value,
            category=spec.category,
            effect=spec.effect,
            origin=origin,
            accepted=None,
            effective=None,
            baseline_neutral=spec.baseline_neutral,
            redacted=was_redacted,
        )
        records.append(record)
        categories[spec.category] = categories.get(spec.category, 0) + 1

    if profile.lower() == "custom":
        detection = "CUSTOM"
    else:
        detection = "DEFAULT"
    execution = "EXPLICIT" if records else "DEFAULT"
    scope = "EXPLICIT" if CATEGORY_SCOPE in categories else "DEFAULT"
    reporting = "EXPLICIT_NON_CRITICAL" if CATEGORY_OUTPUT in categories else "HARNESS_CONTROLLED"

    limiting = [
        category
        for category in (CATEGORY_DETECTION, CATEGORY_SCOPE, CATEGORY_UNKNOWN, CATEGORY_SECURITY)
        if category in categories
    ]
    baseline_detection = detection == "DEFAULT" and not limiting
    baseline_metrics = bool(baseline_detection)
    reasons: list[str] = []
    if detection == "CUSTOM":
        reasons.append("CUSTOM profile is excluded from DEFAULT baseline metrics.")
    for category in limiting:
        reasons.append(
            f"{category.lower()} arguments change or may change detection/source comparability: "
            f"{', '.join(record.flag for record in records if record.category == category)}"
        )
    if CATEGORY_UNKNOWN in categories:
        comparability = COMPARABILITY_EXPERIMENTAL
    elif not baseline_detection:
        comparability = COMPARABILITY_NOT_BASELINE
    elif CATEGORY_PERFORMANCE in categories:
        comparability = COMPARABILITY_PERFORMANCE
        reasons.append(
            "Performance/execution settings are explicit; detection configuration remains the registered DEFAULT."
        )
    elif CATEGORY_OUTPUT in categories:
        comparability = COMPARABILITY_OUTPUT
    else:
        comparability = COMPARABILITY_BASELINE
    return ArgumentPolicy(
        adapter=adapter,
        profile=profile.lower(),
        origin=origin,
        arguments=records,
        categories=categories,
        detection_configuration=detection,
        execution_configuration=execution,
        source_scope_configuration=scope,
        reporting_configuration=reporting,
        comparability=comparability,
        baseline_metrics_included=baseline_metrics,
        baseline_detection_comparable=baseline_detection,
        reasons=reasons,
    )


def _powershell_quote(value: str) -> str:
    if value and re.fullmatch(r"<[A-Z_]+>", value):
        return value
    if value and re.fullmatch(r"[A-Za-z0-9_./:@%+=,-]+", value):
        return value
    return "'" + value.replace("'", "''") + "'"


def render_command(argv: Sequence[str], *, shell: str = "powershell") -> str:
    """Render an argv for display.  This is presentation, never execution."""
    items = [str(item) for item in argv]
    if shell == "posix":
        return shlex.join(items)
    return " ".join(_powershell_quote(item) for item in items)


def normalize_command(
    argv: Sequence[str],
    replacements: Sequence[tuple[str, str]],
) -> str:
    """Return a clearly labelled template by replacing volatile path values.

    The template is derived from the actual argv, but it is never represented as
    the literal command that was executed.
    """
    ordered = sorted(
        ((str(value), label) for value, label in replacements if value),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    normalized: list[str] = []
    for item in argv:
        rendered = str(item)
        for value, label in ordered:
            rendered = rendered.replace(value, label)
        normalized.append(rendered)
    return render_command(normalized)


def command_digest(argv: Sequence[str]) -> str:
    import hashlib

    return hashlib.sha256(
        json.dumps(list(argv), separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def invocation_sequence_label(experiment_id: str, sequence: int) -> str:
    return f"{experiment_id}-inv-{sequence:04d}"


def lane_for_workload(workload: str | None, suite: str | None = None) -> str:
    value = (workload or "").lower()
    if not value and not suite:
        return "not-applicable"
    if "git" in value or "history" in value:
        return "git-history"
    if "filesystem" in value or "levain" in value or "leaky" in value:
        return "filesystem"
    if suite in ("git-history",):
        return "git-history"
    return "filesystem"


def load_profile_from_workload(workload: str | None) -> str | None:
    value = (workload or "").lower()
    for marker in ("legacy-5x", "legacy-10x"):
        if marker in value:
            return marker
    return None


def normalize_replacements(
    *,
    repo_root: Path | str | None = None,
    workspace_root: Path | str | None = None,
    target_path: Path | str | None = None,
    report_path: Path | str | None = None,
    config_path: Path | str | None = None,
    run_id: str | None = None,
) -> list[tuple[str, str]]:
    replacements: list[tuple[str, str]] = []
    if target_path:
        replacements.append((str(target_path), "<TARGET>"))
    if report_path:
        replacements.append((str(report_path), "<REPORT>"))
    if config_path:
        replacements.append((str(config_path), "<CONFIG>"))
    if workspace_root:
        replacements.append((str(workspace_root), "<WORKSPACE>"))
    if repo_root:
        replacements.append((str(repo_root), "<REPO>"))
    if run_id:
        replacements.append((str(run_id), "<RUN_ID>"))
    return replacements


def sanitized_cwd(value: Path | str | None) -> str:
    if value is None or str(value) == "":
        return ""
    return safe_path(value)


def environment_record(
    cleared: Iterable[str] = (),
    overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    safe_overrides = {
        key: text(value)
        for key, value in (overrides or {}).items()
        if not any(marker in key.upper() for marker in ("TOKEN", "SECRET", "PASSWORD", "KEY", "AUTH"))
    }
    return {
        "origin": ORIGIN_HARNESS,
        "cleared_config_keys": sorted(str(item) for item in cleared),
        "explicit_overrides": safe_overrides,
        "sensitive_values_recorded": False,
    }


def artifact_identity(artifact: Any) -> dict[str, Any]:
    metadata = (getattr(artifact, "metadata", None) or {}) if artifact is not None else {}
    platform = getattr(artifact, "platform", None) if artifact is not None else None
    return {
        "kind": "docker" if platform is not None and platform.is_docker else "executable",
        "executable": safe_path(getattr(artifact, "artifact_path", None)) if artifact is not None else None,
        "executable_sha256": getattr(artifact, "artifact_sha256", None) if artifact is not None else None,
        "docker_image": getattr(artifact, "image_tag", None) if artifact is not None else None,
        "docker_image_id": getattr(artifact, "image_id", None) if artifact is not None else None,
        "version": getattr(artifact, "version", None) if artifact is not None else None,
        "build_id": metadata.get("build_id"),
        "source_commit": metadata.get("source_commit"),
        "source_identity": metadata.get("source_identity") or "manifest-metadata",
        "manifest_sha256": (metadata.get("manifest") or {}).get("sha256"),
        "platform": platform.key if platform is not None else metadata.get("platform"),
        "os": platform.os_name if platform is not None else None,
        "arch": platform.arch if platform is not None else None,
        "execution_method": "docker" if platform is not None and platform.is_docker else "native",
        "verified": getattr(artifact, "status", None) == "PASS" if artifact is not None else False,
    }


__all__ = [
    "ArgumentPolicy",
    "ArgumentPolicyError",
    "ArgumentRecord",
    "CATEGORIES",
    "CATEGORY_DETECTION",
    "CATEGORY_OUTPUT",
    "CATEGORY_PERFORMANCE",
    "CATEGORY_SCOPE",
    "CATEGORY_SECURITY",
    "CATEGORY_UNKNOWN",
    "COMPARABILITY_BASELINE",
    "COMPARABILITY_EXPERIMENTAL",
    "COMPARABILITY_NOT_BASELINE",
    "COMPARABILITY_PERFORMANCE",
    "ORIGIN_ADAPTER",
    "ORIGIN_CLI",
    "ORIGIN_CONFIGURATION",
    "ORIGIN_HARNESS",
    "ORIGIN_MANIFEST",
    "ORIGIN_MATRIX",
    "artifact_identity",
    "build_argument_policy",
    "command_digest",
    "environment_record",
    "invocation_sequence_label",
    "lane_for_workload",
    "load_profile_from_workload",
    "normalize_command",
    "normalize_replacements",
    "redact_argv",
    "render_command",
    "sanitized_cwd",
    "split_arguments",
]
