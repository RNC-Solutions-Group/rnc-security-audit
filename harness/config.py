"""TOML harness configuration and safe-output validation."""

from __future__ import annotations

import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .adapters import PLATFORMS, adapter_keys, expand_platform_selection
from .errors import HarnessError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "harness.toml"
SUITE_KEYS = (
    "gitleaks",
    "git-history",
    "levain",
    "leaky-repo",
    "rnclab",
    "synthetic-filesystem",
)
# The Gitleaks-specific fixtures remain an explicit adapter regression only.
DEFAULT_SUITE_KEYS = ("levain", "leaky-repo")
# All is intentionally only the two independent baseline corpora.
# Gitleaks fixtures and synthetic controls remain explicit opt-in.
FORMATS = ("markdown", "json")


class ConfigError(HarnessError):
    pass


@dataclass(frozen=True)
class SourceDefaults:
    repository: str | None = None
    commit: str | None = None


@dataclass(frozen=True)
class ReportConfig:
    console: bool = True
    sanitized: bool = True
    raw: bool = False
    formats: tuple[str, ...] = ("markdown", "json")
    output_dir: Path = ROOT / "reports" / "experiments"
    raw_output_dir: Path = ROOT / "work" / "raw"
    naming: str = "{timestamp}-{scanner}-{commit}-{profile}"
    exception_mode: str = "exceptions-only"
    exceptions_enabled: bool = True
    include_coverage_gaps: bool = True
    include_skipped: bool = True
    include_not_applicable: bool = False
    include_baseline_deltas: bool = True


@dataclass(frozen=True)
class HarnessConfig:
    schema_version: int = 1
    source: SourceDefaults = field(default_factory=SourceDefaults)
    scanner: str = "gitleaks"
    platforms: tuple[str, ...] = ("host",)
    suites: tuple[str, ...] = DEFAULT_SUITE_KEYS
    benchmark_warmups: int = 1
    benchmark_runs: int = 5
    benchmark_environment: str = "DEV"
    stress_profile: str = "none"
    reports: ReportConfig = field(default_factory=ReportConfig)
    cache_dir: Path = ROOT / "datasets" / "cache"
    timeout: int = 1200
    path: Path | None = None

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "source": {
                "repository": self.source.repository,
                "commit": self.source.commit,
            },
            "scanner": self.scanner,
            "platforms": list(self.platforms),
            "suites": list(self.suites),
            "performance": {
                "warmups": self.benchmark_warmups,
                "measured_runs": self.benchmark_runs,
                "environment": self.benchmark_environment,
                "stress_profile": self.stress_profile,
            },
            "reports": {
                "console": self.reports.console,
                "sanitized": self.reports.sanitized,
                "raw": self.reports.raw,
                "formats": list(self.reports.formats),
                "output_dir": str(self.reports.output_dir),
                "raw_output_dir": str(self.reports.raw_output_dir),
                "naming": self.reports.naming,
                "exception_mode": self.reports.exception_mode,
                "exceptions_enabled": self.reports.exceptions_enabled,
                "include_coverage_gaps": self.reports.include_coverage_gaps,
                "include_skipped": self.reports.include_skipped,
                "include_not_applicable": self.reports.include_not_applicable,
                "include_baseline_deltas": self.reports.include_baseline_deltas,
            },
            "cache_dir": str(self.cache_dir),
            "timeout": self.timeout,
            "path": str(self.path) if self.path else None,
        }


def _bool(table: dict, key: str, default: bool, where: str) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key} must be a boolean")
    return value


def _str(table: dict, key: str, default: str, where: str) -> str:
    value = table.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def _path(table: dict, key: str, default: Path, where: str, base: Path) -> Path:
    value = table.get(key)
    if value is None:
        return default
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}.{key} must be a non-empty path string")
    path = Path(value).expanduser()
    return (path if path.is_absolute() else base / path).resolve()


def _tuple_strings(table: dict, key: str, default: tuple[str, ...], where: str) -> tuple[str, ...]:
    value = table.get(key, list(default))
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise ConfigError(f"{where}.{key} must be a non-empty array of strings")
    return tuple(value)


def load_config(path: Path | str | None = None) -> HarnessConfig:
    explicit = path is not None
    target = Path(path) if path is not None else DEFAULT_CONFIG
    if not target.is_file():
        if explicit:
            raise ConfigError(f"harness configuration not found: {target}")
        return HarnessConfig()
    try:
        with target.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read harness configuration {target}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("harness configuration must be a TOML table")
    version = data.get("schema_version", 1)
    if version != 1:
        raise ConfigError(f"unsupported harness configuration schema_version {version!r}")

    base = target.resolve().parent
    source_table = data.get("source", {})
    scanner_table = data.get("scanner", {})
    reports_table = data.get("reports", {})
    targets_table = data.get("targets", {})
    suites_table = data.get("suites", {})
    cache_table = data.get("cache", {})
    performance_table = data.get("performance", {})
    for name, value in (
        ("source", source_table),
        ("scanner", scanner_table),
        ("reports", reports_table),
        ("targets", targets_table),
        ("suites", suites_table),
        ("cache", cache_table),
        ("performance", performance_table),
    ):
        if not isinstance(value, dict):
            raise ConfigError(f"{name} must be a TOML table")
    source = SourceDefaults(
        repository=(
            _str(source_table, "repository", "", "source")
            if source_table.get("repository")
            else None
        ),
        commit=source_table.get("commit"),
    )
    if source.commit is not None and (not isinstance(source.commit, str) or len(source.commit) != 40):
        raise ConfigError("source.commit must be a full 40-character SHA when set")
    scanner = _str(scanner_table, "default", "gitleaks", "scanner")
    if scanner not in adapter_keys():
        raise ConfigError(f"unknown scanner {scanner!r}; available: {', '.join(adapter_keys())}")

    platforms = _tuple_strings(targets_table, "platforms", ("host",), "targets")
    for item in platforms:
        if item in ("host", "all", "executable", "executables", "native", "docker"):
            continue
        if item not in PLATFORMS:
            raise ConfigError(f"unknown target platform {item!r}")
    try:
        expand_platform_selection(platforms)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    suites = _tuple_strings(suites_table, "default", DEFAULT_SUITE_KEYS, "suites")
    for item in suites:
        if item != "all" and item not in SUITE_KEYS:
            raise ConfigError(f"unknown suite {item!r}; choose from {', '.join(SUITE_KEYS)} or all")
    benchmark_warmups = performance_table.get("warmups", 1)
    benchmark_runs = performance_table.get("measured_runs", 5)
    if not isinstance(benchmark_warmups, int) or benchmark_warmups < 0:
        raise ConfigError("performance.warmups must be a non-negative integer")
    if not isinstance(benchmark_runs, int) or benchmark_runs < 1:
        raise ConfigError("performance.measured_runs must be a positive integer")
    benchmark_environment = _str(
        performance_table, "environment", "DEV", "performance"
    ).upper()
    if benchmark_environment not in ("DEV", "CONTROLLED", "RELEASE"):
        raise ConfigError("performance.environment must be DEV, CONTROLLED, or RELEASE")
    stress_profile = _str(
        performance_table, "stress_profile", "none", "performance"
    ).lower()
    if stress_profile not in ("none", "cpu", "memory", "io", "network"):
        raise ConfigError("performance.stress_profile is not supported")
    if benchmark_environment == "RELEASE" and stress_profile != "none":
        raise ConfigError("RELEASE performance measurements must use stress_profile = none")

    formats = _tuple_strings(reports_table, "formats", FORMATS, "reports")
    for item in formats:
        if item not in FORMATS:
            raise ConfigError(f"unsupported report format {item!r}; choose from {', '.join(FORMATS)}")

    sanitized_table = reports_table.get("sanitized", {})
    unsanitized_table = reports_table.get("unsanitized", {})
    summary_table = reports_table.get("summary", {})
    exceptions_table = reports_table.get("exceptions", {})
    for name, table in (
        ("reports.sanitized", sanitized_table),
        ("reports.unsanitized", unsanitized_table),
        ("reports.summary", summary_table),
        ("reports.exceptions", exceptions_table),
    ):
        if not isinstance(table, dict):
            raise ConfigError(f"{name} must be a TOML table")
    sanitized = (
        _bool(sanitized_table, "enabled", True, "reports.sanitized")
        if sanitized_table
        else _bool(reports_table, "sanitized", True, "reports")
    )
    raw = (
        _bool(unsanitized_table, "enabled", False, "reports.unsanitized")
        if unsanitized_table
        else _bool(reports_table, "raw", False, "reports")
    )
    output_dir = (
        _path(
            sanitized_table,
            "location",
            ROOT / "reports" / "experiments",
            "reports.sanitized",
            base,
        )
        if sanitized_table
        else _path(
            reports_table,
            "output_dir",
            ROOT / "reports" / "experiments",
            "reports",
            base,
        )
    )
    raw_output_dir = (
        _path(unsanitized_table, "location", ROOT / "work" / "raw", "reports.unsanitized", base)
        if unsanitized_table
        else _path(reports_table, "raw_output_dir", ROOT / "work" / "raw", "reports", base)
    )
    console = _bool(reports_table, "console", True, "reports")
    if summary_table:
        console = _bool(summary_table, "enabled", True, "reports.summary") and _bool(
            summary_table, "console", True, "reports.summary"
        )
    reports = ReportConfig(        console=console,
        sanitized=sanitized,
        raw=raw,
        formats=formats,
        output_dir=output_dir,
        raw_output_dir=raw_output_dir,
        naming=_str(
            reports_table,
            "naming",
            "{timestamp}-{scanner}-{commit}-{profile}",
            "reports",
        ),
        exception_mode=_str(exceptions_table, "mode", "exceptions-only", "reports.exceptions")
        if exceptions_table
        else "exceptions-only",
        exceptions_enabled=_bool(
            exceptions_table, "enabled", True, "reports.exceptions"
        )
        and _str(exceptions_table, "mode", "exceptions-only", "reports.exceptions") != "none",
        include_coverage_gaps=_bool(
            exceptions_table, "include_coverage_gaps", True, "reports.exceptions"
        ),
        include_skipped=_bool(
            exceptions_table, "include_skipped", True, "reports.exceptions"
        ),
        include_not_applicable=_bool(
            exceptions_table, "include_not_applicable", False, "reports.exceptions"
        ),
        include_baseline_deltas=_bool(
            exceptions_table, "include_baseline_deltas", True, "reports.exceptions"
        ),
    )
    if reports.exception_mode not in ("exceptions-only", "summary-only", "none"):
        raise ConfigError("reports.exceptions.mode must be exceptions-only, summary-only, or none")
    execution_table = data.get("execution", {})
    if not isinstance(execution_table, dict):
        raise ConfigError("execution must be a TOML table")
    timeout = execution_table.get("timeout", data.get("timeout", 1200))
    if not isinstance(timeout, int) or timeout <= 0:
        raise ConfigError("execution.timeout must be a positive integer")
    cache_dir = _path(cache_table, "dir", ROOT / "datasets" / "cache", "cache", base)
    return HarnessConfig(
        schema_version=1,
        source=source,
        scanner=scanner,
        platforms=platforms,
        suites=suites,
        benchmark_warmups=benchmark_warmups,
        benchmark_runs=benchmark_runs,
        benchmark_environment=benchmark_environment,
        stress_profile=stress_profile,
        reports=reports,
        cache_dir=cache_dir,
        timeout=timeout,
        path=target.resolve(),
    )


def raw_destination_is_safe(path: Path | str) -> tuple[bool, str]:
    resolved = Path(path).expanduser().resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return True, "outside the tracked harness repository"
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "-q", "--", str(resolved)],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"cannot verify ignore status: {exc}"
    if result.returncode == 0:
        return True, "Git-ignored destination"
    return False, "raw destination is inside tracked source and is not Git-ignored"


def validate_raw_destination(config: HarnessConfig) -> None:
    if not config.reports.raw:
        return
    safe, reason = raw_destination_is_safe(config.reports.raw_output_dir)
    if not safe:
        raise ConfigError(
            f"raw report destination {config.reports.raw_output_dir} is unsafe: {reason}"
        )
