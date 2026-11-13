"""Experiment configuration profiles.

DEFAULT uses the scanner's bundled detection rules. CUSTOM is an explicit,
provenance-tracked controlled experiment and is never merged into default
baseline metrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .errors import HarnessError

DEFAULT = "default"
CUSTOM = "custom"
PROFILES = (DEFAULT, CUSTOM)


@dataclass(frozen=True)
class ExperimentProfile:
    name: str
    config_source: str | None = None
    config_path: Path | None = None
    config_sha256: str | None = None
    applied_settings: dict = field(default_factory=dict)
    default_isolation: dict = field(default_factory=dict)
    limitations: tuple[str, ...] = ()

    @property
    def is_default(self) -> bool:
        return self.name == DEFAULT

    @property
    def scanner_config(self) -> Path | None:
        return self.config_path if self.name == CUSTOM else None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "is_default": self.is_default,
            "config_source": self.config_source,
            "config_path": str(self.config_path) if self.config_path else None,
            "config_sha256": self.config_sha256,
            "applied_settings": self.applied_settings,
            "default_isolation": self.default_isolation,
            "limitations": list(self.limitations),
            "baseline_metrics_included": self.is_default,
        }


def load_profile(adapter, name: str | None, config_path: Path | str | None) -> ExperimentProfile:
    name = (name or DEFAULT).strip().lower()
    if name not in PROFILES:
        raise HarnessError(
            f"unknown configuration profile {name!r}; choose from {', '.join(PROFILES)}"
        )
    if name == DEFAULT:
        if config_path is not None:
            raise HarnessError(
                "the DEFAULT profile does not accept --scanner-config; use --profile custom"
            )
        description = adapter.default_configuration()
        return ExperimentProfile(
            name=DEFAULT,
            config_source="scanner bundled default rules",
            applied_settings={
                "profile": "DEFAULT",
                "scanner_config_argument": None,
                "working_directory": "empty run-owned scanner-cwd",
                "cleared_environment": description.get("removed_environment", []),
                "configuration_file_required": False,
            },
            default_isolation=description,
            limitations=tuple(description.get("limitations") or ()),
        )
    if config_path is None:
        raise HarnessError("the CUSTOM profile requires --scanner-config")
    try:
        resolved, digest = adapter.validate_config(config_path)
    except (OSError, ValueError) as exc:
        raise HarnessError(f"scanner configuration is invalid: {exc}") from exc
    return ExperimentProfile(
        name=CUSTOM,
        config_source=str(resolved),
        config_path=resolved,
        config_sha256=digest,
        applied_settings={
            "profile": "CUSTOM",
            "scanner_config_argument": "--config",
            "scanner_config_path": str(resolved),
            "scanner_config_sha256": digest,
            "working_directory": "empty run-owned scanner-cwd",
            "cleared_environment": list(adapter.config_environment_keys()),
        },
        limitations=(
            "CUSTOM results are a separate experiment profile and are excluded from DEFAULT baseline metrics.",
        ),
    )
