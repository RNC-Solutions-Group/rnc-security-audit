"""Small explicit scanner-adapter registry (no plugin discovery)."""

from __future__ import annotations

from .base import (
    PLATFORM_CATALOG,
    PLATFORMS,
    BuildArtifact,
    NormalizedFinding,
    ScannerAdapter,
    TargetPlatform,
    expand_platform_selection,
    host_platform,
    platform_for,
)

_ADAPTERS = {
    "gitleaks": "harness.adapters.gitleaks:GitleaksAdapter",
    "betterleaks": "harness.adapters.betterleaks:BetterleaksAdapter",
    "rnc": "harness.adapters.rnc:RNCAdapter",
}


def adapter_keys() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))


def get_adapter(key: str) -> ScannerAdapter:
    if key not in _ADAPTERS:
        raise ValueError(
            f"unknown scanner adapter {key!r}; available: {', '.join(adapter_keys())}"
        )
    module_name, class_name = _ADAPTERS[key].split(":", 1)
    module = __import__(module_name, fromlist=[class_name])
    return getattr(module, class_name)()


def default_adapter() -> ScannerAdapter:
    return get_adapter("gitleaks")


__all__ = [
    "PLATFORM_CATALOG",
    "PLATFORMS",
    "BuildArtifact",
    "NormalizedFinding",
    "ScannerAdapter",
    "TargetPlatform",
    "adapter_keys",
    "default_adapter",
    "expand_platform_selection",
    "get_adapter",
    "host_platform",
    "platform_for",
]
