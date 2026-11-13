"""Explicit testing-suite registry."""

from __future__ import annotations

from ..adapters.base import ScannerAdapter
from .base import SuiteContext, TestingSuite
from .gitleaks_fixtures import GitleaksFixtureSuite
from .git_history import GitHistorySuite
from .leaky_repo import LeakyRepoSuite
from .levain import LevainSuite
from .rnclab import RncLabSuite
from .synthetic_filesystem import SyntheticFilesystemSuite

_SUITES: dict[str, type[TestingSuite]] = {
    "gitleaks": GitleaksFixtureSuite,
    "git-history": GitHistorySuite,
    "levain": LevainSuite,
    "leaky-repo": LeakyRepoSuite,
    "rnclab": RncLabSuite,
    "synthetic-filesystem": SyntheticFilesystemSuite,
}


def suite_keys() -> tuple[str, ...]:
    return tuple(sorted(_SUITES))


def get_suite(key: str) -> TestingSuite:
    if key not in _SUITES:
        raise ValueError(f"unknown testing suite {key!r}; choose from {', '.join(suite_keys())}")
    return _SUITES[key]()


def resolve_suites(names: list[str] | tuple[str, ...] | None, adapter: ScannerAdapter) -> list[tuple[str, TestingSuite | None, str | None]]:
    requested = list(names) if names is not None else list(adapter.supported_suites)
    if "all" in requested:
        # "all" is the everyday baseline, NOT every available diagnostic suite.
        # Explicit-only: Gitleaks regression, synthetic controls and standalone RNC lab.
        requested = ["levain", "leaky-repo"]
    resolved: list[tuple[str, TestingSuite | None, str | None]] = []
    seen: set[str] = set()
    for name in requested:
        if name in seen:
            continue
        seen.add(name)
        if name not in _SUITES:
            resolved.append((name, None, f"unknown suite {name!r}"))
        elif name not in adapter.supported_suites:
            resolved.append(
                (name, None, f"scanner adapter {adapter.key!r} does not support suite {name!r}")
            )
        else:
            resolved.append((name, get_suite(name), None))
    return resolved


__all__ = [
    "SuiteContext",
    "TestingSuite",
    "get_suite",
    "resolve_suites",
    "suite_keys",
]
