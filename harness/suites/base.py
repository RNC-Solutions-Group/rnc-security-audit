"""Testing-suite contracts.

Suites own test selection, assertions, and scoring methodology. They do not own
scanner build commands or scanner report parsers; those are adapter methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from .. import status as statuses
from ..adapters.base import BuildArtifact, ScannerAdapter
from ..artifacts import RegisteredBuild
from ..config import HarnessConfig
from ..profile import ExperimentProfile


@dataclass
class SuiteContext:
    adapter: ScannerAdapter
    build: RegisteredBuild
    config: HarnessConfig
    builds: dict[str, BuildArtifact]
    work_dir: Path
    report_dir: Path
    run_id: str
    offline: bool
    timeout: int
    profile: ExperimentProfile | None = None
    scanner_config: Path | None = None
    scanner_config_sha256: str | None = None
    raw_artifacts: list[dict] = field(default_factory=list)
    performance_workloads: list[dict] = field(default_factory=list)
    performance_loads: list[dict] = field(default_factory=list)
    performance_copies: int = 10
    _cache: dict[str, object] = field(default_factory=dict)

    @property
    def source_commit(self) -> str:
        """Source commit metadata supplied by the operator manifest."""
        return self.build.source_commit

    @property
    def profile_name(self) -> str:
        return self.profile.name if self.profile else "default"

    @property
    def executable_artifacts(self) -> dict[str, BuildArtifact]:
        return {key: item for key, item in self.builds.items() if item.platform.is_executable}

    @property
    def docker_artifacts(self) -> dict[str, BuildArtifact]:
        return {key: item for key, item in self.builds.items() if item.platform.is_docker}

    def runnable(self, artifact: BuildArtifact) -> bool:
        return artifact.status == statuses.PASS and self.adapter.can_execute(artifact.platform)

    def cached(self, key: str, factory):
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]


class TestingSuite(ABC):
    key: str
    title: str
    required_capabilities: tuple[str, ...] = ()

    def applicable(self, context: SuiteContext) -> tuple[bool, str | None]:
        if self.key not in context.adapter.supported_suites:
            return False, f"scanner adapter {context.adapter.key!r} does not declare suite {self.key!r}"
        return True, None

    @abstractmethod
    def run(self, context: SuiteContext) -> dict:
        raise NotImplementedError

    def result(
        self,
        *,
        status: str,
        summary: dict | None = None,
        metrics: dict | None = None,
        targets: dict | None = None,
        comparisons: dict | None = None,
        limitations: list[str] | None = None,
        reason: str | None = None,
        applicable: bool = True,
        details: dict | None = None,
        outcome: str | None = None,
        results: list[dict] | None = None,
        baseline_metric: bool = True,
        scored: bool = True,
    ) -> dict:
        return {
            "key": self.key,
            "title": self.title,
            "status": status,
            "outcome": outcome or statuses.outcome(status, scored=scored),
            "applicable": applicable,
            "baseline_metric": baseline_metric,
            "reason": reason,
            "summary": summary or {},
            "metrics": metrics or {},
            "targets": targets or {},
            "results": results or [],
            "comparisons": comparisons or {},
            "limitations": limitations or [],
            "details": details or {},
        }


def combine_targets(targets: dict[str, dict]) -> str:
    return statuses.combine([item.get("status") for item in targets.values()])


def platform_status(
    artifact: BuildArtifact | None,
    *,
    context: SuiteContext,
    applicable: bool = True,
) -> tuple[str, str | None]:
    if not applicable:
        return statuses.NOT_APPLICABLE, "suite is not applicable to this platform"
    if artifact is None:
        return statuses.NOT_APPLICABLE, "platform was not selected for this run"
    if artifact.status == statuses.FAIL:
        return statuses.BLOCKED, "target artifact failed verification"
    if artifact.status == statuses.BLOCKED:
        return statuses.BLOCKED, "target artifact was blocked"
    if not context.adapter.can_execute(artifact.platform):
        return statuses.NOT_APPLICABLE, context.adapter.execution_reason(artifact.platform)
    return statuses.NOT_RUN, "target is executable but the suite has not run yet"


__all__ = [
    "SuiteContext",
    "TestingSuite",
    "combine_targets",
    "platform_status",
]
