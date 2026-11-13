"""Run-owned disposable workspace and scoped cleanup."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import status as statuses
from .errors import HarnessError
from .util import remove_tree, utc_stamp


def new_run_id() -> str:
    return f"{utc_stamp()}-{uuid.uuid4().hex[:8]}"


def _safe_label_value(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in value)
    return cleaned.strip("-.") or "run"


@dataclass
class RunWorkspace:
    run_id: str
    root: Path
    retain: bool = False
    created: bool = False

    @classmethod
    def create(cls, run_id: str | None = None, *, retain: bool = False) -> "RunWorkspace":
        run_id = run_id or new_run_id()
        parent = Path(tempfile.gettempdir()) / "rnc-scan-harness"
        parent.mkdir(parents=True, exist_ok=True)
        root = parent / _safe_label_value(run_id)
        if root.exists():
            raise HarnessError(f"run workspace already exists: {root}")
        root.mkdir(parents=True)
        return cls(run_id=run_id, root=root.resolve(), retain=retain, created=True)

    @property
    def evidence(self) -> Path:
        return self.root / "evidence"

    @property
    def target(self) -> Path:
        return self.root / "target"

    @property
    def docker_label(self) -> str:
        return f"rnc-scan-harness.run={_safe_label_value(self.run_id)}"

    @property
    def container_prefix(self) -> str:
        return f"rnc-{_safe_label_value(self.run_id)}"

    def prepare(self) -> None:
        for path in (self.evidence, self.target):
            path.mkdir(parents=True, exist_ok=True)

    def cleanup(self, *, inspect_docker: bool = True) -> dict:
        """Remove only run-created containers and this run's workspace.

        Registered Docker images are immutable operator-provided artifacts and
        are never removed, retagged, or treated as disposable build output. No
        Docker prune command is used.
        """
        report: dict = {
            "status": statuses.PASS,
            "retained": bool(self.retain),
            "workspace": str(self.root),
            "workspace_removed": False,
            "images_removed": [],
            "containers_removed": [],
            "failures": [],
            "actions": [],
        }
        if self.retain:
            report["actions"].append(
                "Temporary benchmark workspace and run-created Docker containers retained by request. "
                "Registered images were never disposable."
            )
            return report
        if not self.created:
            report["status"] = statuses.NOT_APPLICABLE
            report["actions"].append("No run-owned workspace was created.")
            return report

        label = self.docker_label
        docker_available = inspect_docker and shutil.which("docker") is not None
        if not inspect_docker:
            report["actions"].append(
                "No Docker artifact was executed; no container cleanup was required."
            )
        elif not docker_available:
            report["actions"].append(
                "Docker CLI unavailable; no run-created container cleanup was possible."
            )
        elif docker_available:
            try:
                listed = subprocess.run(
                    ["docker", "ps", "-aq", "--filter", f"label={label}"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if listed.returncode != 0:
                    raise RuntimeError(listed.stderr.strip() or "docker listing failed")
                ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
                if ids:
                    removed = subprocess.run(
                        ["docker", "rm", "-f", *ids],
                        capture_output=True,
                        text=True,
                        timeout=180,
                    )
                    if removed.returncode != 0:
                        raise RuntimeError(removed.stderr.strip() or "docker remove failed")
                    report["containers_removed"].extend(ids)
                    report["actions"].append(
                        f"Removed {len(ids)} run-created container(s); registered images were left intact."
                    )
                else:
                    report["actions"].append("No run-created containers found.")
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
                report["status"] = statuses.BLOCKED
                report["failures"].append(f"container cleanup: {exc}")

        try:
            remove_tree(self.root)
            report["workspace_removed"] = not self.root.exists()
            report["actions"].append(
                "Removed run-owned benchmark workspace, generated datasets, and evidence."
            )
        except OSError as exc:
            report["status"] = statuses.BLOCKED
            report["failures"].append(f"workspace cleanup: {exc}")

        if report["failures"]:
            report["status"] = statuses.BLOCKED
        return report
