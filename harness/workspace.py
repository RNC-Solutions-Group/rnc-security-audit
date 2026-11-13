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
    def source(self) -> Path:
        return self.root / "source"

    @property
    def builds(self) -> Path:
        return self.root / "builds"

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
        for path in (self.builds, self.evidence, self.target):
            path.mkdir(parents=True, exist_ok=True)

    def cleanup(self, *, image_tags: list[str] | None = None, inspect_docker: bool = True) -> dict:
        """Remove only resources proven to belong to this run.

        Containers and images are selected by the run-specific label. Tags are a
        secondary exact-match fallback for an interrupted build. No Docker prune
        command and no recursive Git cleanup is ever used.
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
                "Temporary source, build outputs, and run-owned Docker resources retained by request."
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
                "No Docker product was built or invoked; no container cleanup was required."
            )
        elif not docker_available:
            report["actions"].append(
                "Docker CLI unavailable; no run-owned image or container cleanup was possible."
            )
        for kind, list_argv, remove_argv in (
            (
                "container",
                ["docker", "ps", "-aq", "--filter", f"label={label}"],
                ["docker", "rm", "-f"],
            ),
            (
                "image",
                ["docker", "image", "ls", "-aq", "--filter", f"label={label}"],
                ["docker", "image", "rm", "-f"],
            ),
        ):
            if not docker_available:
                break
            try:
                listed = subprocess.run(
                    list_argv, capture_output=True, text=True, timeout=60
                )
                if listed.returncode != 0:
                    raise RuntimeError(listed.stderr.strip() or "docker listing failed")
                ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
                if ids:
                    removed = subprocess.run(
                        [*remove_argv, *ids], capture_output=True, text=True, timeout=180
                    )
                    if removed.returncode != 0:
                        raise RuntimeError(removed.stderr.strip() or "docker remove failed")
                    report[f"{kind}s_removed"].extend(ids)
                    report["actions"].append(f"Removed {len(ids)} run-owned {kind}(s).")
                else:
                    report["actions"].append(f"No run-owned {kind}s found.")
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
                report["status"] = statuses.BLOCKED
                report["failures"].append(f"{kind} cleanup: {exc}")

        if image_tags:
            for tag in image_tags:
                if not tag:
                    continue
                if not docker_available:
                    break
                try:
                    removed = subprocess.run(
                        ["docker", "image", "rm", "-f", tag],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if removed.returncode == 0:
                        if tag not in report["images_removed"]:
                            report["images_removed"].append(tag)
                        report["actions"].append(f"Removed image tag {tag}.")
                except (OSError, subprocess.TimeoutExpired) as exc:
                    report["status"] = statuses.BLOCKED
                    report["failures"].append(f"image tag {tag}: {exc}")

        try:
            remove_tree(self.root)
            report["workspace_removed"] = not self.root.exists()
            report["actions"].append("Removed run-owned checkout, build outputs, and evidence workspace.")
        except OSError as exc:
            report["status"] = statuses.BLOCKED
            report["failures"].append(f"workspace cleanup: {exc}")

        if report["failures"]:
            report["status"] = statuses.BLOCKED
        return report
