"""Disposable exact-commit source checkout.

The source commit is the canonical scanner identity. Acquisition is deliberately
separate from scanner-specific build strategy: the harness validates the
repository and commit, creates one run-owned checkout in a disposable workspace,
and proves that checkout HEAD is the requested commit.
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .errors import HarnessError
from .util import is_commit_sha, sha256_bytes


@dataclass(frozen=True)
class SourceCheckout:
    repository: str
    commit: str
    path: Path
    requested_commit: str
    head: str
    clone_command: tuple[str, ...]
    fetch_command: tuple[str, ...] | None
    clone_duration_seconds: float
    fetch_duration_seconds: float | None
    clone_stdout_sha256: str
    clone_stderr_sha256: str
    fetch_stdout_sha256: str | None
    fetch_stderr_sha256: str | None

    @property
    def head_verified(self) -> bool:
        return self.head == self.commit

    def to_dict(self) -> dict:
        return {
            "repository": self.repository,
            "commit": self.commit,
            "requested_commit": self.requested_commit,
            "head": self.head,
            "head_verified": self.head == self.commit,
            "path": str(self.path),
            "clone_command": list(self.clone_command),
            "fetch_command": list(self.fetch_command) if self.fetch_command else None,
            "clone_duration_seconds": self.clone_duration_seconds,
            "fetch_duration_seconds": self.fetch_duration_seconds,
            "clone_stdout_sha256": self.clone_stdout_sha256,
            "clone_stderr_sha256": self.clone_stderr_sha256,
            "fetch_stdout_sha256": self.fetch_stdout_sha256,
            "fetch_stderr_sha256": self.fetch_stderr_sha256,
        }


def _run_git(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 300.0,
) -> tuple[subprocess.CompletedProcess, float]:
    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
    }
    started = time.perf_counter()
    try:
        result = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise HarnessError(
            f"source command timed out after {timeout:g}s: {' '.join(argv[:3])}"
        ) from exc
    except OSError as exc:
        raise HarnessError(f"could not run git: {exc}") from exc
    return result, round(time.perf_counter() - started, 3)


def _git_ok(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 300.0,
) -> tuple[subprocess.CompletedProcess, float]:
    result, duration = _run_git(argv, cwd=cwd, timeout=timeout)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip().splitlines()
        raise HarnessError(
            f"git {' '.join(argv[1:3])} failed (exit {result.returncode}): "
            f"{detail[0][:300] if detail else 'no diagnostic'}"
        )
    return result, duration


def _git_text(argv: list[str], *, cwd: Path | None = None) -> str:
    result, _ = _git_ok(argv, cwd=cwd, timeout=120)
    return result.stdout.decode("utf-8", "replace").strip()


def acquire(
    repository: str,
    commit: str,
    destination: Path | str,
    *,
    timeout: float = 900.0,
) -> SourceCheckout:
    """Clone and check out exactly ``commit`` into an empty destination.

    A short commit, moving branch name, tag, or release artifact is never
    accepted as the scanner identity. A shallow fetch of the exact commit is
    attempted when the commit is not already present in the clone.
    """
    repository = (repository or "").strip()
    if not repository:
        raise HarnessError("source repository must be a non-empty Git URL or path")
    if not is_commit_sha(commit):
        raise HarnessError("source commit must be a full 40-character lowercase SHA")
    destination = Path(destination)
    if destination.exists():
        raise HarnessError(f"source checkout destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    clone_command = [
        "git",
        "clone",
        "--quiet",
        "--filter=blob:none",
        "--no-checkout",
        "--",
        repository,
        str(destination),
    ]
    clone_result, clone_duration = _git_ok(clone_command, timeout=timeout)
    clone_stdout_sha = sha256_bytes(clone_result.stdout)
    clone_stderr_sha = sha256_bytes(clone_result.stderr)

    fetch_command: tuple[str, ...] | None = None
    fetch_duration: float | None = None
    fetch_stdout_sha: str | None = None
    fetch_stderr_sha: str | None = None

    present = _run_git(
        ["git", "-C", str(destination), "cat-file", "-e", f"{commit}^{{commit}}"],
        timeout=60,
    )[0]
    if present.returncode != 0:
        fetch = [
            "git",
            "-C",
            str(destination),
            "fetch",
            "--quiet",
            "--depth=1",
            "origin",
            commit,
        ]
        fetch_result, fetch_duration = _git_ok(fetch, timeout=timeout)
        fetch_command = tuple(fetch)
        fetch_stdout_sha = sha256_bytes(fetch_result.stdout)
        fetch_stderr_sha = sha256_bytes(fetch_result.stderr)

    _git_ok(
        ["git", "-C", str(destination), "checkout", "--quiet", "--detach", commit],
        timeout=120,
    )
    head = _git_text(["git", "-C", str(destination), "rev-parse", "HEAD"])
    if head != commit:
        raise HarnessError(
            f"source checkout HEAD is {head}, requested commit is {commit}"
        )
    status = _git_ok(
        ["git", "-C", str(destination), "status", "--porcelain"], timeout=60
    )[0]
    if status.stdout.strip():
        raise HarnessError("source checkout working tree is not clean")

    return SourceCheckout(
        repository=repository,
        commit=commit,
        path=destination.resolve(),
        requested_commit=commit,
        head=head,
        clone_command=tuple(clone_command),
        fetch_command=fetch_command,
        clone_duration_seconds=clone_duration,
        fetch_duration_seconds=fetch_duration,
        clone_stdout_sha256=clone_stdout_sha,
        clone_stderr_sha256=clone_stderr_sha,
        fetch_stdout_sha256=fetch_stdout_sha,
        fetch_stderr_sha256=fetch_stderr_sha,
    )


def ensure_version_tag(source: SourceCheckout, tag: str) -> str:
    """Create a run-local tag only when the checkout has no describable tag.

    Some upstream Dockerfiles derive their build version from ``git describe``.
    Creating a local lightweight tag in the disposable checkout does not modify
    any tracked file and does not change the checked-out commit.
    """
    probe = _run_git(
        ["git", "-C", str(source.path), "describe", "--tags", "--abbrev=0"],
        timeout=30,
    )[0]
    if probe.returncode == 0:
        return _git_text(
            ["git", "-C", str(source.path), "describe", "--tags", "--abbrev=0"]
        )
    _git_ok(
        ["git", "-C", str(source.path), "tag", "-f", tag, source.commit], timeout=60
    )
    return tag
