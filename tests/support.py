"""Shared fixtures for the CP1 test suite (no network access required)."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from harness.control import secret_values
from harness.execution import Invocation
from harness.model import ExpectedSecret, Section

FIXTURES = Path(__file__).resolve().parent / "fixtures"
STUB = FIXTURES / "stub_scanner.py"

LICENSE_TEXT = """MIT License

Copyright (c) 2026 Test Fixture

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
"""

NEGATIVE_SECTIONS = [
    {
        "name": "ordinary log",
        "lines": 2,
        "text": "GET / 200\nuser=alice\n",
        "secrets": [],
        "personal_data": [{"text": "alice"}],
    },
    {
        "name": "build output",
        "lines": 2,
        "text": "BUILD OK\nnone\n",
        "secrets": [],
        "personal_data": [],
    },
]

POSITIVE_SECTIONS = [
    {
        "name": "core env",
        "lines": 2,
        "text": "unit-secret-alpha\nunit-secret-beta\n",
        "secrets": [
            {"kind": "alpha", "text": "unit-secret-alpha"},
            {"kind": "beta", "text": "unit-secret-beta"},
        ],
        "personal_data": [],
    },
    {
        "name": "hard prose",
        "lines": 1,
        "text": "correct horse\n",
        "secrets": [{"kind": "hard-password", "text": "correct horse"}],
        "personal_data": [],
        "hard": True,
    },
]


@dataclass(frozen=True)
class MiniFixture:
    root: Path
    repo: Path
    manifest: Path
    revision: str

    def sensitive_strings(self) -> tuple[str, ...]:
        return (
            "unit-secret-alpha",
            "unit-secret-beta",
            "correct horse",
            "alice",
            *secret_values(),
        )


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=True,
        text=True,
    )
    return result.stdout.strip()


def write_mini_repo(root: Path) -> MiniFixture:
    root.mkdir(parents=True, exist_ok=True)
    repo = root / "repo"
    repo.mkdir()

    negative = {
        "name": "mini negative",
        "counts": {"formats": 2, "lines": 4, "personal_data": 1},
        "sections": NEGATIVE_SECTIONS,
    }
    positive = {
        "name": "mini positive",
        "counts": {"formats": 2, "lines": 3, "secrets": 3, "core": 1, "hard": 1},
        "sections": POSITIVE_SECTIONS,
    }
    negative_bytes = (json.dumps(negative, indent=2) + "\n").encode("utf-8")
    positive_bytes = (json.dumps(positive, indent=2) + "\n").encode("utf-8")
    files = {
        "LICENSE": LICENSE_TEXT.encode("utf-8"),
        "README.md": b"# mini corpus\n",
        "fp-corpus.json": negative_bytes,
        "fp-corpus.txt": b"GET / 200\nuser=alice\nBUILD OK\nnone\n",
        "tp-corpus.json.b64": base64.b64encode(positive_bytes) + b"\n",
        "tp-corpus.txt.b64": base64.b64encode(b"unit-secret-alpha\n") + b"\n",
        "materialize.py": b"# mini fixture materializer\n",
    }
    for name, data in files.items():
        (repo / name).write_bytes(data)

    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=CP1 Fixture",
        "-c",
        "user.email=cp1@example.invalid",
        "commit",
        "-q",
        "-m",
        "mini corpus fixture",
    )
    revision = _git(repo, "rev-parse", "HEAD")

    import hashlib

    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    artifacts = {name: digest(data) for name, data in files.items()}
    derived = {
        "tp-corpus.json": digest(positive_bytes),
        "tp-corpus.txt": digest(b"unit-secret-alpha\n"),
    }
    manifest = root / "manifest.toml"
    artifact_lines = "\n".join(f'"{name}" = "{value}"' for name, value in sorted(artifacts.items()))
    derived_lines = "\n".join(f'"{name}" = "{value}"' for name, value in sorted(derived.items()))
    manifest.write_text(
        f"""schema_version = 1

[datasets.levain]
name = "Mini Levain fixture"
source_repository = "{repo.as_uri()}"
author_reference = "https://example.invalid/fixture"
license = "MIT"
license_url = "https://example.invalid/LICENSE"
license_sha256 = "{artifacts['LICENSE']}"
revision = "{revision}"
revision_tag = "test"
revision_date = "2026-01-01T00:00:00Z"
enabled = true
status = "PINNED_AND_VERIFIED"
counting_unit = "test case"
license_notice = "datasets/THIRD_PARTY_NOTICES.md"

[datasets.levain.expected]
negative_sections = 2
negative_lines = 4
negative_secrets = 0
negative_personal_data = 1
positive_sections = 2
positive_lines = 3
positive_secrets = 3
positive_hard_sections = 1
positive_hard_secrets = 1
positive_personal_data = 0

[datasets.levain.artifact_sha256]
{artifact_lines}

[datasets.levain.derived_sha256]
{derived_lines}
""",
        encoding="utf-8",
    )
    return MiniFixture(root=root, repo=repo, manifest=manifest, revision=revision)


def make_stub_wrapper(directory: Path) -> Path:
    """Create an executable wrapper around the Python stub for this platform."""
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        wrapper = directory / "stub-gitleaks.cmd"
        wrapper.write_text(
            f'@echo off\r\n"{sys.executable}" "{STUB}" %*\r\n',
            encoding="utf-8",
        )
    else:
        wrapper = directory / "stub-gitleaks.sh"
        wrapper.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{STUB}" "$@"\n',
            encoding="utf-8",
        )
        wrapper.chmod(0o755)
    return wrapper


def section(
    name: str,
    text: str,
    *,
    secrets: tuple[tuple[str, str], ...] = (),
    personal: tuple[str, ...] = (),
    hard: bool = False,
    filename: str | None = None,
    lines: int | None = None,
) -> Section:
    return Section(
        name=name,
        text=text,
        secrets=tuple(ExpectedSecret(kind=kind, text=value) for kind, value in secrets),
        personal_data=personal,
        hard=hard,
        filename=filename or (name.replace(" ", "-") + ".log"),
        lines=lines if lines is not None else len(text.splitlines()),
    )


def fake_invocation(
    report: bytes | None,
    *,
    exit_code: int = 0,
    timed_out: bool = False,
    error_code: str | None = None,
    stderr: bytes = b"",
    stdout: bytes = b"",
) -> Invocation:
    return Invocation(
        binary_path="stub",
        binary_sha256="0" * 64,
        argv=("stub", "dir", "<target>", "--report-format", "json", "--report-path", "<report>"),
        mode="dir",
        report_path="<report>",
        exit_code=exit_code,
        timed_out=timed_out,
        duration_seconds=0.01,
        timeout_seconds=300.0,
        stdout=stdout,
        stderr=stderr,
        report_bytes=report,
        error_code=error_code,
        error_message="synthetic failure" if error_code else "",
    )
