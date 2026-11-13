"""Small, dependency-free helpers shared by the harness."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX64.fullmatch(value))


def is_commit_sha(value: object) -> bool:
    return isinstance(value, str) and bool(_HEX40.fullmatch(value))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "section"


def basename(path: str) -> str:
    """Return the final path component for POSIX and Windows inputs."""
    return re.split(r"[\\/]", path.rstrip("\\/"))[-1]


def remove_tree(path: Path | str) -> None:
    """Remove a run-owned tree, including read-only Git object files on Windows."""

    def _retry(function, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
            function(target)
        except OSError:
            # One final attempt with both read/write and execute bits.
            os.chmod(target, stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            function(target)

    shutil.rmtree(path, onerror=_retry)


def display_path(value: str | Path) -> str:
    """Prefer a repository-relative path when one is available."""
    path = Path(value)
    try:
        return path.resolve().relative_to(Path(__file__).resolve().parents[1]).as_posix()
    except (OSError, ValueError):
        return str(value)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def platform_summary() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def redact_stderr(text: str, known_secrets: tuple[str, ...] = ()) -> str:
    """Produce a short first-line diagnostic that cannot carry secret values.

    Known corpus/control secrets are replaced first; any remaining long
    credential-shaped run is masked. Only the first non-empty line is retained.
    """
    if not text:
        return ""
    line = next((item.strip() for item in text.splitlines() if item.strip()), "")
    for secret in known_secrets:
        if secret and secret in line:
            line = line.replace(secret, "[redacted]")
    line = _LONG_TOKEN.sub("[redacted]", line)
    return line[:300]


def rate(part: int, whole: int) -> float | None:
    if whole <= 0:
        return None
    return round(100.0 * part / whole, 2)
