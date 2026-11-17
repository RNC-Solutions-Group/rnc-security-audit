"""Build a minimal RNC Scanner development evaluation package.

This is not a production installer or release pipeline. It packages the native
executable, the current provider ruleset, version/commit metadata and checksums
so the scanner can be exercised outside its source checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES = ROOT / "rules" / "rnc-providers-v1.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "cp4a" / "packages"
ZIP_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def workspace_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("cannot determine workspace version")
    return match.group(1)


def git_output(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(arguments)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def platform_name() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    return f"{system}-{machine}"


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def readme(version: str, commit: str, platform_value: str, rules_name: str) -> str:
    return f"""# RNC Scanner development evaluation package

This is a **development evaluation package**, not a production release or
installer. It contains one native scanner executable and the first-party
provider ruleset used by this build.

- Version: `{version}`
- Source commit: `{commit}`
- Platform: `{platform_value}`
- Ruleset: `rules/{rules_name}`

## Contents

```text
rnc{" (or rnc.exe)" if platform.system() == "Windows" else ""}
rules/{rules_name}
VERSION
SOURCE_COMMIT
PLATFORM
SHA256SUMS
README.md
```

Verify the payload with `sha256sum -c SHA256SUMS` on Unix, or compare the
listed digests on Windows.

## Quick start

```sh
./rnc --version
./rnc rules validate --rules rules/{rules_name}
./rnc scan --root /path/to/authorized/source --rules rules/{rules_name} \\
  --format sanitized --output /path/outside/source/sanitized.json
```

Use `--format private --output PATH` only for access-controlled private evidence.
Private reports contain finding identifiers, source locators, evidence digests
and, for database URI findings, password-component digests. They do not contain
raw matched secrets. Treat the digests as sensitive because low-entropy passwords
can be guessed offline. Keep private reports outside the scanned tree.

The scanner result code is not the process exit code. By default, actionable
findings exit non-zero unless the invocation explicitly accepts result `3`:

```sh
./rnc scan ... --accept-result 3
```

Review the repository operator guide for policy, configuration, history and CI
semantics.

## Runtime prerequisites

- Windows x86_64 or Linux x86_64 for the validated development packages.
- No installer or service is required.
- Git-history mode additionally requires an installed `git` executable. A
  working-tree scan does not require Git.
- The executable does not bundle the ruleset; keep `rules/` next to the package
  or pass the rules path explicitly.

## Limitations

- This package exists to prove package readiness and external evaluability.
- It is not a supported production release, has no auto-update and no installer.
- Provider-format recognition is not proof that a credential is active,
  authorized or complete.
- Windows private reports use an explicit protected DACL for the current user,
  LocalSystem and Administrators; verify this meets your local access policy.
- macOS packaging is buildable from source but was not validated in this
  development package pass.
"""


def add_file(archive: zipfile.ZipFile, source: Path, arcname: str, executable: bool = False) -> None:
    info = zipfile.ZipInfo(arcname, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = ((0o755 if executable else 0o644) << 16) | 0o100000
    with source.open("rb") as handle:
        archive.writestr(info, handle.read())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--platform", default=platform_name())
    parser.add_argument("--version", default=None)
    parser.add_argument("--commit", default=None)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()

    version = args.version or workspace_version()
    commit = args.commit or git_output("rev-parse", "HEAD")
    dirty = git_output("status", "--porcelain")
    if dirty and not args.allow_dirty:
        raise SystemExit("working tree is not clean; commit before packaging")

    if not args.skip_build:
        subprocess.run(
            ["cargo", "build", "--release", "--workspace", "--locked"],
            cwd=ROOT,
            check=True,
        )
    binary = args.binary
    if binary is None:
        binary = ROOT / "target" / "release" / ("rnc.exe" if platform.system() == "Windows" else "rnc")
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    rules = args.rules.resolve()
    if not rules.is_file():
        raise SystemExit(f"rules not found: {rules}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    package_name = f"rnc-scanner-{version}-{args.platform}"
    archive_path = args.output_dir / f"{package_name}.zip"
    with tempfile.TemporaryDirectory(prefix="rnc-package-") as temporary:
        staging = Path(temporary) / package_name
        (staging / "rules").mkdir(parents=True)
        binary_name = "rnc.exe" if binary.suffix.lower() == ".exe" else "rnc"
        shutil.copy2(binary, staging / binary_name)
        shutil.copy2(rules, staging / "rules" / rules.name)
        (staging / "VERSION").write_text(version + "\n", encoding="utf-8")
        (staging / "SOURCE_COMMIT").write_text(commit + "\n", encoding="utf-8")
        (staging / "PLATFORM").write_text(args.platform + "\n", encoding="utf-8")
        (staging / "README.md").write_text(
            readme(version, commit, args.platform, rules.name), encoding="utf-8"
        )
        files = [
            binary_name,
            f"rules/{rules.name}",
            "VERSION",
            "SOURCE_COMMIT",
            "PLATFORM",
            "README.md",
        ]
        lines = []
        for relative in files:
            lines.append(f"{sha256(staging / relative)}  {relative}")
        (staging / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for relative in files + ["SHA256SUMS"]:
                add_file(
                    archive,
                    staging / relative,
                    f"{package_name}/{relative}",
                    executable=relative == binary_name,
                )
    result = {
        "archive": str(archive_path),
        "sha256": sha256(archive_path),
        "size": archive_path.stat().st_size,
        "version": version,
        "commit": commit,
        "platform": args.platform,
        "rules": str(rules),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
