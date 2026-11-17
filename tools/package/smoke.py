"""Exercise a packaged RNC Scanner from a clean extraction directory."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def expect(result: subprocess.CompletedProcess[str], code: int, label: str) -> None:
    if result.returncode != code:
        raise SystemExit(
            f"{label}: expected exit {code}, got {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    if not args.archive.is_file():
        raise SystemExit(f"package not found: {args.archive}")
    with tempfile.TemporaryDirectory(prefix="rnc-package-smoke-") as temporary:
        extraction = Path(temporary) / "extract"
        extraction.mkdir()
        with zipfile.ZipFile(args.archive) as archive:
            archive.extractall(extraction)
        roots = [path for path in extraction.iterdir() if path.is_dir()]
        if len(roots) != 1:
            raise SystemExit(f"expected one package root, found {roots}")
        package = roots[0]
        binary = package / ("rnc.exe" if (package / "rnc.exe").exists() else "rnc")
        rules = package / "rules" / "rnc-providers-v1.json"
        version = (package / "VERSION").read_text(encoding="utf-8").strip()
        commit = (package / "SOURCE_COMMIT").read_text(encoding="utf-8").strip()
        if not commit or len(commit) < 7:
            raise SystemExit("SOURCE_COMMIT is missing or implausible")
        if not binary.is_file() or not rules.is_file():
            raise SystemExit("package payload is incomplete")
        if sys.platform != "win32":
            binary.chmod(0o755)

        result = run([str(binary), "--version"], package)
        expect(result, 0, "--version")
        if version not in result.stdout:
            raise SystemExit(f"--version did not report {version}: {result.stdout!r}")

        result = run([str(binary), "rules", "validate", "--rules", str(rules)], package)
        expect(result, 0, "rules validate")
        if "Rules: " not in result.stdout or "Digest: sha256:" not in result.stdout:
            raise SystemExit(f"unexpected rules output: {result.stdout!r}")

        work = Path(temporary) / "work"
        source = work / "source"
        reports = work / "reports"
        source.mkdir(parents=True)
        reports.mkdir()
        password = "pQ7mL2nR9xT4vW8yZ"
        (source / "db.env").write_text(
            f"DATABASE_URL=postgresql://db_user:{password}@db.example.invalid/app\n",
            encoding="utf-8",
        )

        sanitized = reports / "sanitized.json"
        result = run(
            [
                str(binary),
                "scan",
                "--root",
                str(source),
                "--rules",
                str(rules),
                "--format",
                "sanitized",
                "--output",
                str(sanitized),
                "--run-id",
                "package-smoke",
                "--mode",
                "whole",
                "--strategy",
                "regex",
            ],
            package,
        )
        expect(result, 10, "sanitized actionable exit")
        sanitized_doc = load(sanitized)
        if sanitized_doc.get("result_code") != 3:
            raise SystemExit(f"unexpected sanitized result: {sanitized_doc}")
        sanitized_text = sanitized.read_text(encoding="utf-8")
        for forbidden in ("structured_evidence", "source_sha256", "db.env", password):
            if forbidden in sanitized_text:
                raise SystemExit(f"sanitized report leaked {forbidden!r}")

        private = reports / "private.json"
        result = run(
            [
                str(binary),
                "scan",
                "--root",
                str(source),
                "--rules",
                str(rules),
                "--format",
                "private",
                "--output",
                str(private),
                "--run-id",
                "package-smoke",
                "--mode",
                "whole",
                "--strategy",
                "regex",
                "--accept-result",
                "3",
            ],
            package,
        )
        expect(result, 0, "private accepted actionable exit")
        private_text = private.read_text(encoding="utf-8")
        if password in private_text:
            raise SystemExit("private report leaked raw password")
        private_doc = load(private)
        components = private_doc.get("structured_evidence", {}).get("components", [])
        if len(components) != 1:
            raise SystemExit(f"expected one structured component: {private_doc}")
        component = components[0]
        data = (source / "db.env").read_bytes()
        start = component["start_byte"]
        end = component["end_byte"]
        if data[start:end] != password.encode("utf-8"):
            raise SystemExit("component byte range does not identify the password")

        git = shutil.which("git")
        if git:
            repo = work / "history"
            repo.mkdir()
            for command in (
                [git, "init", "-q", "-b", "main"],
                [git, "config", "user.email", "package-smoke@example.invalid"],
                [git, "config", "user.name", "Package Smoke"],
                [git, "config", "commit.gpgsign", "false"],
            ):
                expect(run(command, repo), 0, f"git {' '.join(command[1:])}")
            (repo / "db.env").write_text(
                f"DATABASE_URL=postgresql://db_user:{password}@db.example.invalid/app\n",
                encoding="utf-8",
            )
            for command in ([git, "add", "-A"], [git, "commit", "-qm", "credential"]):
                expect(run(command, repo), 0, f"git {' '.join(command[1:])}")
            history_report = reports / "history.json"
            result = run(
                [
                    str(binary),
                    "scan",
                    "--history",
                    "--root",
                    str(repo),
                    "--rules",
                    str(rules),
                    "--format",
                    "sanitized",
                    "--output",
                    str(history_report),
                    "--run-id",
                    "package-smoke-history",
                    "--mode",
                    "stream",
                    "--strategy",
                    "prefilter",
                    "--accept-result",
                    "3",
                ],
                package,
            )
            expect(result, 0, "history scan accepted actionable exit")
            history_doc = load(history_report)
            if history_doc.get("result_code") != 3 or history_doc["history"]["commits"] != 1:
                raise SystemExit(f"unexpected history report: {history_doc}")

        print(
            json.dumps(
                {
                    "package": args.archive.name,
                    "version": version,
                    "commit": commit,
                    "platform": (package / "PLATFORM").read_text(encoding="utf-8").strip(),
                    "version_ok": True,
                    "rules_ok": True,
                    "filesystem_scan_ok": True,
                    "private_report_ok": True,
                    "history_scan_ok": shutil.which("git") is not None,
                    "exit_semantics_ok": True,
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
