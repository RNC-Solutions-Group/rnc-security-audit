#!/usr/bin/env python3
"""Run manifest-driven Gitleaks Docker acceptance tests."""

from __future__ import annotations

import argparse
import copy
import fnmatch
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence import compare_findings as compare_finding_records
from .evidence import evaluate_finding_assertions
from .evidence import fixture_exclusions
from .inventory_lock import build_inventory_lock
from .inventory_lock import canonical_digest
from .inventory_lock import reconcile_execution_inventory
from .inventory_lock import verify_inventory_lock

BUILD_DIR = Path(__file__).resolve().parent
DEFAULT_FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "datasets" / "cache" / "gitleaks-fixtures" / "5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c" / "source"
REPO_ROOT = Path(os.environ.get("GITLEAKS_FIXTURE_ROOT", str(DEFAULT_FIXTURE_ROOT))).resolve()
CONTAINER_TESTDATA = "/rnc/testdata"
CONTAINER_LOCAL = "/rnc/local"
CONTAINER_WORK = "/rnc/work"
REPORT_VERSION = 2
HARNESS_VERSION = "2.4.0"


def run_command(args: list[str], timeout: int = 120) -> dict[str, Any]:
    try:
        result = subprocess.run(
            args,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timed_out": False,
        }
    except FileNotFoundError as exc:
        return {"returncode": None, "stdout": "", "stderr": str(exc), "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {"returncode": None, "stdout": stdout, "stderr": stderr, "timed_out": True}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def git_value(*args: str) -> str | None:
    result = run_command(["git", "-C", str(REPO_ROOT), *args], timeout=10)
    if result["returncode"] == 0:
        return result["stdout"].strip()
    return None


def safe_finding(finding: dict[str, Any], testdata_root: str, local_root: str) -> dict[str, Any]:
    file_name = str(finding.get("File", ""))
    symlink_file = str(finding.get("SymlinkFile", ""))
    for prefix, replacement in (
        (testdata_root, "testdata/"),
        (local_root, "local/"),
        ("../testdata/", "testdata/"),
        ("../local/", "local/"),
    ):
        if file_name.startswith(prefix):
            file_name = replacement + file_name[len(prefix):].lstrip("/")
        if symlink_file.startswith(prefix):
            symlink_file = replacement + symlink_file[len(prefix):].lstrip("/")
    secret = str(finding.get("Secret", ""))
    match = str(finding.get("Match", ""))
    return {
        "rule_id": finding.get("RuleID", ""),
        "file": file_name.replace("\\", "/"),
        "symlink_file": symlink_file.replace("\\", "/"),
        "commit": finding.get("Commit", ""),
        "start_line": finding.get("StartLine", 0),
        "end_line": finding.get("EndLine", 0),
        "start_column": finding.get("StartColumn", 0),
        "end_column": finding.get("EndColumn", 0),
        "description": finding.get("Description", ""),
        "entropy": finding.get("Entropy", 0),
        "secret_sha256": sha256_text(secret) if secret else None,
        "match_sha256": sha256_text(match) if match else None,
        "secret_redacted": secret == "REDACTED",
    }


def finding_identity(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        finding.get("rule_id"),
        finding.get("file"),
        finding.get("commit"),
        finding.get("start_line"),
        finding.get("start_column"),
        finding.get("secret_sha256"),
    )


def compare_findings(expected: list[dict[str, Any]], actual: list[dict[str, Any]]) -> dict[str, Any]:
    return compare_finding_records(expected, actual)


def host_environment() -> dict[str, Any]:
    docker_version = run_command(["docker", "version", "--format", "{{.Client.Version}}"], timeout=15)
    docker_server = run_command(["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"], timeout=15)
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "host_platform": platform.platform(),
        "host_system": platform.system(),
        "python_version": platform.python_version(),
        "docker_client_version": docker_version["stdout"].strip() if docker_version["returncode"] == 0 else None,
        "docker_daemon_platform": docker_server["stdout"].strip() if docker_server["returncode"] == 0 else None,
        "source_branch": git_value("branch", "--show-current"),
        "source_commit": git_value("rev-parse", "HEAD"),
        "source_worktree_clean": git_value("status", "--porcelain") == "",
    }


def load_image_metadata(image: str) -> tuple[dict[str, Any] | None, str | None]:
    result = run_command(["docker", "image", "inspect", image], timeout=30)
    if result["returncode"] != 0:
        return None, "Docker image is not available locally; no pull was attempted."
    try:
        raw = json.loads(result["stdout"])[0]
    except (ValueError, IndexError, TypeError):
        return None, "Docker returned image metadata that could not be parsed."
    config = raw.get("Config") or {}
    return {
        "requested_tag": image,
        "image_id": raw.get("Id"),
        "repo_digests": raw.get("RepoDigests", []),
        "repo_tags": raw.get("RepoTags", []),
        "created": raw.get("Created"),
        "os": raw.get("Os"),
        "architecture": raw.get("Architecture"),
        "entrypoint": config.get("Entrypoint"),
        "command": config.get("Cmd"),
        "labels": config.get("Labels") or {},
    }, None


def image_runtime_version(image: str) -> dict[str, Any]:
    result = run_command(["docker", "run", "--rm", "--pull=never", "--network", "none", image, "version"], timeout=30)
    return {
        "returncode": result["returncode"],
        "version_output": result["stdout"].strip() if result["returncode"] == 0 else None,
        "diagnostic": "version command failed; output omitted" if result["returncode"] != 0 else None,
    }


def fixture_id(origin: str, path: str) -> str:
    return f"{origin}:{path.rstrip('/')}"


def upstream_tests_for(path: str) -> list[str]:
    if path.startswith("testdata/repos/nogit/"):
        return ["detect.TestFromFiles"]
    if path.startswith("testdata/repos/small/"):
        return ["detect.TestFromGit"]
    if path.startswith("testdata/repos/staged/"):
        return ["detect.TestFromGitStaged"]
    if path.startswith("testdata/repos/symlinks/"):
        return ["detect.TestDetectWithSymlinks"]
    if path.startswith("testdata/repos/archives/"):
        return ["detect.TestFromGit"]
    if path.startswith("testdata/archives/"):
        return ["detect.TestDetectWithArchives"]
    if path.startswith("testdata/config/invalid/") or path.startswith("testdata/config/valid/"):
        return ["config.TestTranslate", "config.TestTranslateAllowlists", "config.TestTranslateExtend"]
    if path.startswith("testdata/config/"):
        return ["detect.TestDetect"]
    if path.startswith("testdata/baseline/"):
        return ["detect.TestLoadBaseline", "detect.TestAddBaseline"]
    if path.startswith("testdata/expected/report/") or path.startswith("testdata/report/"):
        return ["report.TestWriteJSON", "report.TestWriteCSV", "report.TestWriteJunit", "report.TestWriteSarif", "report.TestWriteTemplate"]
    if path.startswith("testdata/expected/git/"):
        return ["detect.TestFromGit"]
    if path.startswith("testdata/gitleaksignore/"):
        return ["detect.TestNormalizeGitleaksIgnorePaths"]
    return []


def classify_fixture(path: str, rule: dict[str, Any], origin: str, scenarios: list[str] | None = None) -> str:
    if rule.get("classification"):
        return rule["classification"]
    if origin == "synthetic":
        return "ASSERTABLE"
    if path.startswith("testdata/repos/nogit/"):
        return "ASSERTABLE"
    if path.startswith("testdata/archives/"):
        return "SUPPORTING" if path.endswith(".gitleaksignore") else "ASSERTABLE"
    if path.startswith("testdata/repos/symlinks/"):
        return "ASSERTABLE"
    if path.startswith("testdata/repos/small/dotGit/") or path.endswith("/.gitleaksignore"):
        return "SUPPORTING"
    exact_git_assertions = {
        "testdata/repos/small/main.go": "git-history",
        "testdata/repos/small/api/api.go": "git-api-clean",
        "testdata/repos/small/api/ignoreGlobal.go": "git-ignore-global",
        "testdata/repos/small/api/ignoreCommit.go": "git-ignore-commit",
        "testdata/repos/small/README.md": "git-readme-clean",
    }
    scenario_ids = scenarios if scenarios is not None else rule.get("tests", [])
    if path in exact_git_assertions and exact_git_assertions[path] in scenario_ids:
        return "ASSERTABLE"
    if path.startswith("testdata/repos/small/"):
        return "EXERCISED"
    if path.startswith("testdata/repos/staged/dotGit/"):
        return "SUPPORTING"
    if path == "testdata/repos/staged/api/api.go" and "git-staged" in rule.get("tests", []):
        return "ASSERTABLE"
    if path.startswith("testdata/repos/staged/"):
        return "SUPPORTING"
    if path.startswith("testdata/repos/staged/") or path.startswith("testdata/repos/archives/"):
        return "INTERNAL_GO"
    if path == "testdata/config/invalid/allowlist_global_empty.toml":
        return "ASSERTABLE"
    if path.startswith("testdata/config/valid/") or path.startswith("testdata/config/invalid/"):
        return "INTERNAL_GO"
    if path.startswith(("testdata/baseline/", "testdata/expected/", "testdata/report/", "testdata/gitleaksignore/")):
        return "INTERNAL_GO"
    if path.startswith("testdata/config/"):
        return "SUPPORTING"
    return "UNTESTED"


def fixture_type_for(path: str, rule: dict[str, Any]) -> str:
    if rule.get("fixture_type"):
        return rule["fixture_type"]
    if path == "testdata/repos/symlinks/file_symlink/symlinked_id_ed25519":
        return "symlink"
    if "/dotGit/" in f"/{path}/":
        return "git-metadata"
    if path.endswith(".gitleaksignore"):
        return "ignore-file"
    if path.endswith(".toml"):
        return "configuration"
    if path.endswith((".tar", ".zip", ".7z", ".tar.xz", ".tar.zst", ".tar.gz")):
        return "archive"
    if path.endswith((".gz", ".xz", ".zst")):
        return "compressed-file"
    if "/." in path:
        return "hidden-file"
    return Path(path).suffix.lstrip(".") or "file"


def expand_inventory(
    manifest: dict[str, Any],
    cases: list[dict[str, Any]],
    fixture_source_revision: str | None = None,
) -> list[dict[str, Any]]:
    case_ids = {case["id"] for case in cases}
    synthetic_source_revision = git_value("rev-parse", "HEAD") or fixture_source_revision
    records: dict[str, dict[str, Any]] = {}
    missing: list[dict[str, Any]] = []
    for rule in manifest.get("inventory", []):
        root = rule.get("root", "repo")
        base = REPO_ROOT if root == "repo" else BUILD_DIR
        pattern = rule["glob"]
        matches = [path for path in sorted(base.glob(pattern)) if path.is_file() or path.is_symlink()]
        if not matches:
            missing.append({
                "fixture_id": fixture_id("upstream" if root == "repo" else "synthetic", pattern),
                "path": pattern,
                "origin": "upstream" if root == "repo" else "synthetic",
                "fixture_type": "missing-pattern",
                "purpose": rule.get("reason", "Manifest fixture pattern has no matching files."),
                "expected_behavior": "Fixture should exist in the source checkout.",
                "scenarios": [],
                "required_assertions": [],
                "validation_method": "fixture inventory discovery",
                "classification": "UNSUPPORTED",
                "coverage_status": "UNSUPPORTED",
                "exclusion_reason": "No matching fixture exists in this checkout.",
                "upstream_tests": rule.get("upstream_tests", []),
                "source_revision": fixture_source_revision if root == "repo" else synthetic_source_revision,
            })
            continue
        for path in matches:
            relative = path.relative_to(base).as_posix()
            origin = "upstream" if root == "repo" else "synthetic"
            key = fixture_id(origin, relative)
            scenario_map = rule.get("scenario_fixtures", {})
            scenario_source = scenario_map.get(relative, rule.get("tests", []))
            scenarios = [test_id for test_id in scenario_source if test_id in case_ids]
            classification = classify_fixture(relative, rule, origin, scenarios)
            records[key] = {
                "fixture_id": key,
                "path": relative,
                "origin": origin,
                "source_revision": fixture_source_revision if origin == "upstream" else synthetic_source_revision,
                "fixture_type": fixture_type_for(relative, rule),
                "purpose": rule.get("purpose", rule.get("reason", "")),
                "expected_behavior": rule.get("expected_behavior", rule.get("reason", "")),
                "scenarios": scenarios,
                "required_assertions": [],
                "validation_method": rule.get(
                    "validation_method",
                    "Docker CLI structured findings" if classification == "ASSERTABLE"
                    else "upstream Go test contract" if classification == "INTERNAL_GO"
                    else "scenario input or supporting metadata",
                ),
                "classification": classification,
                "coverage_status": "UNTESTED" if classification in ("ASSERTABLE", "UNTESTED", "UNSUPPORTED") else classification,
                "exclusion_reason": rule.get("exclusion_reason", ""),
                "upstream_tests": rule.get("upstream_tests") or upstream_tests_for(relative),
            }

    for case in cases:
        bundle_path = case.get("fixture_bundle")
        if not bundle_path and str(case.get("fixture", "")).endswith("/"):
            bundle_path = case["fixture"].rstrip("/")
        if not bundle_path:
            continue
        origin = "upstream" if bundle_path.startswith("testdata/") else "synthetic"
        key = fixture_id(origin, bundle_path)
        records.setdefault(key, {
            "fixture_id": key,
            "path": bundle_path,
            "origin": origin,
            "source_revision": fixture_source_revision if origin == "upstream" else synthetic_source_revision,
            "fixture_type": "scenario-bundle",
            "purpose": case.get("name", "Scenario fixture bundle"),
            "expected_behavior": case.get("expectation", ""),
            "scenarios": [case["id"]],
            "required_assertions": [],
            "validation_method": "Docker CLI scenario with exact structured assertions",
            "classification": "ASSERTABLE",
            "coverage_status": "UNTESTED",
            "exclusion_reason": "",
            "upstream_tests": case.get("upstream_tests", []),
        })

    return list(records.values()) + missing


def create_fixture_inventory_lock(manifest: dict[str, Any], source_revision: str | None) -> dict[str, Any]:
    manifest_digest = canonical_digest(manifest)
    entries = expand_inventory(manifest, manifest.get("cases", []), source_revision)
    return build_inventory_lock(
        manifest,
        entries,
        REPO_ROOT,
        BUILD_DIR,
        source_revision,
        manifest_digest,
    )


def harness_implementation_identity() -> str:
    digest = hashlib.sha256()
    for name in ("validate.py", "evidence.py", "inventory_lock.py", "aggregate.py", "exclusions.py"):
        path = BUILD_DIR / name
        content = path.read_bytes()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def materialize_git_fixture(source: Path, destination: Path) -> tuple[Path | None, str | None, str | None]:
    if not source.exists():
        return None, "Git fixture source is missing.", None
    shutil.copytree(source, destination, symlinks=True)
    dot_git = destination / "dotGit"
    if dot_git.is_dir():
        dot_git.rename(destination / ".git")
    if not (destination / ".git").exists():
        return None, "Git fixture has no .git directory after staging.", None

    adaptations: list[str] = []
    packed_refs = destination / ".git" / "packed-refs"
    if packed_refs.is_file():
        original_lines = packed_refs.read_text(encoding="ascii").splitlines()
        retained_lines = [
            line for line in original_lines
            if not line.endswith(" refs/remotes/origin/main")
        ]
        if retained_lines != original_lines:
            packed_refs.write_text("\n".join(retained_lines) + "\n", encoding="ascii")
            adaptations.append("removed the stale packed refs/remotes/origin/main reference")

    remote_main = destination / ".git" / "refs" / "remotes" / "origin" / "main"
    if remote_main.exists():
        remote_main.unlink()
        adaptations.append("removed the stale loose refs/remotes/origin/main reference")
    remote_head = destination / ".git" / "refs" / "remotes" / "origin" / "HEAD"
    if remote_head.is_file() and remote_head.read_text(encoding="ascii").strip() == "ref: refs/remotes/origin/main":
        remote_head.unlink()
        adaptations.append("removed the dangling refs/remotes/origin/HEAD symbolic reference")

    adaptation = "; ".join(adaptations) or None
    return destination, None, adaptation


def materialize_linux_symlink_volume(
    testdata: Path,
    fixture_source_revision: str | None,
    symlink_path: str,
) -> tuple[str | None, dict[str, Any], str | None]:
    metadata: dict[str, Any] = {
        "method": "temporary Docker volume seeded by a Linux helper container",
        "helper_image": "alpine:3.24",
        "fixture_source_revision": fixture_source_revision,
        "symlink_path": symlink_path,
    }
    if not fixture_source_revision:
        return None, metadata, "Could not identify the upstream fixture source revision."

    source_path = f"testdata/{symlink_path}"
    tree_entry = git_value("ls-tree", fixture_source_revision, "--", source_path)
    if not tree_entry or not tree_entry.startswith("120000 blob "):
        return None, metadata, "The fixture source revision does not record this path as a Git symlink."
    target_result = run_command(
        ["git", "-C", str(REPO_ROOT), "cat-file", "-p", f"{fixture_source_revision}:{source_path}"],
        timeout=15,
    )
    if target_result["returncode"] != 0:
        return None, metadata, "Could not read the symlink target from the fixture source revision."
    target = target_result["stdout"].strip()
    metadata["link_target"] = target
    metadata["git_mode"] = "120000"
    metadata["git_blob"] = tree_entry.split()[2]

    helper_inspect = run_command(["docker", "image", "inspect", metadata["helper_image"]], timeout=20)
    if helper_inspect["returncode"] == 0:
        try:
            metadata["helper_image_id"] = json.loads(helper_inspect["stdout"])[0].get("Id")
        except (ValueError, IndexError, TypeError):
            metadata["helper_image_id"] = None

    volume_name = f"rnc-gitleaks-accept-{uuid.uuid4().hex}"
    created = run_command(["docker", "volume", "create", volume_name], timeout=30)
    if created["returncode"] != 0:
        return None, metadata, "Could not create a temporary Docker volume for Linux symlink staging."
    metadata["temporary_volume_created"] = True

    script = (
        "set -eu; cp -a /source/. /fixture/; "
        "link=/fixture/$RNC_LINK_PATH; rm -f \"$link\"; "
        "ln -s \"$RNC_LINK_TARGET\" \"$link\"; "
        "test -L \"$link\"; test -e \"$link\"; "
        "test \"$(readlink \"$link\")\" = \"$RNC_LINK_TARGET\"; "
        "printf 'link_type=symlink\\ntarget_resolves=yes\\n'"
    )
    helper_args = [
        "docker", "run", "--rm", "--pull=never", "--network", "none",
        "--mount", mount_arg(testdata, "/source"),
        "--mount", f"type=volume,source={volume_name},target=/fixture",
        "--env", f"RNC_LINK_PATH=repos/symlinks/file_symlink/{Path(symlink_path).name}",
        "--env", f"RNC_LINK_TARGET={target}",
        "--entrypoint", "/bin/sh", metadata["helper_image"], "-c", script,
    ]
    helper = run_command(helper_args, timeout=120)
    metadata["staging_stdout"] = helper["stdout"].strip()
    metadata["staging_stdout_sha256"] = sha256_text(helper["stdout"])
    if helper["returncode"] != 0 or "target_resolves=yes" not in helper["stdout"]:
        run_command(["docker", "volume", "rm", volume_name], timeout=30)
        metadata["temporary_volume_created"] = False
        return None, metadata, "Linux helper could not create and verify the relative symlink fixture."
    metadata["staging_verified"] = True
    return volume_name, metadata, None


def mount_arg(source: Path, target: str) -> str:
    return f"type=bind,source={source.resolve()},target={target},readonly"


def build_docker_args(
    image: str,
    case: dict[str, Any],
    testdata: Path,
    local_fixtures: Path,
    empty_ignore: Path,
    work_dir: Path,
    source: str,
    testdata_mount: str | None = None,
) -> list[str]:
    command = [
        "docker", "run", "--rm", "--pull=never", "--network", "none",
        "--env", "GIT_OPTIONAL_LOCKS=0",
        "--mount", testdata_mount or mount_arg(testdata, CONTAINER_TESTDATA),
        "--mount", mount_arg(local_fixtures, CONTAINER_LOCAL),
        "--mount", mount_arg(empty_ignore, "/rnc/empty-ignore"),
        "--mount", mount_arg(work_dir, CONTAINER_WORK),
        "--workdir", CONTAINER_WORK,
        image,
        case["command"],
        "--config", container_path(case["config"]),
        "--no-banner",
        "--report-format", "json",
        "--report-path", "-",
        "--exit-code", "1",
        "--gitleaks-ignore-path",
        container_relative_path(case["gitleaks_ignore_path"])
        if case.get("relative_source") and case.get("gitleaks_ignore_path")
        else container_path(case["gitleaks_ignore_path"])
        if case.get("gitleaks_ignore_path")
        else "/rnc/empty-ignore",
    ]
    for option in case.get("options", []):
        command.extend(option)
    if case.get("baseline_path"):
        baseline_path = container_relative_path(case["baseline_path"]) if case.get("relative_source") else container_path(case["baseline_path"])
        command.extend(["--baseline-path", baseline_path])
    command.append(source)
    return command


def container_path(path: str) -> str:
    if path.startswith("testdata/"):
        return f"{CONTAINER_TESTDATA}/{path[len('testdata/'):]}"
    if path.startswith("fixtures/"):
        return f"{CONTAINER_LOCAL}/{path[len('fixtures/'):]}"
    raise ValueError(f"Manifest path must start with testdata/ or fixtures/: {path}")


def container_relative_path(path: str) -> str:
    if path.startswith("testdata/"):
        return f"../testdata/{path[len('testdata/'):]}"
    if path.startswith("fixtures/"):
        return f"../local/{path[len('fixtures/'):]}"
    raise ValueError(f"Manifest path must start with testdata/ or fixtures/: {path}")


def fixture_id_from_report_path(path: str) -> str | None:
    normalized = path.replace("\\", "/")
    if normalized.startswith("../testdata/"):
        normalized = normalized[len("../"):]
    if normalized.startswith("testdata/"):
        return fixture_id("upstream", normalized.split("!", 1)[0])
    if normalized.startswith("../local/"):
        normalized = normalized[len("../"):]
    if normalized.startswith("local/"):
        return fixture_id("synthetic", "fixtures/" + normalized[len("local/"):].split("!", 1)[0])
    return None


def fixture_id_for_case(case: dict[str, Any]) -> str | None:
    bundle = case.get("fixture_bundle") or case.get("fixture", "")
    bundle = str(bundle).rstrip("/")
    if bundle.startswith("testdata/"):
        return fixture_id("upstream", bundle)
    if bundle.startswith("fixtures/"):
        return fixture_id("synthetic", bundle)
    return None


def run_case(
    case: dict[str, Any],
    image: str,
    testdata: Path,
    local_fixtures: Path,
    workspace: Path,
    testdata_mount: str | None = None,
    symlink_staging_error: str | None = None,
    symlink_staging_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    case_result: dict[str, Any] = {
        "id": case["id"],
        "name": case["name"],
        "fixture": case["fixture"],
        "expected": case.get("expectation", ""),
        "actual": "not executed",
        "status": "NOT RUN",
        "actual_exit_code": None,
        "expected_exit_code": case.get("expected_exit_code"),
        "duration_seconds": 0,
        "findings": [],
        "missing_findings": [],
        "added_findings": [],
        "changed_findings": [],
        "stdout_sha256": None,
        "stderr_sha256": None,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "fixture_adaptation": None,
        "assertions": [],
        "diagnostic": None,
        "read_only_mounts": True,
    }
    empty_ignore = workspace / "empty-ignore"
    empty_ignore.mkdir(parents=True, exist_ok=True)
    case_work = workspace / case["id"]
    case_work.mkdir(parents=True, exist_ok=True)
    source_spec = case["source"]

    if case.get("prepare_git_copy"):
        original = testdata / source_spec.removeprefix("testdata/")
        staged, issue, adaptation = materialize_git_fixture(original, case_work / "git-repository")
        if issue:
            case_result.update(status="UNSUPPORTED", actual="not executed: Git fixture unavailable", diagnostic=issue)
            return case_result
        case_result["fixture_adaptation"] = adaptation
        source = f"{CONTAINER_WORK}/git-repository"
    else:
        source = container_relative_path(source_spec) if case.get("relative_source") else container_path(source_spec)

    if case.get("requires_linux_symlink") and symlink_staging_error:
        case_result.update(
            status="UNSUPPORTED",
            actual="not executed: Linux-native symlink fixture could not be staged",
            diagnostic=symlink_staging_error,
            fixture_adaptation=symlink_staging_metadata,
        )
        return case_result

    docker_args = build_docker_args(image, case, testdata, local_fixtures, empty_ignore, case_work, source, testdata_mount)
    if case.get("requires_linux_symlink"):
        case_result["fixture_adaptation"] = symlink_staging_metadata
    image_argument = docker_args.index(image)
    case_result["execution"] = {
        "network": "none",
        "docker_command": list(docker_args),
        "container_argv": docker_args[image_argument + 1:],
        "config_path": container_path(case["config"]),
        "mounts_read_only": [CONTAINER_TESTDATA, CONTAINER_LOCAL, "/rnc/empty-ignore", CONTAINER_WORK],
        "image_pull": "never",
    }
    process = run_command(docker_args, timeout=case.get("timeout_seconds", 120))
    case_result["actual_exit_code"] = process["returncode"]
    case_result["stdout_sha256"] = sha256_text(process["stdout"])
    case_result["stderr_sha256"] = sha256_text(process["stderr"])
    case_result["stdout_bytes"] = len(process["stdout"].encode("utf-8"))
    case_result["stderr_bytes"] = len(process["stderr"].encode("utf-8"))
    if process["timed_out"]:
        case_result.update(status="FAIL", diagnostic="Docker scan exceeded the case timeout.")
        case_result["duration_seconds"] = round(time.monotonic() - started, 3)
        return case_result
    if process["returncode"] is None:
        case_result.update(status="ERROR", diagnostic="Docker CLI could not be started.")
        case_result["duration_seconds"] = round(time.monotonic() - started, 3)
        return case_result

    if case.get("expect_config_error"):
        contains = case["expect_config_error"]
        passed = process["returncode"] == case.get("expected_exit_code") and contains in process["stderr"]
        case_result["assertions"] = [
            {
                "assertion_id": f"{case['id']}.exit_code",
                "type": "exit_code",
                "fixture_id": fixture_id_for_case(case),
                "expected": case.get("expected_exit_code"),
                "actual": process["returncode"],
                "status": "PASS" if process["returncode"] == case.get("expected_exit_code") else "FAIL",
            },
            {
                "assertion_id": f"{case['id']}.config_error",
                "type": "configuration_rejected",
                "fixture_id": fixture_id_for_case(case),
                "expected": "known invalid allowlist diagnostic",
                "actual": "matched" if contains in process["stderr"] else "not matched",
                "status": "PASS" if contains in process["stderr"] else "FAIL",
            },
        ]
        case_result["actual"] = "expected config rejection" if passed else "config error did not match expectation"
        case_result["diagnostic"] = None if passed else "Expected config diagnostic was absent; stderr omitted to protect fixture contents."
        case_result["status"] = "PASS" if passed else "FAIL"
        case_result["duration_seconds"] = round(time.monotonic() - started, 3)
        return case_result

    try:
        raw_findings = json.loads(process["stdout"])
        if not isinstance(raw_findings, list):
            raise ValueError("JSON report is not an array")
    except (ValueError, TypeError):
        case_result.update(status="FAIL", diagnostic="Container did not return a parseable JSON findings array.")
        case_result["duration_seconds"] = round(time.monotonic() - started, 3)
        return case_result

    normalized = [safe_finding(finding, CONTAINER_TESTDATA, CONTAINER_LOCAL) for finding in raw_findings]
    case_result["findings"] = normalized
    expected_findings = copy.deepcopy(case.get("expected_findings", []))
    forbidden_findings = copy.deepcopy(case.get("forbidden_findings", []))
    for finding in expected_findings:
        finding.setdefault(
            "fixture_id",
            fixture_id_from_report_path(finding.get("symlink_file", ""))
            or fixture_id_from_report_path(finding.get("file", ""))
            or fixture_id_for_case(case),
        )
        related = fixture_id_from_report_path(finding.get("file", ""))
        if related and related != finding["fixture_id"]:
            finding["related_fixture_ids"] = [related]
    for finding in forbidden_findings:
        finding.setdefault("fixture_id", fixture_id_from_report_path(finding.get("file", "")))
    comparison, assertions = evaluate_finding_assertions(
        case["id"], expected_findings, normalized, forbidden_findings
    )
    case_result["assertions"] = assertions
    scenario_fixture_id = fixture_id_for_case(case)
    for assertion in case_result["assertions"]:
        if not assertion.get("fixture_id") and scenario_fixture_id:
            assertion["fixture_id"] = scenario_fixture_id
        if assertion["type"] == "suppression_absence" and case.get("gitleaks_ignore_path"):
            ignore_id = fixture_id_from_report_path(case["gitleaks_ignore_path"] + "/.gitleaksignore")
            if ignore_id:
                assertion.setdefault("related_fixture_ids", []).append(ignore_id)
    case_result["assertions"].append({
        "assertion_id": f"{case['id']}.json_report",
        "type": "json_report_valid",
        "fixture_id": scenario_fixture_id,
        "expected": "JSON array",
        "actual": "JSON array",
        "status": "PASS",
    })
    case_result["assertions"].append({
        "assertion_id": f"{case['id']}.exit_code",
        "type": "exit_code",
        "fixture_id": scenario_fixture_id,
        "expected": case.get("expected_exit_code"),
        "actual": process["returncode"],
        "status": "PASS" if process["returncode"] == case.get("expected_exit_code") else "FAIL",
    })
    if case.get("baseline_path"):
        case_result["assertions"].append({
            "assertion_id": f"{case['id']}.baseline_suppression",
            "type": "baseline_suppression",
            "fixture_id": fixture_id_from_report_path("local/" + case["baseline_path"][len("fixtures/"):]),
            "expected": "known finding suppressed by explicit baseline",
            "actual": "no findings" if not normalized else f"{len(normalized)} finding(s) remain",
            "status": "PASS" if not normalized else "FAIL",
        })
    plain_stderr = re.sub(r"\x1b\[[0-9;]*m", "", process["stderr"])
    for index, expected_trace in enumerate(case.get("assert_stderr_contains", []), 1):
        observed = expected_trace in plain_stderr
        case_result["assertions"].append({
            "assertion_id": f"{case['id']}.traversal.{index}",
            "type": "fixture_traversal",
            "fixture_id": fixture_id_for_case(case),
            "expected": expected_trace,
            "actual": "observed" if observed else "not observed",
            "status": "PASS" if observed else "FAIL",
        })
    case_result["missing_findings"] = comparison["missing"]
    case_result["added_findings"] = comparison["added"]
    case_result["changed_findings"] = comparison["changed"]
    case_result["unexpected_forbidden_findings"] = comparison["unexpected_forbidden"]
    forbidden = case.get("forbidden_findings", [])
    case_result["unexpected_forbidden_findings"] = [
        finding for finding in normalized
        if any(all(finding.get(key) == value for key, value in forbidden_finding.items()) for forbidden_finding in forbidden)
    ]
    expected_exit = case.get("expected_exit_code")
    passed = (
        process["returncode"] == expected_exit
        and not comparison["missing"]
        and not comparison["added"]
        and not comparison["changed"]
        and not case_result["unexpected_forbidden_findings"]
        and all(assertion["status"] == "PASS" for assertion in case_result["assertions"])
    )
    case_result["actual"] = f"exit {process['returncode']}; {len(normalized)} finding(s)"
    case_result["status"] = "PASS" if passed else "FAIL"
    if not passed:
        case_result["diagnostic"] = "Exit code or finding-level expectations differed; see finding diff fields."
    case_result["duration_seconds"] = round(time.monotonic() - started, 3)
    return case_result


def markdown_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    rows = [
        "# RNC Solutions Group, Inc. | Gitleaks Docker Acceptance",
        "",
        "```text",
        "RRRRR  N   N  CCCCC",
        "R   R  NN  N  C",
        "RRRRR  N N N  C",
        "R  R   N  NN  C",
        "R   R  N   N  CCCCC",
        "```",
        "",
        "**RNC Solutions Group, Inc.**<br>",
        "Turning Complexity into Clarity.<br>",
        "[www.rncsolutionsgroup.com](http://www.rncsolutionsgroup.com)<br>",
        "Contributed by: Dave Woods (@davidwoods15)",
        "",
        "## Executive Summary",
        "",
        f"- Functional result: **{report['functional_result']}**",
        f"- Coverage result: **{report['coverage_result']}**",
        f"- Overall acceptance: **{report['overall_acceptance']}**",
        f"- Image build status: **{report['build_status']}**",
        f"- Image: `{report['image'].get('requested_tag', 'unknown')}` ({report['image'].get('image_id', 'unavailable')})",
        f"- Scenarios: {summary['scenario_passed']} passed, {summary['scenario_failed']} failed, {summary['scenario_unsupported']} unsupported, {summary['scenario_not_run']} not run",
        f"- Assertions: {summary['assertion_passed']} passed, {summary['assertion_failed']} failed, {summary['assertion_unsupported']} unsupported, {summary['assertion_not_run']} not run",
        f"- Physical fixtures: {summary['physical_fixture_discovered']} discovered; {summary['docker_applicable_fixtures']} Docker-applicable; {summary['docker_validated_fixtures']} validated",
        f"- Scenario bundles: {summary['scenario_bundle_validated']} / {summary['scenario_bundle_count']} validated ({summary['scenario_bundle_unvalidated']} unvalidated)",
        "",
        "## Scenario Results",
        "",
        "| Scenario | Group | Test | Fixture | Expected | Actual | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for case in report["tests"]:
        rows.append(
            "| {id} | {group} | {name} | {fixture} | {expected} | {actual} | {status} |".format(
                **{
                    key: str(value or "").replace("|", "\\|").replace("\n", " ")
                    for key, value in {
                        "id": case.get("id"),
                        "group": case.get("scenario_group", "general"),
                        "name": case.get("name"),
                        "fixture": case.get("fixture"),
                        "expected": case.get("expected", case.get("expectation", "")),
                        "actual": case.get("actual"),
                        "status": case.get("status"),
                    }.items()
                }
            )
        )
    rows.extend(["", "## Assertion Results", "", "| Assertion | Scenario | Fixture | Expected | Actual | Status |", "|---|---|---|---|---|---|"])
    for case in report["tests"]:
        for assertion in case.get("assertions", []):
            expected = json.dumps(assertion.get("expected"), sort_keys=True) if isinstance(assertion.get("expected"), (dict, list)) else assertion.get("expected", "")
            actual = json.dumps(assertion.get("actual"), sort_keys=True) if isinstance(assertion.get("actual"), (dict, list)) else assertion.get("actual", "")
            rows.append(
                "| {assertion} | {scenario} | {fixture} | {expected} | {actual} | {status} |".format(
                    assertion=assertion.get("assertion_id", ""),
                    scenario=case.get("id", ""),
                    fixture=assertion.get("fixture_id", ""),
                    expected=str(expected).replace("|", "\\|").replace("\n", " "),
                    actual=str(actual).replace("|", "\\|").replace("\n", " "),
                    status=assertion.get("status", "NOT RUN"),
                )
            )
    comparison = report.get("comparison")
    if comparison:
        rows.extend([
            "",
            "## Image Comparison",
            "",
            f"Compared with `{comparison['baseline_image'].get('requested_tag')}` ({comparison['baseline_image'].get('image_id')}):",
            "",
            "| Scenario | Comparison | Findings removed/added/changed | Exit code baseline/candidate | Scenario status baseline/candidate |",
            "|---|---|---|---|---|",
        ])
        for case in comparison["tests"]:
            if case.get("status") == "N/A":
                rows.append(f"| {case['id']} | N/A | N/A | N/A | N/A |")
            else:
                exit_difference = case["exit_code_difference"]
                status_difference = case["scenario_status_difference"]
                rows.append(
                    f"| {case['id']} | {case['parity_status']} | {len(case['missing'])}/{len(case['added'])}/{len(case['changed'])} | "
                    f"{exit_difference['baseline']} / {exit_difference['candidate']} | "
                    f"{status_difference['baseline']} / {status_difference['candidate']} |"
                )
    rows.extend([
        "",
        "## Physical Fixture Coverage",
        "",
        f"- Discovered: {summary['physical_fixture_discovered']}",
        f"- Docker-applicable: {summary['docker_applicable_fixtures']}",
        f"- Validated: {summary['docker_validated_fixtures'] + summary['internal_go_validated']}",
        f"- Exercised without individual proof: {summary['exercised_fixtures']}",
        f"- Internal Go only: {summary['internal_go_fixtures']} ({summary['internal_go_validated']} validated, {summary['internal_go_not_run']} pending)",
        f"- Supporting: {summary['supporting_fixtures']}",
        f"- Unsupported: {summary['unsupported_fixtures']}",
        f"- Unvalidated applicable: {summary['unvalidated_fixtures']}",
        "",
        "| Fixture ID | Path | Origin | Type | Classification | Status | Scenarios | Upstream tests |",
        "|---|---|---|---|---|---|---|---|",
    ])
    for entry in report["fixture_coverage"]:
        if entry.get("fixture_type") == "scenario-bundle":
            continue
        rows.append(
            "| `{fixture_id}` | `{path}` | {origin} | {fixture_type} | {classification} | {status} | {scenarios} | {upstream_tests} |".format(
                fixture_id=entry["fixture_id"],
                path=entry["path"],
                origin=entry["origin"],
                fixture_type=entry["fixture_type"],
                classification=entry["classification"],
                status=entry["coverage_status"],
                scenarios=", ".join(entry.get("scenarios", [])),
                upstream_tests=", ".join(entry.get("upstream_tests", [])),
            )
        )
    rows.extend([
        "",
        "## Scenario Coverage",
        "",
        f"- Scenarios executed: {summary['scenario_executed']} / {summary['scenario_total']}",
        f"- Scenarios passed / failed: {summary['scenario_passed']} / {summary['scenario_failed']}",
        f"- Assertions executed / passed / failed: {summary['assertion_total'] - summary['assertion_not_run']} / {summary['assertion_passed']} / {summary['assertion_failed']}",
        f"- Scenario bundles validated: {summary['scenario_bundle_validated']} / {summary['scenario_bundle_count']} ({summary['scenario_bundle_unvalidated']} unvalidated)",
        "",
        "| Bundle ID | Path | Status | Scenarios |",
        "|---|---|---|---|",
    ])
    for entry in report["fixture_coverage"]:
        if entry.get("fixture_type") != "scenario-bundle":
            continue
        rows.append(f"| `{entry['fixture_id']}` | `{entry['path']}` | {entry['coverage_status']} | {', '.join(entry.get('scenarios', []))} |")
    rows.extend(["", "## Failures and Limitations", ""])
    failure_cases = [case for case in report["tests"] if case["status"] not in ("PASS",)]
    if failure_cases:
        for case in failure_cases:
            rows.append(f"- **{case['status']} - {case['id']}**: {case.get('diagnostic') or 'finding mismatch'}")
    else:
        rows.append("No failures, unsupported cases, or unexecuted tests.")
    rows.extend(["", "Known limitations:"])
    for limitation in report.get("limitations", []):
        rows.append(f"- {limitation}")
    rows.extend(["", "Finding values in this report are represented by SHA-256 hashes.", "", "## Reproducibility", ""])
    rows.append(f"- Image ID: `{report['image'].get('image_id', 'unavailable')}`")
    rows.append(f"- Image platform: `{report['image'].get('os', 'unknown')}/{report['image'].get('architecture', 'unknown')}`")
    rows.append(f"- Runtime version: `{report.get('runtime', {}).get('version_output') or 'unavailable'}`")
    rows.append(f"- Source commit: `{report['environment'].get('source_commit') or 'unknown'}`")
    rows.append(f"- Host: `{report['environment'].get('host_platform')}`; Docker daemon: `{report['environment'].get('docker_daemon_platform') or 'unavailable'}`")
    rows.append(f"- Generated: `{report['environment']['timestamp_utc']}`")
    exclusions = report.get("fixture_exclusions", [])
    rows.extend([
        "",
        "## Fixture Exclusions",
        "",
        f"Applicable physical fixtures: {summary['applicable_fixtures']}",
        f"Validated physical fixtures this run: {summary['docker_validated_fixtures'] + summary['internal_go_validated']}",
        f"Not validated this run: {len(exclusions)}",
        "",
        "UNVALIDATED FIXTURES",
        "--------------------------------------------------",
    ])
    if not exclusions:
        rows.append("NONE")
    else:
        for entry in exclusions:
            rows.append(f"- `{entry['path']}` | expected: {entry.get('expected_behavior', '')} | reason: {entry.get('exclusion_reason', '')} | scenario: {', '.join(entry.get('scenarios', []))} | next: {entry.get('next_action', '')}")
    rows.extend([
        "",
        f"FUNCTIONAL RESULT: {report['functional_result']}",
        f"COVERAGE: {report['coverage_result']} ({summary['validated_fixtures']}/{summary['applicable_fixtures']})",
        f"OVERALL ACCEPTANCE: {report['overall_acceptance']}",
    ])
    return "\n".join(rows) + "\n"


def render_terminal(report: dict[str, Any]) -> str:
    image = report.get("image") or {}
    environment = report["environment"]
    summary = report["summary"]
    lines = [
        "/// RNC Solutions Group, Inc.",
        "/// Contributed by: Dave Woods (@davidwoods15)",
        "",
        "RNC SECURITY TOOLKIT",
        "GITLEAKS DOCKER ACCEPTANCE",
        "==========================================================",
        f"Image: {image.get('requested_tag')} | ID: {image.get('image_id') or 'unavailable'}",
        f"Platform: {image.get('os', 'unknown')}/{image.get('architecture', 'unknown')} | Runtime: {report.get('runtime', {}).get('version_output') or 'unavailable'}",
        f"Host: {environment.get('host_system')} | Docker daemon: {environment.get('docker_daemon_platform') or 'unavailable'}",
        f"Scenarios: {summary['scenario_passed']} passed / {summary['scenario_total']}; {summary['scenario_failed']} failed; {summary['scenario_unsupported']} unsupported; {summary['scenario_not_run']} not run",
        f"Assertions: {summary['assertion_passed']} passed / {summary['assertion_total']}; {summary['assertion_failed']} failed; {summary['assertion_unsupported']} unsupported; {summary['assertion_not_run']} not run",
        f"Physical fixtures: {summary['physical_fixture_discovered']} discovered; {summary['docker_applicable_fixtures']} Docker-applicable; {summary['docker_validated_fixtures']} Docker-validated; {summary['exercised_fixtures']} exercised/unproven; {summary['internal_go_fixtures']} INTERNAL_GO; {summary['supporting_fixtures']} SUPPORTING; {summary['unsupported_fixtures']} unsupported",
        f"Scenario bundles: {summary['scenario_bundle_validated']}/{summary['scenario_bundle_count']} validated; {summary['scenario_bundle_unvalidated']} unvalidated",
        f"Image build: {report['build_status']}",
        "",
        "Scenario | Test | Fixture | Expected | Actual | Status",
        "-" * 100,
    ]
    for case in report["tests"]:
        lines.append(" | ".join(str(case.get(key, "")) for key in ("id", "name", "fixture", "expected", "actual", "status")))
        if case.get("diagnostic"):
            lines.append(f"  Diagnostic: {case['diagnostic']}")
        if case.get("fixture_adaptation"):
            lines.append(f"  Staged fixture adaptation: {case['fixture_adaptation']}")
        if case.get("missing_findings") or case.get("added_findings") or case.get("changed_findings"):
            lines.append(
                f"  Finding diff: {len(case.get('missing_findings', []))} missing, "
                f"{len(case.get('added_findings', []))} added, {len(case.get('changed_findings', []))} changed"
            )
            for kind, key in (("missing", "missing_findings"), ("added", "added_findings")):
                for finding in case.get(key, []):
                    lines.append(
                        f"    {kind}: {finding.get('rule_id')} {finding.get('file')}:{finding.get('start_line')} "
                        f"secret-sha256={str(finding.get('secret_sha256') or '')[:12]}"
                    )
            for finding in case.get("changed_findings", []):
                actual = finding["actual"]
                lines.append(
                    f"    changed: {actual.get('rule_id')} {actual.get('file')}:{actual.get('start_line')} "
                    f"fields={','.join(finding.get('differences', {}))}"
                )
    comparison = report.get("comparison")
    if comparison:
        lines.extend(["", f"Comparison to {comparison['baseline_image'].get('requested_tag')}:"])
        for case in comparison["tests"]:
            if case.get("status") == "N/A":
                lines.append(f"  {case['id']}: N/A (not executed or unsupported in one image)")
            else:
                lines.append(
                    f"  {case['id']}: {len(case['missing'])} removed, {len(case['added'])} added, "
                    f"{len(case['changed'])} changed finding(s); "
                    f"exit {case['exit_code_difference']['baseline']} -> {case['exit_code_difference']['candidate']}; "
                    f"scenario {case['scenario_status_difference']['baseline']} -> {case['scenario_status_difference']['candidate']} "
                    f"({case['parity_status']})"
                )
    exclusions = report.get("fixture_exclusions", [])
    lines.extend(["", "FIXTURE EXCLUSIONS", "=================================================="])
    lines.append(f"Applicable: {summary['applicable_fixtures']} | Validated: {summary['validated_fixtures']} | Not validated: {len(exclusions)}")
    if exclusions:
        for fixture in exclusions:
            lines.append(f"{fixture['path']} | {fixture['coverage_status']} | {fixture['exclusion_reason']} | Next: {fixture['next_action']}")
    else:
        lines.append("NONE")
    lines.extend([
        "",
        f"FUNCTIONAL RESULT: {report['functional_result']}",
        f"COVERAGE RESULT: {report['coverage_result']}",
        f"OVERALL ACCEPTANCE: {report['overall_acceptance']}",
    ])
    return "\n".join(lines)


def apply_fixture_outcomes(
    fixtures: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    tests: list[dict[str, Any]],
) -> None:
    case_by_id = {case["id"]: case for case in cases}
    result_by_id = {result["id"]: result for result in tests}
    for fixture in fixtures:
        assertion_ids: list[str] = []
        related_scenarios = [
            (case_by_id[scenario_id], result_by_id[scenario_id])
            for scenario_id in fixture.get("scenarios", [])
            if scenario_id in case_by_id and scenario_id in result_by_id
        ]
        for result in tests:
            for assertion in result.get("assertions", []):
                assertion_fixture_ids = {assertion.get("fixture_id")}
                assertion_fixture_ids.update(assertion.get("related_fixture_ids", []))
                expected = assertion.get("expected")
                if isinstance(expected, dict):
                    assertion_fixture_ids.add(expected.get("fixture_id"))
                    assertion_fixture_ids.update(expected.get("related_fixture_ids", []))
                if fixture["fixture_id"] in assertion_fixture_ids:
                    assertion_ids.append(assertion["assertion_id"])

        bundle = fixture.get("fixture_type") == "scenario-bundle"
        if bundle:
            for _, result in related_scenarios:
                assertion_ids.extend(item["assertion_id"] for item in result.get("assertions", []))
        fixture["observed_assertions"] = sorted(set(assertion_ids))
        assertion_status = {
            assertion["assertion_id"]: assertion["status"]
            for result in tests for assertion in result.get("assertions", [])
        }
        selected_statuses = [assertion_status[item] for item in fixture["required_assertions"] if item in assertion_status]

        if fixture["classification"] == "INTERNAL_GO":
            fixture["coverage_status"] = "INTERNAL_GO_NOT_RUN"
            fixture["go_test_status"] = "NOT EXECUTED IN THIS HARNESS RUN"
        elif fixture["classification"] == "SUPPORTING":
            fixture["coverage_status"] = "SUPPORTING"
        elif any(status == "FAIL" for status in selected_statuses):
            fixture["coverage_status"] = "FAILED"
        elif (
            fixture["required_assertions"]
            and len(selected_statuses) == len(fixture["required_assertions"])
            and all(status == "PASS" for status in selected_statuses)
        ):
            fixture["coverage_status"] = "VALIDATED"
        elif any(result["status"] == "UNSUPPORTED" for _, result in related_scenarios):
            fixture["coverage_status"] = "UNSUPPORTED"
            fixture["exclusion_reason"] = next(
                (result.get("diagnostic") for _, result in related_scenarios if result["status"] == "UNSUPPORTED"),
                "Scenario is unsupported in this environment.",
            )
        elif any(result.get("actual_exit_code") is not None for _, result in related_scenarios):
            fixture["coverage_status"] = "EXERCISED" if fixture["classification"] == "EXERCISED" else "UNTESTED"
        else:
            fixture["coverage_status"] = "UNTESTED"


def fixture_exclusion_records(fixtures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    exclusions = fixture_exclusions(fixtures)
    for fixture in exclusions:
        if fixture.get("classification") == "INTERNAL_GO":
            reason = "An upstream Go test contract is recorded, but no Go-test evidence was executed or imported for this run."
            next_action = "Run the named upstream Go test and import its verified result as separate INTERNAL_GO evidence."
        elif fixture.get("coverage_status") == "FAILED":
            reason = "A required fixture assertion failed."
            next_action = "Investigate the fixture-level assertion and retain the failure in history."
        elif fixture.get("coverage_status") == "UNSUPPORTED":
            reason = fixture.get("exclusion_reason", "Required scenario is unsupported in this environment.")
            next_action = "Run the scenario in a compatible environment and preserve this execution as unsupported."
        elif fixture.get("coverage_status") == "EXERCISED":
            reason = "The fixture was encountered, but no fixture-specific assertion validated its behavior."
            next_action = "Add an independently derived fixture-level assertion."
        else:
            reason = fixture.get("exclusion_reason") or "No successful fixture-specific assertion exists for this run."
            next_action = "Add or execute an applicable scenario with explicit expected behavior."
        fixture["exclusion_reason"] = reason
        fixture["next_action"] = next_action
    return exclusions


def compare_reports(baseline: dict[str, Any], current_tests: list[dict[str, Any]]) -> dict[str, Any]:
    baseline_tests = {case["id"]: case for case in baseline.get("tests", [])}
    comparisons: list[dict[str, Any]] = []
    for case in current_tests:
        previous = baseline_tests.get(case["id"])
        if (
            previous is None
            or case.get("actual_exit_code") is None
            or previous.get("actual_exit_code") is None
            or case.get("status") in ("UNSUPPORTED", "NOT RUN", "BUILD FAILED")
            or previous.get("status") in ("UNSUPPORTED", "NOT RUN", "BUILD FAILED")
        ):
            comparisons.append({
                "id": case["id"],
                "status": "N/A",
                "parity_status": "N/A",
                "missing": [],
                "added": [],
                "changed": [],
                "exit_code_difference": {"baseline": None, "candidate": None},
                "scenario_status_difference": {"baseline": None, "candidate": None},
            })
            continue
        diff = compare_findings(previous.get("findings", []), case.get("findings", []))
        exit_codes = {"baseline": previous.get("actual_exit_code"), "candidate": case.get("actual_exit_code")}
        scenario_statuses = {"baseline": previous.get("status"), "candidate": case.get("status")}
        differs = (
            exit_codes["baseline"] != exit_codes["candidate"]
            or scenario_statuses["baseline"] != scenario_statuses["candidate"]
            or bool(diff["missing"] or diff["added"] or diff["changed"])
        )
        comparisons.append({
            "id": case["id"],
            "status": "COMPARED",
            "parity_status": "DIFFERENT" if differs else "PARITY",
            "exit_code_difference": exit_codes,
            "scenario_status_difference": scenario_statuses,
            **diff,
        })
    return {
        "baseline_image": baseline.get("image", {}),
        "baseline_source_commit": baseline.get("environment", {}).get("source_commit"),
        "tests": comparisons,
    }


def summarize(tests: list[dict[str, Any]], fixtures: list[dict[str, Any]]) -> dict[str, int]:
    assertions = [item for case in tests for item in case.get("assertions", [])]
    physical = [fixture for fixture in fixtures if fixture.get("fixture_type") != "scenario-bundle"]
    applicable = [
        fixture for fixture in physical
        if fixture.get("classification") in {"ASSERTABLE", "EXERCISED", "INTERNAL_GO", "UNTESTED", "UNSUPPORTED"}
    ]
    docker_applicable = [fixture for fixture in applicable if fixture.get("classification") != "INTERNAL_GO"]
    scenario_bundles = [fixture for fixture in fixtures if fixture.get("fixture_type") == "scenario-bundle"]
    return {
        "scenario_total": len(tests),
        "scenario_executed": sum(case.get("actual_exit_code") is not None for case in tests),
        "scenario_passed": sum(case["status"] == "PASS" for case in tests),
        "scenario_failed": sum(case["status"] in ("FAIL", "ERROR") for case in tests),
        "scenario_unsupported": sum(case["status"] == "UNSUPPORTED" for case in tests),
        "scenario_not_run": sum(case["status"] in ("NOT RUN", "BUILD FAILED") for case in tests),
        "assertion_total": len(assertions),
        "assertion_passed": sum(item["status"] == "PASS" for item in assertions),
        "assertion_failed": sum(item["status"] == "FAIL" for item in assertions),
        "assertion_unsupported": sum(item["status"] == "UNSUPPORTED" for item in assertions),
        "assertion_not_run": sum(item["status"] in ("NOT RUN", "BUILD FAILED") for item in assertions),
        "passed": sum(case["status"] == "PASS" for case in tests),
        "failed": sum(case["status"] in ("FAIL", "ERROR") for case in tests),
        "unsupported": sum(case["status"] == "UNSUPPORTED" for case in tests),
        "not_run": sum(case["status"] == "NOT RUN" for case in tests),
        "fixture_records": len(physical),
        "physical_fixture_discovered": len(physical),
        "applicable_fixtures": len(applicable),
        "docker_applicable_fixtures": len(docker_applicable),
        "docker_validated_fixtures": sum(item.get("coverage_status") == "VALIDATED" for item in docker_applicable),
        "validated_fixtures": sum(item.get("coverage_status") in ("VALIDATED", "GO_TEST_VALIDATED") for item in applicable),
        "scenario_bundle_count": len(scenario_bundles),
        "scenario_bundle_validated": sum(item.get("coverage_status") == "VALIDATED" for item in scenario_bundles),
        "scenario_bundle_failed": sum(item.get("coverage_status") == "FAILED" for item in scenario_bundles),
        "scenario_bundle_unvalidated": sum(item.get("coverage_status") != "VALIDATED" for item in scenario_bundles),
        "exercised_fixtures": sum(item.get("coverage_status") == "EXERCISED" for item in applicable),
        "failed_fixtures": sum(item.get("coverage_status") == "FAILED" for item in applicable),
        "unsupported_fixtures": sum(item.get("coverage_status") == "UNSUPPORTED" for item in applicable),
        "unvalidated_fixtures": sum(item.get("coverage_status") not in ("VALIDATED", "GO_TEST_VALIDATED") for item in applicable),
        "internal_go_fixtures": sum(item.get("classification") == "INTERNAL_GO" for item in physical),
        "internal_go_validated": sum(item.get("coverage_status") == "GO_TEST_VALIDATED" for item in physical),
        "internal_go_not_run": sum(item.get("coverage_status") == "INTERNAL_GO_NOT_RUN" for item in physical),
        "supporting_fixtures": sum(item.get("classification") == "SUPPORTING" for item in physical),
        "build_failed": sum(case["status"] == "BUILD FAILED" for case in tests),
    }


def write_reports(report: dict[str, Any], report_dir: Path) -> tuple[Path, Path]:
    execution_dir = report_dir / "runs" / report["execution_id"]
    execution_dir.mkdir(parents=True, exist_ok=False)
    json_path = execution_dir / "execution.json"
    markdown_path = execution_dir / "execution.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(markdown_report(report), encoding="utf-8")
    ledger_path = execution_dir / "fixture-assertions.json"
    ledger_path.write_text(json.dumps({
        "execution_id": report["execution_id"],
        "fixture_source_revision": report["fixture_source_revision"],
        "fixtures": report["fixture_coverage"],
        "assertions": report["assertions"],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    exclusions_path = execution_dir / "fixture-exclusions.json"
    exclusions_path.write_text(json.dumps({
        "execution_id": report["execution_id"],
        "applicable_fixture_count": report["summary"]["applicable_fixtures"],
        "validated_fixture_count": report["summary"]["validated_fixtures"],
        "unvalidated_fixtures": report["fixture_exclusions"],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return json_path, markdown_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Gitleaks acceptance cases in a local Docker image.")
    parser.add_argument("--image", help="operator-supplied local Docker image reference")
    parser.add_argument("--manifest", type=Path, default=BUILD_DIR / "cases.json", help="JSON acceptance manifest")
    parser.add_argument("--inventory-lock", type=Path, default=BUILD_DIR / "fixture-inventory.lock.json", help="pinned fixture inventory lock")
    parser.add_argument("--refresh-inventory-lock", action="store_true", help="explicitly regenerate the fixture lock from the manifest and discovered source tree")
    parser.add_argument("--reports-dir", type=Path, default=BUILD_DIR / "reports", help="directory for sanitized reports")
    parser.add_argument("--timeout", type=int, default=120, help="per-case timeout in seconds")
    parser.add_argument("--compare-to", type=Path, help="compare finding-level results with a prior harness JSON report")
    parser.add_argument("--build-failed", action="store_true", help="record an operator-reported image build failure without running containers")
    parser.add_argument("--scenario-group", action="append", default=[], help="run only this scenario group; may be repeated")
    parser.add_argument("--fixture-root", type=Path, help="pinned Gitleaks fixture checkout (contains testdata/ and .git)")
    parser.add_argument("--fixture-revision", help="full 40-character pinned fixture source revision")
    args = parser.parse_args()

    global REPO_ROOT
    if args.fixture_root is not None:
        REPO_ROOT = args.fixture_root.resolve()
    if not (REPO_ROOT / "testdata").is_dir():
        parser.error(f"fixture root does not contain testdata/: {REPO_ROOT}")

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        parser.error(f"cannot load manifest: {exc}")

    if not args.refresh_inventory_lock and not args.image:
        parser.error("--image is required unless --refresh-inventory-lock is specified")

    cases = manifest.get("cases", [])
    selected_groups = set(args.scenario_group)
    source_revision = args.fixture_revision or git_value("merge-base", "HEAD", "origin/master")
    if not source_revision or len(source_revision) != 40:
        parser.error("cannot determine a full fixture source revision; pass --fixture-revision")
    expected_lock = create_fixture_inventory_lock(manifest, source_revision)
    if args.refresh_inventory_lock:
        if expected_lock.get("integrity_errors"):
            print("Cannot refresh fixture inventory lock:")
            for error in expected_lock["integrity_errors"]:
                print(f"- {error}")
            return 1
        args.inventory_lock.parent.mkdir(parents=True, exist_ok=True)
        args.inventory_lock.write_text(json.dumps(expected_lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Refreshed fixture inventory lock: {args.inventory_lock}")
        print(f"Inventory digest: {expected_lock['inventory_digest']}")
        return 0
    try:
        actual_lock = json.loads(args.inventory_lock.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        parser.error(f"cannot load fixture inventory lock: {exc}; review changes and use --refresh-inventory-lock explicitly")
    lock_errors = verify_inventory_lock(actual_lock, expected_lock)
    if lock_errors:
        parser.error("fixture inventory integrity check failed: " + "; ".join(lock_errors) + "; review changes before refreshing the lock")
    manifest_digest = expected_lock["manifest_digest"]
    fixture_inventory_digest = expected_lock["inventory_digest"]
    harness_identity = harness_implementation_identity()
    fixture_coverage = copy.deepcopy(expected_lock["entries"])
    try:
        baseline_report = json.loads(args.compare_to.read_text(encoding="utf-8")) if args.compare_to else None
    except (OSError, ValueError) as exc:
        parser.error(f"cannot load comparison report: {exc}")
    environment = host_environment()
    image, inspect_error = (None, "Operator reported an image build failure; no container tests were run.") if args.build_failed else load_image_metadata(args.image)
    runtime: dict[str, Any] = {"returncode": None, "version_output": None, "diagnostic": inspect_error}
    tests: list[dict[str, Any]] = []
    symlink_volume: str | None = None
    symlink_metadata: dict[str, Any] | None = None
    symlink_staging_error: str | None = None
    testdata_mount: str | None = None

    if image is not None:
        runtime = image_runtime_version(args.image)
        testdata = REPO_ROOT / "testdata"
        local_fixtures = BUILD_DIR / "fixtures"
        symlink_case = next(
            (
                case for case in cases
                if case.get("requires_linux_symlink")
                and (not selected_groups or case.get("scenario_group", "general") in selected_groups)
            ),
            None,
        )
        if symlink_case:
            symlink_volume, symlink_metadata, symlink_staging_error = materialize_linux_symlink_volume(
                testdata, source_revision, symlink_case["symlink_path"]
            )
            if symlink_volume:
                testdata_mount = f"type=volume,source={symlink_volume},target={CONTAINER_TESTDATA},readonly"
        work_root = BUILD_DIR / ".work" / uuid.uuid4().hex
        work_root.mkdir(parents=True, exist_ok=True)
        try:
            for case in cases:
                scenario_group = case.get("scenario_group", "general")
                if selected_groups and scenario_group not in selected_groups:
                    tests.append({
                        "id": case["id"], "name": case["name"], "fixture": case["fixture"],
                        "scenario_group": scenario_group, "expected": case.get("expectation", ""),
                        "actual": "not executed: scenario group not selected", "status": "NOT RUN",
                        "expected_exit_code": case.get("expected_exit_code"), "actual_exit_code": None,
                        "duration_seconds": 0, "findings": [], "assertions": [],
                        "missing_findings": [], "added_findings": [], "changed_findings": [],
                        "diagnostic": "Scenario group was not selected for this execution.", "read_only_mounts": True,
                    })
                    continue
                if args.timeout:
                    case = copy.deepcopy(case)
                    case["timeout_seconds"] = args.timeout
                result = run_case(
                    case,
                    args.image,
                    testdata,
                    local_fixtures,
                    work_root,
                    testdata_mount,
                    symlink_staging_error if case.get("requires_linux_symlink") else None,
                    symlink_metadata if case.get("requires_linux_symlink") else None,
                )
                result["scenario_group"] = scenario_group
                tests.append(result)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)
            if symlink_volume:
                cleanup = run_command(["docker", "volume", "rm", symlink_volume], timeout=30)
                if symlink_metadata is not None:
                    symlink_metadata["temporary_volume_removed"] = cleanup["returncode"] == 0
    else:
        for case in cases:
            status = "BUILD FAILED" if args.build_failed else "NOT RUN"
            tests.append({
                "id": case["id"], "name": case["name"], "fixture": case["fixture"],
                "scenario_group": case.get("scenario_group", "general"),
                "expected": case.get("expectation", ""),
                "actual": "not executed: image build failed" if args.build_failed else "not executed: image unavailable",
                "status": status, "expected_exit_code": case.get("expected_exit_code"),
                "actual_exit_code": None, "duration_seconds": 0, "findings": [], "assertions": [],
                "missing_findings": [], "added_findings": [], "changed_findings": [],
                "diagnostic": inspect_error, "read_only_mounts": True,
            })

    for result in tests:
        if not result.get("assertions"):
            assertion_status = (
                result["status"] if result["status"] in ("UNSUPPORTED", "BUILD FAILED", "FAIL", "ERROR")
                else "NOT RUN"
            )
            result["assertions"] = [{
                "assertion_id": f"{result['id']}.scenario_execution",
                "type": "scenario_execution",
                "expected": "scenario executed",
                "actual": result.get("actual", "not executed"),
                "status": assertion_status,
            }]

    failed = any(case["status"] in ("FAIL", "ERROR") for case in tests)
    unavailable = image is None
    assertion_failed = any(assertion["status"] == "FAIL" for case in tests for assertion in case.get("assertions", []))
    functional_result = "NOT RUN" if unavailable else "FAIL" if failed or assertion_failed else "PASS"
    apply_fixture_outcomes(fixture_coverage, cases, tests)
    exclusions = fixture_exclusion_records(fixture_coverage)
    summary = summarize(tests, fixture_coverage)
    coverage_result = "PASS" if (
        summary["applicable_fixtures"]
        and not exclusions
        and summary["scenario_bundle_count"] > 0
        and summary["scenario_bundle_unvalidated"] == 0
    ) else "INCOMPLETE"
    overall_acceptance = "PASS" if functional_result == "PASS" and coverage_result == "PASS" else "NOT COMPLETE"
    result = "BUILD FAILED" if args.build_failed else "FAIL" if functional_result == "FAIL" else "PASS" if overall_acceptance == "PASS" else "INCOMPLETE"
    report = {
        "report_version": REPORT_VERSION,
        "manifest_version": manifest.get("manifest_version"),
        "inventory_lock_version": expected_lock.get("lock_version"),
        "harness_version": HARNESS_VERSION,
        "execution_id": uuid.uuid4().hex,
        "product": "Gitleaks Docker Acceptance",
        "attribution": "RNC Solutions Group, Inc.; Contributed by Dave Woods (@davidwoods15)",
        "result": result,
        "functional_result": functional_result,
        "coverage_result": coverage_result,
        "overall_acceptance": overall_acceptance,
        "build_status": "FAILED (operator reported)" if args.build_failed else "NOT PERFORMED BY HARNESS",
        "image": image or {"requested_tag": args.image, "image_id": None},
        "runtime": runtime,
        "environment": environment,
        "fixture_source_revision": source_revision,
        "manifest_digest": manifest_digest,
        "fixture_inventory_digest": fixture_inventory_digest,
        "harness_identity": harness_identity,
        "inventory_integrity_status": "PASS",
        "inventory_integrity_errors": [],
        "test_definitions": cases,
        "tests": tests,
        "assertions": [assertion for test in tests for assertion in test.get("assertions", [])],
        "comparison": compare_reports(baseline_report, tests) if baseline_report else None,
        "fixture_coverage": fixture_coverage,
        "fixture_exclusions": exclusions,
        "summary": summary,
        "limitations": manifest.get("limitations", []),
    }
    inventory_errors = reconcile_execution_inventory(
        report,
        expected_lock["entries"],
        expected_lock,
        harness_identity,
    )
    report["inventory_integrity_status"] = "FAIL" if inventory_errors else "PASS"
    report["inventory_integrity_errors"] = inventory_errors
    if inventory_errors:
        report["coverage_result"] = "INCOMPLETE"
        report["overall_acceptance"] = "NOT COMPLETE"
        report["result"] = "INVENTORY INTEGRITY FAILURE"
        result = report["result"]
    json_path, markdown_path = write_reports(report, args.reports_dir)
    print(render_terminal(report))
    print(f"\nJSON report: {json_path.relative_to(BUILD_DIR) if json_path.is_relative_to(BUILD_DIR) else json_path}")
    print(f"Markdown report: {markdown_path.relative_to(BUILD_DIR) if markdown_path.is_relative_to(BUILD_DIR) else markdown_path}")
    if result == "PASS":
        return 0
    if result in ("INCOMPLETE", "BUILD FAILED"):
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
