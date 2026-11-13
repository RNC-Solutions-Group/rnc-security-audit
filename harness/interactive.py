"""Interactive front-end for one registered-artifact experiment."""

from __future__ import annotations

import sys
from pathlib import Path

from .adapters import expand_platform_selection
from .artifacts import load_manifest
from .config import HarnessConfig, load_config
from .experiment import run as run_experiment
from .reporting import render_console
from .suites import get_suite, suite_keys


def _ask(prompt: str, default: str, input_func) -> str:
    value = input_func(f"{prompt} [{default}]: ").strip()
    return value or default


def _ask_yes(prompt: str, default: bool, input_func) -> bool:
    marker = "Y/n" if default else "y/N"
    value = input_func(f"{prompt} [{marker}]: ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


def _select_suites(config: HarnessConfig, input_func, output) -> list[str]:
    all_keys = list(suite_keys())
    output("Test suites:")
    for index, key in enumerate(all_keys, 1):
        marker = "*" if key in config.suites else " "
        output(f"  {index}. [{marker}] {get_suite(key).title} ({key})")
    output("Enter numbers or names separated by commas, or 'all'. Press Enter to keep configured selections.")
    raw = input_func("Selection: ").strip()
    if not raw:
        return list(config.suites) if config.suites else all_keys
    if raw.lower() == "all":
        return all_keys
    selected: list[str] = []
    for item in [part.strip() for part in raw.replace(" ", ",").split(",") if part.strip()]:
        if item.isdigit():
            index = int(item)
            if not 1 <= index <= len(all_keys):
                raise ValueError(f"suite number out of range: {item}")
            selected.append(all_keys[index - 1])
        elif item in all_keys:
            selected.append(item)
        else:
            raise ValueError(f"unknown suite selection: {item}")
    return selected


def _select_platforms(config: HarnessConfig, input_func, output) -> list[str]:
    output("Execution products:")
    for item in ("windows-amd64", "docker-linux-amd64", "docker-linux-arm64"):
        marker = "*" if item in config.platforms else " "
        output(f"  [{marker}] {item}")
    default = ",".join(config.platforms)
    output("Enter platform keys separated by commas, or 'host', 'executable', 'docker', or 'all'.")
    raw = _ask("Platforms", default, input_func)
    expand_platform_selection(raw)
    return [part.strip() for part in raw.split(",") if part.strip()]


def run_interactive(
    *,
    config_path: Path | str | None = None,
    offline: bool = False,
    input_func=input,
    output=print,
) -> int:
    config = load_config(config_path)
    manifest = load_manifest(config.artifact.manifest)
    output("Registered scanner experiment")
    output(f"Artifact manifest: {manifest.path}")
    output("Registered builds:")
    for item in manifest.builds:
        artifacts = []
        if item.executable:
            artifacts.append(f"exe={item.executable}")
        if item.docker_image:
            artifacts.append(f"image={item.docker_image}")
        output(
            f"  - {item.id} ({item.scanner} {item.version or 'version n/a'}, "
            f"source {item.source_commit[:12]}): " + ", ".join(artifacts)
        )
    default_build = config.artifact.build or (
        manifest.builds[0].id if len(manifest.builds) == 1 else ""
    )
    build_id = _ask("Registered build", default_build, input_func)
    if not build_id:
        raise ValueError("a registered build id is required")
    selected = manifest.select(build_id)
    profile = _ask("Configuration profile (default/custom)", "default", input_func).lower()
    scanner_config = None
    if profile == "custom":
        scanner_config = input_func("Scanner configuration path: ").strip()
        if not scanner_config:
            raise ValueError("CUSTOM profile requires a scanner configuration path")
    suites = _select_suites(config, input_func, output)
    platforms = _select_platforms(config, input_func, output)
    output("")
    output("Execution scope:")
    output(f"  Build:     {selected.id}")
    output(f"  Scanner:   {selected.scanner}")
    output(f"  Source:    {selected.source_commit} (manifest metadata; not checked out)")
    output(f"  Executable:{selected.executable or 'not registered'}")
    output(f"  Image:     {selected.docker_image or 'not registered'}")
    output(f"  Profile:   {profile}")
    output(f"  Suites:    {', '.join(suites)}")
    output(f"  Products:  {', '.join(platforms)}")
    if not _ask_yes("Proceed", True, input_func):
        output("Cancelled.")
        return 0
    document = run_experiment(
        build=selected.id,
        artifact_manifest=manifest.path,
        platforms=platforms,
        suites=suites,
        profile_name=profile,
        scanner_config=scanner_config,
        config=config,
        offline=offline,
    )
    output("")
    output(render_console(document))
    if document["summary"]["overall"] == "FAIL":
        return 1
    return 0 if document["summary"]["overall"] == "COMPLETE" else 3


def interactive_available() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()
