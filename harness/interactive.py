"""Interactive front-end for one source-commit experiment."""

from __future__ import annotations

import sys
from pathlib import Path

from .adapters import adapter_keys, expand_platform_selection, get_adapter
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
    adapter = get_adapter(config.scanner)
    output("Execution products:")
    for item in adapter.platforms:
        marker = "*" if item.key in config.platforms else " "
        output(f"  [{marker}] {item.key} ({item.kind})")
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
    adapters = list(adapter_keys())
    output("Source-commit scanner experiment")
    if len(adapters) > 1:
        output("Available scanners: " + ", ".join(adapters))
        scanner = _ask("Scanner", config.scanner, input_func)
        if scanner not in adapters:
            raise ValueError(f"unknown scanner: {scanner}")
    else:
        scanner = config.scanner
        output(f"Scanner: {scanner}")
    adapter = get_adapter(scanner)
    repository = _ask(
        "Source repository",
        config.source.repository or adapter.default_repository,
        input_func,
    )
    commit = input_func("Exact 40-character source commit: ").strip()
    if not commit:
        raise ValueError("an exact source commit is required")
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
    output(f"  Scanner:   {scanner}")
    output(f"  Source:    {repository}")
    output(f"  Commit:    {commit}")
    output(f"  Profile:   {profile}")
    output(f"  Suites:    {', '.join(suites)}")
    output(f"  Products:  {', '.join(platforms)}")
    if not _ask_yes("Proceed", True, input_func):
        output("Cancelled.")
        return 0
    document = run_experiment(
        scanner=scanner,
        repository=repository,
        commit=commit,
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
