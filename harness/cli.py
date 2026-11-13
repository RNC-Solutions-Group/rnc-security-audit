"""Command-line interface for source-commit scanner experiments.

Exit codes:
  0  the experiment completed and every applicable benchmark was executed
  1  a benchmark, build, or experiment-supporting check failed
  2  invalid harness input or setup
  3  the experiment report was written but is incomplete or blocked
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config
from .dataset import DEFAULT_CACHE, load_corpora, prepare, short_dataset_report
from .errors import HarnessError
from .manifest import DEFAULT_MANIFEST, load_levain


def _manifest_argument(value: str | None) -> Path | None:
    return Path(value).expanduser() if value else None


def _print_dataset(prepared, corpora) -> None:
    print(f"Dataset:  {prepared.spec.name}")
    print(f"Revision: {prepared.spec.revision} (tag {prepared.spec.revision_tag})")
    print(f"License:  {prepared.spec.license} (sha256 {prepared.spec.license_sha256[:12]}...)")
    print(f"Manifest: {prepared.manifest.path} sha256={prepared.manifest_sha256}")
    print(f"Cache:    {prepared.root}")
    print(
        "Negative: %d sections, %d lines, 0 credentials, %d personal-data spans"
        % (
            corpora.negative_counts["sections"],
            corpora.negative_counts["lines"],
            corpora.negative_counts["personal_data"],
        )
    )
    print(
        "Positive: %d sections, %d lines, %d credentials (%d hard), %d personal-data spans"
        % (
            corpora.positive_counts["sections"],
            corpora.positive_counts["lines"],
            corpora.positive_counts["secrets"],
            corpora.positive_counts["hard_secrets"],
            corpora.positive_counts["personal_data"],
        )
    )


def _prepare(args: argparse.Namespace) -> int:
    prepared = prepare(
        _manifest_argument(args.manifest),
        Path(args.cache_dir),
        offline=args.offline,
        refresh=args.refresh,
    )
    corpora = load_corpora(prepared)
    if args.json:
        print(json.dumps(short_dataset_report(prepared, corpora), indent=2, sort_keys=True))
    else:
        _print_dataset(prepared, corpora)
        print("Status:   verified")
    return 0


def _verify(args: argparse.Namespace) -> int:
    prepared = prepare(_manifest_argument(args.manifest), Path(args.cache_dir), offline=True)
    corpora = load_corpora(prepared)
    if args.json:
        print(json.dumps(short_dataset_report(prepared, corpora), indent=2, sort_keys=True))
    else:
        _print_dataset(prepared, corpora)
        print("Status:   verified offline; no network access was performed")
    return 0


def _status(args: argparse.Namespace) -> int:
    manifest, spec = load_levain(_manifest_argument(args.manifest))
    print(f"Manifest: {manifest.path}")
    print(f"Dataset:  {spec.key} - {spec.status}")
    print(f"Revision: {spec.revision} (tag {spec.revision_tag})")
    print(f"Enabled:  {spec.enabled}")
    try:
        prepared = prepare(_manifest_argument(args.manifest), Path(args.cache_dir), offline=True)
        corpora = load_corpora(prepared)
    except HarnessError as exc:
        print(f"Cache:    not ready ({exc})")
        return 0
    _print_dataset(prepared, corpora)
    print("Status:   cached and verified")
    return 0


def _experiment(args: argparse.Namespace) -> int:
    from .experiment import run as run_experiment

    config = load_config(args.config)
    if args.out_dir:
        config = replace(
            config,
            reports=replace(
                config.reports, output_dir=Path(args.out_dir).expanduser()
            ),
        )
    if args.name:
        if Path(args.name).name != args.name:
            raise HarnessError("--name must be a plain filename stem")
        config = replace(
            config,
            reports=replace(
                config.reports, naming=args.name + "-{commit}-{profile}"
            ),
        )
    document = run_experiment(
        build=args.build,
        artifact_manifest=args.artifact_manifest,
        scanner=args.scanner,
        platforms=args.platforms,
        suites=args.suites,
        profile_name=args.profile,
        scanner_config=args.scanner_config,
        config=config,
        warmups=args.warmups,
        runs=args.runs,
        copies=args.copies,
        retain_work=args.retain_work,
        timeout=args.timeout,
        offline=args.offline,
        compact=args.compact,
        benchmark_environment=args.benchmark_environment,
        stress_profile=args.stress_profile,
    )
    if config.reports.console:
        print(document["_paths"]["console"])
    if document["summary"]["overall"] == "FAIL":
        return 1
    return 0 if document["summary"]["overall"] == "COMPLETE" else 3


def _interactive(args: argparse.Namespace) -> int:
    from .interactive import run_interactive

    return run_interactive(config_path=args.config, offline=args.offline)


def _synthetic(args: argparse.Namespace) -> int:
    from . import synthetic_validation

    out_dir = Path(args.out_dir) if args.out_dir else Path("reports/cp1d")
    json_path, markdown_path = synthetic_validation.write_reports(
        out_dir / "synthetic-scoring-validation.json",
        out_dir / "synthetic-scoring-validation.md",
    )
    document = synthetic_validation.run()
    summary = document["summary"]
    print(
        f"Synthetic scoring: {summary['correct']}/{summary['cases']} correct "
        f"({summary['scoring_accuracy_percent']}%)"
    )
    print(f"JSON: {json_path}")
    if markdown_path:
        print(f"Markdown: {markdown_path}")
    return 0 if summary["incorrect"] == 0 else 1


def _rescore_history(args: argparse.Namespace) -> int:
    from . import rescore

    report_path = Path(args.report).expanduser()
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HarnessError(f"cannot read retained report {report_path}: {exc}") from exc
    document = rescore.rescore_report(
        report,
        platform=args.platform,
        cache_dir=Path(args.cache_dir),
    )
    if args.out:
        path = rescore.write(document, args.out)
        print(f"Rescored history report: {path}")
    else:
        print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if document["status"] == "PASS" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m harness",
        description=(
            "Registered-artifact scanner benchmark application. One invocation "
            "executes one operator-provided scanner build and writes one report."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "--manifest", default=None, help=f"manifest path (default: {DEFAULT_MANIFEST})"
    )
    parent.add_argument(
        "--cache-dir", default=str(DEFAULT_CACHE), help="ignored dataset cache directory"
    )

    prepare_parser = subparsers.add_parser(
        "prepare",
        parents=[parent],
        help="fetch, verify, decode, and cache the pinned dataset",
    )
    prepare_parser.add_argument("--offline", action="store_true")
    prepare_parser.add_argument("--refresh", action="store_true")
    prepare_parser.add_argument("--json", action="store_true")
    prepare_parser.set_defaults(func=_prepare)

    verify_parser = subparsers.add_parser(
        "verify", parents=[parent], help="verify an existing cache offline"
    )
    verify_parser.add_argument("--json", action="store_true")
    verify_parser.set_defaults(func=_verify)

    status_parser = subparsers.add_parser(
        "status", parents=[parent], help="show manifest and cache readiness"
    )
    status_parser.set_defaults(func=_status)

    experiment_parser = subparsers.add_parser(
        "experiment",
        help="execute one registered scanner build, run benchmarks, and write one report",
    )
    experiment_parser.add_argument(
        "--build",
        default=None,
        help="registered build id from run/manifest.toml (required when several are registered)",
    )
    experiment_parser.add_argument(
        "--artifact-manifest",
        default=None,
        help="local artifact manifest (default: run/manifest.toml)",
    )
    experiment_parser.add_argument(
        "--scanner", default=None, help="assert the registered build's scanner adapter"
    )
    experiment_parser.add_argument(
        "--platforms",
        default=None,
        help="host, all, executable, docker, or comma-separated product keys",
    )
    experiment_parser.add_argument(
        "--suites", default=None, help="comma-separated suite keys or all"
    )
    experiment_parser.add_argument(
        "--profile",
        choices=("default", "custom"),
        default="default",
        help="DEFAULT registered rules or explicit CUSTOM configuration",
    )
    experiment_parser.add_argument(
        "--scanner-config", default=None, help="CUSTOM profile scanner configuration"
    )
    experiment_parser.add_argument("--config", default=None, help="harness TOML configuration")
    experiment_parser.add_argument("--warmups", type=int, default=None)
    experiment_parser.add_argument("--runs", type=int, default=None)
    experiment_parser.add_argument(
        "--copies", type=int, default=10, help="performance workload replicas"
    )
    experiment_parser.add_argument(
        "--retain-work",
        action="store_true",
        help="retain the run-owned benchmark workspace and Docker containers",
    )
    experiment_parser.add_argument("--offline", action="store_true", help="datasets use cache only")
    experiment_parser.add_argument("--compact", action="store_true")
    experiment_parser.add_argument("--timeout", type=int, default=None)
    experiment_parser.add_argument(
        "--benchmark-environment",
        choices=("DEV", "CONTROLLED", "RELEASE"),
        default=None,
        help="declared measurement conditions; DEV is the contended default",
    )
    experiment_parser.add_argument(
        "--stress-profile",
        choices=("none", "cpu", "memory", "io", "network"),
        default="none",
        help="future optional stress profile; recorded separately",
    )
    experiment_parser.add_argument("--out-dir", default=None)
    experiment_parser.add_argument("--name", default=None, help="report stem prefix")
    experiment_parser.set_defaults(func=_experiment)

    rescore_parser = subparsers.add_parser(
        "rescore-history",
        help="rescore retained Leaky Repo history findings without rerunning a scanner",
    )
    rescore_parser.add_argument("--report", required=True)
    rescore_parser.add_argument("--platform", default=None)
    rescore_parser.add_argument("--out", default=None)
    rescore_parser.add_argument(
        "--cache-dir", default=str(DEFAULT_CACHE), help="ignored dataset cache directory"
    )
    rescore_parser.set_defaults(func=_rescore_history)

    interactive_parser = subparsers.add_parser(
        "interactive", help="prompt for a registered build, suites, and products"
    )
    interactive_parser.add_argument("--config", default=None)
    interactive_parser.add_argument("--offline", action="store_true")
    interactive_parser.set_defaults(func=_interactive)

    synthetic_parser = subparsers.add_parser(
        "synthetic", help="run the controlled scoring-engine validation matrix"
    )
    synthetic_parser.add_argument("--out-dir", default="reports/cp1d")
    synthetic_parser.set_defaults(func=_synthetic)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    effective = list(sys.argv[1:] if argv is None else argv)
    if not effective:
        if sys.stdin.isatty() and sys.stdout.isatty():
            from .interactive import run_interactive

            try:
                return run_interactive()
            except (HarnessError, ValueError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
        parser.print_help()
        return 2
    args = parser.parse_args(effective)
    try:
        return args.func(args)
    except HarnessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except (FileNotFoundError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
