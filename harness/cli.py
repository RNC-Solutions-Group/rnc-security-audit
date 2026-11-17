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
import subprocess
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
    from .provenance import split_arguments

    config = load_config(args.config)
    scanner_extra_args = split_arguments(args.scanner_args)
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
        scanner_extra_args=scanner_extra_args,
        harness_argv=getattr(args, "harness_argv", None),
    )
    if config.reports.console:
        print(document["_paths"]["console"])
    if document["summary"]["overall"] == "FAIL":
        return 1
    return 0 if document["summary"]["overall"] == "COMPLETE" else 3


def _interactive(args: argparse.Namespace) -> int:
    from .interactive import run_interactive

    return run_interactive(config_path=args.config, offline=args.offline)


def _matrix(args: argparse.Namespace) -> int:
    from . import cp4c_matrix

    command = [
        "python",
        "-m",
        "harness",
        "matrix",
        "--experiment",
        args.experiment,
        "--out-dir",
        args.out_dir,
        "--cache-dir",
        args.cache_dir,
        "--build",
        args.build,
        "--cp4b-build",
        args.cp4b_build,
        "--seed",
        str(args.seed),
        "--repetitions",
        str(args.repetitions),
    ]
    if args.artifact_manifest:
        command.extend(["--artifact-manifest", args.artifact_manifest])
    if args.resume:
        command.append("--resume")
    if args.report_only:
        command.append("--report-only")
    if args.reference_only:
        command.append("--reference-only")
    document = cp4c_matrix.run_matrix(
        out_dir=Path(args.out_dir),
        cache_dir=Path(args.cache_dir),
        manifest_path=Path(args.artifact_manifest) if args.artifact_manifest else None,
        build_id=args.build,
        cp4b_build_id=args.cp4b_build,
        seed=args.seed,
        repetitions=args.repetitions,
        resume=args.resume,
        report_only=args.report_only,
        reference_only=args.reference_only,
        command=command,
    )
    if args.report_only:
        print(Path(args.out_dir) / "matrix0-summary.md")
    elif args.reference_only:
        print("Matrix 0 reference equivalence: PASS")
        print(Path(args.out_dir) / "matrix0-reference.json")
    else:
        print(
            f"Matrix 0: {document['summary']['executive_outcome']}\n"
            f"Report: {Path(args.out_dir) / 'matrix0-summary.md'}"
        )
    return 0



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


def _detection_gaps(args: argparse.Namespace) -> int:
    from .detection_gaps import (
        SourceResolver,
        analyse_scanner,
        build_cross_scanner,
        generate_reports,
        load_canonical_targets,
        load_scanner_evidence,
    )
    from .detection_gaps.analysis import load_cp4c_rules
    from .detection_gaps.inputs import select_report
    from .detection_gaps.sources import repo_root

    root = repo_root()
    cache = Path(args.cache_dir).expanduser()
    rnclab_root = Path(args.rnclab_root).expanduser() if args.rnclab_root else cache / "rnc-synth-lab"
    levain_root = Path(args.levain_root).expanduser() if args.levain_root else cache / "levain"
    if args.leaky_root:
        leaky_root = Path(args.leaky_root).expanduser()
    else:
        candidates = sorted((cache / "leaky-repo").glob("*/source"))
        if not candidates:
            raise HarnessError("Leaky Repo source cache is missing; pass --leaky-root")
        leaky_root = candidates[-1]
    leaky_truth = Path(args.leaky_truth).expanduser() if args.leaky_truth else root / "datasets" / "leaky-repo.rnc-truth.json"
    leaky_oracle = Path(args.leaky_oracle).expanduser() if args.leaky_oracle else root / "datasets" / "leaky-repo.history-oracle.json"
    selected = [item.strip() for item in (args.scanners or "cp4c,v14,v16").split(",") if item.strip()]
    comparators = [item.strip() for item in (args.comparators or "gitleaks,betterleaks").split(",") if item.strip()]
    allowed = {"cp4c", "v14", "v16", "gitleaks", "betterleaks"}
    unknown = [item for item in [*selected, *comparators] if item not in allowed]
    if unknown:
        raise HarnessError(f"unknown scanner key(s): {', '.join(unknown)}")
    report_paths = {
        "cp4c": args.cp4c_report,
        "v14": args.v14_report,
        "v16": args.v16_report,
        "gitleaks": args.gitleaks_report,
        "betterleaks": args.betterleaks_report,
    }
    if args.write_input_lock:
        from .detection_gaps.inputs import REPORT_GLOBS, build_lock, write_lock

        paths: dict[str, Path] = {}
        lock_target = Path(args.write_input_lock).expanduser()
        if not lock_target.is_absolute():
            lock_target = root / lock_target
        for key in dict.fromkeys([*selected, *comparators]):
            explicit = report_paths.get(key)
            if explicit:
                paths[key] = Path(explicit).expanduser()
                continue
            existing_lock = Path(args.input_lock).expanduser()
            if not existing_lock.is_absolute():
                existing_lock = root / existing_lock
            if existing_lock.exists():
                paths[key] = select_report(
                    key, lock_path=existing_lock, root=root
                ).path
                continue
            matches = sorted(
                path
                for path in root.glob(REPORT_GLOBS[key])
                if path.is_file()
            )
            if len(matches) != 1:
                raise HarnessError(
                    f"cannot pin {key}: expected exactly one matching retained report, "
                    f"found {len(matches)}. Pass an explicit report path."
                )
            paths[key] = matches[0]
        try:
            head = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            harness_commit = head.stdout.strip() if head.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            harness_commit = None
        from . import __version__

        document = build_lock(
            paths,
            root=root,
            harness_version=__version__,
            harness_source_commit=harness_commit,
        )
        write_lock(lock_target, document)
        print(f"Analysis input lock: {lock_target}")
        return 0
    resolver = SourceResolver(rnclab_root=rnclab_root, leaky_root=leaky_root, levain_root=levain_root)
    targets = load_canonical_targets(
        rnclab_root=rnclab_root,
        leaky_root=leaky_root,
        levain_root=levain_root,
        leaky_truth=leaky_truth,
        leaky_oracle=leaky_oracle,
        resolver=resolver,
    )
    selections = {}
    all_evidence = {}
    for key in dict.fromkeys([*selected, *comparators]):
        lock_path = Path(args.input_lock).expanduser() if args.input_lock else None
        if lock_path is not None and not lock_path.is_absolute():
            lock_path = root / lock_path
        selection = select_report(
            key,
            explicit=report_paths.get(key),
            lock_path=lock_path,
            root=root,
        )
        selections[key] = selection
        all_evidence[key] = load_scanner_evidence(
            key, selection.path, targets, selection=selection
        )
    rules_path = Path(args.cp4c_rules).expanduser() if args.cp4c_rules else root / "run" / "rules" / "rnc-cp4c-providers-v1.json"
    cp4c_rules = load_cp4c_rules(rules_path)
    analyses = {
        key: analyse_scanner(evidence, targets, cp4c_rules, all_evidence)
        for key, evidence in all_evidence.items()
    }
    cross = build_cross_scanner(analyses, targets)
    from .provenance import redact_argv

    command, command_redactions = redact_argv(
        ["python", "-m", "harness", "detection-gaps", *sys.argv[1:]]
    )
    run_metadata = {
        "command": command,
        "command_redacted": bool(command_redactions),
        "input_lock": str(args.input_lock or "reports/detection-gaps/analysis-inputs.json"),
        "input_selections": {
            key: selection.to_dict() for key, selection in selections.items()
        },
    }
    written = generate_reports(
        analyses=analyses,
        cross=cross,
        output_dir=Path(args.out_dir).expanduser(),
        run_metadata=run_metadata,
        replace=args.replace,
    )
    print(f"Target universe: {len(targets)}")
    for key in selected:
        if key in analyses:
            summary = analyses[key]["stats"]
            print(f"{analyses[key]['label']}: {summary['matched']}/{summary['expected']} matched, {summary['missed']} missed")
    print(f"All-scanner common misses: {cross['counts']['all_scanner_misses']}")
    print(f"Reports: {Path(args.out_dir).expanduser()}")
    print(f"Validation: {written['validation']}")
    return 0


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
    experiment_parser.add_argument(
        "--scanner-args",
        default=None,
        help="experiment-owned extra scanner arguments as a shell-like string, e.g. \"--workers auto\"",
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

    gaps_parser = subparsers.add_parser(
        "detection-gaps",
        help="generate target-level detection-gap reports from retained current-scoring evidence",
    )
    gaps_parser.add_argument("--out-dir", default="reports/detection-gaps")
    gaps_parser.add_argument(
        "--input-lock",
        default="reports/detection-gaps/analysis-inputs.json",
        help="pinned report-input lock; modification-time selection is never used",
    )
    gaps_parser.add_argument(
        "--replace",
        action="store_true",
        help="replace an existing non-finalized output directory",
    )
    gaps_parser.add_argument(
        "--write-input-lock",
        default=None,
        help="pin the selected report paths and hashes to this JSON lock, then exit",
    )
    gaps_parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE))
    gaps_parser.add_argument("--scanners", default="cp4c,v14,v16")
    gaps_parser.add_argument("--comparators", default="gitleaks,betterleaks")
    gaps_parser.add_argument("--cp4c-report", default=None)
    gaps_parser.add_argument("--v14-report", default=None)
    gaps_parser.add_argument("--v16-report", default=None)
    gaps_parser.add_argument("--gitleaks-report", default=None)
    gaps_parser.add_argument("--betterleaks-report", default=None)
    gaps_parser.add_argument("--rnclab-root", default=None)
    gaps_parser.add_argument("--leaky-root", default=None)
    gaps_parser.add_argument("--levain-root", default=None)
    gaps_parser.add_argument("--leaky-truth", default=None)
    gaps_parser.add_argument("--leaky-oracle", default=None)
    gaps_parser.add_argument("--cp4c-rules", default=None)
    gaps_parser.set_defaults(func=_detection_gaps)

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

    matrix_parser = subparsers.add_parser(
        "matrix", help="run or report the CP4C Matrix 0 worker/profiler experiment"
    )
    matrix_parser.add_argument("--experiment", choices=("cp4c",), default="cp4c")
    matrix_parser.add_argument(
        "--out-dir", default="run/reports/cp4c-matrix0"
    )
    matrix_parser.add_argument(
        "--cache-dir", default="datasets/cache/rnc-synth-lab"
    )
    matrix_parser.add_argument("--artifact-manifest", default=None)
    matrix_parser.add_argument("--build", default="rnc-cp4c")
    matrix_parser.add_argument("--cp4b-build", default="rnc-cp4b")
    matrix_parser.add_argument("--seed", type=int, default=20261115)
    matrix_parser.add_argument("--repetitions", type=int, default=5)
    matrix_parser.add_argument("--resume", action="store_true")
    matrix_parser.add_argument("--report-only", action="store_true")
    matrix_parser.add_argument("--reference-only", action="store_true")
    matrix_parser.set_defaults(func=_matrix)
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
    # Preserve the exact harness invocation separately from scanner argv.  The
    # program name is the current Python executable; the rest is the parsed argv.
    args.harness_argv = [sys.executable, "-m", "harness", *effective]
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
