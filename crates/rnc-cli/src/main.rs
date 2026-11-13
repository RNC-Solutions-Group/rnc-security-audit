//! RNC Scanner CP4 CLI: filesystem/history detection, policy, reporting and CI acceptance.

use std::env;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

mod report;

use rnc_core::{
    load_effective, scan_with_options, BackendRequest, CliOverrides, GitHistoryMode,
    GitHistoryOptions, GitHistorySource, GitIoMode, LoadedBundle, LocalSource, Profiler, RunConfig,
    ScanExecutionOptions, ScanLimits, ScanMode, ENGINE_VERSION,
};

const USAGE: &str = "rnc — RNC Scanner CP4C

Usage:
  rnc scan --root DIR --rules FILE [options]
  rnc rules validate --rules FILE [--strategy regex|regexset|prefilter|auto]
  rnc --version

Scan options:
  --history                     Read-only Git-history scan instead of working tree
  --ref NAME                    Restrict history to a ref/commit (repeatable)
  --max-history-commits N       Fail closed beyond this commit count
  --max-history-units N         Fail closed beyond this commit/path revision count
  --workers 1|2|4|8|auto        Configurable scan workers (default: 1)
  --git-io process|batch        Git object acquisition strategy (default: process)
  --history-mode whole|diff     Full revisions or introduced-line scanning
  --context-lines 0|1|3|5       Diff context; requires --history-mode diff
  --profile-output PATH         Opt-in JSON performance profile (outside root)
  --output PATH                 Report output (outside the scan root)
  --format summary|sanitized|json|private
                                summary (default), sanitized public JSON, or private evidence
  --run-id ID                   Stable run identifier
  --mode auto|whole|stream      Acquisition mode (default: auto)
  --strategy NAME               regex|regexset|prefilter|auto (default: auto)
  --config PATH                 Repository configuration; otherwise auto-discover
  --global-config PATH          Global configuration with mandatory caps
  --accept-result CODE          Accepted completed result code (repeatable)
  --exclude PATH                Pre-scan block selector (alias: --block)
  --block SELECTOR              Pre-scan block glob selector (repeatable)
  --exempt SELECTOR             Post-scan exemption selector (repeatable)
  --skip SELECTOR               Record matching paths uninspected
  --optional SELECTOR           Mark matching units optional
  --max-file-bytes N            Per-file cap (may only be narrowed by config)
  --max-total-bytes N           Total byte cap
  --timeout-ms N                Scan timeout
  --max-findings N              Finding cap
  --stream-chunk-bytes N        Bounded streaming chunk
  --stream-threshold N          Auto-stream threshold

Private evidence contains finding IDs, evidence digests, policy selectors and
locators. It is never printed to the console. Sanitized output contains only
counts, result codes and safe metadata.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerSetting {
    Fixed(usize),
    Auto,
}

impl WorkerSetting {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "1" => Ok(Self::Fixed(1)),
            "2" => Ok(Self::Fixed(2)),
            "4" => Ok(Self::Fixed(4)),
            "8" => Ok(Self::Fixed(8)),
            "auto" => Ok(Self::Auto),
            _ => Err("--workers must be 1, 2, 4, 8 or auto".to_string()),
        }
    }

    fn requested(self) -> String {
        match self {
            Self::Fixed(value) => value.to_string(),
            Self::Auto => "auto".to_string(),
        }
    }

    fn effective(self) -> usize {
        match self {
            Self::Fixed(value) => value,
            Self::Auto => std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1)
                .clamp(1, 8),
        }
    }
}

#[derive(Debug)]
struct ScanArgs {
    root: PathBuf,
    rules: PathBuf,
    output: Option<PathBuf>,
    format: OutputFormat,
    run_id: String,
    config: Option<PathBuf>,
    global_config: Option<PathBuf>,
    overrides: CliOverrides,
    history: bool,
    refs: Vec<String>,
    max_history_commits: usize,
    max_history_units: usize,
    workers: WorkerSetting,
    git_io: GitIoMode,
    history_mode: GitHistoryMode,
    context_lines: usize,
    profile_output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Summary,
    Sanitized,
    Private,
}

fn default_run_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("rnc-{millis}")
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a positive integer"))
}

fn parse_usize(value: &str, name: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be a positive integer"))
}

fn parse_scan_args(arguments: &[String]) -> Result<ScanArgs, String> {
    let mut root = None;
    let mut rules = None;
    let mut output = None;
    let mut format = OutputFormat::Summary;
    let mut run_id = default_run_id();
    let mut config = None;
    let mut global_config = None;
    let mut overrides = CliOverrides::default();
    let mut history = false;
    let mut refs = Vec::new();
    let mut max_history_commits = rnc_core::git::DEFAULT_MAX_COMMITS;
    let mut max_history_units = rnc_core::git::DEFAULT_MAX_UNITS;
    let mut workers = WorkerSetting::Fixed(1);
    let mut git_io = None;
    let mut history_mode = None;
    let mut context_lines = None;
    let mut profile_output = None;
    let mut index = 0;
    while index < arguments.len() {
        let name = arguments[index].as_str();
        if name == "--history" {
            history = true;
            index += 1;
            continue;
        }
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{name} requires a value"))?;
        match name {
            "--root" => root = Some(PathBuf::from(value)),
            "--ref" => refs.push(value.clone()),
            "--max-history-commits" => {
                max_history_commits = parse_usize(value, name)?;
            }
            "--max-history-units" => {
                max_history_units = parse_usize(value, name)?;
            }
            "--rules" => rules = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            "--format" => {
                format = match value.as_str() {
                    "summary" => OutputFormat::Summary,
                    "sanitized" => OutputFormat::Sanitized,
                    "json" | "private" => OutputFormat::Private,
                    _ => {
                        return Err(
                            "--format must be summary, sanitized, json or private".to_string()
                        )
                    }
                }
            }
            "--run-id" => run_id = value.clone(),
            "--mode" => {
                overrides.mode = Some(match value.as_str() {
                    "auto" => ScanMode::Auto,
                    "whole" => ScanMode::Whole,
                    "stream" => ScanMode::Stream,
                    _ => return Err("--mode must be auto, whole or stream".to_string()),
                })
            }
            "--strategy" => {
                overrides.strategy =
                    Some(BackendRequest::parse(value).map_err(|error| error.to_string())?)
            }
            "--config" => config = Some(PathBuf::from(value)),
            "--global-config" => global_config = Some(PathBuf::from(value)),
            "--exclude" | "--block" => overrides.blocks.push(value.clone()),
            "--exempt" => overrides.exemptions.push(value.clone()),
            "--skip" => overrides.skips.push(value.clone()),
            "--optional" => overrides.optional.push(value.clone()),
            "--accept-result" => {
                let code = value
                    .parse::<u8>()
                    .map_err(|_| "--accept-result must be 1, 2 or 3".to_string())?;
                if !matches!(code, 1..=3) {
                    return Err("--accept-result must be 1, 2 or 3".to_string());
                }
                overrides.accepted_result_codes.push(code);
            }
            "--max-file-bytes" => overrides.max_file_bytes = Some(parse_u64(value, name)?),
            "--max-total-bytes" => overrides.max_total_bytes = Some(parse_u64(value, name)?),
            "--timeout-ms" => overrides.timeout_ms = Some(parse_u64(value, name)?),
            "--max-findings" => overrides.max_findings = Some(parse_usize(value, name)?),
            "--stream-chunk-bytes" => {
                overrides.stream_chunk_bytes = Some(parse_usize(value, name)?)
            }
            "--stream-threshold" => {
                overrides.stream_threshold_bytes = Some(parse_u64(value, name)?)
            }
            "--workers" => workers = WorkerSetting::parse(value)?,
            "--git-io" => {
                git_io = Some(GitIoMode::parse(value).map_err(|error| error.to_string())?)
            }
            "--history-mode" => {
                history_mode =
                    Some(GitHistoryMode::parse(value).map_err(|error| error.to_string())?)
            }
            "--context-lines" => {
                let parsed = parse_usize(value, name)?;
                if !matches!(parsed, 0 | 1 | 3 | 5) {
                    return Err("--context-lines must be 0, 1, 3 or 5".to_string());
                }
                context_lines = Some(parsed);
            }
            "--profile-output" => profile_output = Some(PathBuf::from(value)),
            other => return Err(format!("unknown option {other}")),
        }
        index += 2;
    }
    let root = root.ok_or_else(|| "--root is required".to_string())?;
    let rules = rules.ok_or_else(|| "--rules is required".to_string())?;
    if output.is_some() && format == OutputFormat::Summary {
        return Err("--output requires --format sanitized, json or private".to_string());
    }
    if format == OutputFormat::Private && output.is_none() {
        return Err("--format json/private requires --output for private evidence".to_string());
    }
    if overrides.stream_chunk_bytes == Some(0) || overrides.stream_threshold_bytes == Some(0) {
        return Err("stream sizes must be positive".to_string());
    }
    if !history
        && (!refs.is_empty()
            || max_history_commits != rnc_core::git::DEFAULT_MAX_COMMITS
            || max_history_units != rnc_core::git::DEFAULT_MAX_UNITS)
    {
        return Err("--ref and history limits require --history".to_string());
    }
    if max_history_commits == 0 || max_history_units == 0 {
        return Err("history limits must be positive".to_string());
    }
    if !history {
        if git_io.is_some() {
            return Err("--git-io requires --history".to_string());
        }
        if history_mode.is_some() {
            return Err("--history-mode requires --history".to_string());
        }
        if context_lines.is_some() {
            return Err("--context-lines requires --history-mode diff".to_string());
        }
    }
    let git_io = git_io.unwrap_or(GitIoMode::Process);
    let history_mode = history_mode.unwrap_or(GitHistoryMode::Whole);
    if context_lines.is_some() && history_mode != GitHistoryMode::Diff {
        return Err("--context-lines requires --history-mode diff".to_string());
    }
    let context_lines = context_lines.unwrap_or(0);
    Ok(ScanArgs {
        root,
        rules,
        output,
        format,
        run_id,
        config,
        global_config,
        overrides,
        history,
        refs,
        max_history_commits,
        max_history_units,
        workers,
        git_io,
        history_mode,
        context_lines,
        profile_output,
    })
}

fn run_scan(arguments: &[String]) -> i32 {
    let process_started = Instant::now();
    let args = match parse_scan_args(arguments) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("error: {error}");
            return 64;
        }
    };
    let profiler = args
        .profile_output
        .as_ref()
        .map(|_| Arc::new(Profiler::from_start(process_started)));
    if let Some(profiler) = &profiler {
        profiler.record_wall("startup.cli", process_started);
        profiler.set_requested("workers", args.workers.requested());
        profiler.set_effective("workers", args.workers.effective().to_string());
        if args.history {
            profiler.set_requested("git_io", args.git_io.as_str());
            profiler.set_effective("git_io", args.git_io.as_str());
            profiler.set_requested("history_mode", args.history_mode.as_str());
            profiler.set_effective("history_mode", args.history_mode.as_str());
            profiler.set_requested("context_lines", args.context_lines.to_string());
            profiler.set_effective("context_lines", args.context_lines.to_string());
        }
        profiler.set_requested(
            "mode",
            format!("{:?}", args.overrides.mode.unwrap_or(ScanMode::Auto)).to_lowercase(),
        );
    }
    let rules_started = Instant::now();
    let bundle = match LoadedBundle::load(&args.rules) {
        Ok(bundle) => bundle,
        Err(error) => {
            eprintln!("error: {error}");
            return 64;
        }
    };
    if let Some(profiler) = &profiler {
        profiler.record_wall("rules.load", rules_started);
    }
    let config_started = Instant::now();
    let effective = match load_effective(
        &args.root,
        args.config.as_deref(),
        args.global_config.as_deref(),
        &args.overrides,
    ) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return 64;
        }
    };
    if let Some(profiler) = &profiler {
        profiler.record_wall("startup.config", config_started);
    }
    if let Some(id) = &effective.ruleset.id {
        if id != &bundle.definition.ruleset_id {
            eprintln!("error: effective configuration selects a different ruleset");
            return 64;
        }
    }
    if let Some(version) = &effective.ruleset.version {
        if !effective.migrated_legacy && version != &bundle.definition.ruleset_version {
            eprintln!("error: effective configuration selects a different ruleset version");
            return 64;
        }
    }
    if let Some(digest) = &effective.ruleset.digest {
        if digest != &bundle.digest {
            eprintln!("error: effective configuration selects a different ruleset digest");
            return 64;
        }
    }
    let root = match std::fs::canonicalize(&args.root) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("error: cannot resolve scan root: {error}");
            return 64;
        }
    };
    let destination = match (&args.output, args.format) {
        (Some(output), form) => {
            match report::ReportDestination::new(output, &root, form == OutputFormat::Private) {
                Ok(destination) => Some(destination),
                Err(error) => {
                    eprintln!("error: {error}");
                    return 64;
                }
            }
        }
        (None, _) => None,
    };
    let profile_destination = match &args.profile_output {
        Some(output) => match report::ReportDestination::new(output, &root, false) {
            Ok(destination) => Some(destination),
            Err(error) => {
                eprintln!("error: {error}");
                return 64;
            }
        },
        None => None,
    };
    if let (Some(report), Some(profile)) = (&destination, &profile_destination) {
        if report.resolved_path() == profile.resolved_path() {
            eprintln!("error: report output and profile output must be different paths");
            return 64;
        }
    }
    let started = Instant::now();
    let deadline = started
        .checked_add(effective.limits.timeout)
        .unwrap_or(started);
    let discovery_started = Instant::now();
    let mut discovery = if args.history {
        let git_started = Instant::now();
        let source = match GitHistorySource::open(
            root.clone(),
            &GitHistoryOptions {
                refs: args.refs.clone(),
                max_commits: args.max_history_commits,
                max_units: args.max_history_units,
                io: args.git_io,
                history_mode: args.history_mode,
                context_lines: args.context_lines,
                profiler: profiler.clone(),
            },
        ) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("error: {error}");
                return 64;
            }
        };
        let discovery = source.discover_until(deadline);
        if let Some(profiler) = &profiler {
            profiler.record_wall("discovery.git", git_started);
        }
        discovery
    } else {
        let filesystem_started = Instant::now();
        let source = match LocalSource::new_with_policy(root, &effective.policy) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("error: {error}");
                return 64;
            }
        };
        let discovery = source.discover_until(deadline);
        if let Some(profiler) = &profiler {
            profiler.record_wall("discovery.filesystem", filesystem_started);
        }
        discovery
    };
    if let Some(profiler) = &profiler {
        profiler.record_wall("discovery", discovery_started);
    }
    if args.history {
        LocalSource::apply_policy_to_discovery(&mut discovery, &effective.policy);
    }
    let run_id = args.run_id.clone();
    let config = RunConfig {
        run_id: args.run_id,
        limits: ScanLimits {
            max_file_bytes: effective.limits.max_file_bytes,
            max_total_bytes: effective.limits.max_total_bytes,
            timeout: effective.limits.timeout,
            max_findings: effective.limits.max_findings,
        },
        mode: effective.mode,
        stream_threshold_bytes: effective.stream_threshold_bytes,
        stream_chunk_bytes: effective.stream_chunk_bytes,
        strategy: effective.strategy,
        policy: effective.policy.clone(),
        accepted_result_codes: effective.accepted_result_codes.clone(),
        config_source: effective.source.clone(),
        config_provenance: effective.provenance.clone(),
        deadline: Some(deadline),
    };
    let execution_options = ScanExecutionOptions {
        workers: args.workers.effective(),
        profiler: profiler.clone(),
    };
    let report = match scan_with_options(discovery, &bundle, &config, &execution_options) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {error}");
            return 30;
        }
    };

    let reporting_started = Instant::now();
    match args.format {
        OutputFormat::Summary => {
            let write_started = Instant::now();
            print!("{}", report.summary());
            for warning in &report.warnings {
                println!("Warning: {warning}");
            }
            if let Some(profiler) = &profiler {
                profiler.record_wall("reporting.write", write_started);
            }
        }
        OutputFormat::Sanitized => {
            let serialize_started = Instant::now();
            let payload = match serde_json::to_string_pretty(&report.sanitized_value()) {
                Ok(payload) => payload,
                Err(error) => {
                    eprintln!("error: sanitized report failed: {error}");
                    return 30;
                }
            };
            if let Some(profiler) = &profiler {
                profiler.record_wall("reporting.serialize", serialize_started);
            }
            let write_started = Instant::now();
            if let Some(destination) = &destination {
                if let Err(error) = destination.write(payload.as_bytes()) {
                    eprintln!("error: {error}");
                    return 30;
                }
            } else {
                println!("{payload}");
            }
            if let Some(profiler) = &profiler {
                profiler.record_wall("reporting.write", write_started);
            }
        }
        OutputFormat::Private => {
            let serialize_started = Instant::now();
            let value = match report.private_value() {
                Ok(value) => value,
                Err(error) => {
                    eprintln!("error: private report failed: {error}");
                    return 30;
                }
            };
            let payload = match serde_json::to_string_pretty(&value) {
                Ok(payload) => payload,
                Err(error) => {
                    eprintln!("error: private report failed: {error}");
                    return 30;
                }
            };
            if let Some(profiler) = &profiler {
                profiler.record_wall("reporting.serialize", serialize_started);
            }
            let write_started = Instant::now();
            if let Some(destination) = &destination {
                if let Err(error) = destination.write(payload.as_bytes()) {
                    eprintln!("error: {error}");
                    return 30;
                }
            } else {
                eprintln!("error: private report requires --output");
                return 64;
            }
            print!("{}", report.summary());
            if let Some(profiler) = &profiler {
                profiler.record_wall("reporting.write", write_started);
            }
        }
    }

    if let (Some(profiler), Some(destination)) = (&profiler, &profile_destination) {
        profiler.set_effective("strategy", report.plan.effective.as_str());
        profiler.set_requested("strategy", report.plan.requested.as_str());
        profiler.set_effective("mode", format!("{:?}", effective.mode).to_lowercase());
        profiler.record_wall("reporting", reporting_started);
        let document = profiler.finish(&run_id);
        let payload = match serde_json::to_string_pretty(&document) {
            Ok(payload) => payload,
            Err(error) => {
                eprintln!("error: profile serialization failed: {error}");
                return 30;
            }
        };
        if let Err(error) = destination.write(payload.as_bytes()) {
            eprintln!("error: profile publication failed: {error}");
            return 30;
        }
    }
    report.ci.process_exit_code
}

fn run_rules_validate(arguments: &[String]) -> i32 {
    let mut rules = None;
    let mut strategy = BackendRequest::Auto;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--rules" => {
                let value = match arguments.get(index + 1) {
                    Some(value) => value,
                    None => {
                        eprintln!("error: --rules requires a value");
                        return 64;
                    }
                };
                rules = Some(PathBuf::from(value));
                index += 2;
            }
            "--strategy" => {
                let value = match arguments.get(index + 1) {
                    Some(value) => value,
                    None => {
                        eprintln!("error: --strategy requires a value");
                        return 64;
                    }
                };
                strategy = match BackendRequest::parse(value) {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("error: {error}");
                        return 64;
                    }
                };
                index += 2;
            }
            other => {
                eprintln!("error: unknown option {other}");
                return 64;
            }
        }
    }
    let rules = match rules {
        Some(rules) => rules,
        None => {
            eprintln!("error: --rules is required");
            return 64;
        }
    };
    match LoadedBundle::load(&rules) {
        Ok(bundle) => {
            let plan = match rnc_core::backend::MatchPlan::new(&bundle, strategy) {
                Ok(plan) => plan,
                Err(error) => {
                    eprintln!("error: {error}");
                    return 64;
                }
            };
            println!("Ruleset: {}", bundle.definition.ruleset_id);
            println!("Version: {}", bundle.definition.ruleset_version);
            println!("Rules: {}", bundle.rule_count());
            println!("Digest: {}", bundle.digest);
            println!("Max match bytes: {}", bundle.max_match_bytes);
            println!(
                "Requested strategy: {}",
                plan.provenance().requested.as_str()
            );
            println!(
                "Effective strategy: {}",
                plan.provenance().effective.as_str()
            );
            println!(
                "Required literals: {} of {} rules",
                plan.provenance().rules_with_required_literals,
                plan.provenance().rule_count
            );
            if let Some(reason) = &plan.provenance().fallback_reason {
                println!("Fallback: {reason}");
            }
            0
        }
        Err(error) => {
            eprintln!("error: {error}");
            64
        }
    }
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.is_empty() || arguments[0] == "--help" || arguments[0] == "-h" {
        println!("{USAGE}");
        process::exit(if arguments.is_empty() { 64 } else { 0 });
    }
    if arguments[0] == "--version" {
        println!("rnc {ENGINE_VERSION}");
        process::exit(0);
    }
    let status = match arguments[0].as_str() {
        "scan" => run_scan(&arguments[1..]),
        "rules" if arguments.get(1).map(String::as_str) == Some("validate") => {
            run_rules_validate(&arguments[2..])
        }
        other => {
            eprintln!("error: unknown command {other}");
            println!("{USAGE}");
            64
        }
    };
    process::exit(status);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_json_requires_output() {
        let args = vec![
            "--root".to_string(),
            ".".to_string(),
            "--rules".to_string(),
            "rules.json".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];
        assert!(parse_scan_args(&args).is_err());
    }

    #[test]
    fn default_run_id_is_nonempty() {
        assert!(default_run_id().starts_with("rnc-"));
    }

    #[test]
    fn strategy_names_are_validated() {
        assert!(BackendRequest::parse("prefilter").is_ok());
        assert!(BackendRequest::parse("hyperscan").is_err());
    }

    fn base_args() -> Vec<String> {
        vec![
            "--root".to_string(),
            ".".to_string(),
            "--rules".to_string(),
            "rules.json".to_string(),
        ]
    }

    #[test]
    fn worker_values_are_restricted_and_auto_resolves() {
        for value in ["1", "2", "4", "8", "auto"] {
            assert!(WorkerSetting::parse(value).is_ok(), "{value}");
        }
        assert!(WorkerSetting::parse("3").is_err());
        assert!(WorkerSetting::parse("auto").unwrap().effective() >= 1);
        assert_eq!(WorkerSetting::Fixed(4).effective(), 4);
    }

    #[test]
    fn git_only_flags_require_history() {
        for flag in [
            vec!["--git-io", "batch"],
            vec!["--history-mode", "diff"],
            vec!["--context-lines", "3"],
        ] {
            let mut args = base_args();
            args.extend(flag.iter().map(|value| value.to_string()));
            assert!(parse_scan_args(&args).is_err());
        }
    }

    #[test]
    fn diff_history_accepts_required_combinations() {
        let mut args = base_args();
        args.extend(
            [
                "--history",
                "--git-io",
                "batch",
                "--history-mode",
                "diff",
                "--context-lines",
                "3",
                "--workers",
                "auto",
                "--profile-output",
                "profile.json",
            ]
            .iter()
            .map(|value| value.to_string()),
        );
        let parsed = parse_scan_args(&args).expect("valid CP4C arguments");
        assert!(parsed.history);
        assert_eq!(parsed.git_io, GitIoMode::Batch);
        assert_eq!(parsed.history_mode, GitHistoryMode::Diff);
        assert_eq!(parsed.context_lines, 3);
        assert_eq!(parsed.workers, WorkerSetting::Auto);
        assert_eq!(parsed.profile_output, Some(PathBuf::from("profile.json")));
    }

    #[test]
    fn whole_history_rejects_context_override() {
        let mut args = base_args();
        args.extend(
            [
                "--history",
                "--history-mode",
                "whole",
                "--context-lines",
                "0",
            ]
            .iter()
            .map(|value| value.to_string()),
        );
        assert!(parse_scan_args(&args).is_err());
    }
}
