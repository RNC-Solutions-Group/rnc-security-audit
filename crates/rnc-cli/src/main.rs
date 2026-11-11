//! RNC Scanner CP2 CLI: detection, policy, reporting and CI acceptance.

use std::env;
use std::path::PathBuf;
use std::process;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

mod report;

use rnc_core::{
    load_effective, scan, BackendRequest, CliOverrides, LoadedBundle, LocalSource, RunConfig,
    ScanLimits, ScanMode, ENGINE_VERSION,
};

const USAGE: &str = "rnc — RNC Scanner CP2

Usage:
  rnc scan --root DIR --rules FILE [options]
  rnc rules validate --rules FILE [--strategy regex|regexset|prefilter|auto]
  rnc --version

Scan options:
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
    let mut index = 0;
    while index < arguments.len() {
        let name = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{name} requires a value"))?;
        match name {
            "--root" => root = Some(PathBuf::from(value)),
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
    Ok(ScanArgs {
        root,
        rules,
        output,
        format,
        run_id,
        config,
        global_config,
        overrides,
    })
}

fn run_scan(arguments: &[String]) -> i32 {
    let args = match parse_scan_args(arguments) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("error: {error}");
            return 64;
        }
    };
    let bundle = match LoadedBundle::load(&args.rules) {
        Ok(bundle) => bundle,
        Err(error) => {
            eprintln!("error: {error}");
            return 64;
        }
    };
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
    let source = match LocalSource::new_with_policy(root, &effective.policy) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("error: {error}");
            return 64;
        }
    };
    let started = Instant::now();
    let deadline = started
        .checked_add(effective.limits.timeout)
        .unwrap_or(started);
    let discovery = source.discover_until(deadline);
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
    let report = match scan(discovery, &bundle, &config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {error}");
            return 30;
        }
    };

    match args.format {
        OutputFormat::Summary => {
            print!("{}", report.summary());
            for warning in &report.warnings {
                println!("Warning: {warning}");
            }
        }
        OutputFormat::Sanitized => {
            let payload = match serde_json::to_string_pretty(&report.sanitized_value()) {
                Ok(payload) => payload,
                Err(error) => {
                    eprintln!("error: sanitized report failed: {error}");
                    return 30;
                }
            };
            if let Some(destination) = &destination {
                if let Err(error) = destination.write(payload.as_bytes()) {
                    eprintln!("error: {error}");
                    return 30;
                }
            } else {
                println!("{payload}");
            }
        }
        OutputFormat::Private => {
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
}
