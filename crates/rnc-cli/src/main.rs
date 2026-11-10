//! Minimal RNC Scanner development CLI. Detection evidence only.

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use rnc_core::{scan, LoadedBundle, LocalSource, RunConfig, ScanLimits, ScanMode, ENGINE_VERSION};

const USAGE: &str = "rnc — RNC Scanner CP1 development CLI

Usage:
  rnc scan --root DIR --rules FILE [options]
  rnc rules validate --rules FILE
  rnc --version

Scan options:
  --output PATH              Write private normalized JSON evidence
  --format summary|json      Output format; json requires --output
  --run-id ID                Stable run identifier (default: rnc-<unix-ms>)
  --mode auto|whole|stream   Scan mode (default: auto)
  --exclude PATH             Verified pre-scan block; do not read PATH (repeatable)
  --skip PATH                Record PATH as uninspected, do not read it (repeatable)
  --optional PATH            Mark PATH optional for coverage (repeatable)
  --max-file-bytes N         Per-file byte limit (default: 8388608)
  --max-total-bytes N        Total inspected byte limit (default: 67108864)
  --timeout-ms N             Scan timeout in milliseconds (default: 300000)
  --max-findings N           Maximum findings before a hard stop (default: 10000)
  --stream-chunk-bytes N     Streaming chunk size (default: 65536)
  --stream-threshold N       Auto-stream files at least this large (default: 1048576)

The JSON output contains private finding IDs and evidence digests. Store it as
private evidence; ordinary logs and summaries never contain them.";

#[derive(Debug)]
struct ScanArgs {
    root: PathBuf,
    rules: PathBuf,
    output: Option<PathBuf>,
    format: String,
    run_id: String,
    mode: ScanMode,
    excludes: Vec<String>,
    skips: Vec<String>,
    optional: Vec<String>,
    limits: ScanLimits,
    stream_chunk_bytes: usize,
    stream_threshold: u64,
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
    let mut format = "summary".to_string();
    let mut run_id = default_run_id();
    let mut mode = ScanMode::Auto;
    let mut excludes = Vec::new();
    let mut skips = Vec::new();
    let mut optional = Vec::new();
    let mut limits = ScanLimits::default();
    let mut stream_chunk_bytes = rnc_core::input::DEFAULT_STREAM_CHUNK_BYTES;
    let mut stream_threshold = 1024 * 1024u64;
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
            "--format" => format = value.clone(),
            "--run-id" => run_id = value.clone(),
            "--mode" => {
                mode = match value.as_str() {
                    "auto" => ScanMode::Auto,
                    "whole" => ScanMode::Whole,
                    "stream" => ScanMode::Stream,
                    _ => return Err("--mode must be auto, whole or stream".to_string()),
                }
            }
            "--exclude" => excludes.push(value.clone()),
            "--skip" => skips.push(value.clone()),
            "--optional" => optional.push(value.clone()),
            "--max-file-bytes" => limits.max_file_bytes = parse_u64(value, name)?,
            "--max-total-bytes" => limits.max_total_bytes = parse_u64(value, name)?,
            "--timeout-ms" => {
                limits.timeout = std::time::Duration::from_millis(parse_u64(value, name)?)
            }
            "--max-findings" => limits.max_findings = parse_usize(value, name)?,
            "--stream-chunk-bytes" => stream_chunk_bytes = parse_usize(value, name)?,
            "--stream-threshold" => stream_threshold = parse_u64(value, name)?,
            other => return Err(format!("unknown option {other}")),
        }
        index += 2;
    }
    let root = root.ok_or_else(|| "--root is required".to_string())?;
    let rules = rules.ok_or_else(|| "--rules is required".to_string())?;
    if format != "summary" && format != "json" {
        return Err("--format must be summary or json".to_string());
    }
    if format == "json" && output.is_none() {
        return Err("--format json requires --output for private evidence".to_string());
    }
    if format == "summary" && output.is_some() {
        return Err("--output requires --format json".to_string());
    }
    if stream_chunk_bytes == 0 || stream_threshold == 0 {
        return Err("stream sizes must be positive".to_string());
    }
    limits.validate().map_err(|error| error.to_string())?;
    Ok(ScanArgs {
        root,
        rules,
        output,
        format,
        run_id,
        mode,
        excludes,
        skips,
        optional,
        limits,
        stream_chunk_bytes,
        stream_threshold,
    })
}

fn write_private_json(path: &PathBuf, value: &serde_json::Value) -> Result<(), String> {
    let payload = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create output: {error}"))?;
    file.write_all(&payload)
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|error| format!("cannot write output: {error}"))
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
    let source = match LocalSource::new(args.root, &args.excludes, &args.skips, &args.optional) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("error: {error}");
            return 1;
        }
    };
    let discovery = source.discover();
    let config = RunConfig {
        run_id: args.run_id,
        limits: args.limits,
        mode: args.mode,
        stream_threshold_bytes: args.stream_threshold,
        stream_chunk_bytes: args.stream_chunk_bytes,
    };
    let report = match scan(discovery, &bundle, &config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("error: {error}");
            return 1;
        }
    };
    if args.format == "json" {
        let output = args.output.expect("validated output");
        match report.to_json_value() {
            Ok(value) => {
                if let Err(error) = write_private_json(&output, &value) {
                    eprintln!("error: {error}");
                    return 1;
                }
            }
            Err(error) => {
                eprintln!("error: {error}");
                return 1;
            }
        }
    }
    print!("{}", report.summary());
    for warning in &report.warnings {
        println!("Warning: {warning}");
    }
    if report.execution.state == rnc_core::ExecutionState::Completed {
        0
    } else {
        1
    }
}

fn run_rules_validate(arguments: &[String]) -> i32 {
    let mut rules = None;
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
            println!("Ruleset: {}", bundle.definition.ruleset_id);
            println!("Version: {}", bundle.definition.ruleset_version);
            println!("Rules: {}", bundle.rule_count());
            println!("Digest: {}", bundle.digest);
            println!("Max match bytes: {}", bundle.max_match_bytes);
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
    fn json_requires_private_output() {
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
}
