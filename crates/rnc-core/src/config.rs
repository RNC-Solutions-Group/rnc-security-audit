//! Production unified configuration loader.
//!
//! One immutable effective configuration is produced from optional global and
//! repository files plus explicit CLI overrides. Lower-trust sources may narrow
//! mandatory controls but cannot broaden or remove them.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::backend::BackendRequest;
use crate::error::CoreError;
use crate::input::ScanLimits;
use crate::policy::{PolicyOrigin, PolicySpec};
use crate::stream::ScanMode;

pub const CONFIG_VERSION: &str = "0.2.0";
pub const UNIFIED_NAME: &str = ".rncscanner.toml";
pub const LEGACY_NAME: &str = "security.config";

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub schema_version: String,
    pub ruleset: Option<FileRuleset>,
    pub scan: Option<FileScan>,
    pub policy: Option<FilePolicy>,
    pub reporting: Option<FileReporting>,
    pub ci: Option<FileCi>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileRuleset {
    pub id: Option<String>,
    pub version: Option<String>,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileScan {
    pub max_file_bytes: Option<u64>,
    pub max_total_bytes: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub max_findings: Option<usize>,
    pub stream_chunk_bytes: Option<usize>,
    pub stream_threshold_bytes: Option<u64>,
    pub mode: Option<String>,
    pub strategy: Option<String>,
    pub follow_symlinks: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FilePolicy {
    #[serde(default)]
    pub blocks: Vec<FilePolicyEntry>,
    #[serde(default)]
    pub exemptions: Vec<FilePolicyEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePolicyEntry {
    pub policy_id: String,
    pub selector: String,
    pub reason: String,
    pub version: Option<String>,
    pub mandatory: Option<bool>,
    pub expires_unix: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileReporting {
    pub sanitized_only: Option<bool>,
    pub redaction_fail_closed: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileCi {
    pub accepted_result_codes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyConfig {
    version: u32,
    secret_detection: Option<LegacyDetection>,
    exclusions: Option<LegacyExclusions>,
    limits: Option<LegacyLimits>,
    reporting: Option<LegacyReporting>,
    ci: Option<FileCi>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDetection {
    enabled: bool,
    ruleset: Option<String>,
    ruleset_digest: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyExclusions {
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyLimits {
    max_file_bytes: Option<u64>,
    max_total_bytes: Option<u64>,
    timeout_ms: Option<u64>,
    max_findings: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyReporting {
    sanitized: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub max_file_bytes: Option<u64>,
    pub max_total_bytes: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub max_findings: Option<usize>,
    pub stream_chunk_bytes: Option<usize>,
    pub stream_threshold_bytes: Option<u64>,
    pub mode: Option<ScanMode>,
    pub strategy: Option<BackendRequest>,
    pub accepted_result_codes: Vec<u8>,
    pub blocks: Vec<String>,
    pub exemptions: Vec<String>,
    pub skips: Vec<String>,
    pub optional: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesetExpectation {
    pub id: Option<String>,
    pub version: Option<String>,
    pub digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub limits: ScanLimits,
    pub mode: ScanMode,
    pub strategy: BackendRequest,
    pub stream_chunk_bytes: usize,
    pub stream_threshold_bytes: u64,
    pub accepted_result_codes: Vec<u8>,
    pub policy: PolicySpec,
    pub ruleset: RulesetExpectation,
    pub provenance: BTreeMap<String, String>,
    pub source: String,
    pub migrated_legacy: bool,
}

#[derive(Debug, Clone)]
struct Source {
    origin: PolicyOrigin,
    path: PathBuf,
    config: FileConfig,
    migrated_legacy: bool,
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, CoreError> {
    let raw = fs::read(path)
        .map_err(|error| CoreError::Input(format!("configuration unreadable: {}", error.kind())))?;
    let raw = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&raw);
    let text = std::str::from_utf8(raw)
        .map_err(|_| CoreError::Input("configuration is not UTF-8".to_string()))?;
    toml::from_str(text).map_err(|error| {
        CoreError::Input(format!(
            "configuration TOML invalid at line {}: {}",
            error.span().map(|span| span.start).unwrap_or(0),
            error.message()
        ))
    })
}

fn validate_file(config: &FileConfig, origin: PolicyOrigin) -> Result<(), CoreError> {
    if config.schema_version != CONFIG_VERSION {
        return Err(CoreError::Input(format!(
            "unsupported configuration schema_version {}",
            config.schema_version
        )));
    }
    if let Some(reporting) = &config.reporting {
        if reporting.sanitized_only == Some(false) {
            return Err(CoreError::Input(
                "reporting.sanitized_only must be true".to_string(),
            ));
        }
        if reporting.redaction_fail_closed == Some(false) {
            return Err(CoreError::Input(
                "reporting.redaction_fail_closed must be true".to_string(),
            ));
        }
    }
    if let Some(scan) = &config.scan {
        if scan.follow_symlinks == Some(true) {
            return Err(CoreError::Input(
                "follow_symlinks is not permitted".to_string(),
            ));
        }
        if scan
            .mode
            .as_deref()
            .is_some_and(|mode| !matches!(mode, "auto" | "whole" | "stream"))
        {
            return Err(CoreError::Input(
                "scan.mode must be auto, whole or stream".to_string(),
            ));
        }
        if scan
            .strategy
            .as_deref()
            .is_some_and(|strategy| BackendRequest::parse(strategy).is_err())
        {
            return Err(CoreError::Input(
                "scan.strategy must be regex, regexset, prefilter or auto".to_string(),
            ));
        }
    }
    if let Some(policy) = &config.policy {
        for entry in policy.blocks.iter().chain(policy.exemptions.iter()) {
            if entry.mandatory == Some(true) && origin != PolicyOrigin::Global {
                return Err(CoreError::Input(
                    "mandatory policy may only originate in global configuration".to_string(),
                ));
            }
            if entry.policy_id.trim().is_empty() || entry.reason.trim().is_empty() {
                return Err(CoreError::Input(
                    "policy_id and reason must be non-empty".to_string(),
                ));
            }
        }
    }
    if let Some(ci) = &config.ci {
        if let Some(codes) = &ci.accepted_result_codes {
            if codes.is_empty()
                || codes.iter().any(|code| !matches!(code, 1..=3))
                || codes.windows(2).any(|pair| pair[0] > pair[1])
            {
                return Err(CoreError::Input(
                    "accepted_result_codes must be sorted, unique and a subset of 1,2,3"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn load_source(path: PathBuf, origin: PolicyOrigin) -> Result<Source, CoreError> {
    let config: FileConfig = read_toml(&path)?;
    validate_file(&config, origin)?;
    Ok(Source {
        origin,
        path,
        config,
        migrated_legacy: false,
    })
}

fn load_legacy(path: PathBuf) -> Result<Source, CoreError> {
    let legacy: LegacyConfig = read_toml(&path)?;
    if legacy.version != 1 {
        return Err(CoreError::Input(
            "legacy security.config must use version 1".to_string(),
        ));
    }
    let detection = legacy
        .secret_detection
        .ok_or_else(|| CoreError::Input("legacy secret_detection is required".to_string()))?;
    if !detection.enabled {
        return Err(CoreError::Input(
            "legacy scanner disabled cannot migrate a scan policy".to_string(),
        ));
    }
    let ruleset_id = detection
        .ruleset
        .ok_or_else(|| CoreError::Input("legacy ruleset is required".to_string()))?;
    let ruleset_digest = detection
        .ruleset_digest
        .ok_or_else(|| CoreError::Input("legacy ruleset_digest is required".to_string()))?;
    if !ruleset_digest.starts_with("sha256:") {
        return Err(CoreError::Input(
            "legacy ruleset_digest must be sha256".to_string(),
        ));
    }
    if legacy
        .reporting
        .as_ref()
        .and_then(|reporting| reporting.sanitized)
        == Some(false)
    {
        return Err(CoreError::Input(
            "legacy unsanitized reporting cannot be migrated".to_string(),
        ));
    }
    let limits = legacy.limits.unwrap_or(LegacyLimits {
        max_file_bytes: None,
        max_total_bytes: None,
        timeout_ms: None,
        max_findings: None,
    });
    let paths = legacy
        .exclusions
        .map(|exclusions| exclusions.paths)
        .unwrap_or_default();
    let blocks = paths
        .into_iter()
        .map(|selector| FilePolicyEntry {
            policy_id: "LEGACY-SECURITY-CONFIG".to_string(),
            selector,
            reason: "Migrated from legacy security.config exclusions".to_string(),
            version: Some("legacy-security-config-v1".to_string()),
            mandatory: Some(false),
            expires_unix: None,
        })
        .collect();
    let config = FileConfig {
        schema_version: CONFIG_VERSION.to_string(),
        ruleset: Some(FileRuleset {
            id: Some(ruleset_id),
            version: Some("legacy-security-config-v1".to_string()),
            digest: Some(ruleset_digest),
        }),
        scan: Some(FileScan {
            max_file_bytes: limits.max_file_bytes,
            max_total_bytes: limits.max_total_bytes,
            timeout_ms: limits.timeout_ms,
            max_findings: limits.max_findings,
            ..FileScan::default()
        }),
        policy: Some(FilePolicy {
            blocks,
            exemptions: Vec::new(),
        }),
        reporting: Some(FileReporting {
            sanitized_only: Some(true),
            redaction_fail_closed: Some(true),
        }),
        ci: legacy.ci,
    };
    validate_file(&config, PolicyOrigin::Repository)?;
    Ok(Source {
        origin: PolicyOrigin::Repository,
        path,
        config,
        migrated_legacy: true,
    })
}

fn intersect_acceptance(
    global: Option<&Source>,
    repository: Option<&Source>,
    cli: &[u8],
) -> Result<(Vec<u8>, BTreeMap<u8, String>), CoreError> {
    let default = vec![1u8, 2u8];
    let global_codes = global.and_then(|source| {
        source
            .config
            .ci
            .as_ref()
            .and_then(|ci| ci.accepted_result_codes.clone())
    });
    let repository_codes = repository.and_then(|source| {
        source
            .config
            .ci
            .as_ref()
            .and_then(|ci| ci.accepted_result_codes.clone())
    });
    let mut effective = global_codes.clone().unwrap_or_else(|| default.clone());
    let mut authority: BTreeMap<u8, String> = effective
        .iter()
        .map(|code| {
            (
                *code,
                if global_codes.is_some() {
                    "global"
                } else {
                    "default"
                }
                .to_string(),
            )
        })
        .collect();

    if let Some(codes) = &repository_codes {
        if codes.is_empty() || codes.iter().any(|code| !matches!(code, 1..=3)) {
            return Err(CoreError::Input(
                "repository accepted_result_codes must be a non-empty subset of 1,2,3".to_string(),
            ));
        }
        let trusted_cap = global_codes.as_ref().unwrap_or(&default);
        if let Some(code) = codes.iter().find(|code| !trusted_cap.contains(code)) {
            return Err(CoreError::Input(format!(
                "repository configuration may not authorize result code {code}"
            )));
        }
        effective = codes.clone();
        authority = effective
            .iter()
            .map(|code| (*code, "repository".to_string()))
            .collect();
    }

    if !cli.is_empty() {
        if let Some(code) = cli.iter().find(|code| !matches!(code, 1..=3)) {
            return Err(CoreError::Input(format!(
                "CLI requested an invalid result code {code}"
            )));
        }
        if let Some(global_codes) = &global_codes {
            if let Some(code) = cli.iter().find(|code| !global_codes.contains(code)) {
                return Err(CoreError::Input(format!(
                    "CLI acceptance of result code {code} is prohibited by mandatory global policy"
                )));
            }
        }
        effective = cli.to_vec();
        authority = effective
            .iter()
            .map(|code| (*code, "cli".to_string()))
            .collect();
    }

    effective.sort_unstable();
    effective.dedup();
    if effective.is_empty() {
        return Err(CoreError::Input(
            "configuration sources leave no accepted result code".to_string(),
        ));
    }
    Ok((effective, authority))
}

/// Load the immutable effective configuration.
///
/// `explicit_repository_path` selects one repository file. When omitted, the
/// loader discovers `.rncscanner.toml` or `security.config`; both present is a
/// hard failure. Global configuration is independent and optional.
pub fn load_effective(
    root: &Path,
    explicit_repository_path: Option<&Path>,
    global_path: Option<&Path>,
    cli: &CliOverrides,
) -> Result<EffectiveConfig, CoreError> {
    let mut provenance = BTreeMap::new();
    let mut global = None;
    if let Some(path) = global_path {
        let source = load_source(path.to_path_buf(), PolicyOrigin::Global)?;
        provenance.insert("global_config".to_string(), "global".to_string());
        global = Some(source);
    }

    let repository = if let Some(path) = explicit_repository_path {
        if path.file_name().and_then(|name| name.to_str()) == Some(LEGACY_NAME) {
            Some(load_legacy(path.to_path_buf())?)
        } else {
            Some(load_source(path.to_path_buf(), PolicyOrigin::Repository)?)
        }
    } else {
        let unified = root.join(UNIFIED_NAME);
        let legacy = root.join(LEGACY_NAME);
        if unified.exists() && legacy.exists() {
            return Err(CoreError::Input(
                "both .rncscanner.toml and security.config exist; choose one explicitly"
                    .to_string(),
            ));
        }
        if unified.exists() {
            Some(load_source(unified, PolicyOrigin::Repository)?)
        } else if legacy.exists() {
            Some(load_legacy(legacy)?)
        } else {
            None
        }
    };
    if let Some(source) = &repository {
        provenance.insert(
            "repository_config".to_string(),
            if source.migrated_legacy {
                "legacy".to_string()
            } else {
                "repository".to_string()
            },
        );
    }

    let sources: Vec<&Source> = global.iter().chain(repository.iter()).collect();
    let mut max_file_bytes: Option<(u64, PolicyOrigin)> = None;
    let mut max_total_bytes: Option<(u64, PolicyOrigin)> = None;
    let mut timeout_ms: Option<(u64, PolicyOrigin)> = None;
    let mut max_findings: Option<(usize, PolicyOrigin)> = None;
    let mut stream_chunk_bytes: Option<(usize, PolicyOrigin)> = None;
    let mut stream_threshold_bytes: Option<(u64, PolicyOrigin)> = None;
    let mut mode = None;
    let mut strategy = None;
    let mut ruleset = RulesetExpectation::default();

    fn narrow<T: Ord + Copy>(
        slot: &mut Option<(T, PolicyOrigin)>,
        value: Option<T>,
        origin: PolicyOrigin,
    ) {
        if let Some(value) = value {
            if slot.as_ref().is_none_or(|(current, _)| value < *current) {
                *slot = Some((value, origin));
            }
        }
    }

    for source in &sources {
        if let Some(scan) = &source.config.scan {
            narrow(&mut max_file_bytes, scan.max_file_bytes, source.origin);
            narrow(&mut max_total_bytes, scan.max_total_bytes, source.origin);
            narrow(&mut timeout_ms, scan.timeout_ms, source.origin);
            narrow(&mut max_findings, scan.max_findings, source.origin);
            narrow(
                &mut stream_chunk_bytes,
                scan.stream_chunk_bytes,
                source.origin,
            );
            narrow(
                &mut stream_threshold_bytes,
                scan.stream_threshold_bytes,
                source.origin,
            );
            if let Some(value) = &scan.mode {
                mode = Some(parse_mode(value)?);
                provenance.insert("scan.mode".to_string(), source.origin.as_str().to_string());
            }
            if let Some(value) = &scan.strategy {
                strategy = Some(BackendRequest::parse(value)?);
                provenance.insert(
                    "scan.strategy".to_string(),
                    source.origin.as_str().to_string(),
                );
            }
        }
        if let Some(declared) = &source.config.ruleset {
            merge_ruleset(&mut ruleset, declared, source.origin)?;
            provenance.insert("ruleset".to_string(), source.origin.as_str().to_string());
        }
    }
    narrow(&mut max_file_bytes, cli.max_file_bytes, PolicyOrigin::Cli);
    narrow(&mut max_total_bytes, cli.max_total_bytes, PolicyOrigin::Cli);
    narrow(&mut timeout_ms, cli.timeout_ms, PolicyOrigin::Cli);
    narrow(&mut max_findings, cli.max_findings, PolicyOrigin::Cli);
    narrow(
        &mut stream_chunk_bytes,
        cli.stream_chunk_bytes,
        PolicyOrigin::Cli,
    );
    narrow(
        &mut stream_threshold_bytes,
        cli.stream_threshold_bytes,
        PolicyOrigin::Cli,
    );
    if let Some((_, origin)) = &max_file_bytes {
        provenance.insert(
            "scan.max_file_bytes".to_string(),
            origin.as_str().to_string(),
        );
    }
    if let Some((_, origin)) = &max_total_bytes {
        provenance.insert(
            "scan.max_total_bytes".to_string(),
            origin.as_str().to_string(),
        );
    }
    if let Some((_, origin)) = &timeout_ms {
        provenance.insert("scan.timeout_ms".to_string(), origin.as_str().to_string());
    }
    if let Some((_, origin)) = &max_findings {
        provenance.insert("scan.max_findings".to_string(), origin.as_str().to_string());
    }
    if let Some((_, origin)) = &stream_chunk_bytes {
        provenance.insert(
            "scan.stream_chunk_bytes".to_string(),
            origin.as_str().to_string(),
        );
    }
    if let Some((_, origin)) = &stream_threshold_bytes {
        provenance.insert(
            "scan.stream_threshold_bytes".to_string(),
            origin.as_str().to_string(),
        );
    }
    if cli.mode.is_some() {
        mode = cli.mode;
        provenance.insert("scan.mode".to_string(), "cli".to_string());
    }
    if cli.strategy.is_some() {
        strategy = cli.strategy;
        provenance.insert("scan.strategy".to_string(), "cli".to_string());
    }

    let defaults = ScanLimits::default();
    let limits = ScanLimits {
        max_file_bytes: max_file_bytes
            .map(|(value, _)| value)
            .unwrap_or(defaults.max_file_bytes),
        max_total_bytes: max_total_bytes
            .map(|(value, _)| value)
            .unwrap_or(defaults.max_total_bytes),
        timeout: std::time::Duration::from_millis(
            timeout_ms.map(|(value, _)| value).unwrap_or(300_000),
        ),
        max_findings: max_findings
            .map(|(value, _)| value)
            .unwrap_or(defaults.max_findings),
    };

    let (accepted, accepted_authority) = intersect_acceptance(
        global.as_ref(),
        repository.as_ref(),
        &cli.accepted_result_codes,
    )?;
    for (code, origin) in accepted_authority {
        provenance.insert(format!("ci.accepted_result_codes.{code}"), origin);
    }
    let mut policy = PolicySpec::empty();
    for source in &sources {
        if let Some(file_policy) = &source.config.policy {
            for entry in &file_policy.blocks {
                policy.add_block(
                    &entry.policy_id,
                    source.origin,
                    &entry.selector,
                    &entry.reason,
                    entry.version.as_deref().unwrap_or("1"),
                    entry.mandatory.unwrap_or(false),
                )?;
            }
            for entry in &file_policy.exemptions {
                policy.add_exemption(
                    &entry.policy_id,
                    source.origin,
                    &entry.selector,
                    &entry.reason,
                    entry.version.as_deref().unwrap_or("1"),
                    entry.mandatory.unwrap_or(false),
                    entry.expires_unix,
                )?;
            }
        }
    }
    for selector in &cli.blocks {
        let id = format!(
            "CLI-BLOCK-{}",
            crate::policy::request_id("CLI", "BLOCK", selector)
        );
        policy.add_block(
            &id,
            PolicyOrigin::Cli,
            selector,
            "CLI pre-scan block",
            "1",
            false,
        )?;
    }
    for selector in &cli.exemptions {
        let id = format!(
            "CLI-EXEMPT-{}",
            crate::policy::request_id("CLI", "EXEMPTION", selector)
        );
        policy.add_exemption(
            &id,
            PolicyOrigin::Cli,
            selector,
            "CLI post-scan exemption",
            "1",
            false,
            None,
        )?;
    }
    for selector in &cli.skips {
        policy.add_skip(selector)?;
    }
    for selector in &cli.optional {
        policy.add_optional(selector)?;
    }
    policy.validate()?;

    let source = repository
        .as_ref()
        .map(|source| {
            format!(
                "{}{}",
                source.path.display(),
                if source.migrated_legacy {
                    " (legacy)"
                } else {
                    ""
                }
            )
        })
        .unwrap_or_else(|| "defaults".to_string());

    Ok(EffectiveConfig {
        limits,
        mode: mode.unwrap_or(ScanMode::Auto),
        strategy: strategy.unwrap_or(BackendRequest::Auto),
        stream_chunk_bytes: stream_chunk_bytes
            .map(|(value, _)| value)
            .unwrap_or(crate::input::DEFAULT_STREAM_CHUNK_BYTES),
        stream_threshold_bytes: stream_threshold_bytes
            .map(|(value, _)| value)
            .unwrap_or(1024 * 1024),
        accepted_result_codes: accepted,
        policy,
        ruleset,
        provenance,
        source,
        migrated_legacy: repository
            .as_ref()
            .is_some_and(|source| source.migrated_legacy),
    })
}

fn parse_mode(value: &str) -> Result<ScanMode, CoreError> {
    match value {
        "auto" => Ok(ScanMode::Auto),
        "whole" => Ok(ScanMode::Whole),
        "stream" => Ok(ScanMode::Stream),
        _ => Err(CoreError::Input(
            "scan.mode must be auto, whole or stream".to_string(),
        )),
    }
}

fn merge_ruleset(
    target: &mut RulesetExpectation,
    declared: &FileRuleset,
    origin: PolicyOrigin,
) -> Result<(), CoreError> {
    for (slot, value) in [
        (&mut target.id, declared.id.as_ref()),
        (&mut target.version, declared.version.as_ref()),
        (&mut target.digest, declared.digest.as_ref()),
    ] {
        if let Some(value) = value {
            if slot.as_ref().is_some_and(|existing| existing != value) {
                return Err(CoreError::Input(format!(
                    "ruleset declaration conflicts across configuration sources ({origin:?})"
                )));
            }
            *slot = Some(value.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn write(path: &Path, value: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut file = fs::File::create(path).unwrap();
        file.write_all(value.as_bytes()).unwrap();
    }

    #[test]
    fn repository_cannot_broaden_global_acceptance_or_enable_links() {
        let temp = tempdir().unwrap();
        write(
            &temp.path().join("global.toml"),
            "schema_version = \"0.2.0\"\n[ci]\naccepted_result_codes = [1, 2]\n[policy]\n[[policy.blocks]]\npolicy_id = \"GLOBAL-BLOCK\"\nselector = \"secrets/**\"\nreason = \"org policy\"\nmandatory = true\n",
        );
        write(
            &temp.path().join(UNIFIED_NAME),
            "schema_version = \"0.2.0\"\n[ci]\naccepted_result_codes = [1, 2]\n[scan]\nfollow_symlinks = false\n",
        );
        assert!(load_effective(
            temp.path(),
            None,
            Some(&temp.path().join("global.toml")),
            &CliOverrides {
                accepted_result_codes: vec![3],
                ..CliOverrides::default()
            },
        )
        .is_err());
        let config = load_effective(
            temp.path(),
            None,
            Some(&temp.path().join("global.toml")),
            &CliOverrides {
                accepted_result_codes: vec![1],
                ..CliOverrides::default()
            },
        )
        .unwrap();
        assert_eq!(config.accepted_result_codes, vec![1]);
        assert_eq!(
            config
                .provenance
                .get("ci.accepted_result_codes.1")
                .map(String::as_str),
            Some("cli")
        );
        assert_eq!(config.policy.blocks.len(), 1);
        assert!(config.policy.blocks[0].matcher.matches("secrets/a.txt"));
    }

    #[test]
    fn repository_alone_cannot_authorize_actionable() {
        let temp = tempdir().unwrap();
        write(
            &temp.path().join(UNIFIED_NAME),
            "schema_version = \"0.2.0\"\n[ci]\naccepted_result_codes = [1, 2, 3]\n",
        );
        assert!(load_effective(temp.path(), None, None, &CliOverrides::default()).is_err());
    }

    #[test]
    fn cli_or_global_can_authorize_actionable() {
        let temp = tempdir().unwrap();
        let cli = load_effective(
            temp.path(),
            None,
            None,
            &CliOverrides {
                accepted_result_codes: vec![3],
                ..CliOverrides::default()
            },
        )
        .unwrap();
        assert_eq!(cli.accepted_result_codes, vec![3]);
        assert_eq!(
            cli.provenance
                .get("ci.accepted_result_codes.3")
                .map(String::as_str),
            Some("cli")
        );
        write(
            &temp.path().join("global.toml"),
            "schema_version = \"0.2.0\"\n[ci]\naccepted_result_codes = [1, 2, 3]\n",
        );
        let global = load_effective(
            temp.path(),
            None,
            Some(&temp.path().join("global.toml")),
            &CliOverrides::default(),
        )
        .unwrap();
        assert_eq!(global.accepted_result_codes, vec![1, 2, 3]);
        assert_eq!(
            global
                .provenance
                .get("ci.accepted_result_codes.3")
                .map(String::as_str),
            Some("global")
        );
    }

    #[test]
    fn dual_configuration_sources_fail() {
        let temp = tempdir().unwrap();
        write(
            &temp.path().join(UNIFIED_NAME),
            "schema_version = \"0.2.0\"\n",
        );
        write(
            &temp.path().join(LEGACY_NAME),
            "version = 1\n[secret_detection]\nenabled = true\nruleset = \"x\"\nruleset_digest = \"sha256:abc\"\n",
        );
        assert!(load_effective(temp.path(), None, None, &CliOverrides::default()).is_err());
    }

    #[test]
    fn unknown_configuration_fields_fail() {
        let temp = tempdir().unwrap();
        write(
            &temp.path().join(UNIFIED_NAME),
            "schema_version = \"0.2.0\"\nunknown = true\n",
        );
        assert!(load_effective(temp.path(), None, None, &CliOverrides::default()).is_err());
    }

    #[test]
    fn mandatory_policy_cannot_originate_in_repository() {
        let temp = tempdir().unwrap();
        write(
            &temp.path().join(UNIFIED_NAME),
            "schema_version = \"0.2.0\"\n[policy]\n[[policy.blocks]]\npolicy_id = \"R\"\nselector = \"x\"\nreason = \"r\"\nmandatory = true\n",
        );
        assert!(load_effective(temp.path(), None, None, &CliOverrides::default()).is_err());
    }
}
