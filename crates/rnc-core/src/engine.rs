//! CP1 scan orchestration: coverage accounting around the detection pipeline.

use std::time::Instant;

use crate::coverage::{
    ExecutionRecord, ExecutionState, SourceUnitRecord, ENGINE_VERSION, SCHEMA_VERSION,
};
use crate::error::CoreError;
use crate::finding::{sort_findings, Finding};
use crate::input::{Discovery, PreScanScope, ScanLimits};
use crate::rules::LoadedBundle;
use crate::stream::{scan_file, FileScanError, ScanFileConfig, ScanMode};

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub run_id: String,
    pub limits: ScanLimits,
    pub mode: ScanMode,
    pub stream_threshold_bytes: u64,
    pub stream_chunk_bytes: usize,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            run_id: "rnc-run".to_string(),
            limits: ScanLimits::default(),
            mode: ScanMode::Auto,
            stream_threshold_bytes: 1024 * 1024,
            stream_chunk_bytes: crate::input::DEFAULT_STREAM_CHUNK_BYTES,
        }
    }
}

#[derive(Debug)]
pub struct ScanReport {
    pub execution: ExecutionRecord,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

impl ScanReport {
    pub fn to_json_value(&self) -> Result<serde_json::Value, CoreError> {
        Ok(serde_json::json!({
            "format_version": "rnc-cp1-output-v1",
            "execution": self.execution,
            "findings": self.findings,
        }))
    }

    pub fn summary(&self) -> String {
        let execution = &self.execution;
        format!(
            "RNC Scanner {ENGINE_VERSION}\n\
             Schema: {SCHEMA_VERSION}\n\
             Run: {}\n\
             Execution: {}\n\
             Ruleset: {} ({})\n\
             Inspected: {} (blocked {}, uninspected {}, required uninspected {})\n\
             Findings: {}\n",
            execution.run_id,
            execution.state.as_str(),
            execution.ruleset_id,
            execution.ruleset_digest,
            execution.inspected_count(),
            execution.blocked_count(),
            execution.uninspected_count(),
            execution.required_uninspected_count(),
            self.findings.len()
        )
    }
}

pub fn scan(
    discovery: Discovery,
    rules: &LoadedBundle,
    config: &RunConfig,
) -> Result<ScanReport, CoreError> {
    config.limits.validate()?;
    if config.run_id.trim().is_empty() {
        return Err(CoreError::Input("run_id must be non-empty".to_string()));
    }
    let deadline = Instant::now()
        .checked_add(config.limits.timeout)
        .unwrap_or_else(Instant::now);
    let mut execution = ExecutionRecord::new(&config.run_id, rules);
    let mut findings = Vec::new();
    let mut warnings = discovery.warnings.clone();
    for code in &discovery.fatal_errors {
        execution.add_fatal(code);
    }
    let units = discovery.units;
    let mut total_bytes = 0u64;
    let mut timed_out = false;
    for (index, unit) in units.iter().enumerate() {
        if Instant::now() >= deadline {
            timed_out = true;
            add_remaining_uninspected(&mut execution, &units[index..], "TIMEOUT")?;
            break;
        }
        match unit.scope {
            PreScanScope::Blocked => {
                execution.units.push(SourceUnitRecord::blocked(
                    &config.run_id,
                    &unit.locator,
                    unit.required_scope,
                    "PRE_SCAN_BLOCKED",
                )?);
            }
            PreScanScope::Skipped(reason) => {
                execution.units.push(SourceUnitRecord::uninspected(
                    &config.run_id,
                    &unit.locator,
                    unit.required_scope,
                    reason,
                )?);
            }
            PreScanScope::Inspect => {
                if unit.size > config.limits.max_file_bytes {
                    execution.units.push(SourceUnitRecord::uninspected(
                        &config.run_id,
                        &unit.locator,
                        unit.required_scope,
                        "FILE_SIZE_LIMIT",
                    )?);
                    continue;
                }
                if total_bytes.saturating_add(unit.size) > config.limits.max_total_bytes {
                    execution.units.push(SourceUnitRecord::uninspected(
                        &config.run_id,
                        &unit.locator,
                        unit.required_scope,
                        "TOTAL_BYTE_LIMIT",
                    )?);
                    continue;
                }
                let effective_mode = match config.mode {
                    ScanMode::Auto if unit.size > config.stream_threshold_bytes => ScanMode::Stream,
                    ScanMode::Auto => ScanMode::Whole,
                    mode => mode,
                };
                let file_config = ScanFileConfig {
                    mode: effective_mode,
                    stream_chunk_bytes: config.stream_chunk_bytes,
                    max_file_bytes: config.limits.max_file_bytes,
                    max_findings: config.limits.max_findings.saturating_sub(findings.len()),
                    deadline,
                };
                let unit_id = match crate::path::unit_id(crate::path::SOURCE_ID, &unit.locator) {
                    Ok(unit_id) => unit_id,
                    Err(_) => {
                        execution.units.push(SourceUnitRecord::uninspected(
                            &config.run_id,
                            &unit.locator,
                            unit.required_scope,
                            "NON_CANONICAL_PATH",
                        )?);
                        continue;
                    }
                };
                match scan_file(
                    &unit.path,
                    &unit_id,
                    &config.run_id,
                    rules,
                    &file_config,
                    unit.size,
                    unit.modified,
                ) {
                    Ok(result) => {
                        if total_bytes.saturating_add(result.bytes_read)
                            > config.limits.max_total_bytes
                        {
                            execution.units.push(SourceUnitRecord::uninspected(
                                &config.run_id,
                                &unit.locator,
                                unit.required_scope,
                                "TOTAL_BYTE_LIMIT",
                            )?);
                            continue;
                        }
                        total_bytes = total_bytes.saturating_add(result.bytes_read);
                        execution.units.push(SourceUnitRecord::inspected_with_hash(
                            &config.run_id,
                            &unit.locator,
                            unit.required_scope,
                            result.bytes_read,
                            result.line_count,
                            result.content_sha256,
                        )?);
                        findings.extend(result.findings);
                    }
                    Err(FileScanError::Timeout) => {
                        execution.units.push(SourceUnitRecord::uninspected(
                            &config.run_id,
                            &unit.locator,
                            unit.required_scope,
                            "TIMEOUT",
                        )?);
                        timed_out = true;
                        add_remaining_uninspected(&mut execution, &units[index + 1..], "TIMEOUT")?;
                        break;
                    }
                    Err(FileScanError::FindingsLimit) => {
                        execution.units.push(SourceUnitRecord::uninspected(
                            &config.run_id,
                            &unit.locator,
                            unit.required_scope,
                            "MAX_FINDINGS_EXCEEDED",
                        )?);
                        execution.add_fatal("MAX_FINDINGS_EXCEEDED");
                        add_remaining_uninspected(
                            &mut execution,
                            &units[index + 1..],
                            "MAX_FINDINGS_EXCEEDED",
                        )?;
                        break;
                    }
                    Err(error) => {
                        execution.units.push(SourceUnitRecord::uninspected(
                            &config.run_id,
                            &unit.locator,
                            unit.required_scope,
                            error.reason_code(),
                        )?);
                    }
                }
            }
        }
    }
    if timed_out && execution.state == ExecutionState::Completed {
        execution.state = ExecutionState::Interrupted;
        execution.evidence_valid = false;
        execution.add_failure("TIMEOUT");
    }
    if execution.state != ExecutionState::Completed {
        execution.evidence_valid = false;
    }
    execution
        .units
        .sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
    execution.failure_codes.sort();
    execution.fatal_errors.sort();
    sort_findings(&mut findings);
    warnings.sort();
    warnings.dedup();
    Ok(ScanReport {
        execution,
        findings,
        warnings,
    })
}

fn add_remaining_uninspected(
    execution: &mut ExecutionRecord,
    units: &[crate::input::DiscoveredUnit],
    reason: &str,
) -> Result<(), CoreError> {
    for unit in units {
        execution.units.push(SourceUnitRecord::uninspected(
            &execution.run_id,
            &unit.locator,
            unit.required_scope,
            reason,
        )?);
    }
    Ok(())
}
