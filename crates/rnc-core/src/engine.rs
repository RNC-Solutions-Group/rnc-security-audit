//! CP1 scan orchestration: coverage accounting around the detection pipeline.

use std::time::Instant;

use crate::coverage::{
    ExecutionRecord, ExecutionState, SourceUnitRecord, ENGINE_VERSION, SCHEMA_VERSION,
};
use crate::error::CoreError;
use crate::finding::{sort_findings, Finding};
use crate::git::GitReadError;
use crate::input::{Discovery, GitHistoryInfo, PreScanScope, ScanLimits};
use crate::rules::LoadedBundle;
use crate::stream::{
    scan_content, scan_file, FileScanError, ScanContentConfig, ScanFileConfig, ScanMode,
};

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub run_id: String,
    pub limits: ScanLimits,
    pub mode: ScanMode,
    pub stream_threshold_bytes: u64,
    pub stream_chunk_bytes: usize,
    pub strategy: crate::backend::BackendRequest,
    pub policy: crate::policy::PolicySpec,
    pub accepted_result_codes: Vec<u8>,
    pub config_source: String,
    pub config_provenance: std::collections::BTreeMap<String, String>,
    pub deadline: Option<Instant>,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            run_id: "rnc-run".to_string(),
            limits: ScanLimits::default(),
            mode: ScanMode::Auto,
            stream_threshold_bytes: 1024 * 1024,
            stream_chunk_bytes: crate::input::DEFAULT_STREAM_CHUNK_BYTES,
            strategy: crate::backend::BackendRequest::Auto,
            policy: crate::policy::PolicySpec::empty(),
            accepted_result_codes: vec![1, 2],
            config_source: "defaults".to_string(),
            config_provenance: std::collections::BTreeMap::new(),
            deadline: None,
        }
    }
}

#[derive(Debug)]
pub struct ScanReport {
    pub execution: ExecutionRecord,
    pub findings: Vec<Finding>,
    pub policy: crate::policy::PolicyRecord,
    pub result: crate::result::ResultRecord,
    pub ci: crate::result::CiDecision,
    pub plan: crate::backend::PlanProvenance,
    pub configuration: ConfigurationInfo,
    pub history: Option<GitHistoryInfo>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigurationInfo {
    pub source: String,
    pub provenance: std::collections::BTreeMap<String, String>,
    pub accepted_result_codes: Vec<u8>,
}

impl ScanReport {
    /// Private evidence bundle. The three ledgers are the v0.2 records; the
    /// execution plan and effective policy are additive private metadata.
    pub fn private_value(&self) -> Result<serde_json::Value, CoreError> {
        Ok(serde_json::json!({
            "format_version": "rnc-cp2-output-v1",
            "execution": self.execution,
            "findings": self.findings,
            "policy": self.policy,
            "result": self.result,
            "ci": self.ci,
            "execution_plan": self.plan,
            "configuration": self.configuration,
            "history": self.history,
        }))
    }

    /// CP1-compatible alias. The document remains private.
    pub fn to_json_value(&self) -> Result<serde_json::Value, CoreError> {
        self.private_value()
    }

    /// Sanitized machine-readable summary. It contains no locators, finding
    /// identifiers, evidence digests, policy selectors or raw matched bytes.
    pub fn sanitized_value(&self) -> serde_json::Value {
        let history = self.history.as_ref().map(|history| {
            serde_json::json!({
                "scope": history.scope,
                "commits": history.commits,
                "changed_paths": history.changed_paths,
                "deleted_paths": history.deleted_paths,
                "units": history.units_seen,
            })
        });
        serde_json::json!({
            "format_version": "rnc-cp2-sanitized-v1",
            "engine_version": self.result.engine_version,
            "ruleset_id": self.result.ruleset_id,
            "ruleset_digest": self.result.ruleset_digest,
            "result_code": self.result.result_code,
            "result": self.result.result,
            "coverage": self.result.coverage,
            "evidence_valid": self.result.evidence_valid,
            "counts": self.result.counts,
            "reason_codes": self.result.reason_codes,
            "accepted_result_codes": self.ci.accepted_result_codes,
            "accepted": self.ci.accepted,
            "process_exit_code": self.ci.process_exit_code,
            "history": history,
        })
    }

    pub fn summary(&self) -> String {
        let execution = &self.execution;
        let history = self
            .history
            .as_ref()
            .map(|history| {
                format!(
                    "History: {} commits, {} changed paths, {} deletions, {} revisions ({})\n",
                    history.commits,
                    history.changed_paths,
                    history.deleted_paths,
                    history.units_seen,
                    history.scope
                )
            })
            .unwrap_or_default();
        format!(
            "RNC Scanner {ENGINE_VERSION}\n\
             Schema: {SCHEMA_VERSION}\n\
             Run: {}\n\
             Source: {}\n\
             Execution: {}\n\
             {history}\
             Ruleset: {} ({})\n\
             Backend: {} (requested {})\n\
             Inspected: {} (blocked {}, uninspected {}, required uninspected {})\n\
             Findings: {} (actionable {}, exempted {})\n\
             Result: {} ({}), coverage {}\n\
             CI accepted: {} (exit {})\n",
            execution.run_id,
            execution.source_adapter.id,
            execution.state.as_str(),
            execution.ruleset_id,
            execution.ruleset_digest,
            self.plan.effective.as_str(),
            self.plan.requested.as_str(),
            execution.inspected_count(),
            execution.blocked_count(),
            execution.uninspected_count(),
            execution.required_uninspected_count(),
            self.findings.len(),
            self.result.counts.actionable,
            self.result.counts.exempted,
            self.result.result,
            self.result.result_code,
            self.result.coverage,
            self.ci.accepted,
            self.ci.process_exit_code
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
    let deadline = config.deadline.unwrap_or_else(|| {
        Instant::now()
            .checked_add(config.limits.timeout)
            .unwrap_or_else(Instant::now)
    });
    let plan = crate::backend::MatchPlan::new(rules, config.strategy)?;
    let mut execution = ExecutionRecord::new(&config.run_id, rules);
    if !discovery.source_adapter_id.is_empty() {
        execution.source_adapter = crate::coverage::SourceAdapter::new(
            &discovery.source_adapter_id,
            &discovery.source_adapter_version,
        );
    }
    let history = discovery.git_history.clone();
    let git_source = discovery.git_source.clone();
    let mut findings = Vec::new();
    let mut warnings = discovery.warnings.clone();
    for code in &discovery.fatal_errors {
        execution.add_fatal(code);
    }
    let source_root = discovery.root;
    let units = discovery.units;
    let mut total_bytes = 0u64;
    let mut timed_out = false;
    for (index, unit) in units.iter().enumerate() {
        if Instant::now() >= deadline {
            timed_out = true;
            add_remaining_uninspected(&mut execution, &units[index..], "TIMEOUT")?;
            break;
        }
        let source_id = if unit.source_id.is_empty() {
            crate::path::SOURCE_ID
        } else {
            unit.source_id.as_str()
        };
        let source_kind = if unit.source_kind.is_empty() {
            "working_tree_file"
        } else {
            unit.source_kind.as_str()
        };
        match unit.scope {
            PreScanScope::Blocked => {
                execution.units.push(SourceUnitRecord::blocked_for(
                    &config.run_id,
                    source_id,
                    source_kind,
                    &unit.locator,
                    unit.required_scope,
                    "PRE_SCAN_BLOCKED",
                )?);
            }
            PreScanScope::Skipped(reason) => {
                execution.units.push(SourceUnitRecord::uninspected_for(
                    &config.run_id,
                    source_id,
                    source_kind,
                    &unit.locator,
                    unit.required_scope,
                    reason,
                )?);
            }
            PreScanScope::Inspect => {
                if unit.size > config.limits.max_file_bytes {
                    execution.units.push(SourceUnitRecord::uninspected_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        "FILE_SIZE_LIMIT",
                    )?);
                    continue;
                }
                if total_bytes.saturating_add(unit.size) > config.limits.max_total_bytes {
                    execution.units.push(SourceUnitRecord::uninspected_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        "TOTAL_BYTE_LIMIT",
                    )?);
                    continue;
                }
                if unit.unit_id.is_empty() {
                    execution.units.push(SourceUnitRecord::uninspected_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        "NON_CANONICAL_PATH",
                    )?);
                    continue;
                }
                let result = if let Some(git_ref) = &unit.git {
                    let Some(git_source) = git_source.as_ref() else {
                        execution.units.push(SourceUnitRecord::uninspected_for(
                            &config.run_id,
                            source_id,
                            source_kind,
                            &unit.locator,
                            unit.required_scope,
                            "GIT_SOURCE_UNAVAILABLE",
                        )?);
                        execution.add_fatal("GIT_SOURCE_UNAVAILABLE");
                        continue;
                    };
                    let data = match git_source.read_blob(
                        &git_ref.blob_oid,
                        config.limits.max_file_bytes,
                        deadline,
                    ) {
                        Ok(data) => data,
                        Err(GitReadError::Timeout) => {
                            execution.units.push(SourceUnitRecord::uninspected_for(
                                &config.run_id,
                                source_id,
                                source_kind,
                                &unit.locator,
                                unit.required_scope,
                                "TIMEOUT",
                            )?);
                            timed_out = true;
                            add_remaining_uninspected(
                                &mut execution,
                                &units[index + 1..],
                                "TIMEOUT",
                            )?;
                            break;
                        }
                        Err(error) => {
                            execution.units.push(SourceUnitRecord::uninspected_for(
                                &config.run_id,
                                source_id,
                                source_kind,
                                &unit.locator,
                                unit.required_scope,
                                error.reason_code(),
                            )?);
                            if matches!(error, GitReadError::ObjectUnavailable) {
                                execution.add_fatal("GIT_OBJECT_UNAVAILABLE");
                            }
                            continue;
                        }
                    };
                    if total_bytes.saturating_add(data.len() as u64) > config.limits.max_total_bytes
                    {
                        execution.units.push(SourceUnitRecord::uninspected_for(
                            &config.run_id,
                            source_id,
                            source_kind,
                            &unit.locator,
                            unit.required_scope,
                            "TOTAL_BYTE_LIMIT",
                        )?);
                        continue;
                    }
                    let effective_mode = match config.mode {
                        ScanMode::Auto if data.len() as u64 > config.stream_threshold_bytes => {
                            ScanMode::Stream
                        }
                        ScanMode::Auto => ScanMode::Whole,
                        mode => mode,
                    };
                    scan_content(
                        &data,
                        &unit.unit_id,
                        &config.run_id,
                        &plan,
                        &ScanContentConfig {
                            mode: effective_mode,
                            stream_chunk_bytes: config.stream_chunk_bytes,
                            max_findings: config.limits.max_findings.saturating_sub(findings.len()),
                            deadline,
                        },
                    )
                } else {
                    let effective_mode = match config.mode {
                        ScanMode::Auto if unit.size > config.stream_threshold_bytes => {
                            ScanMode::Stream
                        }
                        ScanMode::Auto => ScanMode::Whole,
                        mode => mode,
                    };
                    scan_file(
                        &source_root,
                        &unit.locator,
                        &unit.unit_id,
                        &config.run_id,
                        &plan,
                        &ScanFileConfig {
                            mode: effective_mode,
                            stream_chunk_bytes: config.stream_chunk_bytes,
                            max_file_bytes: config.limits.max_file_bytes,
                            max_findings: config.limits.max_findings.saturating_sub(findings.len()),
                            deadline,
                        },
                        unit.size,
                        unit.modified,
                    )
                };
                match result {
                    Ok(result) => {
                        if total_bytes.saturating_add(result.bytes_read)
                            > config.limits.max_total_bytes
                        {
                            execution.units.push(SourceUnitRecord::uninspected_for(
                                &config.run_id,
                                source_id,
                                source_kind,
                                &unit.locator,
                                unit.required_scope,
                                "TOTAL_BYTE_LIMIT",
                            )?);
                            continue;
                        }
                        total_bytes = total_bytes.saturating_add(result.bytes_read);
                        execution
                            .units
                            .push(SourceUnitRecord::inspected_with_hash_for(
                                &config.run_id,
                                source_id,
                                source_kind,
                                &unit.locator,
                                unit.required_scope,
                                result.bytes_read,
                                result.line_count,
                                result.content_sha256,
                            )?);
                        findings.extend(result.findings);
                    }
                    Err(FileScanError::Timeout) => {
                        execution.units.push(SourceUnitRecord::uninspected_for(
                            &config.run_id,
                            source_id,
                            source_kind,
                            &unit.locator,
                            unit.required_scope,
                            "TIMEOUT",
                        )?);
                        timed_out = true;
                        add_remaining_uninspected(&mut execution, &units[index + 1..], "TIMEOUT")?;
                        break;
                    }
                    Err(FileScanError::FindingsLimit) => {
                        execution.units.push(SourceUnitRecord::uninspected_for(
                            &config.run_id,
                            source_id,
                            source_kind,
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
                    Err(FileScanError::CandidateLimit) => {
                        execution.units.push(SourceUnitRecord::uninspected_for(
                            &config.run_id,
                            source_id,
                            source_kind,
                            &unit.locator,
                            unit.required_scope,
                            "CANDIDATE_LIMIT",
                        )?);
                        execution.add_failure("CANDIDATE_LIMIT");
                        execution.state = ExecutionState::Interrupted;
                        execution.evidence_valid = false;
                        add_remaining_uninspected(
                            &mut execution,
                            &units[index + 1..],
                            "CANDIDATE_LIMIT",
                        )?;
                        break;
                    }
                    Err(error) => {
                        execution.units.push(SourceUnitRecord::uninspected_for(
                            &config.run_id,
                            source_id,
                            source_kind,
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
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let policy =
        crate::policy::build_policy(&config.run_id, &units, &findings, &config.policy, now_unix)?;
    let result = crate::result::build_result(&execution, &findings, &policy)?;
    let ci = crate::result::ci_decision(&result, &config.accepted_result_codes)?;
    Ok(ScanReport {
        execution,
        findings,
        policy,
        result,
        ci,
        plan: plan.provenance().clone(),
        configuration: ConfigurationInfo {
            source: config.config_source.clone(),
            provenance: config.config_provenance.clone(),
            accepted_result_codes: config.accepted_result_codes.clone(),
        },
        history,
        warnings,
    })
}

fn add_remaining_uninspected(
    execution: &mut ExecutionRecord,
    units: &[crate::input::DiscoveredUnit],
    reason: &str,
) -> Result<(), CoreError> {
    for unit in units {
        let source_id = if unit.source_id.is_empty() {
            crate::path::SOURCE_ID
        } else {
            unit.source_id.as_str()
        };
        let source_kind = if unit.source_kind.is_empty() {
            "working_tree_file"
        } else {
            unit.source_kind.as_str()
        };
        execution.units.push(SourceUnitRecord::uninspected_for(
            &execution.run_id,
            source_id,
            source_kind,
            &unit.locator,
            unit.required_scope,
            reason,
        )?);
    }
    Ok(())
}
