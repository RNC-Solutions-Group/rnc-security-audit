//! CP1 scan orchestration: coverage accounting around the detection pipeline.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
    scan_content_diff, scan_content_profiled, scan_file_profiled, FileScanError, ScanContentConfig,
    ScanFileConfig, ScanMode,
};
use crate::structured::StructuredEvidence;

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

#[derive(Debug, Clone)]
pub struct ScanExecutionOptions {
    pub workers: usize,
    pub profiler: Option<Arc<crate::profile::Profiler>>,
}

impl Default for ScanExecutionOptions {
    fn default() -> Self {
        Self {
            workers: 1,
            profiler: None,
        }
    }
}

#[derive(Debug)]
pub struct ScanReport {
    pub execution: ExecutionRecord,
    pub findings: Vec<Finding>,
    pub structured_evidence: StructuredEvidence,
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
            "structured_evidence": self.structured_evidence,
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
                "history_mode": history.history_mode,
                "git_io": history.git_io,
                "context_lines": history.context_lines,
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
    scan_with_options(discovery, rules, config, &ScanExecutionOptions::default())
}

pub fn scan_with_options(
    discovery: Discovery,
    rules: &LoadedBundle,
    config: &RunConfig,
    options: &ScanExecutionOptions,
) -> Result<ScanReport, CoreError> {
    config.limits.validate()?;
    let workers = options.workers.max(1);
    if workers > 64 {
        return Err(CoreError::Input(
            "worker count must be between 1 and 64".to_string(),
        ));
    }
    if config.run_id.trim().is_empty() {
        return Err(CoreError::Input("run_id must be non-empty".to_string()));
    }
    let deadline = config.deadline.unwrap_or_else(|| {
        Instant::now()
            .checked_add(config.limits.timeout)
            .unwrap_or_else(Instant::now)
    });
    let plan_started = Instant::now();
    let plan = crate::backend::MatchPlan::new(rules, config.strategy)?;
    if let Some(profiler) = &options.profiler {
        profiler.record_wall("rules.plan", plan_started);
    }
    let profile = options.profiler.as_deref();
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
    let mut structured_evidence = StructuredEvidence::new();
    let mut warnings = discovery.warnings.clone();
    for code in &discovery.fatal_errors {
        execution.add_fatal(code);
    }
    let source_root = discovery.root;
    let units = discovery.units;
    let mut total_bytes = 0u64;
    let mut timed_out = false;
    let scan_started = Instant::now();
    if workers > 1 {
        timed_out = scan_parallel_units(
            &units,
            &source_root,
            git_source.as_ref(),
            &plan,
            config,
            workers,
            deadline,
            profile,
            &mut execution,
            &mut findings,
            &mut structured_evidence,
            &mut total_bytes,
        )?;
    } else {
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
                        if total_bytes.saturating_add(data.len() as u64)
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
                        let effective_mode = match config.mode {
                            ScanMode::Auto if data.len() as u64 > config.stream_threshold_bytes => {
                                ScanMode::Stream
                            }
                            ScanMode::Auto => ScanMode::Whole,
                            mode => mode,
                        };
                        let scan_config = ScanContentConfig {
                            mode: effective_mode,
                            stream_chunk_bytes: config.stream_chunk_bytes,
                            max_findings: config.limits.max_findings.saturating_sub(findings.len()),
                            deadline,
                        };
                        if let Some(diff) = &unit.git_diff {
                            scan_content_diff(
                                &data,
                                &unit.unit_id,
                                &config.run_id,
                                &plan,
                                &scan_config,
                                diff,
                                profile,
                            )
                        } else {
                            scan_content_profiled(
                                &data,
                                &unit.unit_id,
                                &config.run_id,
                                &plan,
                                &scan_config,
                                profile,
                            )
                        }
                    } else {
                        let effective_mode = match config.mode {
                            ScanMode::Auto if unit.size > config.stream_threshold_bytes => {
                                ScanMode::Stream
                            }
                            ScanMode::Auto => ScanMode::Whole,
                            mode => mode,
                        };
                        scan_file_profiled(
                            &source_root,
                            &unit.locator,
                            &unit.unit_id,
                            &config.run_id,
                            &plan,
                            &ScanFileConfig {
                                mode: effective_mode,
                                stream_chunk_bytes: config.stream_chunk_bytes,
                                max_file_bytes: config.limits.max_file_bytes,
                                max_findings: config
                                    .limits
                                    .max_findings
                                    .saturating_sub(findings.len()),
                                deadline,
                            },
                            unit.size,
                            unit.modified,
                            profile,
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
                            structured_evidence.components.extend(result.components);
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
                            add_remaining_uninspected(
                                &mut execution,
                                &units[index + 1..],
                                "TIMEOUT",
                            )?;
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
                        Err(FileScanError::Integrity(_)) => {
                            execution.units.push(SourceUnitRecord::uninspected_for(
                                &config.run_id,
                                source_id,
                                source_kind,
                                &unit.locator,
                                unit.required_scope,
                                "EVIDENCE_INTEGRITY",
                            )?);
                            execution.add_failure("EVIDENCE_INTEGRITY");
                            execution.state = ExecutionState::Interrupted;
                            execution.evidence_valid = false;
                            add_remaining_uninspected(
                                &mut execution,
                                &units[index + 1..],
                                "EVIDENCE_INTEGRITY",
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
    }
    if let Some(profiler) = &options.profiler {
        profiler.record_wall("scan", scan_started);
        profiler.add_counter("units_discovered", units.len() as u64);
        profiler.add_counter("findings", findings.len() as u64);
        profiler.add_counter("workers_effective", workers as u64);
        profiler.add_counter("bytes_inspected", total_bytes);
        profiler.add_counter("units_uninspected", execution.uninspected_count() as u64);
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
    structured_evidence.sort();
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
        structured_evidence,
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

#[allow(clippy::too_many_arguments)]
fn scan_unit(
    unit: &crate::input::DiscoveredUnit,
    source_root: &std::path::Path,
    git_source: Option<&crate::git::GitHistorySource>,
    plan: &crate::backend::MatchPlan<'_>,
    config: &RunConfig,
    deadline: Instant,
    max_findings: usize,
    profile: Option<&crate::profile::Profiler>,
) -> Result<crate::stream::ScanFileResult, FileScanError> {
    if let Some(git_ref) = &unit.git {
        let git_source = git_source.ok_or(FileScanError::GitObjectUnavailable)?;
        let data = git_source
            .read_blob(&git_ref.blob_oid, config.limits.max_file_bytes, deadline)
            .map_err(|error| match error {
                GitReadError::Timeout => FileScanError::Timeout,
                GitReadError::TooLarge => FileScanError::TooLarge,
                GitReadError::ObjectUnavailable => FileScanError::GitObjectUnavailable,
            })?;
        let effective_mode = match config.mode {
            ScanMode::Auto if data.len() as u64 > config.stream_threshold_bytes => ScanMode::Stream,
            ScanMode::Auto => ScanMode::Whole,
            mode => mode,
        };
        let scan_config = ScanContentConfig {
            mode: effective_mode,
            stream_chunk_bytes: config.stream_chunk_bytes,
            max_findings,
            deadline,
        };
        if let Some(diff) = &unit.git_diff {
            scan_content_diff(
                &data,
                &unit.unit_id,
                &config.run_id,
                plan,
                &scan_config,
                diff,
                profile,
            )
        } else {
            scan_content_profiled(
                &data,
                &unit.unit_id,
                &config.run_id,
                plan,
                &scan_config,
                profile,
            )
        }
    } else {
        let effective_mode = match config.mode {
            ScanMode::Auto if unit.size > config.stream_threshold_bytes => ScanMode::Stream,
            ScanMode::Auto => ScanMode::Whole,
            mode => mode,
        };
        scan_file_profiled(
            source_root,
            &unit.locator,
            &unit.unit_id,
            &config.run_id,
            plan,
            &ScanFileConfig {
                mode: effective_mode,
                stream_chunk_bytes: config.stream_chunk_bytes,
                max_file_bytes: config.limits.max_file_bytes,
                max_findings,
                deadline,
            },
            unit.size,
            unit.modified,
            profile,
        )
    }
}

enum BatchOutcome {
    Blocked,
    Skipped(&'static str),
    PreLimit(&'static str),
    Fatal(&'static str),
    Scanned(Option<Result<crate::stream::ScanFileResult, FileScanError>>),
}

#[allow(clippy::too_many_arguments)]
fn scan_parallel_units(
    units: &[crate::input::DiscoveredUnit],
    source_root: &Path,
    git_source: Option<&crate::git::GitHistorySource>,
    plan: &crate::backend::MatchPlan<'_>,
    config: &RunConfig,
    workers: usize,
    deadline: Instant,
    profile: Option<&crate::profile::Profiler>,
    execution: &mut ExecutionRecord,
    findings: &mut Vec<Finding>,
    structured_evidence: &mut StructuredEvidence,
    total_bytes: &mut u64,
) -> Result<bool, CoreError> {
    let batch_size = workers.saturating_mul(4).clamp(workers.max(1), 64);
    let mut index = 0usize;
    while index < units.len() {
        if Instant::now() >= deadline {
            add_remaining_uninspected(execution, &units[index..], "TIMEOUT")?;
            return Ok(true);
        }
        let end = index.saturating_add(batch_size).min(units.len());
        let batch = &units[index..end];
        let mut outcomes: Vec<BatchOutcome> = Vec::with_capacity(batch.len());
        let mut scan_jobs: Vec<usize> = Vec::new();
        for (local, unit) in batch.iter().enumerate() {
            match unit.scope {
                PreScanScope::Blocked => outcomes.push(BatchOutcome::Blocked),
                PreScanScope::Skipped(reason) => outcomes.push(BatchOutcome::Skipped(reason)),
                PreScanScope::Inspect => {
                    if unit.unit_id.is_empty() {
                        outcomes.push(BatchOutcome::PreLimit("NON_CANONICAL_PATH"));
                    } else if unit.size > config.limits.max_file_bytes {
                        outcomes.push(BatchOutcome::PreLimit("FILE_SIZE_LIMIT"));
                    } else if unit.git.is_some() && git_source.is_none() {
                        outcomes.push(BatchOutcome::Fatal("GIT_SOURCE_UNAVAILABLE"));
                    } else {
                        outcomes.push(BatchOutcome::Scanned(None));
                        scan_jobs.push(local);
                    }
                }
            }
        }

        if !scan_jobs.is_empty() {
            let results: Mutex<Vec<Option<Result<crate::stream::ScanFileResult, FileScanError>>>> =
                Mutex::new((0..batch.len()).map(|_| None).collect());
            let cursor = AtomicUsize::new(0);
            let worker_count = workers.min(scan_jobs.len()).max(1);
            let dispatch_started = Instant::now();
            std::thread::scope(|scope| {
                for _ in 0..worker_count {
                    let results = &results;
                    let cursor = &cursor;
                    let scan_jobs = &scan_jobs;
                    scope.spawn(move || {
                        if let Some(profiler) = profile {
                            profiler.record_worker(
                                "scheduling.queue_wait",
                                dispatch_started.elapsed(),
                                0,
                                1,
                            );
                        }
                        let busy_started = Instant::now();
                        loop {
                            let position = cursor.fetch_add(1, Ordering::Relaxed);
                            if position >= scan_jobs.len() {
                                break;
                            }
                            let local = scan_jobs[position];
                            let unit = &batch[local];
                            let result = scan_unit(
                                unit,
                                source_root,
                                git_source,
                                plan,
                                config,
                                deadline,
                                config.limits.max_findings,
                                profile,
                            );
                            let mut slot = results
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            slot[local] = Some(result);
                        }
                        if let Some(profiler) = profile {
                            profiler.record_worker(
                                "scheduling.worker_busy",
                                busy_started.elapsed(),
                                0,
                                1,
                            );
                        }
                    });
                }
            });
            let mut results = results
                .into_inner()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            for (local, outcome) in outcomes.iter_mut().enumerate() {
                if let BatchOutcome::Scanned(slot) = outcome {
                    *slot = results[local].take();
                }
            }
        }

        for (local, outcome) in outcomes.into_iter().enumerate() {
            let absolute_index = index + local;
            let unit = &batch[local];
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
            match outcome {
                BatchOutcome::Blocked => {
                    execution.units.push(SourceUnitRecord::blocked_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        "PRE_SCAN_BLOCKED",
                    )?);
                }
                BatchOutcome::Skipped(reason) | BatchOutcome::PreLimit(reason) => {
                    execution.units.push(SourceUnitRecord::uninspected_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        reason,
                    )?);
                }
                BatchOutcome::Fatal(reason) => {
                    execution.units.push(SourceUnitRecord::uninspected_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        reason,
                    )?);
                    execution.add_fatal(reason);
                }
                BatchOutcome::Scanned(Some(Ok(result))) => {
                    if total_bytes.saturating_add(result.bytes_read) > config.limits.max_total_bytes
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
                    if findings.len().saturating_add(result.findings.len())
                        > config.limits.max_findings
                    {
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
                            execution,
                            &units[absolute_index + 1..],
                            "MAX_FINDINGS_EXCEEDED",
                        )?;
                        return Ok(false);
                    }
                    *total_bytes = total_bytes.saturating_add(result.bytes_read);
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
                    structured_evidence.components.extend(result.components);
                    findings.extend(result.findings);
                }
                BatchOutcome::Scanned(Some(Err(FileScanError::Timeout))) => {
                    execution.units.push(SourceUnitRecord::uninspected_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        "TIMEOUT",
                    )?);
                    add_remaining_uninspected(execution, &units[absolute_index + 1..], "TIMEOUT")?;
                    return Ok(true);
                }
                BatchOutcome::Scanned(Some(Err(FileScanError::FindingsLimit))) => {
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
                        execution,
                        &units[absolute_index + 1..],
                        "MAX_FINDINGS_EXCEEDED",
                    )?;
                    return Ok(false);
                }
                BatchOutcome::Scanned(Some(Err(FileScanError::CandidateLimit))) => {
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
                        execution,
                        &units[absolute_index + 1..],
                        "CANDIDATE_LIMIT",
                    )?;
                    return Ok(false);
                }
                BatchOutcome::Scanned(Some(Err(FileScanError::Integrity(_)))) => {
                    execution.units.push(SourceUnitRecord::uninspected_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        "EVIDENCE_INTEGRITY",
                    )?);
                    execution.add_failure("EVIDENCE_INTEGRITY");
                    execution.state = ExecutionState::Interrupted;
                    execution.evidence_valid = false;
                    add_remaining_uninspected(
                        execution,
                        &units[absolute_index + 1..],
                        "EVIDENCE_INTEGRITY",
                    )?;
                    return Ok(false);
                }
                BatchOutcome::Scanned(Some(Err(error))) => {
                    let reason = error.reason_code();
                    execution.units.push(SourceUnitRecord::uninspected_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        reason,
                    )?);
                    if matches!(error, FileScanError::GitObjectUnavailable) {
                        execution.add_fatal("GIT_OBJECT_UNAVAILABLE");
                    }
                }
                BatchOutcome::Scanned(None) => {
                    execution.units.push(SourceUnitRecord::uninspected_for(
                        &config.run_id,
                        source_id,
                        source_kind,
                        &unit.locator,
                        unit.required_scope,
                        "EVIDENCE_INTEGRITY",
                    )?);
                    execution.add_failure("EVIDENCE_INTEGRITY");
                    execution.state = ExecutionState::Interrupted;
                    execution.evidence_valid = false;
                    return Ok(false);
                }
            }
        }
        index = end;
    }
    Ok(false)
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
