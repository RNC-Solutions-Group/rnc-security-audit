//! Finalized five-state result and independent CI acceptance decision.

use serde::{Deserialize, Serialize};

use crate::coverage::{ExecutionRecord, ExecutionState, SCHEMA_VERSION};
use crate::error::CoreError;
use crate::finding::Finding;
use crate::policy::{digest_canonical, PolicyRecord};

pub const RESULT_CLEAN: u8 = 1;
pub const RESULT_POLICY_APPLIED: u8 = 2;
pub const RESULT_ACTIONABLE: u8 = 3;
pub const RESULT_INCOMPLETE: u8 = 4;
pub const RESULT_FAILED: u8 = 5;
pub const EXIT_REJECTED: i32 = 10;
pub const EXIT_INCOMPLETE: i32 = 20;
pub const EXIT_FAILED: i32 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Counts {
    pub discovered: usize,
    pub inspected: usize,
    pub verified_blocked: usize,
    pub uninspected: usize,
    pub required_discovered: usize,
    pub required_inspected: usize,
    pub required_verified_blocked: usize,
    pub required_uninspected: usize,
    pub detected: usize,
    pub actionable: usize,
    pub exempted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordDigests {
    pub execution_digest: String,
    pub findings_digest: String,
    pub policy_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultRecord {
    pub schema_version: String,
    pub run_id: String,
    pub result_code: u8,
    pub result: String,
    pub coverage: String,
    pub evidence_valid: bool,
    pub engine_version: String,
    pub ruleset_id: String,
    pub ruleset_digest: String,
    pub source_adapter: crate::coverage::SourceAdapter,
    pub counts: Counts,
    pub reason_codes: Vec<String>,
    pub records: RecordDigests,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiDecision {
    pub schema_version: String,
    pub run_id: String,
    pub result_code: u8,
    pub result_digest: String,
    pub accepted_result_codes: Vec<u8>,
    pub accepted: bool,
    pub process_exit_code: i32,
}

pub fn compute_counts(
    execution: &ExecutionRecord,
    findings: &[Finding],
    policy: &PolicyRecord,
) -> Counts {
    let required: Vec<_> = execution
        .units
        .iter()
        .filter(|unit| unit.required_scope)
        .collect();
    Counts {
        discovered: execution.units.len(),
        inspected: execution.inspected_count(),
        verified_blocked: execution.blocked_count(),
        uninspected: execution.uninspected_count(),
        required_discovered: required.len(),
        required_inspected: required
            .iter()
            .filter(|unit| unit.disposition == "INSPECTED")
            .count(),
        required_verified_blocked: required
            .iter()
            .filter(|unit| unit.disposition == "VERIFIED_BLOCKED")
            .count(),
        required_uninspected: required
            .iter()
            .filter(|unit| unit.disposition == "UNINSPECTED")
            .count(),
        detected: findings.len(),
        actionable: policy
            .dispositions
            .iter()
            .filter(|entry| entry.status == "ACTIONABLE")
            .count(),
        exempted: policy
            .dispositions
            .iter()
            .filter(|entry| entry.status == "EXEMPTED")
            .count(),
    }
}

pub fn classify(execution: &ExecutionRecord, policy: &PolicyRecord, counts: &Counts) -> u8 {
    if !policy.policy_valid
        || execution.state != ExecutionState::Completed
        || !execution.fatal_errors.is_empty()
    {
        return RESULT_FAILED;
    }
    if counts.required_discovered == 0 {
        return RESULT_INCOMPLETE;
    }
    if counts.required_uninspected > 0 || !execution.evidence_valid {
        return RESULT_INCOMPLETE;
    }
    if counts.actionable > 0 {
        return RESULT_ACTIONABLE;
    }
    if counts.verified_blocked > 0 || counts.exempted > 0 {
        return RESULT_POLICY_APPLIED;
    }
    RESULT_CLEAN
}

pub fn coverage_for(code: u8, counts: &Counts) -> &'static str {
    if code == RESULT_FAILED {
        return "UNVERIFIED";
    }
    if code == RESULT_INCOMPLETE {
        return if counts.required_inspected + counts.required_verified_blocked == 0 {
            "NONE"
        } else {
            "PARTIAL"
        };
    }
    if counts.verified_blocked > 0 || counts.exempted > 0 {
        return "COMPLETE_POLICY_ADJUSTED";
    }
    "COMPLETE"
}

pub fn reason_codes_for(
    execution: &ExecutionRecord,
    policy: &PolicyRecord,
    counts: &Counts,
    code: u8,
) -> Vec<String> {
    if code == RESULT_FAILED {
        let mut values = if !execution.failure_codes.is_empty() {
            execution.failure_codes.clone()
        } else if let Some(errors) = &policy.errors {
            errors.clone()
        } else {
            vec!["EXECUTION_FAILURE".to_string()]
        };
        values.sort();
        values.dedup();
        return values;
    }
    if code == RESULT_INCOMPLETE {
        if counts.required_discovered == 0 {
            return vec!["NO_REQUIRED_SCOPE".to_string()];
        }
        if counts.required_uninspected > 0 {
            return vec!["REQUIRED_COVERAGE_INCOMPLETE".to_string()];
        }
        return vec!["EVIDENCE_UNVERIFIED".to_string()];
    }
    Vec::new()
}

pub fn result_name(code: u8) -> &'static str {
    match code {
        RESULT_CLEAN => "CLEAN",
        RESULT_POLICY_APPLIED => "POLICY_APPLIED",
        RESULT_ACTIONABLE => "ACTIONABLE",
        RESULT_INCOMPLETE => "INCOMPLETE",
        RESULT_FAILED => "FAILED",
        _ => "FAILED",
    }
}

pub fn build_result(
    execution: &ExecutionRecord,
    findings: &[Finding],
    policy: &PolicyRecord,
) -> Result<ResultRecord, CoreError> {
    validate_ledger_links(execution, findings, policy)?;
    let counts = compute_counts(execution, findings, policy);
    let code = classify(execution, policy, &counts);
    let mut reason_codes = reason_codes_for(execution, policy, &counts, code);
    reason_codes.sort();
    reason_codes.dedup();
    Ok(ResultRecord {
        schema_version: SCHEMA_VERSION.to_string(),
        run_id: execution.run_id.clone(),
        result_code: code,
        result: result_name(code).to_string(),
        coverage: coverage_for(code, &counts).to_string(),
        evidence_valid: execution.evidence_valid,
        engine_version: execution.engine_version.clone(),
        ruleset_id: execution.ruleset_id.clone(),
        ruleset_digest: execution.ruleset_digest.clone(),
        source_adapter: execution.source_adapter.clone(),
        counts,
        reason_codes,
        records: RecordDigests {
            execution_digest: digest_canonical(execution)?,
            findings_digest: digest_canonical(findings)?,
            policy_digest: digest_canonical(policy)?,
        },
    })
}

pub fn ci_decision(
    result: &ResultRecord,
    accepted_result_codes: &[u8],
) -> Result<CiDecision, CoreError> {
    let mut accepted = accepted_result_codes.to_vec();
    if accepted.is_empty() || accepted.iter().any(|code| !matches!(code, 1..=3)) {
        return Err(CoreError::Input(
            "accepted result codes must be a non-empty subset of 1,2,3".to_string(),
        ));
    }
    accepted.sort_unstable();
    accepted.dedup();
    let process_exit_code = match result.result_code {
        RESULT_INCOMPLETE => EXIT_INCOMPLETE,
        RESULT_FAILED => EXIT_FAILED,
        code => {
            if accepted.contains(&code) {
                0
            } else {
                EXIT_REJECTED
            }
        }
    };
    Ok(CiDecision {
        schema_version: SCHEMA_VERSION.to_string(),
        run_id: result.run_id.clone(),
        result_code: result.result_code,
        result_digest: digest_canonical(result)?,
        accepted_result_codes: accepted,
        accepted: process_exit_code == 0,
        process_exit_code,
    })
}

pub fn validate_ledger_links(
    execution: &ExecutionRecord,
    findings: &[Finding],
    policy: &PolicyRecord,
) -> Result<(), CoreError> {
    if policy.run_id != execution.run_id
        || findings
            .iter()
            .any(|finding| finding.run_id != execution.run_id)
    {
        return Err(CoreError::Input("ledger run IDs do not match".to_string()));
    }
    let unit_ids: std::collections::BTreeSet<&str> = execution
        .units
        .iter()
        .map(|unit| unit.unit_id.as_str())
        .collect();
    if unit_ids.len() != execution.units.len() {
        return Err(CoreError::Input("duplicate execution unit".to_string()));
    }
    if findings
        .iter()
        .any(|finding| !unit_ids.contains(finding.unit_id.as_str()))
    {
        return Err(CoreError::Input(
            "finding references an unknown unit".to_string(),
        ));
    }
    let finding_ids: std::collections::BTreeSet<&str> = findings
        .iter()
        .map(|finding| finding.finding_id.as_str())
        .collect();
    if finding_ids.len() != findings.len() {
        return Err(CoreError::Input("duplicate finding".to_string()));
    }
    let disposition_ids: std::collections::BTreeSet<&str> = policy
        .dispositions
        .iter()
        .map(|entry| entry.finding_id.as_str())
        .collect();
    if disposition_ids.len() != policy.dispositions.len() || disposition_ids != finding_ids {
        return Err(CoreError::Input(
            "findings and dispositions do not reconcile".to_string(),
        ));
    }
    let blocked_units: std::collections::BTreeSet<&str> = execution
        .units
        .iter()
        .filter(|unit| unit.disposition == "VERIFIED_BLOCKED")
        .map(|unit| unit.unit_id.as_str())
        .collect();
    let applied_units: std::collections::BTreeSet<&str> = policy
        .applied_blocks
        .iter()
        .map(|entry| entry.unit_id.as_str())
        .collect();
    if blocked_units != applied_units {
        return Err(CoreError::Input(
            "verified blocks and applied block evidence do not reconcile".to_string(),
        ));
    }
    if policy
        .applied_blocks
        .iter()
        .any(|entry| !entry.verified_non_access)
    {
        return Err(CoreError::Input(
            "a block lacks verified non-access evidence".to_string(),
        ));
    }
    let counts = compute_counts(execution, findings, policy);
    if counts.discovered != counts.inspected + counts.verified_blocked + counts.uninspected
        || counts.required_discovered
            != counts.required_inspected
                + counts.required_verified_blocked
                + counts.required_uninspected
        || counts.detected != counts.actionable + counts.exempted
    {
        return Err(CoreError::Input(
            "ledger accounting equations do not reconcile".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence_is_failed_incomplete_actionable_policy_clean() {
        let mut execution = ExecutionRecord::new(
            "r",
            &crate::rules::LoadedBundle::load(
                &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../rules/rnc-synthetic-v0.json"),
            )
            .unwrap(),
        );
        let policy = PolicyRecord {
            schema_version: SCHEMA_VERSION.to_string(),
            run_id: "r".to_string(),
            policy_valid: true,
            errors: None,
            effective_policy_digest: digest_canonical(&Vec::<String>::new()).unwrap(),
            effective_policies: Vec::new(),
            requests: Vec::new(),
            applied_blocks: Vec::new(),
            dispositions: Vec::new(),
        };
        let counts = Counts {
            discovered: 0,
            inspected: 0,
            verified_blocked: 0,
            uninspected: 0,
            required_discovered: 0,
            required_inspected: 0,
            required_verified_blocked: 0,
            required_uninspected: 0,
            detected: 0,
            actionable: 0,
            exempted: 0,
        };
        assert_eq!(classify(&execution, &policy, &counts), RESULT_INCOMPLETE);
        execution.state = ExecutionState::Interrupted;
        assert_eq!(classify(&execution, &policy, &counts), RESULT_FAILED);
    }

    #[test]
    fn classifier_covers_all_five_results_and_ci_exit_semantics() {
        let bundle = crate::rules::LoadedBundle::load(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../rules/rnc-synthetic-v0.json"),
        )
        .unwrap();
        let mut execution = ExecutionRecord::new("r", &bundle);
        let policy = PolicyRecord {
            schema_version: SCHEMA_VERSION.to_string(),
            run_id: "r".to_string(),
            policy_valid: true,
            errors: None,
            effective_policy_digest: digest_canonical(&Vec::<String>::new()).unwrap(),
            effective_policies: Vec::new(),
            requests: Vec::new(),
            applied_blocks: Vec::new(),
            dispositions: Vec::new(),
        };
        let mut counts = Counts {
            discovered: 1,
            inspected: 1,
            verified_blocked: 0,
            uninspected: 0,
            required_discovered: 1,
            required_inspected: 1,
            required_verified_blocked: 0,
            required_uninspected: 0,
            detected: 0,
            actionable: 0,
            exempted: 0,
        };
        assert_eq!(classify(&execution, &policy, &counts), RESULT_CLEAN);
        assert_eq!(coverage_for(RESULT_CLEAN, &counts), "COMPLETE");
        counts.actionable = 1;
        assert_eq!(classify(&execution, &policy, &counts), RESULT_ACTIONABLE);
        counts.actionable = 0;
        counts.exempted = 1;
        assert_eq!(
            classify(&execution, &policy, &counts),
            RESULT_POLICY_APPLIED
        );
        counts.exempted = 0;
        counts.required_uninspected = 1;
        assert_eq!(classify(&execution, &policy, &counts), RESULT_INCOMPLETE);
        execution.state = ExecutionState::Interrupted;
        assert_eq!(classify(&execution, &policy, &counts), RESULT_FAILED);
        let mut result = ResultRecord {
            schema_version: SCHEMA_VERSION.to_string(),
            run_id: "r".to_string(),
            result_code: RESULT_POLICY_APPLIED,
            result: "POLICY_APPLIED".to_string(),
            coverage: "COMPLETE_POLICY_ADJUSTED".to_string(),
            evidence_valid: true,
            engine_version: "0".to_string(),
            ruleset_id: "r".to_string(),
            ruleset_digest: "sha256:".to_string() + &"0".repeat(64),
            source_adapter: crate::coverage::SourceAdapter::default(),
            counts,
            reason_codes: Vec::new(),
            records: RecordDigests {
                execution_digest: "sha256:".to_string() + &"0".repeat(64),
                findings_digest: "sha256:".to_string() + &"0".repeat(64),
                policy_digest: "sha256:".to_string() + &"0".repeat(64),
            },
        };
        assert_eq!(ci_decision(&result, &[1, 2]).unwrap().process_exit_code, 0);
        assert_eq!(
            ci_decision(&result, &[1]).unwrap().process_exit_code,
            EXIT_REJECTED
        );
        result.result_code = RESULT_INCOMPLETE;
        assert_eq!(
            ci_decision(&result, &[1, 2, 3]).unwrap().process_exit_code,
            EXIT_INCOMPLETE
        );
        result.result_code = RESULT_FAILED;
        assert_eq!(
            ci_decision(&result, &[1, 2, 3]).unwrap().process_exit_code,
            EXIT_FAILED
        );
    }
}
