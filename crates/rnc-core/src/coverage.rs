//! Execution and coverage records conforming to CP0 source-unit/execution v0.2.

use serde::{Deserialize, Serialize};

use crate::path::{sha256_hex, unit_id};
use crate::rules::LoadedBundle;

pub const SCHEMA_VERSION: &str = "0.2.0";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionState {
    Completed,
    Error,
    Interrupted,
}

impl ExecutionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "COMPLETED",
            Self::Error => "ERROR",
            Self::Interrupted => "INTERRUPTED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAdapter {
    pub id: String,
    pub version: String,
}

impl Default for SourceAdapter {
    fn default() -> Self {
        Self {
            id: "local-working-tree".to_string(),
            version: ENGINE_VERSION.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceUnitRecord {
    pub schema_version: String,
    pub run_id: String,
    pub unit_id: String,
    pub source_id: String,
    pub source_kind: String,
    pub locator: String,
    pub required_scope: bool,
    pub disposition: String,
    pub reason_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_sha256: Option<String>,
}

impl SourceUnitRecord {
    #[allow(clippy::too_many_arguments)]
    fn base(
        run_id: &str,
        locator: &str,
        required_scope: bool,
        disposition: &str,
        reason_codes: Vec<String>,
    ) -> Result<Self, crate::error::CoreError> {
        Ok(Self {
            schema_version: SCHEMA_VERSION.to_string(),
            run_id: run_id.to_string(),
            unit_id: unit_id(crate::path::SOURCE_ID, locator)?,
            source_id: crate::path::SOURCE_ID.to_string(),
            source_kind: "working_tree_file".to_string(),
            locator: locator.to_string(),
            required_scope,
            disposition: disposition.to_string(),
            reason_codes,
            byte_length: None,
            line_count: None,
            content_sha256: None,
        })
    }

    pub fn inspected(
        run_id: &str,
        locator: &str,
        required_scope: bool,
        content: &[u8],
        line_count: usize,
    ) -> Result<Self, crate::error::CoreError> {
        Self::inspected_with_hash(
            run_id,
            locator,
            required_scope,
            content.len() as u64,
            line_count,
            sha256_hex(content),
        )
    }

    pub fn inspected_with_hash(
        run_id: &str,
        locator: &str,
        required_scope: bool,
        byte_length: u64,
        line_count: usize,
        content_sha256: String,
    ) -> Result<Self, crate::error::CoreError> {
        let mut record = Self::base(run_id, locator, required_scope, "INSPECTED", Vec::new())?;
        record.byte_length = Some(byte_length);
        record.line_count = Some(line_count);
        record.content_sha256 = Some(content_sha256);
        Ok(record)
    }

    pub fn blocked(
        run_id: &str,
        locator: &str,
        required_scope: bool,
        reason: &str,
    ) -> Result<Self, crate::error::CoreError> {
        Self::base(
            run_id,
            locator,
            required_scope,
            "VERIFIED_BLOCKED",
            vec![reason.to_string()],
        )
    }

    pub fn uninspected(
        run_id: &str,
        locator: &str,
        required_scope: bool,
        reason: &str,
    ) -> Result<Self, crate::error::CoreError> {
        Self::base(
            run_id,
            locator,
            required_scope,
            "UNINSPECTED",
            vec![reason.to_string()],
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub schema_version: String,
    pub run_id: String,
    pub state: ExecutionState,
    pub evidence_valid: bool,
    pub engine_version: String,
    pub ruleset_id: String,
    pub ruleset_digest: String,
    pub source_adapter: SourceAdapter,
    pub units: Vec<SourceUnitRecord>,
    pub fatal_errors: Vec<String>,
    pub failure_codes: Vec<String>,
}

impl ExecutionRecord {
    pub fn new(run_id: &str, bundle: &LoadedBundle) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            run_id: run_id.to_string(),
            state: ExecutionState::Completed,
            evidence_valid: true,
            engine_version: ENGINE_VERSION.to_string(),
            ruleset_id: bundle.definition.ruleset_id.clone(),
            ruleset_digest: bundle.digest.clone(),
            source_adapter: SourceAdapter::default(),
            units: Vec::new(),
            fatal_errors: Vec::new(),
            failure_codes: Vec::new(),
        }
    }

    pub fn add_fatal(&mut self, code: &str) {
        self.fatal_errors.push(code.to_string());
        if !self.failure_codes.iter().any(|existing| existing == code) {
            self.failure_codes.push(code.to_string());
        }
        self.state = ExecutionState::Error;
        self.evidence_valid = false;
    }

    pub fn add_failure(&mut self, code: &str) {
        if !self.failure_codes.iter().any(|existing| existing == code) {
            self.failure_codes.push(code.to_string());
        }
    }

    pub fn sort_units(&mut self) {
        self.units
            .sort_by(|left, right| left.unit_id.cmp(&right.unit_id));
    }

    pub fn inspected_count(&self) -> usize {
        self.units
            .iter()
            .filter(|unit| unit.disposition == "INSPECTED")
            .count()
    }

    pub fn blocked_count(&self) -> usize {
        self.units
            .iter()
            .filter(|unit| unit.disposition == "VERIFIED_BLOCKED")
            .count()
    }

    pub fn uninspected_count(&self) -> usize {
        self.units
            .iter()
            .filter(|unit| unit.disposition == "UNINSPECTED")
            .count()
    }

    pub fn required_uninspected_count(&self) -> usize {
        self.units
            .iter()
            .filter(|unit| unit.disposition == "UNINSPECTED" && unit.required_scope)
            .count()
    }
}
