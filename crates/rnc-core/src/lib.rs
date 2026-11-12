//! RNC Scanner detection core.
//!
//! The crate owns authorized local input acquisition, versioned rule evaluation,
//! deterministic finding generation and coverage accounting. It does not apply
//! policy dispositions, format public reports, grade its own accuracy or decide
//! CI acceptance.

pub mod backend;
pub mod config;
pub mod coverage;
pub mod engine;
pub mod error;
pub mod finding;
pub mod git;
pub mod input;
pub mod path;
pub mod policy;
pub mod result;
pub mod rules;
pub mod stream;
pub mod structured;
pub mod validate;

pub use backend::{BackendRequest, PlanProvenance};
pub use config::{load_effective, CliOverrides, EffectiveConfig};
pub use coverage::{
    ExecutionRecord, ExecutionState, SourceUnitRecord, ENGINE_VERSION, SCHEMA_VERSION,
};
pub use engine::{scan, RunConfig, ScanReport};
pub use error::CoreError;
pub use finding::Finding;
pub use git::{GitHistoryOptions, GitHistorySource, GitReadError};
pub use input::{GitHistoryInfo, LocalSource, ScanLimits};
pub use policy::{PolicyRecord, PolicySpec};
pub use result::{CiDecision, ResultRecord};
pub use rules::{LoadedBundle, RuleBundle};
pub use stream::ScanMode;
pub use structured::{StructuredComponent, StructuredEvidence};
