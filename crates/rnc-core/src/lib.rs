//! RNC Scanner detection core.
//!
//! The crate owns authorized local input acquisition, versioned rule evaluation,
//! deterministic finding generation and coverage accounting. It does not apply
//! policy dispositions, format public reports, grade its own accuracy or decide
//! CI acceptance.

pub mod coverage;
pub mod engine;
pub mod error;
pub mod finding;
pub mod input;
pub mod path;
pub mod rules;
pub mod stream;
pub mod validate;

pub use coverage::{
    ExecutionRecord, ExecutionState, SourceUnitRecord, ENGINE_VERSION, SCHEMA_VERSION,
};
pub use engine::{scan, RunConfig, ScanReport};
pub use error::CoreError;
pub use finding::Finding;
pub use input::{LocalSource, ScanLimits};
pub use rules::{LoadedBundle, RuleBundle};
pub use stream::ScanMode;
