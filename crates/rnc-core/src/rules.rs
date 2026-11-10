//! Versioned, data-only rule bundles with finite matching bounds.

use std::fs;
use std::path::Path;

use regex::bytes::Regex;
use regex_syntax::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::CoreError;
use crate::path::sha256_hex;
use crate::validate::Validator;

pub const RULE_SCHEMA_VERSION: &str = "0.1.0";
pub const MAX_PATTERN_BYTES: usize = 16 * 1024;
pub const MAX_MATCH_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDefinition {
    pub rule_id: String,
    pub rule_version: String,
    pub category: String,
    pub pattern: String,
    pub capture_group: usize,
    pub validators: Vec<Validator>,
    pub confidence: String,
    pub max_match_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleBundle {
    pub schema_version: String,
    pub ruleset_id: String,
    pub ruleset_version: String,
    pub rules: Vec<RuleDefinition>,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub definition: RuleDefinition,
    pub regex: Regex,
}

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub definition: RuleBundle,
    pub compiled: Vec<CompiledRule>,
    pub digest: String,
    pub max_match_bytes: usize,
}

impl LoadedBundle {
    pub fn load(path: &Path) -> Result<Self, CoreError> {
        let bytes = fs::read(path).map_err(CoreError::Io)?;
        let bundle: RuleBundle = serde_json::from_slice(&bytes)?;
        Self::from_bundle(bundle)
    }

    pub fn from_bundle(bundle: RuleBundle) -> Result<Self, CoreError> {
        if bundle.schema_version != RULE_SCHEMA_VERSION {
            return Err(CoreError::Rule(format!(
                "unsupported schema_version {} (expected {RULE_SCHEMA_VERSION})",
                bundle.schema_version
            )));
        }
        if bundle.ruleset_id.trim().is_empty() || bundle.ruleset_version.trim().is_empty() {
            return Err(CoreError::Rule(
                "ruleset_id and ruleset_version are required".to_string(),
            ));
        }
        if bundle.rules.is_empty() {
            return Err(CoreError::Rule("rule bundle contains no rules".to_string()));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut compiled = Vec::with_capacity(bundle.rules.len());
        let mut maximum = 0usize;
        for definition in &bundle.rules {
            validate_definition(definition, &mut ids)?;
            let hir = Parser::new()
                .parse(&definition.pattern)
                .map_err(|error| CoreError::Rule(format!("{}: {error}", definition.rule_id)))?;
            let properties = hir.properties();
            if properties.minimum_len() == Some(0) {
                return Err(CoreError::Rule(format!(
                    "{} matches an empty string",
                    definition.rule_id
                )));
            }
            let max_len = properties.maximum_len().ok_or_else(|| {
                CoreError::Rule(format!(
                    "{} has no finite maximum match length",
                    definition.rule_id
                ))
            })?;
            if max_len > definition.max_match_bytes {
                return Err(CoreError::Rule(format!(
                    "{} can match {max_len} bytes but declares {}",
                    definition.rule_id, definition.max_match_bytes
                )));
            }
            let regex = Regex::new(&definition.pattern)
                .map_err(|error| CoreError::Rule(format!("{}: {error}", definition.rule_id)))?;
            if definition.capture_group >= regex.captures_len() {
                return Err(CoreError::Rule(format!(
                    "{} capture_group {} does not exist",
                    definition.rule_id, definition.capture_group
                )));
            }
            maximum = maximum.max(max_len);
            compiled.push(CompiledRule {
                definition: definition.clone(),
                regex,
            });
        }
        let digest = bundle_digest(&bundle)?;
        compiled.sort_by(|left, right| left.definition.rule_id.cmp(&right.definition.rule_id));
        Ok(Self {
            definition: bundle,
            compiled,
            digest,
            max_match_bytes: maximum,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.compiled.len()
    }
}

fn validate_definition(
    definition: &RuleDefinition,
    ids: &mut std::collections::BTreeSet<String>,
) -> Result<(), CoreError> {
    if definition.rule_id.trim().is_empty() || definition.rule_id.len() > 128 {
        return Err(CoreError::Rule(
            "rule_id must be 1..=128 characters".to_string(),
        ));
    }
    if definition.rule_version.trim().is_empty() {
        return Err(CoreError::Rule(format!(
            "{} has no rule_version",
            definition.rule_id
        )));
    }
    if definition.category.trim().is_empty() {
        return Err(CoreError::Rule(format!(
            "{} has no category",
            definition.rule_id
        )));
    }
    if definition.pattern.is_empty() || definition.pattern.len() > MAX_PATTERN_BYTES {
        return Err(CoreError::Rule(format!(
            "{} pattern length is outside 1..={MAX_PATTERN_BYTES}",
            definition.rule_id
        )));
    }
    if definition.max_match_bytes == 0 || definition.max_match_bytes > MAX_MATCH_BYTES {
        return Err(CoreError::Rule(format!(
            "{} max_match_bytes must be 1..={MAX_MATCH_BYTES}",
            definition.rule_id
        )));
    }
    if definition.validators.is_empty() {
        return Err(CoreError::Rule(format!(
            "{} must declare at least one validator",
            definition.rule_id
        )));
    }
    if !matches!(
        definition.confidence.as_str(),
        "low" | "medium" | "high" | "unknown"
    ) {
        return Err(CoreError::Rule(format!(
            "{} has unsupported confidence {}",
            definition.rule_id, definition.confidence
        )));
    }
    if !ids.insert(definition.rule_id.clone()) {
        return Err(CoreError::Rule(format!(
            "duplicate rule_id {}",
            definition.rule_id
        )));
    }
    Ok(())
}

/// Deterministic digest over the canonical normalized bundle structure.
///
/// Rules are sorted by rule ID and serde_json's default map is a BTreeMap, so
/// key order and JSON whitespace do not alter the digest. Python integration
/// tests use the same canonical object with sorted keys.
pub fn bundle_digest(bundle: &RuleBundle) -> Result<String, CoreError> {
    let mut rules = bundle.rules.clone();
    rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    let value = json!({
        "schema_version": bundle.schema_version,
        "ruleset_id": bundle.ruleset_id,
        "ruleset_version": bundle.ruleset_version,
        "rules": rules.iter().map(|rule| json!({
            "rule_id": rule.rule_id,
            "rule_version": rule.rule_version,
            "category": rule.category,
            "pattern": rule.pattern,
            "capture_group": rule.capture_group,
            "validators": rule.validators,
            "confidence": rule.confidence,
            "max_match_bytes": rule.max_match_bytes,
        })).collect::<Vec<_>>(),
    });
    let bytes = serde_json::to_vec(&value)?;
    Ok(sha256_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::Validator;

    fn base_bundle() -> RuleBundle {
        serde_json::from_value(json!({
            "schema_version": "0.1.0",
            "ruleset_id": "test",
            "ruleset_version": "1",
            "rules": [{
                "rule_id": "synthetic-test",
                "rule_version": "1",
                "category": "test",
                "pattern": "RNC_SYNTH_KEY_TEST_[A-Z0-9_]{1,32}",
                "capture_group": 0,
                "validators": ["MARKER_FORMAT", "MARKER_SUFFIX"],
                "confidence": "high",
                "max_match_bytes": 128
            }]
        }))
        .unwrap()
    }

    #[test]
    fn loads_valid_bundle_and_computes_finite_bound() {
        let loaded = LoadedBundle::from_bundle(base_bundle()).unwrap();
        assert_eq!(loaded.rule_count(), 1);
        assert!(loaded.max_match_bytes > 16);
        assert!(loaded.digest.starts_with("sha256:"));
    }

    #[test]
    fn rejects_unbounded_repetition() {
        let mut bundle = base_bundle();
        bundle.rules[0].pattern = "RNC_SYNTH_KEY_TEST_[A-Z0-9_]+".to_string();
        assert!(LoadedBundle::from_bundle(bundle).is_err());
    }

    #[test]
    fn rejects_duplicate_ids_and_unknown_validators() {
        let mut bundle = base_bundle();
        bundle.rules.push(bundle.rules[0].clone());
        assert!(LoadedBundle::from_bundle(bundle).is_err());

        let mut bundle = base_bundle();
        bundle.rules[0].validators = Vec::new();
        assert!(LoadedBundle::from_bundle(bundle).is_err());
        let mut bundle = base_bundle();
        bundle.rules[0].validators = vec![Validator::MarkerFormat];
        assert!(LoadedBundle::from_bundle(bundle).is_ok());
    }

    #[test]
    fn rejects_declared_bound_below_regex_bound() {
        let mut bundle = base_bundle();
        bundle.rules[0].pattern = "RNC_SYNTH_KEY_TEST_[A-Z0-9_]{1,64}".to_string();
        bundle.rules[0].max_match_bytes = 32;
        assert!(LoadedBundle::from_bundle(bundle).is_err());
    }

    #[test]
    fn digest_ignores_rule_array_order() {
        let mut one = base_bundle();
        let mut two = base_bundle();
        two.rules.push(RuleDefinition {
            rule_id: "synthetic-second".to_string(),
            rule_version: "1".to_string(),
            category: "test".to_string(),
            pattern: "RNC_SYNTH_KEY_SECOND_[A-Z0-9_]{1,32}".to_string(),
            capture_group: 0,
            validators: vec![Validator::MarkerFormat],
            confidence: "high".to_string(),
            max_match_bytes: 128,
        });
        one.rules = two.rules.clone();
        one.rules.reverse();
        assert_eq!(bundle_digest(&one).unwrap(), bundle_digest(&two).unwrap());
    }
}
