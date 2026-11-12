//! Versioned, data-only rule bundles with finite matching bounds.
//!
//! Schema `0.1.0` is the original synthetic bundle contract. Schema `0.2.0`
//! adds provider, family, credential-type, provenance and fixture metadata used
//! by the first-party credential catalog. Both schemas compile through the same
//! exact regex engine and retain finite maximum match lengths.

use std::fs;
use std::path::Path;

use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::CoreError;
use crate::path::sha256_hex;
use crate::validate::Validator;

pub const RULE_SCHEMA_VERSION: &str = "0.1.0";
pub const PROVIDER_RULE_SCHEMA_VERSION: &str = "0.2.0";
pub const MAX_PATTERN_BYTES: usize = 16 * 1024;
pub const MAX_MATCH_BYTES: usize = 1024 * 1024;
pub const MAX_RULES: usize = 512;
pub const MAX_IDENTIFIER_BYTES: usize = 96;
pub const CONTEXT_KINDS: &[&str] = &["assignment", "bearer", "container", "standalone", "uri"];
pub const COMPONENT_EXTRACTORS: &[&str] = &["database-uri-password"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleProvenance {
    pub source: String,
    pub references: Vec<String>,
    pub reviewed: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDefinition {
    pub rule_id: String,
    pub rule_version: String,
    pub category: String,
    pub pattern: String,
    pub capture_group: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_capture_groups: Option<Vec<usize>>,
    pub validators: Vec<Validator>,
    pub confidence: String,
    pub max_match_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_extractor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_candidate_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixture_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<RuleProvenance>,
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
    pub required_literal: Option<Vec<u8>>,
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
        if !matches!(
            bundle.schema_version.as_str(),
            RULE_SCHEMA_VERSION | PROVIDER_RULE_SCHEMA_VERSION
        ) {
            return Err(CoreError::Rule(format!(
                "unsupported schema_version {} (expected {RULE_SCHEMA_VERSION} or {PROVIDER_RULE_SCHEMA_VERSION})",
                bundle.schema_version
            )));
        }
        let provider_schema = bundle.schema_version == PROVIDER_RULE_SCHEMA_VERSION;
        if bundle.ruleset_id.trim().is_empty() || bundle.ruleset_version.trim().is_empty() {
            return Err(CoreError::Rule(
                "ruleset_id and ruleset_version are required".to_string(),
            ));
        }
        if bundle.rules.is_empty() {
            return Err(CoreError::Rule("rule bundle contains no rules".to_string()));
        }
        if bundle.rules.len() > MAX_RULES {
            return Err(CoreError::Rule(format!(
                "rule bundle contains {} rules; maximum is {MAX_RULES}",
                bundle.rules.len()
            )));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut compiled = Vec::with_capacity(bundle.rules.len());
        let mut maximum = 0usize;
        for definition in &bundle.rules {
            validate_definition(definition, &mut ids, provider_schema)?;
            let hir = regex_syntax::ParserBuilder::new()
                .utf8(false)
                .build()
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
            let capture_groups = definition
                .value_capture_groups
                .clone()
                .unwrap_or_else(|| vec![definition.capture_group]);
            if capture_groups.is_empty() || capture_groups.len() > 16 {
                return Err(CoreError::Rule(format!(
                    "{} value_capture_groups must contain 1..=16 groups",
                    definition.rule_id
                )));
            }
            if definition
                .value_capture_groups
                .as_ref()
                .is_some_and(|groups| groups.iter().any(|group| *group == 0 || *group > 255))
            {
                return Err(CoreError::Rule(format!(
                    "{} value_capture_groups must reference groups 1..=255",
                    definition.rule_id
                )));
            }
            if let Some(declared) = definition.max_candidate_bytes {
                for group in &capture_groups {
                    let candidate_max = capture_max_bytes(&hir, *group).ok_or_else(|| {
                        CoreError::Rule(format!(
                            "{} capture group {} has no finite maximum length",
                            definition.rule_id, group
                        ))
                    })?;
                    if candidate_max > declared {
                        return Err(CoreError::Rule(format!(
                            "{} capture group can match {candidate_max} bytes but declares max_candidate_bytes {declared}",
                            definition.rule_id
                        )));
                    }
                }
            }
            let regex = Regex::new(&definition.pattern)
                .map_err(|error| CoreError::Rule(format!("{}: {error}", definition.rule_id)))?;
            if let Some(group) = capture_groups
                .iter()
                .find(|group| **group >= regex.captures_len())
            {
                return Err(CoreError::Rule(format!(
                    "{} capture_group {} does not exist",
                    definition.rule_id, group
                )));
            }
            maximum = maximum.max(max_len);
            let required_literal = crate::backend::required_literal(&definition.pattern)
                .map_err(|error| CoreError::Rule(format!("{}: {error}", definition.rule_id)))?;
            compiled.push(CompiledRule {
                definition: definition.clone(),
                regex,
                required_literal,
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

    pub fn provider_rule_count(&self) -> usize {
        self.compiled
            .iter()
            .filter(|rule| rule.definition.provider.is_some())
            .count()
    }

    pub fn family_count(&self) -> usize {
        self.compiled
            .iter()
            .filter_map(|rule| rule.definition.family.as_deref())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }
}

fn validate_identifier(name: &str, value: &str) -> Result<(), CoreError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(CoreError::Rule(format!(
            "{name} must be 1..={MAX_IDENTIFIER_BYTES} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(CoreError::Rule(format!(
            "{name} must contain lowercase ASCII letters, digits or hyphens"
        )));
    }
    Ok(())
}

fn validate_definition(
    definition: &RuleDefinition,
    ids: &mut std::collections::BTreeSet<String>,
    provider_schema: bool,
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
    let provider_fields_present = definition.provider.is_some()
        || definition.family.is_some()
        || definition.credential_type.is_some()
        || definition.context.is_some()
        || definition.component_extractor.is_some()
        || definition.max_candidate_bytes.is_some()
        || definition.fixture_set.is_some()
        || definition.provenance.is_some();
    if provider_schema {
        let provider = definition.provider.as_deref().unwrap_or_default();
        let family = definition.family.as_deref().unwrap_or_default();
        let credential_type = definition.credential_type.as_deref().unwrap_or_default();
        validate_identifier("provider", provider)?;
        validate_identifier("family", family)?;
        validate_identifier("credential_type", credential_type)?;
        let context = definition.context.as_deref().ok_or_else(|| {
            CoreError::Rule(format!("{} has no context declaration", definition.rule_id))
        })?;
        if !CONTEXT_KINDS.contains(&context) {
            return Err(CoreError::Rule(format!(
                "{} has unsupported context {context}",
                definition.rule_id
            )));
        }
        if let Some(extractor) = definition.component_extractor.as_deref() {
            if context != "uri" {
                return Err(CoreError::Rule(format!(
                    "{} component_extractor requires uri context",
                    definition.rule_id
                )));
            }
            if !COMPONENT_EXTRACTORS.contains(&extractor) {
                return Err(CoreError::Rule(format!(
                    "{} has unsupported component_extractor {extractor}",
                    definition.rule_id
                )));
            }
        }
        let fixture_set = definition.fixture_set.as_deref().unwrap_or_default();
        if fixture_set.is_empty()
            || fixture_set.contains("..")
            || fixture_set.starts_with('/')
            || fixture_set.starts_with('\\')
        {
            return Err(CoreError::Rule(format!(
                "{} has an unsafe fixture_set",
                definition.rule_id
            )));
        }
        let provenance = definition
            .provenance
            .as_ref()
            .ok_or_else(|| CoreError::Rule(format!("{} has no provenance", definition.rule_id)))?;
        if provenance.source.trim().is_empty() || provenance.reviewed.trim().is_empty() {
            return Err(CoreError::Rule(format!(
                "{} provenance source and reviewed date are required",
                definition.rule_id
            )));
        }
        if provenance.references.is_empty() {
            return Err(CoreError::Rule(format!(
                "{} provenance must contain at least one reference",
                definition.rule_id
            )));
        }
        for reference in &provenance.references {
            if !(reference.starts_with("https://") || reference.starts_with("http://"))
                || reference.contains(char::is_whitespace)
            {
                return Err(CoreError::Rule(format!(
                    "{} has an invalid provenance reference",
                    definition.rule_id
                )));
            }
        }
        let candidate_max = definition.max_candidate_bytes.ok_or_else(|| {
            CoreError::Rule(format!(
                "{} must declare max_candidate_bytes",
                definition.rule_id
            ))
        })?;
        if candidate_max == 0 || candidate_max > definition.max_match_bytes {
            return Err(CoreError::Rule(format!(
                "{} max_candidate_bytes must be 1..=max_match_bytes",
                definition.rule_id
            )));
        }
    } else if provider_fields_present {
        return Err(CoreError::Rule(format!(
            "{} provider metadata requires schema_version {PROVIDER_RULE_SCHEMA_VERSION}",
            definition.rule_id
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

fn checked_add(left: usize, right: usize) -> Option<usize> {
    left.checked_add(right)
}

fn checked_mul(left: usize, right: usize) -> Option<usize> {
    left.checked_mul(right)
}

fn max_match_len(hir: &regex_syntax::hir::Hir) -> Option<usize> {
    use regex_syntax::hir::{HirKind, Literal};
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(0),
        HirKind::Literal(Literal(bytes)) => Some(bytes.len()),
        HirKind::Class(_) => Some(1),
        HirKind::Capture(capture) => max_match_len(&capture.sub),
        HirKind::Repetition(repetition) => {
            let inner = max_match_len(&repetition.sub)?;
            checked_mul(inner, repetition.max? as usize)
        }
        HirKind::Concat(parts) => {
            let mut total = 0usize;
            for part in parts {
                total = checked_add(total, max_match_len(part)?)?;
            }
            Some(total)
        }
        HirKind::Alternation(branches) => {
            let mut maximum = 0usize;
            for branch in branches {
                maximum = maximum.max(max_match_len(branch)?);
            }
            Some(maximum)
        }
    }
}

fn capture_max_bytes(hir: &regex_syntax::hir::Hir, group: usize) -> Option<usize> {
    if group == 0 {
        return max_match_len(hir);
    }
    fn find(hir: &regex_syntax::hir::Hir, group: usize) -> Option<usize> {
        use regex_syntax::hir::HirKind;
        match hir.kind() {
            HirKind::Capture(capture) if capture.index as usize == group => {
                max_match_len(&capture.sub)
            }
            HirKind::Capture(capture) => find(&capture.sub, group),
            HirKind::Repetition(repetition) => find(&repetition.sub, group),
            HirKind::Concat(parts) => parts.iter().find_map(|part| find(part, group)),
            HirKind::Alternation(branches) => {
                branches.iter().find_map(|branch| find(branch, group))
            }
            _ => None,
        }
    }
    find(hir, group)
}

/// Deterministic digest over the canonical normalized bundle structure.
///
/// Schema `0.1.0` is hashed exactly as it was in CP1 so established rule-set
/// digests remain stable. Schema `0.2.0` additionally binds every provider,
/// context, fixture and provenance field. Rules are sorted by rule ID and
/// serde_json's default map ordering is deterministic.
pub fn bundle_digest(bundle: &RuleBundle) -> Result<String, CoreError> {
    let mut rules = bundle.rules.clone();
    rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
    let rule_values: Vec<Value> = if bundle.schema_version == RULE_SCHEMA_VERSION {
        rules
            .iter()
            .map(|rule| {
                json!({
                    "rule_id": rule.rule_id,
                    "rule_version": rule.rule_version,
                    "category": rule.category,
                    "pattern": rule.pattern,
                    "capture_group": rule.capture_group,
                    "validators": rule.validators,
                    "confidence": rule.confidence,
                    "max_match_bytes": rule.max_match_bytes,
                })
            })
            .collect()
    } else {
        rules
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?
    };
    let value = json!({
        "schema_version": bundle.schema_version,
        "ruleset_id": bundle.ruleset_id,
        "ruleset_version": bundle.ruleset_version,
        "rules": rule_values,
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

    fn provider_bundle() -> RuleBundle {
        serde_json::from_value(json!({
            "schema_version": "0.2.0",
            "ruleset_id": "provider-test",
            "ruleset_version": "1",
            "rules": [{
                "rule_id": "aws-access-key-id",
                "rule_version": "1",
                "category": "cloud-credential",
                "provider": "aws",
                "family": "aws-credentials",
                "credential_type": "access-key-id",
                "context": "standalone",
                "pattern": "(?:AKIA|ASIA)[A-Z0-9]{16}",
                "capture_group": 0,
                "validators": ["AWS_ACCESS_KEY_ID"],
                "confidence": "high",
                "max_match_bytes": 32,
                "max_candidate_bytes": 20,
                "fixture_set": "tests/fixtures/providers",
                "provenance": {
                    "source": "provider-documentation",
                    "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html"],
                    "reviewed": "2026-11-11"
                }
            }]
        }))
        .unwrap()
    }

    #[test]
    fn loads_valid_bundle_and_computes_finite_bound() {
        let loaded = LoadedBundle::from_bundle(base_bundle()).unwrap();
        assert_eq!(loaded.rule_count(), 1);
        assert_eq!(loaded.provider_rule_count(), 0);
        assert_eq!(loaded.family_count(), 0);
        assert!(loaded.max_match_bytes > 16);
        assert!(loaded.digest.starts_with("sha256:"));
    }

    #[test]
    fn loads_provider_bundle_and_metadata() {
        let loaded = LoadedBundle::from_bundle(provider_bundle()).unwrap();
        assert_eq!(loaded.rule_count(), 1);
        assert_eq!(loaded.provider_rule_count(), 1);
        assert_eq!(loaded.family_count(), 1);
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
    fn component_extractor_requires_uri_context_and_known_name() {
        let mut bundle = provider_bundle();
        bundle.rules[0].component_extractor = Some("database-uri-password".to_string());
        assert!(LoadedBundle::from_bundle(bundle.clone()).is_err());
        bundle.rules[0].context = Some("uri".to_string());
        assert!(LoadedBundle::from_bundle(bundle.clone()).is_ok());
        bundle.rules[0].component_extractor = Some("unknown-extractor".to_string());
        assert!(LoadedBundle::from_bundle(bundle).is_err());
    }

    #[test]
    fn rejects_candidate_bound_below_capture_bound() {
        let mut bundle = provider_bundle();
        bundle.rules[0].max_candidate_bytes = Some(8);
        assert!(LoadedBundle::from_bundle(bundle).is_err());
    }

    #[test]
    fn rejects_provider_metadata_on_legacy_schema() {
        let mut bundle = base_bundle();
        bundle.rules[0].provider = Some("aws".to_string());
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
            value_capture_groups: None,
            validators: vec![Validator::MarkerFormat],
            confidence: "high".to_string(),
            max_match_bytes: 128,
            provider: None,
            family: None,
            credential_type: None,
            context: None,
            component_extractor: None,
            max_candidate_bytes: None,
            fixture_set: None,
            provenance: None,
        });
        one.rules = two.rules.clone();
        one.rules.reverse();
        assert_eq!(bundle_digest(&one).unwrap(), bundle_digest(&two).unwrap());
    }

    #[test]
    fn provider_digest_ignores_rule_array_order_and_binds_metadata() {
        let mut one = provider_bundle();
        let mut two = provider_bundle();
        two.rules.push(
            serde_json::from_value(json!({
                "rule_id": "google-api-key",
                "rule_version": "1",
                "category": "cloud-credential",
                "provider": "google-cloud",
                "family": "google-cloud-api-key",
                "credential_type": "api-key",
                "context": "standalone",
                "pattern": "AIza[A-Za-z0-9_-]{35}",
                "capture_group": 0,
                "validators": ["GOOGLE_API_KEY"],
                "confidence": "high",
                "max_match_bytes": 64,
                "max_candidate_bytes": 39,
                "fixture_set": "tests/fixtures/providers",
                "provenance": {
                    "source": "provider-documentation",
                    "references": ["https://cloud.google.com/docs/authentication/api-keys"],
                    "reviewed": "2026-11-11"
                }
            }))
            .unwrap(),
        );
        one.rules = two.rules.clone();
        one.rules.reverse();
        assert_eq!(bundle_digest(&one).unwrap(), bundle_digest(&two).unwrap());
        let mut changed = two.clone();
        changed.rules[0].fixture_set = Some("tests/fixtures/other".to_string());
        assert_ne!(
            bundle_digest(&two).unwrap(),
            bundle_digest(&changed).unwrap()
        );
    }

    #[test]
    fn legacy_known_digests_remain_stable() {
        let v0: RuleBundle = serde_json::from_slice(
            &fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-synthetic-v0.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let v1: RuleBundle = serde_json::from_slice(
            &fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-synthetic-v1.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            bundle_digest(&v0).unwrap(),
            "sha256:71218980bc78e8a49fe4a73702357f7cb96058a4f0342c3ea5d610a174603f05"
        );
        assert_eq!(
            bundle_digest(&v1).unwrap(),
            "sha256:6a68625a57f75adcf1aaebd3f8ef1470c339b68fa0b80ab85ecdfc37af33f73d"
        );
    }
}
