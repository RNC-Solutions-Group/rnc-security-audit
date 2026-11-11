//! Pre-scan scope policy, post-scan exemptions and the policy ledger.
//!
//! Selectors are a declared glob grammar over canonical locators. They never
//! rewrite a locator and cannot be used as a traversal mechanism. Detection
//! evidence is immutable; an exemption only adds a disposition.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::coverage::SCHEMA_VERSION;
use crate::error::CoreError;
use crate::finding::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyOrigin {
    Global,
    Repository,
    Cli,
}

impl PolicyOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Repository => "repository",
            Self::Cli => "cli",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePolicy {
    pub policy_id: String,
    pub origin: PolicyOrigin,
    pub version: String,
    pub digest: String,
    pub mandatory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GlobSegment {
    Any,
    Literal(String),
    Pattern(String),
}

#[derive(Debug, Clone)]
pub struct ScopeGlob {
    raw: String,
    segments: Vec<GlobSegment>,
    specificity: usize,
}

impl ScopeGlob {
    pub fn parse(value: &str) -> Result<Self, CoreError> {
        if value.is_empty() {
            return Err(CoreError::Input(
                "policy selector must not be empty".to_string(),
            ));
        }
        if value.chars().count() > 4096 {
            return Err(CoreError::Input(
                "policy selector exceeds the supported length".to_string(),
            ));
        }
        if value
            .chars()
            .any(|character| character.is_control() || character == '\0')
        {
            return Err(CoreError::Input(
                "policy selector contains a control character".to_string(),
            ));
        }
        let normalized: String = value.nfc().collect();
        if normalized != value {
            return Err(CoreError::Input(
                "policy selector must be NFC-normalized".to_string(),
            ));
        }
        if value.contains('\\') || value.starts_with('/') || value.ends_with('/') {
            return Err(CoreError::Input(
                "policy selector must be a relative forward-slash glob".to_string(),
            ));
        }
        if value.starts_with("~") || value.contains("./") || value.contains("/../") {
            return Err(CoreError::Input(
                "policy selector must not contain a traversal prefix".to_string(),
            ));
        }
        let mut segments = Vec::new();
        let mut specificity = 0usize;
        for segment in value.split('/') {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(CoreError::Input(
                    "policy selector must not contain empty or dot segments".to_string(),
                ));
            }
            if segment == "**" {
                segments.push(GlobSegment::Any);
                continue;
            }
            if segment.trim() != segment || segment.ends_with('.') {
                return Err(CoreError::Input(
                    "policy selector has a trailing space or dot segment".to_string(),
                ));
            }
            if segment
                .chars()
                .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|'))
            {
                return Err(CoreError::Input(
                    "policy selector contains a platform-ambiguous character".to_string(),
                ));
            }
            if segment.contains('[')
                || segment.contains(']')
                || segment.contains('{')
                || segment.contains('}')
                || segment.contains(',')
                || segment.contains('\\')
            {
                return Err(CoreError::Input(
                    "policy selector uses an unsupported glob construct".to_string(),
                ));
            }
            let wildcard = segment.contains('*') || segment.contains('?');
            specificity += segment
                .chars()
                .filter(|character| !matches!(character, '*' | '?'))
                .count();
            if wildcard {
                segments.push(GlobSegment::Pattern(segment.to_string()));
            } else {
                segments.push(GlobSegment::Literal(segment.to_string()));
            }
        }
        if segments.is_empty() {
            return Err(CoreError::Input("policy selector is empty".to_string()));
        }
        Ok(Self {
            raw: value.to_string(),
            segments,
            specificity,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn specificity(&self) -> usize {
        self.specificity
    }

    pub fn matches(&self, locator: &str) -> bool {
        let parts: Vec<&str> = locator.split('/').collect();
        matches_segments(&self.segments, &parts)
    }
}

fn matches_segments(pattern: &[GlobSegment], parts: &[&str]) -> bool {
    if pattern.is_empty() {
        return parts.is_empty();
    }
    match &pattern[0] {
        GlobSegment::Any => {
            for skip in 0..=parts.len() {
                if matches_segments(&pattern[1..], &parts[skip..]) {
                    return true;
                }
            }
            false
        }
        GlobSegment::Literal(value) => {
            !parts.is_empty() && parts[0] == value && matches_segments(&pattern[1..], &parts[1..])
        }
        GlobSegment::Pattern(value) => {
            !parts.is_empty()
                && glob_segment(value, parts[0])
                && matches_segments(&pattern[1..], &parts[1..])
        }
    }
}

fn glob_segment(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    for character in pattern {
        let mut current = vec![false; value.len() + 1];
        match character {
            '*' => {
                current[0] = previous[0];
                for index in 1..=value.len() {
                    current[index] = previous[index] || current[index - 1];
                }
            }
            '?' => {
                current[1..].copy_from_slice(&previous[..value.len()]);
            }
            literal => {
                for index in 1..=value.len() {
                    current[index] = previous[index - 1] && value[index - 1] == literal;
                }
            }
        }
        previous = current;
    }
    previous[value.len()]
}

#[derive(Debug, Clone)]
pub struct BlockRule {
    pub request_id: String,
    pub policy_id: String,
    pub origin: PolicyOrigin,
    pub selector: String,
    pub reason: String,
    pub matcher: ScopeGlob,
}

#[derive(Debug, Clone)]
pub enum ExemptionMatcher {
    Finding(String),
    Fingerprint(String),
    RulePath { rule_id: String, path: ScopeGlob },
    Rule(String),
    Path(ScopeGlob),
}

#[derive(Debug, Clone)]
pub struct ExemptionRule {
    pub request_id: String,
    pub policy_id: String,
    pub origin: PolicyOrigin,
    pub selector: String,
    pub reason: String,
    pub matcher: ExemptionMatcher,
    pub expires_unix: Option<u64>,
}

impl ExemptionRule {
    fn specificity(&self) -> usize {
        match &self.matcher {
            ExemptionMatcher::Finding(_) => 1000,
            ExemptionMatcher::Fingerprint(_) => 900,
            ExemptionMatcher::RulePath { .. } => 800,
            ExemptionMatcher::Rule(_) => 400,
            ExemptionMatcher::Path(_) => 300,
        }
    }

    fn matches(&self, finding: &Finding, locator: &str, now_unix: u64) -> bool {
        if self.expires_unix.is_some_and(|expiry| expiry <= now_unix) {
            return false;
        }
        match &self.matcher {
            ExemptionMatcher::Finding(identifier) => finding.finding_id == *identifier,
            ExemptionMatcher::Fingerprint(digest) => finding.evidence_digest == *digest,
            ExemptionMatcher::RulePath { rule_id, path } => {
                finding.rule_id == *rule_id && path.matches(locator)
            }
            ExemptionMatcher::Rule(rule_id) => finding.rule_id == *rule_id,
            ExemptionMatcher::Path(path) => path.matches(locator),
        }
    }
}

pub fn parse_exemption_selector(selector: &str) -> Result<ExemptionMatcher, CoreError> {
    if selector.is_empty() {
        return Err(CoreError::Input("exemption selector is empty".to_string()));
    }
    let mut clauses: BTreeMap<&str, &str> = BTreeMap::new();
    for clause in selector.split(';') {
        let (kind, value) = clause
            .split_once(':')
            .ok_or_else(|| CoreError::Input("exemption clause must be kind:value".to_string()))?;
        if !matches!(kind, "finding" | "fingerprint" | "rule" | "path") || value.is_empty() {
            return Err(CoreError::Input(
                "exemption clause must use finding:, fingerprint:, rule: or path:".to_string(),
            ));
        }
        if clauses.insert(kind, value).is_some() {
            return Err(CoreError::Input(
                "duplicate exemption clause kind".to_string(),
            ));
        }
    }
    if clauses.contains_key("finding") {
        if clauses.len() != 1 {
            return Err(CoreError::Input(
                "finding: must be the only exemption clause".to_string(),
            ));
        }
        let value = clauses["finding"];
        if !value.starts_with("f-") || value.len() != 66 {
            return Err(CoreError::Input(
                "finding: selector is not a finding ID".to_string(),
            ));
        }
        return Ok(ExemptionMatcher::Finding(value.to_string()));
    }
    if clauses.contains_key("fingerprint") {
        if clauses.len() != 1 {
            return Err(CoreError::Input(
                "fingerprint: must be the only exemption clause".to_string(),
            ));
        }
        let value = clauses["fingerprint"];
        if !value.starts_with("sha256:") || value.len() != 71 {
            return Err(CoreError::Input(
                "fingerprint: selector is not a sha256 digest".to_string(),
            ));
        }
        return Ok(ExemptionMatcher::Fingerprint(value.to_string()));
    }
    match (clauses.get("rule"), clauses.get("path")) {
        (Some(rule_id), Some(path)) => Ok(ExemptionMatcher::RulePath {
            rule_id: (*rule_id).to_string(),
            path: ScopeGlob::parse(path)?,
        }),
        (Some(rule_id), None) => Ok(ExemptionMatcher::Rule((*rule_id).to_string())),
        (None, Some(path)) => Ok(ExemptionMatcher::Path(ScopeGlob::parse(path)?)),
        (None, None) => Err(CoreError::Input(
            "exemption selector needs a finding, fingerprint, rule or path clause".to_string(),
        )),
    }
}

#[derive(Debug, Clone)]
pub struct PolicySpec {
    pub effective_policies: Vec<EffectivePolicy>,
    pub blocks: Vec<BlockRule>,
    pub exemptions: Vec<ExemptionRule>,
    pub skips: Vec<ScopeGlob>,
    pub optional: Vec<ScopeGlob>,
    pub errors: Vec<String>,
}

impl Default for PolicySpec {
    fn default() -> Self {
        Self::empty()
    }
}

impl PolicySpec {
    pub fn empty() -> Self {
        Self {
            effective_policies: Vec::new(),
            blocks: Vec::new(),
            exemptions: Vec::new(),
            skips: Vec::new(),
            optional: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn add_block(
        &mut self,
        policy_id: &str,
        origin: PolicyOrigin,
        selector: &str,
        reason: &str,
        version: &str,
        mandatory: bool,
    ) -> Result<(), CoreError> {
        if self.errors.iter().any(|error| error == "POLICY_DUPLICATE") {
            return Err(CoreError::Input("policy is already invalid".to_string()));
        }
        let request_id = request_id(policy_id, "BLOCK", selector);
        if self.blocks.iter().any(|rule| rule.request_id == request_id) {
            return Err(CoreError::Input(
                "duplicate block request selector".to_string(),
            ));
        }
        self.ensure_policy(policy_id, origin, version, mandatory)?;
        self.blocks.push(BlockRule {
            request_id,
            policy_id: policy_id.to_string(),
            origin,
            selector: selector.to_string(),
            reason: reason.to_string(),
            matcher: ScopeGlob::parse(selector)?,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_exemption(
        &mut self,
        policy_id: &str,
        origin: PolicyOrigin,
        selector: &str,
        reason: &str,
        version: &str,
        mandatory: bool,
        expires_unix: Option<u64>,
    ) -> Result<(), CoreError> {
        let request_id = request_id(policy_id, "EXEMPTION", selector);
        if self
            .exemptions
            .iter()
            .any(|rule| rule.request_id == request_id)
        {
            return Err(CoreError::Input(
                "duplicate exemption request selector".to_string(),
            ));
        }
        self.ensure_policy(policy_id, origin, version, mandatory)?;
        self.exemptions.push(ExemptionRule {
            request_id,
            policy_id: policy_id.to_string(),
            origin,
            selector: selector.to_string(),
            reason: reason.to_string(),
            matcher: parse_exemption_selector(selector)?,
            expires_unix,
        });
        Ok(())
    }

    pub fn add_skip(&mut self, selector: &str) -> Result<(), CoreError> {
        self.skips.push(ScopeGlob::parse(selector)?);
        Ok(())
    }

    pub fn add_optional(&mut self, selector: &str) -> Result<(), CoreError> {
        self.optional.push(ScopeGlob::parse(selector)?);
        Ok(())
    }

    fn ensure_policy(
        &mut self,
        policy_id: &str,
        origin: PolicyOrigin,
        version: &str,
        mandatory: bool,
    ) -> Result<(), CoreError> {
        if policy_id.trim().is_empty() || version.trim().is_empty() {
            return Err(CoreError::Input(
                "policy_id and version must be non-empty".to_string(),
            ));
        }
        if mandatory && origin != PolicyOrigin::Global {
            return Err(CoreError::Input(
                "mandatory policy must originate globally".to_string(),
            ));
        }
        let digest = digest_bytes(format!("{policy_id}\0{version}").as_bytes());
        if let Some(existing) = self
            .effective_policies
            .iter()
            .find(|policy| policy.policy_id == policy_id)
        {
            if existing.origin != origin
                || existing.version != version
                || existing.digest != digest
                || existing.mandatory != mandatory
            {
                return Err(CoreError::Input(format!(
                    "conflicting policy declaration for {policy_id}"
                )));
            }
            return Ok(());
        }
        self.effective_policies.push(EffectivePolicy {
            policy_id: policy_id.to_string(),
            origin,
            version: version.to_string(),
            digest,
            mandatory,
        });
        self.effective_policies
            .sort_by(|left, right| left.policy_id.cmp(&right.policy_id));
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CoreError> {
        if !self.errors.is_empty() {
            return Err(CoreError::Input(self.errors.join(",")));
        }
        let mut ids = BTreeSet::new();
        for policy in &self.effective_policies {
            if !ids.insert(policy.policy_id.clone()) {
                return Err(CoreError::Input("duplicate effective policy".to_string()));
            }
        }
        let ids: BTreeSet<&str> = self
            .effective_policies
            .iter()
            .map(|policy| policy.policy_id.as_str())
            .collect();
        for block in &self.blocks {
            if !ids.contains(block.policy_id.as_str()) {
                return Err(CoreError::Input(
                    "block references an unknown policy".to_string(),
                ));
            }
        }
        for exemption in &self.exemptions {
            if !ids.contains(exemption.policy_id.as_str()) {
                return Err(CoreError::Input(
                    "exemption references an unknown policy".to_string(),
                ));
            }
        }
        Ok(())
    }
}

pub fn request_id(policy_id: &str, kind: &str, selector: &str) -> String {
    let material = format!("{policy_id}\0{kind}\0{selector}");
    format!("r-{}", hex::encode(Sha256::digest(material.as_bytes())))
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub request_id: String,
    pub kind: String,
    pub policy_id: String,
    pub origin: PolicyOrigin,
    pub selector: String,
    pub reason: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_unit_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_finding_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedBlock {
    pub unit_id: String,
    pub request_id: String,
    pub policy_id: String,
    pub origin: PolicyOrigin,
    pub reason: String,
    pub enforcement_method: String,
    pub verified_non_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disposition {
    pub finding_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<PolicyOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub schema_version: String,
    pub run_id: String,
    pub policy_valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
    pub effective_policy_digest: String,
    pub effective_policies: Vec<EffectivePolicy>,
    pub requests: Vec<PolicyRequest>,
    pub applied_blocks: Vec<AppliedBlock>,
    pub dispositions: Vec<Disposition>,
}

pub fn build_policy(
    run_id: &str,
    units: &[crate::input::DiscoveredUnit],
    findings: &[Finding],
    spec: &PolicySpec,
    now_unix: u64,
) -> Result<PolicyRecord, CoreError> {
    let locators: BTreeMap<&str, &str> = units
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit.locator.as_str()))
        .collect();

    let mut requests = Vec::new();
    let mut applied_blocks = Vec::new();

    // Each discovered blocked unit has exactly one applied block event. When
    // multiple requests match, the most specific selector wins deterministically;
    // the shadowed requests remain visible as UNSUPPORTED.
    let mut winner_by_unit: BTreeMap<&str, &BlockRule> = BTreeMap::new();
    let mut matched_by_request: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for unit in units
        .iter()
        .filter(|unit| unit.scope == crate::input::PreScanScope::Blocked)
    {
        let matching: Vec<&BlockRule> = spec
            .blocks
            .iter()
            .filter(|request| {
                unit.block_matches
                    .iter()
                    .any(|id| id == &request.request_id)
            })
            .collect();
        if let Some(winner) = matching.iter().max_by(|left, right| {
            left.matcher
                .specificity()
                .cmp(&right.matcher.specificity())
                .then_with(|| left.request_id.cmp(&right.request_id))
        }) {
            winner_by_unit.insert(unit.unit_id.as_str(), winner);
            for request in matching {
                matched_by_request
                    .entry(request.request_id.as_str())
                    .or_default()
                    .push(unit.unit_id.as_str());
            }
        }
    }
    for request in &spec.blocks {
        let matched = matched_by_request
            .get(request.request_id.as_str())
            .cloned()
            .unwrap_or_default();
        let applied: Vec<&str> = matched
            .iter()
            .copied()
            .filter(|unit_id| {
                winner_by_unit
                    .get(*unit_id)
                    .is_some_and(|winner| winner.request_id == request.request_id)
            })
            .collect();
        if !applied.is_empty() {
            requests.push(PolicyRequest {
                request_id: request.request_id.clone(),
                kind: "BLOCK".to_string(),
                policy_id: request.policy_id.clone(),
                origin: request.origin,
                selector: request.selector.clone(),
                reason: request.reason.clone(),
                status: "APPLIED".to_string(),
                matched_unit_ids: applied.iter().map(|id| (*id).to_string()).collect(),
                matched_finding_ids: Vec::new(),
            });
            for unit_id in applied {
                applied_blocks.push(AppliedBlock {
                    unit_id: unit_id.to_string(),
                    request_id: request.request_id.clone(),
                    policy_id: request.policy_id.clone(),
                    origin: request.origin,
                    reason: request.reason.clone(),
                    enforcement_method: "ADAPTER_ENUMERATION_FILTER".to_string(),
                    verified_non_access: true,
                });
            }
        } else if matched.is_empty() {
            requests.push(PolicyRequest {
                request_id: request.request_id.clone(),
                kind: "BLOCK".to_string(),
                policy_id: request.policy_id.clone(),
                origin: request.origin,
                selector: request.selector.clone(),
                reason: request.reason.clone(),
                status: "NOT_MATCHED".to_string(),
                matched_unit_ids: Vec::new(),
                matched_finding_ids: Vec::new(),
            });
        } else {
            let shadow = matched
                .iter()
                .filter_map(|unit_id| winner_by_unit.get(unit_id))
                .map(|winner| winner.request_id.clone())
                .next()
                .unwrap_or_else(|| "UNKNOWN".to_string());
            requests.push(PolicyRequest {
                request_id: request.request_id.clone(),
                kind: "BLOCK".to_string(),
                policy_id: request.policy_id.clone(),
                origin: request.origin,
                selector: request.selector.clone(),
                reason: format!("{} (shadowed by {shadow})", request.reason),
                status: "UNSUPPORTED".to_string(),
                matched_unit_ids: Vec::new(),
                matched_finding_ids: Vec::new(),
            });
        }
    }

    // Exemptions are evaluated after detection. Every finding receives exactly
    // one disposition and the raw finding array remains untouched.
    let mut exemption_winner: BTreeMap<&str, &ExemptionRule> = BTreeMap::new();
    let mut exemption_matches: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for finding in findings {
        let locator = locators
            .get(finding.unit_id.as_str())
            .copied()
            .unwrap_or_default();
        let matching: Vec<&ExemptionRule> = spec
            .exemptions
            .iter()
            .filter(|request| request.matches(finding, locator, now_unix))
            .collect();
        if let Some(winner) = matching.iter().max_by(|left, right| {
            left.specificity()
                .cmp(&right.specificity())
                .then_with(|| left.request_id.cmp(&right.request_id))
        }) {
            exemption_winner.insert(finding.finding_id.as_str(), winner);
            for request in matching {
                exemption_matches
                    .entry(request.request_id.as_str())
                    .or_default()
                    .push(finding.finding_id.as_str());
            }
        }
    }
    for request in &spec.exemptions {
        let matched = exemption_matches
            .get(request.request_id.as_str())
            .cloned()
            .unwrap_or_default();
        let applied: Vec<&str> = matched
            .iter()
            .copied()
            .filter(|finding_id| {
                exemption_winner
                    .get(*finding_id)
                    .is_some_and(|winner| winner.request_id == request.request_id)
            })
            .collect();
        if !applied.is_empty() {
            requests.push(PolicyRequest {
                request_id: request.request_id.clone(),
                kind: "EXEMPTION".to_string(),
                policy_id: request.policy_id.clone(),
                origin: request.origin,
                selector: request.selector.clone(),
                reason: request.reason.clone(),
                status: "APPLIED".to_string(),
                matched_unit_ids: Vec::new(),
                matched_finding_ids: applied.iter().map(|id| (*id).to_string()).collect(),
            });
        } else if matched.is_empty() {
            let expired = request
                .expires_unix
                .is_some_and(|expiry| expiry <= now_unix);
            requests.push(PolicyRequest {
                request_id: request.request_id.clone(),
                kind: "EXEMPTION".to_string(),
                policy_id: request.policy_id.clone(),
                origin: request.origin,
                selector: request.selector.clone(),
                reason: if expired {
                    format!("{} (expired)", request.reason)
                } else {
                    request.reason.clone()
                },
                status: if expired {
                    "UNSUPPORTED"
                } else {
                    "NOT_MATCHED"
                }
                .to_string(),
                matched_unit_ids: Vec::new(),
                matched_finding_ids: Vec::new(),
            });
        } else {
            let shadow = matched
                .iter()
                .filter_map(|finding_id| exemption_winner.get(finding_id))
                .map(|winner| winner.request_id.clone())
                .next()
                .unwrap_or_else(|| "UNKNOWN".to_string());
            requests.push(PolicyRequest {
                request_id: request.request_id.clone(),
                kind: "EXEMPTION".to_string(),
                policy_id: request.policy_id.clone(),
                origin: request.origin,
                selector: request.selector.clone(),
                reason: format!("{} (shadowed by {shadow})", request.reason),
                status: "UNSUPPORTED".to_string(),
                matched_unit_ids: Vec::new(),
                matched_finding_ids: Vec::new(),
            });
        }
    }

    let mut dispositions = Vec::new();
    for finding in findings {
        if let Some(winner) = exemption_winner.get(finding.finding_id.as_str()) {
            dispositions.push(Disposition {
                finding_id: finding.finding_id.clone(),
                status: "EXEMPTED".to_string(),
                request_id: Some(winner.request_id.clone()),
                policy_id: Some(winner.policy_id.clone()),
                origin: Some(winner.origin),
                reason: Some(winner.reason.clone()),
            });
        } else {
            dispositions.push(Disposition {
                finding_id: finding.finding_id.clone(),
                status: "ACTIONABLE".to_string(),
                request_id: None,
                policy_id: None,
                origin: None,
                reason: None,
            });
        }
    }

    requests.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    applied_blocks.sort_by(|left, right| {
        (left.unit_id.as_str(), left.request_id.as_str())
            .cmp(&(right.unit_id.as_str(), right.request_id.as_str()))
    });
    dispositions.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    let effective = spec.effective_policies.clone();
    let effective_digest = digest_canonical(&effective)?;
    let errors = if spec.errors.is_empty() {
        None
    } else {
        let mut errors = spec.errors.clone();
        errors.sort();
        errors.dedup();
        Some(errors)
    };
    let record = PolicyRecord {
        schema_version: SCHEMA_VERSION.to_string(),
        run_id: run_id.to_string(),
        policy_valid: errors.is_none(),
        errors,
        effective_policy_digest: effective_digest,
        effective_policies: effective,
        requests,
        applied_blocks,
        dispositions,
    };
    Ok(record)
}

pub fn digest_canonical<T: Serialize + ?Sized>(value: &T) -> Result<String, CoreError> {
    let serialized =
        serde_json::to_value(value).map_err(|error| CoreError::Json(error.to_string()))?;
    let bytes =
        serde_json::to_vec(&serialized).map_err(|error| CoreError::Json(error.to_string()))?;
    Ok(digest_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_grammar_is_segment_oriented() {
        let glob = ScopeGlob::parse("secrets/**/*.txt").unwrap();
        assert!(glob.matches("secrets/a.txt"));
        assert!(glob.matches("secrets/nested/deep/a.txt"));
        assert!(!glob.matches("other/a.txt"));
        assert!(!glob.matches("secrets/a.md"));
        assert!(ScopeGlob::parse("../secret").is_err());
        assert!(ScopeGlob::parse("/absolute").is_err());
        assert!(ScopeGlob::parse("a\\b").is_err());
        assert!(ScopeGlob::parse("a/[bc]").is_err());
    }

    #[test]
    fn request_identity_is_stable() {
        assert_eq!(
            request_id("POL", "BLOCK", "secrets/**"),
            request_id("POL", "BLOCK", "secrets/**")
        );
        assert_ne!(
            request_id("POL", "BLOCK", "secrets/**"),
            request_id("POL", "EXEMPTION", "secrets/**")
        );
    }

    #[test]
    fn exemption_selector_supports_narrow_composites() {
        assert!(parse_exemption_selector("rule:synthetic-aws;path:fixtures/**").is_ok());
        assert!(parse_exemption_selector("finding:f-").is_err());
        assert!(parse_exemption_selector("rule:x;fingerprint:sha256:bad").is_err());
        assert!(parse_exemption_selector("rule:x;rule:y").is_err());
    }
    #[test]
    fn overlapping_blocks_have_one_winner_and_preserve_requests() {
        let mut spec = PolicySpec::empty();
        spec.add_block(
            "WIDE",
            PolicyOrigin::Repository,
            "secrets/**",
            "wide",
            "1",
            false,
        )
        .unwrap();
        spec.add_block(
            "NARROW",
            PolicyOrigin::Repository,
            "secrets/a.txt",
            "narrow",
            "1",
            false,
        )
        .unwrap();
        let wide = spec.blocks.iter().find(|b| b.policy_id == "WIDE").unwrap();
        let narrow = spec
            .blocks
            .iter()
            .find(|b| b.policy_id == "NARROW")
            .unwrap();
        let unit = crate::input::DiscoveredUnit {
            unit_id: crate::path::unit_id("local-working-tree", "secrets/a.txt").unwrap(),
            locator: "secrets/a.txt".to_string(),
            path: std::path::PathBuf::from("secrets/a.txt"),
            size: 10,
            modified: None,
            required_scope: true,
            scope: crate::input::PreScanScope::Blocked,
            block_matches: vec![wide.request_id.clone(), narrow.request_id.clone()],
            block_request_id: Some(narrow.request_id.clone()),
        };
        let policy = build_policy("r", &[unit], &[], &spec, 0).unwrap();
        assert_eq!(policy.applied_blocks.len(), 1);
        assert_eq!(policy.applied_blocks[0].policy_id, "NARROW");
        let statuses: std::collections::BTreeMap<_, _> = policy
            .requests
            .iter()
            .map(|request| (request.policy_id.as_str(), request.status.as_str()))
            .collect();
        assert_eq!(statuses["NARROW"], "APPLIED");
        assert_eq!(statuses["WIDE"], "UNSUPPORTED");
    }
}
