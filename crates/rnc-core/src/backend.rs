//! Portable matching backends and deterministic execution planning.
//!
//! The reference regex backend is authoritative. RegexSet and Aho-Corasick
//! strategies are acceleration plans: they must produce exactly the same
//! candidates as the reference backend for every supported rule. A rule without
//! a proven required literal is always evaluated by its exact regex in the
//! prefilter strategy, and an unbuildable plan falls back explicitly.

use std::fmt;

use aho_corasick::AhoCorasick;
use regex::bytes::{Regex, RegexSet};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::rules::LoadedBundle;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendRequest {
    Regex,
    RegexSet,
    Prefilter,
    Auto,
}

impl BackendRequest {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::RegexSet => "regexset",
            Self::Prefilter => "prefilter",
            Self::Auto => "auto",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CoreError> {
        match value {
            "regex" => Ok(Self::Regex),
            "regexset" => Ok(Self::RegexSet),
            "prefilter" => Ok(Self::Prefilter),
            "auto" => Ok(Self::Auto),
            _ => Err(CoreError::Input(
                "strategy must be regex, regexset, prefilter or auto".to_string(),
            )),
        }
    }
}

impl Default for BackendRequest {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub multi_pattern: bool,
    pub capture_groups: bool,
    pub literal_prefilter: bool,
    pub streaming_safe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanProvenance {
    pub requested: BackendRequest,
    pub effective: BackendRequest,
    pub implementation: String,
    pub version: String,
    pub rule_count: usize,
    pub rules_with_required_literals: usize,
    pub rules_without_required_literals: usize,
    pub fallback_used: bool,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MatchCandidate {
    pub rule_index: usize,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug)]
pub enum MatchError {
    Timeout,
    Backend(String),
}

impl fmt::Display for MatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("match deadline exceeded"),
            Self::Backend(message) => write!(formatter, "match backend failed: {message}"),
        }
    }
}

pub struct MatchPlan<'a> {
    bundle: &'a LoadedBundle,
    effective: BackendRequest,
    provenance: PlanProvenance,
    regexset: Option<RegexSet>,
    prefilter: Option<AhoCorasick>,
    prefilter_pattern_rule: Vec<usize>,
    rules_without_literals: Vec<usize>,
}

impl<'a> MatchPlan<'a> {
    pub fn new(bundle: &'a LoadedBundle, requested: BackendRequest) -> Result<Self, CoreError> {
        let with_literals = bundle
            .compiled
            .iter()
            .filter(|rule| rule.required_literal.is_some())
            .count();
        let without_literals = bundle.compiled.len() - with_literals;
        let mut fallback_reason = None;

        let effective = match requested {
            BackendRequest::Regex => BackendRequest::Regex,
            BackendRequest::RegexSet => BackendRequest::RegexSet,
            BackendRequest::Prefilter => BackendRequest::Prefilter,
            BackendRequest::Auto => {
                // No portable alternative has demonstrated a defensible
                // whole-workload advantage over the reference matcher for the
                // current bundle. Automatic routing therefore stays on the
                // reference strategy; regexset and prefilter are explicit
                // choices backed by the differential gate.
                BackendRequest::Regex
            }
        };

        let mut regexset = None;
        let mut prefilter = None;
        let mut prefilter_pattern_rule = Vec::new();
        let mut effective = effective;

        if effective == BackendRequest::RegexSet {
            let patterns: Vec<&str> = bundle
                .compiled
                .iter()
                .map(|rule| rule.definition.pattern.as_str())
                .collect();
            match RegexSet::new(patterns) {
                Ok(set) => regexset = Some(set),
                Err(error) => {
                    fallback_reason = Some(format!(
                        "RegexSet could not compile the bundle; reference regex used: {error}"
                    ));
                    effective = BackendRequest::Regex;
                }
            }
        }

        if effective == BackendRequest::Prefilter {
            let mut patterns: Vec<Vec<u8>> = Vec::new();
            for (index, rule) in bundle.compiled.iter().enumerate() {
                if let Some(literal) = &rule.required_literal {
                    patterns.push(literal.clone());
                    prefilter_pattern_rule.push(index);
                }
            }
            if patterns.is_empty() {
                fallback_reason =
                    Some("no rule had a proven required literal; reference regex used".to_string());
                effective = BackendRequest::Regex;
            } else {
                match AhoCorasick::builder().build(&patterns) {
                    Ok(ac) => prefilter = Some(ac),
                    Err(error) => {
                        fallback_reason = Some(format!(
                            "Aho-Corasick prefilter could not be built; reference regex used: {error}"
                        ));
                        effective = BackendRequest::Regex;
                    }
                }
            }
        }

        let rules_without_literals = bundle
            .compiled
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.required_literal.is_none())
            .map(|(index, _)| index)
            .collect();

        if effective == BackendRequest::Prefilter && without_literals > 0 {
            fallback_reason = Some(format!(
                "{without_literals} rule(s) have no proven literal and use exact regex fallback"
            ));
        }
        let provenance = PlanProvenance {
            requested,
            effective,
            implementation: "rnc-match-backend".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            rule_count: bundle.compiled.len(),
            rules_with_required_literals: with_literals,
            rules_without_required_literals: without_literals,
            fallback_used: fallback_reason.is_some(),
            fallback_reason,
        };

        Ok(Self {
            bundle,
            effective,
            provenance,
            regexset,
            prefilter,
            prefilter_pattern_rule,
            rules_without_literals,
        })
    }

    pub fn bundle(&self) -> &LoadedBundle {
        self.bundle
    }

    pub fn provenance(&self) -> &PlanProvenance {
        &self.provenance
    }

    pub fn effective(&self) -> BackendRequest {
        self.effective
    }

    pub fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            multi_pattern: matches!(
                self.effective,
                BackendRequest::RegexSet | BackendRequest::Prefilter
            ),
            capture_groups: true,
            literal_prefilter: self.effective == BackendRequest::Prefilter,
            streaming_safe: true,
        }
    }

    /// Return candidates with exact capture-group byte spans. The caller owns
    /// validation, deduplication and finding construction.
    pub fn candidates(
        &self,
        data: &[u8],
        deadline: std::time::Instant,
    ) -> Result<Vec<MatchCandidate>, MatchError> {
        match self.effective {
            BackendRequest::Regex => self.regex_candidates(data, None, deadline),
            BackendRequest::RegexSet => {
                let set = self
                    .regexset
                    .as_ref()
                    .ok_or_else(|| MatchError::Backend("RegexSet plan lost its set".to_string()))?;
                let matched = set.matches(data);
                let mut candidates = Vec::new();
                for index in matched.iter() {
                    candidates.extend(self.rule_candidates(index, data, deadline)?);
                }
                Ok(candidates)
            }
            BackendRequest::Prefilter => {
                let prefilter = self.prefilter.as_ref().ok_or_else(|| {
                    MatchError::Backend("prefilter plan lost its automaton".to_string())
                })?;
                let mut eligible = vec![false; self.bundle.compiled.len()];
                for index in &self.rules_without_literals {
                    eligible[*index] = true;
                }
                for found in prefilter.find_overlapping_iter(data) {
                    if let Some(rule) = self.prefilter_pattern_rule.get(found.pattern().as_usize())
                    {
                        eligible[*rule] = true;
                    }
                }
                let mut candidates = Vec::new();
                for (index, enabled) in eligible.into_iter().enumerate() {
                    if enabled {
                        candidates.extend(self.rule_candidates(index, data, deadline)?);
                    }
                }
                Ok(candidates)
            }
            BackendRequest::Auto => unreachable!("auto is resolved by the planner"),
        }
    }

    fn regex_candidates(
        &self,
        data: &[u8],
        only: Option<usize>,
        deadline: std::time::Instant,
    ) -> Result<Vec<MatchCandidate>, MatchError> {
        let mut candidates = Vec::new();
        for (index, rule) in self.bundle.compiled.iter().enumerate() {
            if only.is_some_and(|value| value != index) {
                continue;
            }
            candidates.extend(self.rule_candidates_from(&rule.regex, index, data, deadline)?);
        }
        Ok(candidates)
    }

    fn rule_candidates(
        &self,
        index: usize,
        data: &[u8],
        deadline: std::time::Instant,
    ) -> Result<Vec<MatchCandidate>, MatchError> {
        let rule = self
            .bundle
            .compiled
            .get(index)
            .ok_or_else(|| MatchError::Backend("rule index outside bundle".to_string()))?;
        self.rule_candidates_from(&rule.regex, index, data, deadline)
    }

    fn rule_candidates_from(
        &self,
        regex: &Regex,
        index: usize,
        data: &[u8],
        deadline: std::time::Instant,
    ) -> Result<Vec<MatchCandidate>, MatchError> {
        let capture_group = self.bundle.compiled[index].definition.capture_group;
        let mut candidates = Vec::new();
        for captures in regex.captures_iter(data) {
            if std::time::Instant::now() >= deadline {
                return Err(MatchError::Timeout);
            }
            if let Some(matched) = captures.get(capture_group) {
                if matched.start() < matched.end() {
                    candidates.push(MatchCandidate {
                        rule_index: index,
                        start: matched.start(),
                        end: matched.end(),
                    });
                }
            }
        }
        Ok(candidates)
    }
}

/// Conservative required-literal extraction.
///
/// A returned literal is present in every match. `None` means the planner could
/// not prove a literal and must keep the rule on exact regex evaluation.
pub fn required_literal(pattern: &str) -> Result<Option<Vec<u8>>, String> {
    let hir = regex_syntax::Parser::new()
        .parse(pattern)
        .map_err(|error| error.to_string())?;
    match required_prefix(&hir) {
        Some(value) if !value.is_empty() => Ok(Some(value)),
        _ => Ok(None),
    }
}

fn required_prefix(hir: &regex_syntax::hir::Hir) -> Option<Vec<u8>> {
    use regex_syntax::hir::{HirKind, Literal};
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(Vec::new()),
        HirKind::Literal(Literal(bytes)) => Some(bytes.to_vec()),
        HirKind::Capture(capture) => required_prefix(&capture.sub),
        HirKind::Repetition(repetition) => {
            if repetition.min >= 1 {
                required_prefix(&repetition.sub)
            } else {
                None
            }
        }
        HirKind::Concat(parts) => {
            let mut output = Vec::new();
            for part in parts {
                match literal_piece(part) {
                    Some(piece) => output.extend_from_slice(&piece),
                    None => break,
                }
            }
            if output.is_empty() {
                None
            } else {
                Some(output)
            }
        }
        HirKind::Alternation(branches) => {
            let mut iter = branches.iter();
            let first = required_prefix(iter.next()?)?;
            let mut common = first;
            for branch in iter {
                let candidate = required_prefix(branch)?;
                let length = common
                    .iter()
                    .zip(candidate.iter())
                    .take_while(|(left, right)| left == right)
                    .count();
                common.truncate(length);
            }
            if common.is_empty() {
                None
            } else {
                Some(common)
            }
        }
        HirKind::Class(class) => single_byte_class(class),
    }
}

fn single_byte_class(class: &regex_syntax::hir::Class) -> Option<Vec<u8>> {
    match class {
        regex_syntax::hir::Class::Bytes(bytes) => {
            let ranges = bytes.ranges();
            if ranges.len() == 1 && ranges[0].start() == ranges[0].end() {
                Some(vec![ranges[0].start()])
            } else {
                None
            }
        }
        regex_syntax::hir::Class::Unicode(unicode) => {
            let ranges = unicode.ranges();
            if ranges.len() == 1 && ranges[0].start() == ranges[0].end() {
                let value = ranges[0].start();
                if value.is_ascii() {
                    Some(vec![value as u8])
                } else {
                    None
                }
            } else {
                None
            }
        }
    }
}

/// A contiguous literal prefix that may be consumed before a variable part.
fn literal_piece(hir: &regex_syntax::hir::Hir) -> Option<Vec<u8>> {
    use regex_syntax::hir::{HirKind, Literal};
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => Some(Vec::new()),
        HirKind::Literal(Literal(bytes)) => Some(bytes.to_vec()),
        HirKind::Capture(capture) => literal_piece(&capture.sub),
        HirKind::Repetition(repetition) => {
            if repetition.min >= 1 {
                literal_piece(&repetition.sub)
            } else {
                None
            }
        }
        HirKind::Concat(parts) => {
            let mut output = Vec::new();
            for part in parts {
                output.extend_from_slice(&literal_piece(part)?);
            }
            Some(output)
        }
        HirKind::Alternation(branches) => {
            let mut iter = branches.iter();
            let first = literal_piece(iter.next()?)?;
            let mut common = first;
            for branch in iter {
                let candidate = literal_piece(branch)?;
                let length = common
                    .iter()
                    .zip(candidate.iter())
                    .take_while(|(left, right)| left == right)
                    .count();
                common.truncate(length);
            }
            if common.is_empty() {
                None
            } else {
                Some(common)
            }
        }
        HirKind::Class(class) => single_byte_class(class),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_required_literals_conservatively() {
        assert_eq!(
            required_literal("RNC_SYNTH_KEY_AWS_[A-Z0-9_]{1,64}").unwrap(),
            Some(b"RNC_SYNTH_KEY_AWS_".to_vec())
        );
        assert_eq!(
            required_literal("(?:PREFIX|PREFIX_ALT)_[A-Z]+").unwrap(),
            Some(b"PREFIX_".to_vec())
        );
        assert_eq!(required_literal("(?:A|B)[A-Z]+").unwrap(), None);
        assert_eq!(required_literal("[A-Z]{1,4}").unwrap(), None);
    }

    #[test]
    fn plan_resolves_auto_and_explicit() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../rules/rnc-synthetic-v1.json");
        let bundle = LoadedBundle::load(&path).unwrap();
        for request in [
            BackendRequest::Regex,
            BackendRequest::RegexSet,
            BackendRequest::Prefilter,
            BackendRequest::Auto,
        ] {
            let plan = MatchPlan::new(&bundle, request).unwrap();
            assert!(plan.provenance().rule_count >= 10);
            let candidates = plan
                .candidates(
                    b"RNC_SYNTH_KEY_AWS_ALPHA\n",
                    std::time::Instant::now() + std::time::Duration::from_secs(5),
                )
                .unwrap();
            assert!(!candidates.is_empty());
        }
    }
}
