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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureSpan {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub struct MatchCandidate {
    pub rule_index: usize,
    pub start: usize,
    pub end: usize,
    pub match_start: usize,
    pub match_end: usize,
    pub identifier: Option<CaptureSpan>,
}

#[derive(Debug)]
pub enum MatchError {
    Timeout,
    CandidateLimit,
    Backend(String),
}

impl fmt::Display for MatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("match deadline exceeded"),
            Self::CandidateLimit => formatter.write_str("candidate budget exceeded"),
            Self::Backend(message) => write!(formatter, "match backend failed: {message}"),
        }
    }
}

/// Bound candidate materialization per window. Rust regex execution is linear,
/// but a pathological file containing millions of matching spans could still
/// consume unbounded memory when all captures are materialized. Exceeding this
/// budget makes the source unit uninspected and the execution incomplete.
pub const MAX_CANDIDATES_PER_WINDOW: usize = 100_000;

pub struct MatchPlan<'a> {
    bundle: &'a LoadedBundle,
    effective: BackendRequest,
    provenance: PlanProvenance,
    regexset: Option<RegexSet>,
    regexset_pattern_rule: Vec<usize>,
    prefilter: Option<AhoCorasick>,
    prefilter_pattern_rule: Vec<usize>,
    rules_without_literals: Vec<usize>,
}

/// Maximum number of alternative literals retained for one rule. More than this
/// makes the filter less useful than simply running the exact regex, so the
/// planner falls back to an unfiltered rule instead.
const MAX_REQUIRED_LITERALS: usize = 64;
const MAX_REQUIRED_LITERAL_BYTES: usize = 4096;

impl<'a> MatchPlan<'a> {
    pub fn new(bundle: &'a LoadedBundle, requested: BackendRequest) -> Result<Self, CoreError> {
        let with_literals = bundle
            .compiled
            .iter()
            .filter(|rule| rule.has_required_literals())
            .count();
        let without_literals = bundle.compiled.len() - with_literals;
        let mut fallback_reason = None;

        let effective = match requested {
            BackendRequest::Regex => BackendRequest::Regex,
            BackendRequest::RegexSet => BackendRequest::RegexSet,
            BackendRequest::Prefilter => BackendRequest::Prefilter,
            BackendRequest::Auto => {
                // The literal-prefilter plan performs one Aho-Corasick pass and
                // then evaluates only rules whose necessary literals occur.
                // Differential tests require exactly the same candidates and
                // findings as the reference regex backend, while large
                // filesystem loads improved materially. `regex` remains the
                // explicit reference path; `regexset` remains available.
                BackendRequest::Prefilter
            }
        };

        let mut regexset = None;
        let mut regexset_pattern_rule = Vec::new();
        let mut prefilter = None;
        let mut prefilter_pattern_rule = Vec::new();
        let mut effective = effective;

        if effective == BackendRequest::RegexSet {
            let mut patterns = Vec::new();
            for (index, rule) in bundle.compiled.iter().enumerate() {
                for literal in rule.required_literals.iter().flatten() {
                    patterns.push(literal_regex(literal));
                    regexset_pattern_rule.push(index);
                }
            }
            if patterns.is_empty() {
                fallback_reason =
                    Some("no rule had a proven required literal; reference regex used".to_string());
                effective = BackendRequest::Regex;
            } else {
                match RegexSet::new(&patterns) {
                    Ok(set) => regexset = Some(set),
                    Err(error) => {
                        fallback_reason = Some(format!(
                            "RegexSet could not compile the literal filter; reference regex used: {error}"
                        ));
                        effective = BackendRequest::Regex;
                    }
                }
            }
        }

        if effective == BackendRequest::Prefilter {
            let mut patterns: Vec<Vec<u8>> = Vec::new();
            for (index, rule) in bundle.compiled.iter().enumerate() {
                for literal in rule.required_literals.iter().flatten() {
                    patterns.push(literal.clone());
                    prefilter_pattern_rule.push(index);
                }
            }
            if patterns.is_empty() {
                fallback_reason =
                    Some("no rule had a proven required literal; reference regex used".to_string());
                effective = BackendRequest::Regex;
            } else {
                match AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                {
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
            .filter(|(_, rule)| !rule.has_required_literals())
            .map(|(index, _)| index)
            .collect();

        if matches!(
            effective,
            BackendRequest::Prefilter | BackendRequest::RegexSet
        ) && without_literals > 0
        {
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
            regexset_pattern_rule,
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
        self.candidates_profiled(data, deadline, None)
    }

    pub fn candidates_profiled(
        &self,
        data: &[u8],
        deadline: std::time::Instant,
        profiler: Option<&crate::profile::Profiler>,
    ) -> Result<Vec<MatchCandidate>, MatchError> {
        match self.effective {
            BackendRequest::Regex => {
                let started = std::time::Instant::now();
                let candidates = self.regex_candidates(data, deadline);
                if let (Some(profiler), Ok(found)) = (profiler, &candidates) {
                    profiler.record_worker(
                        "matching.regex",
                        started.elapsed(),
                        data.len() as u64,
                        found.len() as u64,
                    );
                }
                candidates
            }
            BackendRequest::RegexSet => {
                let set = self
                    .regexset
                    .as_ref()
                    .ok_or_else(|| MatchError::Backend("RegexSet plan lost its set".to_string()))?;
                let literal_started = std::time::Instant::now();
                let mut eligible = vec![false; self.bundle.compiled.len()];
                for index in &self.rules_without_literals {
                    eligible[*index] = true;
                }
                for index in set.matches(data).iter() {
                    if let Some(rule) = self.regexset_pattern_rule.get(index) {
                        eligible[*rule] = true;
                    }
                }
                if let Some(profiler) = profiler {
                    profiler.record_worker(
                        "matching.literal_filter",
                        literal_started.elapsed(),
                        data.len() as u64,
                        1,
                    );
                }
                let regex_started = std::time::Instant::now();
                let mut candidates = Vec::new();
                for (index, enabled) in eligible.into_iter().enumerate() {
                    if enabled {
                        candidates.extend(self.rule_candidates(index, data, deadline)?);
                        if candidates.len() > MAX_CANDIDATES_PER_WINDOW {
                            return Err(MatchError::CandidateLimit);
                        }
                    }
                }
                if let Some(profiler) = profiler {
                    profiler.record_worker(
                        "matching.regex",
                        regex_started.elapsed(),
                        data.len() as u64,
                        candidates.len() as u64,
                    );
                }
                Ok(candidates)
            }
            BackendRequest::Prefilter => {
                let prefilter = self.prefilter.as_ref().ok_or_else(|| {
                    MatchError::Backend("prefilter plan lost its automaton".to_string())
                })?;
                let literal_started = std::time::Instant::now();
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
                if let Some(profiler) = profiler {
                    profiler.record_worker(
                        "matching.literal_filter",
                        literal_started.elapsed(),
                        data.len() as u64,
                        1,
                    );
                }
                let regex_started = std::time::Instant::now();
                let mut candidates = Vec::new();
                for (index, enabled) in eligible.into_iter().enumerate() {
                    if enabled {
                        candidates.extend(self.rule_candidates(index, data, deadline)?);
                        if candidates.len() > MAX_CANDIDATES_PER_WINDOW {
                            return Err(MatchError::CandidateLimit);
                        }
                    }
                }
                if let Some(profiler) = profiler {
                    profiler.record_worker(
                        "matching.regex",
                        regex_started.elapsed(),
                        data.len() as u64,
                        candidates.len() as u64,
                    );
                }
                Ok(candidates)
            }
            BackendRequest::Auto => unreachable!("auto is resolved by the planner"),
        }
    }

    fn regex_candidates(
        &self,
        data: &[u8],
        deadline: std::time::Instant,
    ) -> Result<Vec<MatchCandidate>, MatchError> {
        let mut candidates = Vec::new();
        for (index, rule) in self.bundle.compiled.iter().enumerate() {
            candidates.extend(self.rule_candidates_from(&rule.regex, index, data, deadline)?);
            if candidates.len() > MAX_CANDIDATES_PER_WINDOW {
                return Err(MatchError::CandidateLimit);
            }
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
        let definition = &self.bundle.compiled[index].definition;
        let capture_groups: &[usize] = definition
            .value_capture_groups
            .as_deref()
            .unwrap_or(std::slice::from_ref(&definition.capture_group));
        let mut candidates = Vec::new();
        for captures in regex.captures_iter(data) {
            if std::time::Instant::now() >= deadline {
                return Err(MatchError::Timeout);
            }
            let Some(full_match) = captures.get(0) else {
                continue;
            };
            let matched = capture_groups.iter().find_map(|group| captures.get(*group));
            if let Some(matched) = matched {
                if matched.start() < matched.end() {
                    let identifier = definition
                        .identifier_capture_group
                        .and_then(|group| captures.get(group))
                        .map(|captured| CaptureSpan {
                            start: captured.start(),
                            end: captured.end(),
                        });
                    candidates.push(MatchCandidate {
                        rule_index: index,
                        start: matched.start(),
                        end: matched.end(),
                        match_start: full_match.start(),
                        match_end: full_match.end(),
                        identifier,
                    });
                    if candidates.len() > MAX_CANDIDATES_PER_WINDOW {
                        return Err(MatchError::CandidateLimit);
                    }
                }
            }
        }
        Ok(candidates)
    }
}

/// Conservative required-literal extraction.
///
/// The returned set has the property that every match of the rule contains at
/// least one member. An empty result means the planner could not prove a
/// literal and must keep the rule on exact regex evaluation.
///
/// Literals are matched ASCII-case-insensitively by the filter. The pattern is
/// normalized to remove case-insensitivity before HIR extraction so a
/// case-insensitive keyword can still contribute a useful required literal;
/// widening the filter is safe because every eligible rule is re-evaluated by
/// its exact regex.
pub fn required_literals(pattern: &str) -> Result<Option<Vec<Vec<u8>>>, String> {
    let normalized = without_case_insensitive_flags(pattern);
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .build()
        .parse(&normalized)
        .or_else(|_| {
            // A pattern whose flag rewrite is not parseable keeps the safe
            // fallback of exact regex evaluation.
            regex_syntax::ParserBuilder::new()
                .utf8(false)
                .build()
                .parse(pattern)
        })
        .map_err(|error| error.to_string())?;
    let Some(mut literals) = required_any_set(&hir) else {
        return Ok(None);
    };
    literals.retain(|value| !value.is_empty());
    literals.sort();
    literals.dedup();
    minimize_required_literals(&mut literals);
    if literals.is_empty()
        || literals.len() > MAX_REQUIRED_LITERALS
        || literals.iter().map(Vec::len).sum::<usize>() > MAX_REQUIRED_LITERAL_BYTES
    {
        return Ok(None);
    }
    Ok(Some(literals))
}

/// Remove a literal when a shorter member is contained in it. A match that
/// contains the longer literal necessarily contains the shorter one, so the
/// filter remains complete while issuing fewer redundant patterns.
fn minimize_required_literals(literals: &mut Vec<Vec<u8>>) {
    literals.sort_by_key(Vec::len);
    let mut kept: Vec<Vec<u8>> = Vec::with_capacity(literals.len());
    for candidate in literals.iter() {
        if kept.iter().any(|short| contains_ascii_ci(candidate, short)) {
            continue;
        }
        kept.push(candidate.clone());
    }
    *literals = kept;
}

fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Return a set of literals such that every match contains at least one of
/// them. A concatenation needs one part's set; an alternation needs every
/// branch's set. `None` means no such set could be proven.
fn required_any_set(hir: &regex_syntax::hir::Hir) -> Option<Vec<Vec<u8>>> {
    use regex_syntax::hir::{HirKind, Literal};
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => None,
        HirKind::Literal(Literal(bytes)) => {
            if bytes.is_empty() {
                None
            } else {
                Some(vec![bytes.to_vec()])
            }
        }
        HirKind::Class(class) => class_literals(class),
        HirKind::Capture(capture) => required_any_set(&capture.sub),
        HirKind::Repetition(repetition) => {
            if repetition.min >= 1 {
                required_any_set(&repetition.sub)
            } else {
                None
            }
        }
        HirKind::Concat(parts) => {
            let mut best: Option<Vec<Vec<u8>>> = None;
            for part in parts {
                if let Some(candidate) = required_any_set(part) {
                    if best
                        .as_ref()
                        .is_none_or(|current| set_score(&candidate) > set_score(current))
                    {
                        best = Some(candidate);
                    }
                }
            }
            best
        }
        HirKind::Alternation(branches) => {
            let mut union = Vec::new();
            for branch in branches {
                union.extend(required_any_set(branch)?);
            }
            if union.is_empty() {
                None
            } else {
                Some(union)
            }
        }
    }
}

/// Prefer the set with the longest guaranteed literal, then the fewest
/// alternatives. Both reduce the number of rules that run unnecessarily while
/// preserving the necessary-literal property.
fn set_score(set: &[Vec<u8>]) -> (usize, usize) {
    let shortest = set.iter().map(Vec::len).min().unwrap_or(0);
    (shortest, usize::MAX - set.len())
}

/// Remove `i` from inline regex flag groups. The resulting pattern is used only
/// for required-literal extraction, never for matching.
fn without_case_insensitive_flags(pattern: &str) -> String {
    const FLAGS: &[u8] = b"imsUuxR";
    let bytes = pattern.as_bytes();
    let mut output = String::with_capacity(pattern.len());
    let mut index = 0usize;
    let mut in_class = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            output.push(byte as char);
            index += 1;
            if index < bytes.len() {
                output.push(bytes[index] as char);
                index += 1;
            }
            continue;
        }
        if in_class {
            output.push(byte as char);
            if byte == b']' {
                in_class = false;
            }
            index += 1;
            continue;
        }
        if byte == b'[' {
            in_class = true;
            output.push('[');
            index += 1;
            continue;
        }
        if byte == b'(' && bytes.get(index + 1) == Some(&b'?') {
            let flags_start = index + 2;
            let mut cursor = flags_start;
            while cursor < bytes.len() && (FLAGS.contains(&bytes[cursor]) || bytes[cursor] == b'-')
            {
                cursor += 1;
            }
            if cursor > flags_start
                && matches!(bytes.get(cursor), Some(b':') | Some(b')'))
                && cursor < bytes.len()
            {
                let scoped = bytes[cursor] == b':';
                let mut positive = String::new();
                let mut negative = String::new();
                let mut negating = false;
                for &flag in &bytes[flags_start..cursor] {
                    match flag {
                        b'-' => negating = true,
                        b'i' => {}
                        _ if negating => negative.push(flag as char),
                        _ => positive.push(flag as char),
                    }
                }
                if scoped {
                    if positive.is_empty() && negative.is_empty() {
                        output.push_str("(?:");
                    } else {
                        output.push_str("(?");
                        output.push_str(&positive);
                        if !negative.is_empty() {
                            output.push('-');
                            output.push_str(&negative);
                        }
                        output.push(':');
                    }
                } else if !(positive.is_empty() && negative.is_empty()) {
                    output.push_str("(?");
                    output.push_str(&positive);
                    if !negative.is_empty() {
                        output.push('-');
                        output.push_str(&negative);
                    }
                    output.push(')');
                }
                index = cursor + 1;
                continue;
            }
        }
        output.push(byte as char);
        index += 1;
    }
    output
}

fn literal_regex(literal: &[u8]) -> String {
    // The required-literal filter is deliberately ASCII-case-insensitive:
    // matching more candidates than necessary is safe because every eligible
    // rule is still evaluated by its exact regex. This also lets a
    // case-insensitive rule contribute a useful literal instead of falling back
    // to an unfiltered scan.
    let mut pattern = String::from("(?i-u)");
    for byte in literal {
        pattern.push_str(&format!("\\x{byte:02X}"));
    }
    pattern
}

/// Expand a small byte class into its members. The regex parser commonly
/// factors short alternations such as `(?:A|B)` into a class, so this recovers
/// the original literal alternatives without making large classes noisy.
fn class_literals(class: &regex_syntax::hir::Class) -> Option<Vec<Vec<u8>>> {
    const MAX_CLASS_LITERALS: usize = 8;
    let mut values = Vec::new();
    match class {
        regex_syntax::hir::Class::Bytes(bytes) => {
            for range in bytes.ranges() {
                for value in range.start()..=range.end() {
                    values.push(vec![value]);
                    if values.len() > MAX_CLASS_LITERALS {
                        return None;
                    }
                }
            }
        }
        regex_syntax::hir::Class::Unicode(unicode) => {
            for range in unicode.ranges() {
                for value in range.start()..=range.end() {
                    if !value.is_ascii() {
                        return None;
                    }
                    values.push(vec![value as u8]);
                    if values.len() > MAX_CLASS_LITERALS {
                        return None;
                    }
                }
            }
        }
    }
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_required_literals_conservatively() {
        assert_eq!(
            required_literals("RNC_SYNTH_KEY_AWS_[A-Z0-9_]{1,64}").unwrap(),
            Some(vec![b"RNC_SYNTH_KEY_AWS_".to_vec()])
        );
        assert_eq!(
            required_literals("(?:PREFIX|PREFIX_ALT)_[A-Z]+").unwrap(),
            Some(vec![b"PREFIX".to_vec()])
        );
        assert_eq!(
            required_literals("(?:A|B)[A-Z]+").unwrap(),
            Some(vec![b"A".to_vec(), b"B".to_vec()])
        );
        assert_eq!(required_literals("[A-Z]{1,4}").unwrap(), None);
        assert_eq!(
            required_literals("(?i-u)(?:alpha|beta)_secret").unwrap(),
            Some(vec![b"_secret".to_vec()])
        );
        assert_eq!(
            required_literals(r"(?i-u)(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24}").unwrap(),
            Some(vec![b"live".to_vec(), b"test".to_vec()])
        );
        assert_eq!(
            required_literals(r"(?i:authorization)\s*:\s*bearer\s+([A-Za-z0-9._~+/=-]{12,4096})")
                .unwrap(),
            Some(vec![b"authorization".to_vec()])
        );
    }

    #[test]
    fn case_insensitive_flag_rewrite_preserves_other_flags() {
        assert_eq!(without_case_insensitive_flags("(?i)abc"), "abc");
        assert_eq!(without_case_insensitive_flags("(?i-u)abc"), "(?-u)abc");
        assert_eq!(without_case_insensitive_flags("(?im-s)abc"), "(?m-s)abc");
        assert_eq!(without_case_insensitive_flags("(?i:abc)def"), "(?:abc)def");
        assert_eq!(without_case_insensitive_flags("(?-i:abc)"), "(?:abc)");
        assert_eq!(
            without_case_insensitive_flags(r"a[()?i]b(?i)c"),
            r"a[()?i]bc"
        );
    }

    #[test]
    fn regex_backend_enforces_the_aggregate_candidate_budget() {
        let bundle: crate::rules::RuleBundle = serde_json::from_value(serde_json::json!({
            "schema_version": "0.1.0",
            "ruleset_id": "candidate-budget",
            "ruleset_version": "1",
            "rules": [
                {
                    "rule_id": "x-rule",
                    "rule_version": "1",
                    "category": "test",
                    "pattern": "x",
                    "capture_group": 0,
                    "validators": ["ASCII_ONLY"],
                    "confidence": "low",
                    "max_match_bytes": 1
                },
                {
                    "rule_id": "y-rule",
                    "rule_version": "1",
                    "category": "test",
                    "pattern": "y",
                    "capture_group": 0,
                    "validators": ["ASCII_ONLY"],
                    "confidence": "low",
                    "max_match_bytes": 1
                }
            ]
        }))
        .unwrap();
        let bundle = LoadedBundle::from_bundle(bundle).unwrap();
        let plan = MatchPlan::new(&bundle, BackendRequest::Regex).unwrap();
        let mut data = vec![b'x'; 60_000];
        data.extend(std::iter::repeat_n(b'y', 60_000));
        let error = plan
            .candidates(
                &data,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .unwrap_err();
        assert!(matches!(error, MatchError::CandidateLimit));
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
        let automatic = MatchPlan::new(&bundle, BackendRequest::Auto).unwrap();
        assert_eq!(automatic.effective(), BackendRequest::Prefilter);
    }
}
