//! Private structured-component evidence derived after detection and validation.
//!
//! Component extraction never changes the primary finding, its rule identity or
//! its evidence span. Database URI findings retain the contextual userinfo
//! capture; this module derives a supplementary password byte range and digests
//! for the private report only.

use serde::{Deserialize, Serialize};

use crate::path::sha256_hex;

pub const STRUCTURED_EVIDENCE_VERSION: &str = "1";
pub const DATABASE_PASSWORD_KIND: &str = "database-password";
pub const DATABASE_PASSWORD_EXTRACTOR: &str = "database-uri-password";
pub const ANSI_SGR_NORMALIZATION: &str = "ansi-sgr-v1";

const ANSI_ESCAPE: u8 = 0x1b;
const MAX_SGR_SEQUENCE_BYTES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredComponent {
    pub finding_id: String,
    pub unit_id: String,
    pub kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_end: Option<usize>,
    pub source_sha256: String,
    pub normalized_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalization: Option<String>,
    pub ansi: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredEvidence {
    pub version: String,
    pub components: Vec<StructuredComponent>,
}

impl Default for StructuredEvidence {
    fn default() -> Self {
        Self::new()
    }
}

impl StructuredEvidence {
    pub fn new() -> Self {
        Self {
            version: STRUCTURED_EVIDENCE_VERSION.to_string(),
            components: Vec::new(),
        }
    }

    pub fn sort(&mut self) {
        self.components.sort_by(|left, right| {
            (
                &left.unit_id,
                left.start_byte,
                left.end_byte,
                &left.kind,
                &left.finding_id,
            )
                .cmp(&(
                    &right.unit_id,
                    right.start_byte,
                    right.end_byte,
                    &right.kind,
                    &right.finding_id,
                ))
        });
    }
}

/// Dispatch a validated component extractor.
///
/// A rule is only processed here after the primary finding has been emitted.
/// Unknown extractors return no component rather than creating a second
/// detection or an unverified span.
pub fn extract_component(
    extractor: &str,
    candidate: &[u8],
    absolute_candidate_start: usize,
    finding_id: &str,
    unit_id: &str,
    line: usize,
) -> Option<StructuredComponent> {
    match extractor {
        DATABASE_PASSWORD_EXTRACTOR => database_password_component(
            candidate,
            absolute_candidate_start,
            finding_id,
            unit_id,
            line,
        ),
        _ => None,
    }
}

fn database_password_component(
    candidate: &[u8],
    absolute_candidate_start: usize,
    finding_id: &str,
    unit_id: &str,
    line: usize,
) -> Option<StructuredComponent> {
    let visible = visible_map(candidate)?;
    let separator = visible.bytes.iter().position(|byte| *byte == b':')?;
    if separator == 0 {
        return None;
    }
    let password_start = separator.checked_add(1)?;
    if password_start >= visible.bytes.len() {
        return None;
    }
    if visible.unsupported_escape {
        return None;
    }
    let source_start = *visible.offsets.get(password_start)?;
    let source_end = visible.offsets.last()?.checked_add(1)?;
    if source_start >= source_end || source_end > candidate.len() {
        return None;
    }
    let source_bytes = candidate.get(source_start..source_end)?;
    let normalized_bytes = visible.bytes.get(password_start..)?;
    if normalized_bytes.is_empty() {
        return None;
    }
    let has_ansi = !visible.sgr_spans.is_empty();
    let internal = visible
        .sgr_spans
        .iter()
        .any(|(start, end)| *start >= source_start && *end <= source_end);
    let ansi = if !has_ansi {
        "NONE"
    } else if internal {
        "INTERNAL"
    } else {
        "TRIMMED"
    };
    Some(StructuredComponent {
        finding_id: finding_id.to_string(),
        unit_id: unit_id.to_string(),
        kind: DATABASE_PASSWORD_KIND.to_string(),
        start_byte: absolute_candidate_start.checked_add(source_start)?,
        end_byte: absolute_candidate_start.checked_add(source_end)?,
        line,
        line_end: Some(line),
        source_sha256: sha256_hex(source_bytes),
        normalized_sha256: sha256_hex(normalized_bytes),
        normalization: has_ansi.then(|| ANSI_SGR_NORMALIZATION.to_string()),
        ansi: ansi.to_string(),
    })
}

struct VisibleMap {
    bytes: Vec<u8>,
    offsets: Vec<usize>,
    sgr_spans: Vec<(usize, usize)>,
    unsupported_escape: bool,
}

/// Map visible bytes to original candidate offsets. Only canonical CSI SGR
/// sequences are removed. Any other ESC sequence marks the candidate as
/// unsupported; it is never silently discarded.
fn visible_map(candidate: &[u8]) -> Option<VisibleMap> {
    let mut bytes = Vec::with_capacity(candidate.len());
    let mut offsets = Vec::with_capacity(candidate.len());
    let mut sgr_spans = Vec::new();
    let mut unsupported_escape = false;
    let mut index = 0usize;
    while index < candidate.len() {
        if candidate[index] == ANSI_ESCAPE {
            if let Some(end) = sgr_end(candidate, index) {
                sgr_spans.push((index, end));
                index = end;
                continue;
            }
            unsupported_escape = true;
            return Some(VisibleMap {
                bytes,
                offsets,
                sgr_spans,
                unsupported_escape,
            });
        }
        bytes.push(candidate[index]);
        offsets.push(index);
        index += 1;
    }
    Some(VisibleMap {
        bytes,
        offsets,
        sgr_spans,
        unsupported_escape,
    })
}

fn sgr_end(data: &[u8], start: usize) -> Option<usize> {
    if data.get(start + 1) != Some(&b'[') {
        return None;
    }
    let limit = start.checked_add(MAX_SGR_SEQUENCE_BYTES)?.min(data.len());
    let mut index = start + 2;
    while index < limit {
        match data[index] {
            b'0'..=b'9' | b';' | b':' => index += 1,
            b'm' => return Some(index + 1),
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "postgresql://";

    fn component(candidate: &str) -> Option<StructuredComponent> {
        let absolute = PREFIX.len();
        database_password_component(candidate.as_bytes(), absolute, "f-test", "u-test", 6)
    }

    #[test]
    fn extracts_plain_password_with_exact_offsets() {
        let value = "rnc_user:kR9d2mQ7xL4pN8sT1vW6yZ3";
        let component = component(value).unwrap();
        assert_eq!(component.start_byte, PREFIX.len() + "rnc_user:".len());
        assert_eq!(component.end_byte, PREFIX.len() + value.len());
        assert_eq!(component.ansi, "NONE");
        assert!(component.normalization.is_none());
        assert_eq!(
            component.source_sha256,
            sha256_hex(b"kR9d2mQ7xL4pN8sT1vW6yZ3")
        );
        assert_eq!(component.normalized_sha256, component.source_sha256);
    }

    #[test]
    fn trims_surrounding_sgr_and_hashes_visible_password() {
        let value = "\x1b[31mcolor_user:zX8cV6bN4mQ2wE9r\x1b[0m";
        let component = component(value).unwrap();
        assert_eq!(component.ansi, "TRIMMED");
        assert_eq!(
            component.normalization.as_deref(),
            Some(ANSI_SGR_NORMALIZATION)
        );
        assert_eq!(
            &value.as_bytes()
                [component.start_byte - PREFIX.len()..component.end_byte - PREFIX.len()],
            b"zX8cV6bN4mQ2wE9r"
        );
        assert_eq!(component.normalized_sha256, sha256_hex(b"zX8cV6bN4mQ2wE9r"));
    }

    #[test]
    fn excludes_internal_sgr_from_normalized_digest_but_not_source_range() {
        let value = "svc_user:pa\x1b[1mss\x1b[0m";
        let component = component(value).unwrap();
        assert_eq!(component.ansi, "INTERNAL");
        assert_eq!(
            &value.as_bytes()
                [component.start_byte - PREFIX.len()..component.end_byte - PREFIX.len()],
            b"pa\x1b[1mss"
        );
        assert_eq!(component.source_sha256, sha256_hex(b"pa\x1b[1mss"));
        assert_eq!(component.normalized_sha256, sha256_hex(b"pass"));
    }

    #[test]
    fn rejects_unknown_and_malformed_escape_sequences() {
        for value in [
            "user:pa\x1b]0;title\x07ss",
            "user:pa\x1b[99",
            "user:pa\x1b[?25lss",
            "user:pa\x1b",
        ] {
            assert!(component(value).is_none(), "{value:?}");
        }
    }

    #[test]
    fn does_not_decode_percent_encoding() {
        let value = "user:p%40ss%3Aword";
        let component = component(value).unwrap();
        assert_eq!(component.normalized_sha256, sha256_hex(b"p%40ss%3Aword"));
    }

    #[test]
    fn empty_and_colonless_values_have_no_component() {
        assert!(component("user:").is_none());
        assert!(component("user").is_none());
        assert!(component(":password").is_none());
    }
}
