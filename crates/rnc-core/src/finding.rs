//! Normalized finding events and byte/line mapping.
//!
//! The evidence digest and finding ID are private correlation values. They are
//! never printed by the ordinary CLI summary or published as report fields.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::coverage::SCHEMA_VERSION;
use crate::error::CoreError;
use crate::path::sha256_hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub schema_version: String,
    pub run_id: String,
    pub finding_id: String,
    pub unit_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub category: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_end: Option<usize>,
    pub confidence: String,
    pub validation: Vec<String>,
    pub evidence_digest: String,
}

pub fn line_for_offset(data: &[u8], offset: usize) -> Result<usize, CoreError> {
    if offset > data.len() {
        return Err(CoreError::Input(
            "byte offset is outside content".to_string(),
        ));
    }
    let mut line = 1usize;
    let mut index = 0usize;
    while index < offset {
        match data[index] {
            13 => {
                if index + 1 < offset && data[index + 1] == 10 {
                    index += 2;
                } else {
                    index += 1;
                }
                line += 1;
            }
            10 => {
                index += 1;
                line += 1;
            }
            _ => index += 1,
        }
    }
    Ok(line)
}

pub fn line_count(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let mut count = 0usize;
    let mut index = 0usize;
    while index < data.len() {
        match data[index] {
            13 => {
                if index + 1 < data.len() && data[index + 1] == 10 {
                    index += 2;
                } else {
                    index += 1;
                }
                count += 1;
            }
            10 => {
                index += 1;
                count += 1;
            }
            _ => index += 1,
        }
    }
    if !matches!(data.last(), Some(10 | 13)) {
        count += 1;
    }
    count
}

pub fn line_end_for_range(data: &[u8], start: usize, end: usize) -> Result<usize, CoreError> {
    if start >= end || end > data.len() {
        return Err(CoreError::Input("invalid finding byte range".to_string()));
    }
    let mut last = end - 1;
    while last > start && matches!(data[last], 10 | 13) {
        last -= 1;
    }
    line_for_offset(data, last)
}

/// Precomputed line-start index for O(log n) whole-file line mapping.
#[derive(Debug, Clone)]
pub struct LineIndex {
    starts: Vec<usize>,
    len: usize,
}

impl LineIndex {
    pub fn new(data: &[u8]) -> Self {
        let mut starts = vec![0usize];
        let mut index = 0usize;
        while index < data.len() {
            match data[index] {
                13 => {
                    if index + 1 < data.len() && data[index + 1] == 10 {
                        index += 2;
                    } else {
                        index += 1;
                    }
                    starts.push(index);
                }
                10 => {
                    index += 1;
                    starts.push(index);
                }
                _ => index += 1,
            }
        }
        Self {
            starts,
            len: data.len(),
        }
    }

    pub fn line_at(&self, offset: usize) -> Result<usize, CoreError> {
        if offset > self.len {
            return Err(CoreError::Input(
                "byte offset is outside content".to_string(),
            ));
        }
        let position = self.starts.partition_point(|start| *start <= offset);
        Ok(position.max(1))
    }

    /// Absolute byte range for an inclusive one-based line range.
    pub fn byte_range_for_lines(
        &self,
        start_line: usize,
        end_line: usize,
    ) -> Option<(usize, usize)> {
        if start_line == 0 || start_line > end_line {
            return None;
        }
        let start = *self.starts.get(start_line - 1)?;
        let end = self.starts.get(end_line).copied().unwrap_or(self.len);
        (start < end).then_some((start, end))
    }
}

pub fn finding_id(
    unit_id: &str,
    rule_id: &str,
    rule_version: &str,
    start_byte: usize,
    end_byte: usize,
    evidence_digest: &str,
) -> String {
    let mut hasher = Sha256::new();
    let start = start_byte.to_string();
    let end = end_byte.to_string();
    let parts = [
        unit_id,
        rule_id,
        rule_version,
        start.as_str(),
        end.as_str(),
        evidence_digest,
    ];
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            hasher.update([0]);
        }
        hasher.update(part.as_bytes());
    }
    format!("f-{}", hex::encode(hasher.finalize()))
}

#[allow(clippy::too_many_arguments)]
pub fn build_finding(
    run_id: &str,
    unit_id: &str,
    rule_id: &str,
    rule_version: &str,
    category: &str,
    start_byte: usize,
    end_byte: usize,
    line: usize,
    line_end: Option<usize>,
    confidence: &str,
    validation: Vec<String>,
    data: &[u8],
) -> Result<Finding, CoreError> {
    if start_byte >= end_byte || end_byte > data.len() {
        return Err(CoreError::Input("invalid finding byte range".to_string()));
    }
    let evidence = &data[start_byte..end_byte];
    let digest = sha256_hex(evidence);
    let identifier = finding_id(
        unit_id,
        rule_id,
        rule_version,
        start_byte,
        end_byte,
        &digest,
    );
    Ok(Finding {
        schema_version: SCHEMA_VERSION.to_string(),
        run_id: run_id.to_string(),
        finding_id: identifier,
        unit_id: unit_id.to_string(),
        rule_id: rule_id.to_string(),
        rule_version: rule_version.to_string(),
        category: category.to_string(),
        start_byte,
        end_byte,
        line,
        line_end,
        confidence: confidence.to_string(),
        validation,
        evidence_digest: digest,
    })
}

pub fn finding_key(finding: &Finding) -> (String, usize, usize) {
    (
        finding.rule_id.clone(),
        finding.start_byte,
        finding.end_byte,
    )
}

pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        (
            &left.unit_id,
            left.start_byte,
            left.end_byte,
            &left.rule_id,
            &left.rule_version,
            &left.finding_id,
        )
            .cmp(&(
                &right.unit_id,
                right.start_byte,
                right.end_byte,
                &right.rule_id,
                &right.rule_version,
                &right.finding_id,
            ))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_mapping_handles_lf_crlf_and_cr() {
        assert_eq!(line_for_offset(b"a\nb\r\nc\rd", 0).unwrap(), 1);
        assert_eq!(line_for_offset(b"a\nb\r\nc\rd", 2).unwrap(), 2);
        assert_eq!(line_for_offset(b"a\nb\r\nc\rd", 5).unwrap(), 3);
        assert_eq!(line_for_offset(b"a\nb\r\nc\rd", 7).unwrap(), 4);
        assert_eq!(line_count(b""), 0);
        assert_eq!(line_count(b"a\nb\r\nc\rd"), 4);
        assert_eq!(line_count(b"a\n"), 1);
    }

    #[test]
    fn finding_identity_matches_cross_language_formula() {
        let digest = sha256_hex(b"RNC_SYNTH_KEY_EXAMPLE");
        let first = finding_id("u-test", "rule", "1", 3, 10, &digest);
        let second = finding_id("u-test", "rule", "1", 3, 10, &digest);
        assert_eq!(first, second);
        assert_ne!(first, finding_id("u-test", "rule", "2", 3, 10, &digest));
    }

    #[test]
    fn line_index_maps_offsets() {
        let data = b"a\nb\r\nc\rd";
        let index = LineIndex::new(data);
        assert_eq!(index.line_at(0).unwrap(), 1);
        assert_eq!(index.line_at(2).unwrap(), 2);
        assert_eq!(index.line_at(5).unwrap(), 3);
        assert_eq!(index.line_at(7).unwrap(), 4);
    }

    #[test]
    fn line_index_maps_inclusive_line_ranges() {
        let data = b"a\nbb\r\nccc\rdddd";
        let index = LineIndex::new(data);
        assert_eq!(index.byte_range_for_lines(1, 1), Some((0, 2)));
        assert_eq!(index.byte_range_for_lines(2, 3), Some((2, 10)));
        assert_eq!(index.byte_range_for_lines(4, 4), Some((10, 14)));
        assert_eq!(index.byte_range_for_lines(0, 1), None);
        assert_eq!(index.byte_range_for_lines(3, 2), None);
    }

    #[test]
    fn line_end_strips_trailing_newlines() {
        let data = b"start\nvalue\n";
        assert_eq!(line_end_for_range(data, 0, data.len()).unwrap(), 2);
    }
}
