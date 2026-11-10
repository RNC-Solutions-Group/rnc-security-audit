//! Bounded whole-file and streaming matching over validated finite-length rules.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Take};
use std::path::Path;
use std::time::{Instant, SystemTime};

use sha2::{Digest, Sha256};

use crate::finding::{
    build_finding, line_count, line_end_for_range, line_for_offset, Finding, LineIndex,
};
use crate::path::sha256_hex;
use crate::rules::LoadedBundle;
use crate::validate::validate_candidate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Auto,
    Whole,
    Stream,
}
#[derive(Debug, Clone)]
pub struct ScanFileConfig {
    pub mode: ScanMode,
    pub stream_chunk_bytes: usize,
    pub max_file_bytes: u64,
    pub max_findings: usize,
    pub deadline: Instant,
}

#[derive(Debug)]
pub enum FileScanError {
    TooLarge,
    Changed,
    Timeout,
    FindingsLimit,
    Io(&'static str),
}

impl FileScanError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::TooLarge => "FILE_SIZE_LIMIT",
            Self::Changed => "FILE_CHANGED",
            Self::Timeout => "TIMEOUT",
            Self::FindingsLimit => "MAX_FINDINGS_EXCEEDED",
            Self::Io(_) => "READ_ERROR",
        }
    }
}

impl fmt::Display for FileScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(context) => write!(formatter, "{} ({context})", self.reason_code()),
            _ => write!(formatter, "{}", self.reason_code()),
        }
    }
}

#[derive(Debug)]
pub struct ScanFileResult {
    pub findings: Vec<Finding>,
    pub content_sha256: String,
    pub line_count: usize,
    pub bytes_read: u64,
}

pub fn scan_file(
    path: &Path,
    unit_id: &str,
    run_id: &str,
    rules: &LoadedBundle,
    config: &ScanFileConfig,
    expected_size: u64,
    expected_modified: Option<SystemTime>,
) -> Result<ScanFileResult, FileScanError> {
    if expected_size > config.max_file_bytes {
        return Err(FileScanError::TooLarge);
    }
    match config.mode {
        ScanMode::Whole | ScanMode::Auto => scan_whole(
            path,
            unit_id,
            run_id,
            rules,
            config,
            expected_size,
            expected_modified,
        ),
        ScanMode::Stream => scan_stream(
            path,
            unit_id,
            run_id,
            rules,
            config,
            expected_size,
            expected_modified,
        ),
    }
}

fn metadata_changed(
    path: &Path,
    expected_size: u64,
    expected_modified: Option<SystemTime>,
) -> bool {
    match fs::metadata(path) {
        Ok(metadata) => {
            let size_changed = metadata.len() != expected_size;
            let modified_changed = match (metadata.modified().ok(), expected_modified) {
                (Some(actual), Some(expected)) => actual != expected,
                _ => false,
            };
            size_changed || modified_changed
        }
        Err(_) => true,
    }
}

fn scan_whole(
    path: &Path,
    unit_id: &str,
    run_id: &str,
    rules: &LoadedBundle,
    config: &ScanFileConfig,
    expected_size: u64,
    expected_modified: Option<SystemTime>,
) -> Result<ScanFileResult, FileScanError> {
    if Instant::now() >= config.deadline {
        return Err(FileScanError::Timeout);
    }
    let file = File::open(path).map_err(|_| FileScanError::Io("open"))?;
    let mut reader: Take<File> = file.take(config.max_file_bytes.saturating_add(1));
    let mut data = Vec::with_capacity(expected_size.min(config.max_file_bytes) as usize);
    reader
        .read_to_end(&mut data)
        .map_err(|_| FileScanError::Io("whole_read"))?;
    if data.len() as u64 > config.max_file_bytes {
        return Err(FileScanError::TooLarge);
    }
    if data.len() as u64 != expected_size
        || metadata_changed(path, expected_size, expected_modified)
    {
        return Err(FileScanError::Changed);
    }
    if Instant::now() >= config.deadline {
        return Err(FileScanError::Timeout);
    }
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    let line_index = LineIndex::new(&data);
    scan_window(
        &data,
        0,
        1,
        Some(&line_index),
        unit_id,
        run_id,
        rules,
        &mut findings,
        &mut seen,
        config.max_findings,
        true,
        config.deadline,
    )?;
    Ok(ScanFileResult {
        findings,
        content_sha256: sha256_hex(&data),
        line_count: line_count(&data),
        bytes_read: data.len() as u64,
    })
}

fn scan_stream(
    path: &Path,
    unit_id: &str,
    run_id: &str,
    rules: &LoadedBundle,
    config: &ScanFileConfig,
    expected_size: u64,
    expected_modified: Option<SystemTime>,
) -> Result<ScanFileResult, FileScanError> {
    if config.stream_chunk_bytes == 0 {
        return Err(FileScanError::Io("stream_config"));
    }
    let overlap = rules.max_match_bytes.max(1);
    let mut file = File::open(path).map_err(|_| FileScanError::Io("open"))?;
    let mut chunk = vec![0u8; config.stream_chunk_bytes];
    let mut carry: Vec<u8> = Vec::with_capacity(overlap);
    let mut carry_offset = 0usize;
    let mut line_at_carry = 1usize;
    let mut bytes_read = 0u64;
    let mut hasher = Sha256::new();
    let mut counter = LineCounter::default();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    loop {
        if Instant::now() >= config.deadline {
            return Err(FileScanError::Timeout);
        }
        let read = file
            .read(&mut chunk)
            .map_err(|_| FileScanError::Io("stream_read"))?;
        if read == 0 {
            break;
        }
        bytes_read += read as u64;
        if bytes_read > config.max_file_bytes {
            return Err(FileScanError::TooLarge);
        }
        hasher.update(&chunk[..read]);
        counter.push(&chunk[..read]);
        let mut window = Vec::with_capacity(carry.len() + read);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&chunk[..read]);
        let window_offset = carry_offset;
        scan_window(
            &window,
            window_offset,
            line_at_carry,
            None,
            unit_id,
            run_id,
            rules,
            &mut findings,
            &mut seen,
            config.max_findings,
            false,
            config.deadline,
        )?;
        let next_start = window.len().saturating_sub(overlap);
        if next_start > 0 {
            line_at_carry = line_at_carry
                + line_for_offset(&window, next_start)
                    .map_err(|_| FileScanError::Io("carry_line"))?
                - 1;
        }
        carry = window[next_start..].to_vec();
        carry_offset += next_start;
    }
    if !carry.is_empty() {
        let final_offset = carry_offset;
        scan_window(
            &carry,
            final_offset,
            line_at_carry,
            None,
            unit_id,
            run_id,
            rules,
            &mut findings,
            &mut seen,
            config.max_findings,
            true,
            config.deadline,
        )?;
    }
    if metadata_changed(path, expected_size, expected_modified) || bytes_read != expected_size {
        return Err(FileScanError::Changed);
    }
    if Instant::now() >= config.deadline {
        return Err(FileScanError::Timeout);
    }
    Ok(ScanFileResult {
        findings,
        content_sha256: format!("sha256:{}", hex::encode(hasher.finalize())),
        line_count: counter.finish(),
        bytes_read,
    })
}

#[allow(clippy::too_many_arguments)]
fn scan_window(
    data: &[u8],
    absolute_offset: usize,
    line_at_window_start: usize,
    line_index: Option<&LineIndex>,
    unit_id: &str,
    run_id: &str,
    rules: &LoadedBundle,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, usize, usize)>,
    max_findings: usize,
    final_window: bool,
    deadline: Instant,
) -> Result<(), FileScanError> {
    for rule in &rules.compiled {
        if Instant::now() >= deadline {
            return Err(FileScanError::Timeout);
        }
        let compiled = &rule.regex;
        for captures in compiled.captures_iter(data) {
            if Instant::now() >= deadline {
                return Err(FileScanError::Timeout);
            }
            let matched = captures.get(rule.definition.capture_group);
            let matched = match matched {
                Some(value) => value,
                None => continue,
            };
            let start = matched.start();
            let end = matched.end();
            if start >= end {
                continue;
            }
            if !final_window && end == data.len() {
                // The regex may have matched a prefix cut by the chunk edge.
                // The overlap guarantees the complete match is visible in the
                // next window; do not emit the truncated candidate now.
                continue;
            }
            let candidate = &data[start..end];
            let validation = match validate_candidate(candidate, &rule.definition.validators) {
                Ok(validation) => validation,
                Err(_) => continue,
            };
            let absolute_start = absolute_offset + start;
            let absolute_end = absolute_offset + end;
            if !seen.insert((
                rule.definition.rule_id.clone(),
                absolute_start,
                absolute_end,
            )) {
                continue;
            }
            let (line, last_line) = if let Some(index) = line_index {
                (
                    index
                        .line_at(absolute_start)
                        .map_err(|_| FileScanError::Io("match_line"))?,
                    index
                        .line_at({
                            let mut last = absolute_end - 1;
                            while last > absolute_start
                                && matches!(data[last - absolute_offset], 10 | 13)
                            {
                                last -= 1;
                            }
                            last
                        })
                        .map_err(|_| FileScanError::Io("match_line_end"))?,
                )
            } else {
                (
                    line_at_window_start
                        + line_for_offset(data, start)
                            .map_err(|_| FileScanError::Io("match_line"))?
                        - 1,
                    line_at_window_start
                        + line_end_for_range(data, start, end)
                            .map_err(|_| FileScanError::Io("match_line_end"))?
                        - 1,
                )
            };
            let line_end = if last_line > line {
                Some(last_line)
            } else {
                None
            };
            let finding = build_finding(
                run_id,
                unit_id,
                &rule.definition.rule_id,
                &rule.definition.rule_version,
                &rule.definition.category,
                start,
                end,
                line,
                line_end,
                &rule.definition.confidence,
                validation,
                data,
            )
            .map_err(|_| FileScanError::Io("build_finding"))?;
            // The finding builder computed offsets relative to the window for
            // digesting, then absolute offsets for identity. Rebuild is
            // unnecessary; rewrite the byte range to the absolute coordinates
            // and recompute the digest/identity over the full match bytes.
            let mut finding = finding;
            finding.start_byte = absolute_start;
            finding.end_byte = absolute_end;
            finding.finding_id = crate::finding::finding_id(
                unit_id,
                &rule.definition.rule_id,
                &rule.definition.rule_version,
                absolute_start,
                absolute_end,
                &finding.evidence_digest,
            );
            findings.push(finding);
            if findings.len() > max_findings {
                return Err(FileScanError::FindingsLimit);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
struct LineCounter {
    count: usize,
    pending_cr: bool,
    last: u8,
    saw_any: bool,
}

impl LineCounter {
    fn push(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.saw_any = true;
            if self.pending_cr {
                self.pending_cr = false;
                if byte == 10 {
                    self.last = 10;
                    continue;
                }
            }
            if byte == 13 {
                self.count += 1;
                self.pending_cr = true;
                self.last = 13;
            } else if byte == 10 {
                self.count += 1;
                self.last = 10;
            } else {
                self.last = byte;
            }
        }
    }

    fn finish(self) -> usize {
        if !self.saw_any {
            0
        } else if matches!(self.last, 10 | 13) {
            self.count
        } else {
            self.count + 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{LoadedBundle, RuleBundle};
    use serde_json::json;

    fn bundle(pattern: &str, max: usize) -> LoadedBundle {
        let definition: RuleBundle = serde_json::from_value(json!({
            "schema_version": "0.1.0",
            "ruleset_id": "test",
            "ruleset_version": "1",
            "rules": [{
                "rule_id": "synthetic-test",
                "rule_version": "1",
                "category": "test",
                "pattern": pattern,
                "capture_group": 0,
                "validators": ["MARKER_FORMAT", "MARKER_SUFFIX"],
                "confidence": "high",
                "max_match_bytes": max
            }]
        }))
        .unwrap();
        LoadedBundle::from_bundle(definition).unwrap()
    }

    #[test]
    fn whole_and_stream_find_same_marker_across_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fixture.txt");
        let prefix = vec![b'a'; 31];
        let mut data = prefix;
        data.extend_from_slice(b"RNC_SYNTH_KEY_TEST_BOUNDARY");
        data.extend_from_slice(b" suffix\n");
        fs::write(&path, &data).unwrap();
        let rules = bundle("RNC_SYNTH_KEY_TEST_[A-Z0-9_]{1,32}", 128);
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let whole = scan_file(
            &path,
            "u-test",
            "r",
            &rules,
            &ScanFileConfig {
                mode: ScanMode::Whole,
                stream_chunk_bytes: 32,
                max_file_bytes: 1024,
                max_findings: 10,
                deadline,
            },
            data.len() as u64,
            fs::metadata(&path).unwrap().modified().ok(),
        )
        .unwrap();
        let stream = scan_file(
            &path,
            "u-test",
            "r",
            &rules,
            &ScanFileConfig {
                mode: ScanMode::Stream,
                stream_chunk_bytes: 32,
                max_file_bytes: 1024,
                max_findings: 10,
                deadline,
            },
            data.len() as u64,
            fs::metadata(&path).unwrap().modified().ok(),
        )
        .unwrap();
        assert_eq!(whole.findings.len(), 1);
        assert_eq!(stream.findings.len(), 1);
        assert_eq!(whole.findings[0].start_byte, stream.findings[0].start_byte);
        assert_eq!(whole.findings[0].end_byte, stream.findings[0].end_byte);
        assert_eq!(whole.content_sha256, stream.content_sha256);
        assert_eq!(whole.line_count, stream.line_count);
    }

    #[test]
    fn line_counter_matches_line_count() {
        for data in [b"".as_slice(), b"a", b"a\n", b"a\r\nb", b"a\rb\r"] {
            let mut counter = LineCounter::default();
            counter.push(data);
            assert_eq!(counter.finish(), line_count(data));
        }
    }
}
