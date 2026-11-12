//! Bounded whole-file and streaming matching over validated finite-length rules.

use std::collections::HashSet;
use std::fmt;
#[cfg(windows)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Take};
use std::path::Path;
use std::time::{Instant, SystemTime};

use sha2::{Digest, Sha256};

use crate::backend::{MatchError, MatchPlan};
use crate::finding::{
    build_finding, line_count, line_end_for_range, line_for_offset, Finding, LineIndex,
};
use crate::path::sha256_hex;

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
    CandidateLimit,
    Io(&'static str),
}

impl FileScanError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::TooLarge => "FILE_SIZE_LIMIT",
            Self::Changed => "FILE_CHANGED",
            Self::Timeout => "TIMEOUT",
            Self::FindingsLimit => "MAX_FINDINGS_EXCEEDED",
            Self::CandidateLimit => "CANDIDATE_LIMIT",
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

/// Open an authorized source file while preserving root containment on Unix.
///
/// The root and every intermediate directory are opened with `O_NOFOLLOW`, so
/// replacing an ancestor with a symlink after discovery cannot redirect the
/// read. The final component is also opened with `O_NOFOLLOW`.
#[cfg(unix)]
fn open_contained(root: &Path, locator: &str) -> std::io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

    fn cstring(value: &std::ffi::OsStr) -> std::io::Result<CString> {
        CString::new(value.as_bytes())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))
    }
    fn open_dir(fd: RawFd, component: &std::ffi::OsStr) -> std::io::Result<RawFd> {
        let name = cstring(component)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let opened = unsafe { libc::openat(fd, name.as_ptr(), flags) };
        if opened < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(opened)
    }
    let root_name = cstring(root.as_os_str())?;
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut current = root_fd;
    let components: Vec<&std::ffi::OsStr> = std::path::Path::new(locator)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value),
            _ => None,
        })
        .collect();
    if components.is_empty() {
        unsafe { libc::close(current) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source locator has no file component",
        ));
    }
    for component in &components[..components.len() - 1] {
        match open_dir(current, component) {
            Ok(next) => {
                unsafe { libc::close(current) };
                current = next;
            }
            Err(error) => {
                unsafe { libc::close(current) };
                return Err(error);
            }
        }
    }
    let final_name = cstring(components[components.len() - 1])?;
    let file_fd = unsafe {
        libc::openat(
            current,
            final_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    unsafe { libc::close(current) };
    if file_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(file_fd) })
}

#[cfg(windows)]
fn path_within_root(root: &Path, candidate: &Path) -> bool {
    let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let candidate = fs::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf());
    let normalize = |path: &Path| {
        path.to_string_lossy()
            .replace("\\\\?\\", "")
            .replace('/', "\\")
            .to_ascii_lowercase()
    };
    let root = normalize(&root);
    let candidate = normalize(&candidate);
    if candidate == root {
        return true;
    }
    let prefix = if root.ends_with('\\') {
        root
    } else {
        format!("{root}\\")
    };
    candidate.starts_with(&prefix)
}

#[cfg(windows)]
fn final_handle_path(file: &File) -> std::io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    let handle = file.as_raw_handle();
    let length = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, 0) };
    if length == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buffer = vec![0u16; length as usize + 1];
    let written =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    if written == 0 {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(written as usize);
    Ok(std::ffi::OsString::from_wide(&buffer).into())
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetFinalPathNameByHandleW(
        handle: std::os::windows::raw::HANDLE,
        path: *mut u16,
        length: u32,
        flags: u32,
    ) -> u32;
}

/// Windows verifies the opened handle's final normalized path remains beneath
/// the canonical root. This closes ancestor substitution for the content read;
/// reparse-point attributes are also rejected before opening.
#[cfg(windows)]
fn open_contained(root: &Path, locator: &str) -> std::io::Result<File> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    // The locator is canonical and relative, so root.join(locator) is
    // lexically contained. Check every component for a reparse point before
    // opening the final component without following a substituted link.
    let mut ancestor = root.to_path_buf();
    let mut components = std::path::Path::new(locator).components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(value) = component else {
            continue;
        };
        ancestor.push(value);
        let metadata = fs::symlink_metadata(&ancestor)?;
        if metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "source path contains a reparse point",
            ));
        }
        if components.peek().is_some() && !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "source ancestor is not a directory",
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_OPEN_REPARSE_POINT: do not follow a substituted final link.
    options.custom_flags(0x0020_0000);
    let file = options.open(ancestor)?;
    let final_path = final_handle_path(&file)?;
    if !path_within_root(root, &final_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "source handle escaped the authorized root",
        ));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_contained(root: &Path, locator: &str) -> std::io::Result<File> {
    let candidate = fs::canonicalize(root.join(locator))?;
    if !path_within_root(root, &candidate) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "source target escaped the authorized root",
        ));
    }
    OpenOptions::new().read(true).open(candidate)
}

#[derive(Debug)]
pub struct ScanFileResult {
    pub findings: Vec<Finding>,
    pub content_sha256: String,
    pub line_count: usize,
    pub bytes_read: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn scan_file(
    root: &Path,
    locator: &str,
    unit_id: &str,
    run_id: &str,
    plan: &MatchPlan,
    config: &ScanFileConfig,
    expected_size: u64,
    expected_modified: Option<SystemTime>,
) -> Result<ScanFileResult, FileScanError> {
    if expected_size > config.max_file_bytes {
        return Err(FileScanError::TooLarge);
    }
    match config.mode {
        ScanMode::Whole | ScanMode::Auto => scan_whole(
            root,
            locator,
            unit_id,
            run_id,
            plan,
            config,
            expected_size,
            expected_modified,
        ),
        ScanMode::Stream => scan_stream(
            root,
            locator,
            unit_id,
            run_id,
            plan,
            config,
            expected_size,
            expected_modified,
        ),
    }
}

#[derive(Debug, Clone)]
pub struct ScanContentConfig {
    pub mode: ScanMode,
    pub stream_chunk_bytes: usize,
    pub max_findings: usize,
    pub deadline: Instant,
}

/// Scan an already-acquired bounded byte buffer. Git history blobs use this
/// path after `cat-file` enforces the per-object limit. Stream mode still
/// exercises overlapping fixed windows, so backend and boundary behavior remain
/// equivalent to file streaming.
pub fn scan_content(
    data: &[u8],
    unit_id: &str,
    run_id: &str,
    plan: &MatchPlan,
    config: &ScanContentConfig,
) -> Result<ScanFileResult, FileScanError> {
    if config.stream_chunk_bytes == 0 {
        return Err(FileScanError::Io("stream_config"));
    }
    if Instant::now() >= config.deadline {
        return Err(FileScanError::Timeout);
    }
    let line_index = LineIndex::new(data);
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    match config.mode {
        ScanMode::Whole | ScanMode::Auto => {
            if !data.is_empty() {
                scan_window(
                    data,
                    0,
                    1,
                    Some(&line_index),
                    unit_id,
                    run_id,
                    plan,
                    &mut findings,
                    &mut seen,
                    config.max_findings,
                    true,
                    config.deadline,
                )?;
            }
        }
        ScanMode::Stream => {
            let overlap = plan.bundle().max_match_bytes.max(1);
            let step = config.stream_chunk_bytes.max(1);
            let chunk = overlap.saturating_add(step);
            let mut start = 0usize;
            while start < data.len() {
                if Instant::now() >= config.deadline {
                    return Err(FileScanError::Timeout);
                }
                let end = start.saturating_add(chunk).min(data.len());
                scan_window(
                    &data[start..end],
                    start,
                    1,
                    Some(&line_index),
                    unit_id,
                    run_id,
                    plan,
                    &mut findings,
                    &mut seen,
                    config.max_findings,
                    end == data.len(),
                    config.deadline,
                )?;
                if end == data.len() {
                    break;
                }
                start = start.saturating_add(step);
            }
        }
    }
    Ok(ScanFileResult {
        findings,
        content_sha256: sha256_hex(data),
        line_count: line_count(data),
        bytes_read: data.len() as u64,
    })
}

fn metadata_changed(
    metadata: &fs::Metadata,
    expected_size: u64,
    expected_modified: Option<SystemTime>,
) -> bool {
    let size_changed = metadata.len() != expected_size;
    let modified_changed = match (metadata.modified().ok(), expected_modified) {
        (Some(actual), Some(expected)) => actual != expected,
        _ => false,
    };
    size_changed || modified_changed
}

#[allow(clippy::too_many_arguments)]
fn scan_whole(
    root: &Path,
    locator: &str,
    unit_id: &str,
    run_id: &str,
    plan: &MatchPlan,
    config: &ScanFileConfig,
    expected_size: u64,
    expected_modified: Option<SystemTime>,
) -> Result<ScanFileResult, FileScanError> {
    if Instant::now() >= config.deadline {
        return Err(FileScanError::Timeout);
    }
    let file = open_contained(root, locator).map_err(|_| FileScanError::Io("open"))?;
    let mut reader: Take<File> = file.take(config.max_file_bytes.saturating_add(1));
    let mut data = Vec::with_capacity(expected_size.min(config.max_file_bytes) as usize);
    reader
        .read_to_end(&mut data)
        .map_err(|_| FileScanError::Io("whole_read"))?;
    if data.len() as u64 > config.max_file_bytes {
        return Err(FileScanError::TooLarge);
    }
    if data.len() as u64 != expected_size
        || metadata_changed(
            &reader
                .get_ref()
                .metadata()
                .map_err(|_| FileScanError::Io("metadata"))?,
            expected_size,
            expected_modified,
        )
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
        plan,
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

#[allow(clippy::too_many_arguments)]
fn scan_stream(
    root: &Path,
    locator: &str,
    unit_id: &str,
    run_id: &str,
    plan: &MatchPlan,
    config: &ScanFileConfig,
    expected_size: u64,
    expected_modified: Option<SystemTime>,
) -> Result<ScanFileResult, FileScanError> {
    if config.stream_chunk_bytes == 0 {
        return Err(FileScanError::Io("stream_config"));
    }
    let overlap = plan.bundle().max_match_bytes.max(1);
    let mut file = open_contained(root, locator).map_err(|_| FileScanError::Io("open"))?;
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
            plan,
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
            plan,
            &mut findings,
            &mut seen,
            config.max_findings,
            true,
            config.deadline,
        )?;
    }
    if bytes_read != expected_size
        || metadata_changed(
            &file.metadata().map_err(|_| FileScanError::Io("metadata"))?,
            expected_size,
            expected_modified,
        )
    {
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
    plan: &MatchPlan,
    findings: &mut Vec<Finding>,
    seen: &mut HashSet<(String, usize, usize)>,
    max_findings: usize,
    final_window: bool,
    deadline: Instant,
) -> Result<(), FileScanError> {
    let candidates = plan
        .candidates(data, deadline)
        .map_err(|error| match error {
            MatchError::Timeout => FileScanError::Timeout,
            MatchError::CandidateLimit => FileScanError::CandidateLimit,
            MatchError::Backend(_) => FileScanError::Io("backend"),
        })?;
    for candidate in candidates {
        if Instant::now() >= deadline {
            return Err(FileScanError::Timeout);
        }
        let start = candidate.start;
        let end = candidate.end;
        if start >= end || end > data.len() {
            continue;
        }
        if !final_window && end == data.len() {
            // The backend may have matched a prefix cut by the chunk edge. The
            // overlap guarantees the complete match is visible in the next
            // window; do not emit the truncated candidate now.
            continue;
        }
        let rule = plan
            .bundle()
            .compiled
            .get(candidate.rule_index)
            .ok_or(FileScanError::Io("backend_rule"))?;
        let candidate_bytes = &data[start..end];
        let outcome =
            match crate::validate::validate_candidate(candidate_bytes, &rule.definition.validators)
            {
                Ok(outcome) => outcome,
                Err(_) => continue,
            };
        let confidence = effective_confidence(&rule.definition.confidence, outcome.status);
        let mut validation = outcome.applied;
        if rule.definition.provider.is_some() {
            validation.push(outcome.status.name().to_string());
            validation.extend(outcome.notes);
            validation.sort();
            validation.dedup();
        }
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
                    + line_for_offset(data, start).map_err(|_| FileScanError::Io("match_line"))?
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
            &confidence,
            validation,
            data,
        )
        .map_err(|_| FileScanError::Io("build_finding"))?;
        // The finding builder computes the digest over the window match, then
        // the absolute byte coordinates and identity are applied here.
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
    Ok(())
}

fn effective_confidence(declared: &str, status: crate::validate::ValidationStatus) -> String {
    use crate::validate::ValidationStatus;
    match (declared, status) {
        ("high", ValidationStatus::PlausibleUnverified) => "medium".to_string(),
        ("medium", ValidationStatus::PlausibleUnverified) => "low".to_string(),
        (value, _) => value.to_string(),
    }
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
        let plan = MatchPlan::new(&rules, crate::backend::BackendRequest::Regex).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let whole = scan_file(
            temp.path(),
            "fixture.txt",
            "u-test",
            "r",
            &plan,
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
            temp.path(),
            "fixture.txt",
            "u-test",
            "r",
            &plan,
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
