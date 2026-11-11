//! CP1 core integration tests against real temporary files.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rnc_core::{
    scan, ExecutionState, LoadedBundle, LocalSource, PolicySpec, RunConfig, ScanLimits, ScanMode,
};
use tempfile::tempdir;

fn rules_v1() -> LoadedBundle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-synthetic-v1.json");
    LoadedBundle::load(&path).expect("v1 rules")
}

fn config(mode: ScanMode) -> RunConfig {
    RunConfig {
        run_id: "test-run".to_string(),
        limits: ScanLimits::default(),
        mode,
        stream_threshold_bytes: 1024 * 1024,
        stream_chunk_bytes: 32,
        strategy: rnc_core::BackendRequest::Auto,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![1, 2],
        config_source: "test-defaults".to_string(),
        config_provenance: std::collections::BTreeMap::new(),
    }
}

fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, bytes).unwrap();
}

fn scan_tree(
    root: &Path,
    rules: &LoadedBundle,
    config: &RunConfig,
    excludes: &[String],
    skips: &[String],
    optional: &[String],
) -> rnc_core::ScanReport {
    let mut spec = PolicySpec::empty();
    for (index, selector) in excludes.iter().enumerate() {
        spec.add_block(
            &format!("TEST-EXCLUDE-{index}"),
            rnc_core::policy::PolicyOrigin::Cli,
            selector,
            "test pre-scan block",
            "1",
            false,
        )
        .unwrap();
    }
    for selector in skips {
        spec.add_skip(selector).unwrap();
    }
    for selector in optional {
        spec.add_optional(selector).unwrap();
    }
    let source = LocalSource::new_with_policy(root.to_path_buf(), &spec).unwrap();
    let discovery = source.discover();
    let mut effective = config.clone();
    effective.policy = spec;
    scan(discovery, rules, &effective).unwrap()
}

#[test]
fn detects_marker_and_preserves_offsets_and_line() {
    let temp = tempdir().unwrap();
    write(
        &temp.path().join("env.txt"),
        b"prefix\nKEY=RNC_SYNTH_KEY_GENERIC_ALPHA\n",
    );
    let report = scan_tree(
        temp.path(),
        &rules_v1(),
        &config(ScanMode::Whole),
        &[],
        &[],
        &[],
    );
    assert_eq!(report.execution.state, ExecutionState::Completed);
    assert_eq!(report.findings.len(), 1);
    let finding = &report.findings[0];
    assert_eq!(finding.rule_id, "synthetic-generic");
    assert_eq!(finding.start_byte, 11);
    assert_eq!(finding.end_byte, 38);
    assert_eq!(finding.line, 2);
    assert_eq!(finding.line_end, None);
    assert!(finding.evidence_digest.starts_with("sha256:"));
    assert_eq!(report.execution.units[0].disposition, "INSPECTED");
}

#[test]
fn blocked_target_is_not_inspected_and_has_no_evidence() {
    let temp = tempdir().unwrap();
    write(
        &temp.path().join("blocked.txt"),
        b"DO_NOT_SCAN=RNC_SYNTH_KEY_BLOCKED_ALPHA\n",
    );
    let exclusions = vec!["blocked.txt".to_string()];
    let report = scan_tree(
        temp.path(),
        &rules_v1(),
        &config(ScanMode::Whole),
        &exclusions,
        &[],
        &[],
    );
    assert!(report.findings.is_empty());
    let unit = &report.execution.units[0];
    assert_eq!(unit.disposition, "VERIFIED_BLOCKED");
    assert_eq!(unit.reason_codes, vec!["PRE_SCAN_BLOCKED"]);
    assert!(unit.byte_length.is_none());
    assert!(unit.content_sha256.is_none());
}

#[test]
fn optional_uninspected_does_not_break_completed_execution() {
    let temp = tempdir().unwrap();
    write(
        &temp.path().join("optional.txt"),
        b"RNC_SYNTH_KEY_OPTIONAL_ALPHA\n",
    );
    let skips = vec!["optional.txt".to_string()];
    let optional = vec!["optional.txt".to_string()];
    let report = scan_tree(
        temp.path(),
        &rules_v1(),
        &config(ScanMode::Whole),
        &[],
        &skips,
        &optional,
    );
    assert_eq!(report.execution.state, ExecutionState::Completed);
    let unit = &report.execution.units[0];
    assert_eq!(unit.disposition, "UNINSPECTED");
    assert!(!unit.required_scope);
    assert!(report.execution.required_uninspected_count() == 0);
}

#[test]
fn oversize_target_is_uninspected_with_reason() {
    let temp = tempdir().unwrap();
    write(
        &temp.path().join("large.txt"),
        b"RNC_SYNTH_KEY_AWS_ALPHA_AND_MORE\n",
    );
    let mut cfg = config(ScanMode::Whole);
    cfg.limits.max_file_bytes = 10;
    cfg.limits.max_total_bytes = 20;
    let report = scan_tree(temp.path(), &rules_v1(), &cfg, &[], &[], &[]);
    assert!(report.findings.is_empty());
    assert_eq!(report.execution.units[0].disposition, "UNINSPECTED");
    assert_eq!(
        report.execution.units[0].reason_codes,
        vec!["FILE_SIZE_LIMIT"]
    );
}

#[test]
fn timeout_produces_interrupted_execution_with_coverage_gap() {
    let temp = tempdir().unwrap();
    write(&temp.path().join("one.txt"), b"RNC_SYNTH_KEY_AWS_ALPHA\n");
    let mut cfg = config(ScanMode::Whole);
    cfg.limits.timeout = Duration::from_nanos(1);
    let report = scan_tree(temp.path(), &rules_v1(), &cfg, &[], &[], &[]);
    assert_eq!(report.execution.state, ExecutionState::Interrupted);
    assert!(!report.execution.evidence_valid);
    assert_eq!(report.execution.required_uninspected_count(), 1);
}

#[test]
fn duplicate_occurrences_are_distinct_findings() {
    let temp = tempdir().unwrap();
    write(
        &temp.path().join("dup.txt"),
        b"RNC_SYNTH_KEY_REPEAT_ALPHA\nsame\nRNC_SYNTH_KEY_REPEAT_ALPHA\n",
    );
    let report = scan_tree(
        temp.path(),
        &rules_v1(),
        &config(ScanMode::Whole),
        &[],
        &[],
        &[],
    );
    assert_eq!(report.findings.len(), 2);
    assert_eq!(report.findings[0].rule_id, "synthetic-generic");
}

#[test]
fn whole_and_stream_match_across_small_chunks() {
    let temp = tempdir().unwrap();
    let mut data = vec![b'a'; 31];
    data.extend_from_slice(b"RNC_SYNTH_KEY_GENERIC_BOUNDARY\n");
    write(&temp.path().join("boundary.txt"), &data);
    let whole = scan_tree(
        temp.path(),
        &rules_v1(),
        &config(ScanMode::Whole),
        &[],
        &[],
        &[],
    );
    let stream = scan_tree(
        temp.path(),
        &rules_v1(),
        &config(ScanMode::Stream),
        &[],
        &[],
        &[],
    );
    assert_eq!(whole.findings.len(), 1);
    assert_eq!(stream.findings.len(), 1);
    assert_eq!(whole.findings[0].start_byte, stream.findings[0].start_byte);
    assert_eq!(whole.findings[0].end_byte, stream.findings[0].end_byte);
    assert_eq!(whole.findings[0].finding_id, stream.findings[0].finding_id);
    assert_eq!(
        whole.execution.units[0].content_sha256,
        stream.execution.units[0].content_sha256
    );
}

#[test]
fn multiline_rule_reports_marker_span_and_line() {
    let temp = tempdir().unwrap();
    write(&temp.path().join("multiline.pem"), b"-----BEGIN RNC SYNTHETIC KEY-----\nRNC_SYNTH_KEY_MULTILINE_ALPHA\n-----END RNC SYNTHETIC KEY-----\n");
    let report = scan_tree(
        temp.path(),
        &rules_v1(),
        &config(ScanMode::Whole),
        &[],
        &[],
        &[],
    );
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "synthetic-multiline");
    assert_eq!(report.findings[0].line, 2);
}

#[cfg(unix)]
#[test]
fn symlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let temp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    write(
        &outside.path().join("outside.txt"),
        b"RNC_SYNTH_KEY_AWS_OUTSIDE\n",
    );
    symlink(
        outside.path().join("outside.txt"),
        temp.path().join("link.txt"),
    )
    .unwrap();
    let report = scan_tree(
        temp.path(),
        &rules_v1(),
        &config(ScanMode::Whole),
        &[],
        &[],
        &[],
    );
    assert!(report.findings.is_empty());
    assert_eq!(report.execution.units[0].disposition, "UNINSPECTED");
    assert_eq!(
        report.execution.units[0].reason_codes,
        vec!["SYMLINK_NOT_FOLLOWED"]
    );
}

#[test]
fn findings_limit_discards_current_unit_and_fails() {
    let temp = tempdir().unwrap();
    write(
        &temp.path().join("two.txt"),
        b"RNC_SYNTH_KEY_GENERIC_ALPHA\nRNC_SYNTH_KEY_GENERIC_BRAVO\n",
    );
    let mut cfg = config(ScanMode::Whole);
    cfg.limits.max_findings = 1;
    let report = scan_tree(temp.path(), &rules_v1(), &cfg, &[], &[], &[]);
    assert_eq!(report.execution.state, ExecutionState::Error);
    assert!(report.findings.is_empty());
    assert_eq!(report.execution.units[0].disposition, "UNINSPECTED");
    assert_eq!(
        report.execution.units[0].reason_codes,
        vec!["MAX_FINDINGS_EXCEEDED"]
    );
}

#[test]
fn total_byte_limit_marks_units_uninspected() {
    let temp = tempdir().unwrap();
    write(
        &temp.path().join("one.txt"),
        b"RNC_SYNTH_KEY_GENERIC_ALPHA\n",
    );
    write(
        &temp.path().join("two.txt"),
        b"RNC_SYNTH_KEY_GENERIC_BRAVO\n",
    );
    let mut cfg = config(ScanMode::Whole);
    cfg.limits.max_file_bytes = 30;
    cfg.limits.max_total_bytes = 30;
    let report = scan_tree(temp.path(), &rules_v1(), &cfg, &[], &[], &[]);
    assert_eq!(report.execution.state, ExecutionState::Completed);
    let uninspected: Vec<_> = report
        .execution
        .units
        .iter()
        .filter(|unit| unit.disposition == "UNINSPECTED")
        .collect();
    assert_eq!(uninspected.len(), 1);
    assert_eq!(uninspected[0].reason_codes, vec!["TOTAL_BYTE_LIMIT"]);
}

#[test]
fn changed_file_is_not_inspected() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("changing.txt");
    write(&path, b"RNC_SYNTH_KEY_GENERIC_ALPHA\n");
    let source = LocalSource::new(temp.path().to_path_buf(), &[], &[], &[]).unwrap();
    let discovery = source.discover();
    write(&path, b"RNC_SYNTH_KEY_GENERIC_ALPHA_CHANGED_MORE\n");
    let report = scan(discovery, &rules_v1(), &config(ScanMode::Whole)).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.execution.units[0].disposition, "UNINSPECTED");
    assert_eq!(report.execution.units[0].reason_codes, vec!["FILE_CHANGED"]);
}

#[cfg(unix)]
#[test]
fn replaced_file_is_not_followed_as_symlink() {
    use std::os::unix::fs::symlink;
    let temp = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let path = temp.path().join("swap.txt");
    write(&path, b"RNC_SYNTH_KEY_GENERIC_ALPHA\n");
    let source = LocalSource::new(temp.path().to_path_buf(), &[], &[], &[]).unwrap();
    let discovery = source.discover();
    fs::remove_file(&path).unwrap();
    write(
        &outside.path().join("outside.txt"),
        b"RNC_SYNTH_KEY_GENERIC_BRAVO\n",
    );
    symlink(outside.path().join("outside.txt"), &path).unwrap();
    let report = scan(discovery, &rules_v1(), &config(ScanMode::Whole)).unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.execution.units[0].disposition, "UNINSPECTED");
}

#[test]
fn invalid_policy_fails_even_with_no_findings() {
    let temp = tempdir().unwrap();
    write(&temp.path().join("clean.txt"), b"benign\n");
    let mut spec = PolicySpec::empty();
    spec.errors.push("POLICY_INVALID".to_string());
    let source = LocalSource::new_with_policy(temp.path().to_path_buf(), &spec).unwrap();
    let discovery = source.discover();
    let mut cfg = config(ScanMode::Whole);
    cfg.policy = spec;
    let report = scan(discovery, &rules_v1(), &cfg).unwrap();
    assert_eq!(report.result.result_code, 5);
    assert!(!report.policy.policy_valid);
    assert!(report
        .result
        .reason_codes
        .contains(&"POLICY_INVALID".to_string()));
    assert_eq!(report.ci.process_exit_code, 30);
}
