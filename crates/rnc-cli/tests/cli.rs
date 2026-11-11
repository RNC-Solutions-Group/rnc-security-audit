//! End-to-end CLI tests: output, redaction and operational errors.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rnc"))
}

fn rules() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-synthetic-v1.json")
}

#[test]
fn scan_writes_private_json_and_safe_summary() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("env.txt"),
        b"KEY=RNC_SYNTH_KEY_GENERIC_CLI_ALPHA\n",
    )
    .unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let output = output_dir.path().join("private.json");
    let completed = Command::new(binary())
        .args([
            "scan",
            "--root",
            temp.path().to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "json",
            "--output",
            output.to_str().unwrap(),
            "--run-id",
            "cli-test",
            "--mode",
            "whole",
        ])
        .output()
        .unwrap();
    assert!(completed.status.success(), "{:?}", completed);
    let summary = String::from_utf8(completed.stdout).unwrap();
    assert!(summary.contains("Findings: 1"), "{summary}");
    assert!(!summary.contains("RNC_SYNTH_KEY_"));
    assert!(!summary.contains("evidence_digest"));
    assert!(!summary.contains("finding_id"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&output).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private evidence must be owner-only");
    }
    let raw = fs::read_to_string(&output).unwrap();
    assert!(!raw.contains("RNC_SYNTH_KEY_"));
    let document: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(document["execution"]["state"], "COMPLETED");
    assert_eq!(document["findings"].as_array().unwrap().len(), 1);
    assert!(document["findings"][0]["evidence_digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
}

#[test]
fn json_requires_output_path() {
    let temp = tempfile::tempdir().unwrap();
    let completed = Command::new(binary())
        .args([
            "scan",
            "--root",
            temp.path().to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(64));
    assert!(!String::from_utf8(completed.stdout)
        .unwrap()
        .contains("RNC_SYNTH_KEY_"));
}

#[test]
fn rules_validate_is_useful_and_safe() {
    let completed = Command::new(binary())
        .args(["rules", "validate", "--rules", rules().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(completed.status.success());
    let stdout = String::from_utf8(completed.stdout).unwrap();
    assert!(stdout.contains("Ruleset: rnc-synthetic-v1"));
    assert!(stdout.contains("Rules: 10"));
    assert!(stdout.contains("Digest: sha256:"));
}

#[test]
fn private_output_inside_scan_root_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("env.txt"),
        b"KEY=RNC_SYNTH_KEY_GENERIC_CLI_ALPHA\n",
    )
    .unwrap();
    let output = temp.path().join("private.json");
    let completed = Command::new(binary())
        .args([
            "scan",
            "--root",
            temp.path().to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "json",
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(1));
    assert!(!output.exists());
}
