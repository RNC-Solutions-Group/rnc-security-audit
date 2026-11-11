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
    assert_eq!(completed.status.code(), Some(10), "{:?}", completed);
    let summary = String::from_utf8(completed.stdout).unwrap();
    assert!(summary.contains("Result: ACTIONABLE (3)"), "{summary}");
    assert!(
        summary.contains("CI accepted: false (exit 10)"),
        "{summary}"
    );
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
    assert_eq!(completed.status.code(), Some(64));
    assert!(!output.exists());
}

#[test]
fn sanitized_output_contains_no_private_evidence() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("env.txt"),
        b"KEY=RNC_SYNTH_KEY_GENERIC_CLI_ALPHA\n",
    )
    .unwrap();
    let completed = Command::new(binary())
        .args([
            "scan",
            "--root",
            temp.path().to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "sanitized",
            "--run-id",
            "sanitized-test",
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(10));
    let stdout = String::from_utf8(completed.stdout).unwrap();
    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(document["result_code"], 3);
    assert_eq!(document["accepted"], false);
    for forbidden in [
        "RNC_SYNTH_KEY_",
        "finding_id",
        "evidence_digest",
        "env.txt",
        "locator",
    ] {
        assert!(!stdout.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn publication_failure_is_not_a_successful_scan() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("env.txt"),
        b"KEY=RNC_SYNTH_KEY_GENERIC_CLI_ALPHA\n",
    )
    .unwrap();
    let blocker = tempfile::tempdir().unwrap();
    let parent = blocker.path().join("not-a-directory");
    fs::write(&parent, b"blocker").unwrap();
    let output = parent.join("evidence.json");
    let completed = Command::new(binary())
        .args([
            "scan",
            "--root",
            temp.path().to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "private",
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(64));
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn private_report_symlink_is_rejected() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("env.txt"),
        b"KEY=RNC_SYNTH_KEY_GENERIC_CLI_ALPHA\n",
    )
    .unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let target = output_dir.path().join("target.json");
    fs::write(&target, b"unchanged").unwrap();
    let link = output_dir.path().join("link.json");
    symlink(&target, &link).unwrap();
    let completed = Command::new(binary())
        .args([
            "scan",
            "--root",
            temp.path().to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "private",
            "--output",
            link.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(64));
    assert_eq!(fs::read(&target).unwrap(), b"unchanged");
}

#[cfg(unix)]
#[test]
fn report_write_failure_is_not_success() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("env.txt"),
        b"KEY=RNC_SYNTH_KEY_GENERIC_CLI_ALPHA\n",
    )
    .unwrap();
    let reports = tempfile::tempdir().unwrap();
    let output = reports.path().join("locked.json");
    fs::set_permissions(reports.path(), fs::Permissions::from_mode(0o555)).unwrap();
    let completed = Command::new(binary())
        .args([
            "scan",
            "--root",
            temp.path().to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "private",
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    fs::set_permissions(reports.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(completed.status.code(), Some(30));
    assert!(!output.exists());
}
#[test]
fn bare_relative_output_inside_scan_root_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("env.txt"),
        b"KEY=RNC_SYNTH_KEY_GENERIC_CLI_ALPHA\n",
    )
    .unwrap();
    let completed = Command::new(binary())
        .current_dir(temp.path())
        .args([
            "scan",
            "--root",
            ".",
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "private",
            "--output",
            "report.json",
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(64));
    assert!(!temp.path().join("report.json").exists());
}

#[test]
fn dot_dot_output_inside_scan_root_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("sub")).unwrap();
    fs::write(
        temp.path().join("env.txt"),
        b"KEY=RNC_SYNTH_KEY_GENERIC_CLI_ALPHA\n",
    )
    .unwrap();
    let completed = Command::new(binary())
        .current_dir(temp.path().join("sub"))
        .args([
            "scan",
            "--root",
            "..",
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "private",
            "--output",
            "../report.json",
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(64));
    assert!(!temp.path().join("report.json").exists());
}
