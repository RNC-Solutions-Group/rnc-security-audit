//! CP4C CLI, profile publication and configuration-validation tests.

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
fn profile_is_written_outside_root_and_contains_no_secret() {
    let temp = tempfile::tempdir().unwrap();
    let value = "RNC_SYNTH_KEY_GENERIC_CLI_ALPHA";
    fs::write(temp.path().join("env.txt"), format!("KEY={value}\n")).unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let profile = output_dir.path().join("profile.json");
    let completed = Command::new(binary())
        .args([
            "scan",
            "--root",
            temp.path().to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "summary",
            "--run-id",
            "cp4c-cli",
            "--workers",
            "auto",
            "--mode",
            "whole",
            "--strategy",
            "auto",
            "--profile-output",
            profile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(10), "{completed:?}");
    let raw = fs::read_to_string(&profile).unwrap();
    assert!(!raw.contains(value));
    assert!(!raw.contains("env.txt"));
    let document: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(document["schema_version"], "1");
    assert_eq!(document["settings"]["requested"]["workers"], "auto");
    assert!(
        document["settings"]["effective"]["workers"]
            .as_str()
            .unwrap()
            .parse::<usize>()
            .unwrap()
            >= 1
    );
    assert_eq!(document["settings"]["effective"]["strategy"], "regex");
    assert!(document["phases"]["execution"]["ns"].as_u64().unwrap() > 0);
    assert!(document["worker_phases"]["scan.validation"]["ns"]
        .as_u64()
        .is_some());
}

#[test]
fn profile_inside_scan_root_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("env.txt"), b"clean\n").unwrap();
    let profile = temp.path().join("profile.json");
    let completed = Command::new(binary())
        .args([
            "scan",
            "--root",
            temp.path().to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "summary",
            "--profile-output",
            profile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(64), "{completed:?}");
    assert!(!profile.exists());
}

#[test]
fn profile_and_report_output_must_differ() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("env.txt"), b"clean\n").unwrap();
    let reports = tempfile::tempdir().unwrap();
    let output = reports.path().join("same.json");
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
            "--profile-output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(completed.status.code(), Some(64), "{completed:?}");
    assert!(!output.exists());
}

#[test]
fn git_only_flags_without_history_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    for flag in [
        ["--git-io", "batch"],
        ["--history-mode", "diff"],
        ["--context-lines", "3"],
    ] {
        let completed = Command::new(binary())
            .args([
                "scan",
                "--root",
                temp.path().to_str().unwrap(),
                "--rules",
                rules().to_str().unwrap(),
                "--format",
                "summary",
                flag[0],
                flag[1],
            ])
            .output()
            .unwrap();
        assert_eq!(completed.status.code(), Some(64), "{flag:?}");
    }
}
