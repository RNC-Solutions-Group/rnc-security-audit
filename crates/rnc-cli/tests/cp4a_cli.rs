//! CP4A private/sanitized report isolation for structured component evidence.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::Digest;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rnc"))
}

fn rules() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-providers-v1.json")
}

fn scan(root: &Path, format: &str, output: &Path) -> Output {
    Command::new(binary())
        .args([
            "scan",
            "--root",
            root.to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            format,
            "--output",
            output.to_str().unwrap(),
            "--run-id",
            "cp4a-cli-structured",
            "--mode",
            "whole",
            "--strategy",
            "regex",
            "--accept-result",
            "3",
        ])
        .output()
        .unwrap()
}

#[test]
fn structured_components_are_private_only() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    let reports = temp.path().join("reports");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&reports).unwrap();
    let password = "pQ7mL2nR9xT4vW8yZ";
    let data = format!("DATABASE_URL=postgresql://db_user:{password}@db.example.invalid/app\n");
    fs::write(root.join("db.env"), &data).unwrap();

    let private_path = reports.join("private.json");
    let completed = scan(&root, "json", &private_path);
    assert_eq!(completed.status.code(), Some(0), "{completed:?}");
    let private_bytes = fs::read(&private_path).unwrap();
    let private_text = String::from_utf8(private_bytes.clone()).unwrap();
    assert!(!private_text.contains(password));
    let document: serde_json::Value = serde_json::from_slice(&private_bytes).unwrap();
    assert_eq!(document["structured_evidence"]["version"], "1");
    let components = document["structured_evidence"]["components"]
        .as_array()
        .unwrap();
    assert_eq!(components.len(), 1);
    let component = &components[0];
    assert_eq!(component["kind"], "database-password");
    assert_eq!(component["unit_id"], document["findings"][0]["unit_id"]);
    assert_eq!(
        component["finding_id"],
        document["findings"][0]["finding_id"]
    );
    assert_eq!(component["line"], component["line_end"]);
    let start = component["start_byte"].as_u64().unwrap() as usize;
    let end = component["end_byte"].as_u64().unwrap() as usize;
    assert_eq!(&data.as_bytes()[start..end], password.as_bytes());
    assert_eq!(
        component["normalized_sha256"].as_str().unwrap(),
        format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(password.as_bytes()))
        )
    );

    let summary = String::from_utf8(completed.stdout).unwrap();
    assert!(!summary.contains(password));
    assert!(!summary.contains("source_sha256"));
    assert!(!summary.contains("structured_evidence"));

    let sanitized_path = reports.join("sanitized.json");
    let completed = scan(&root, "sanitized", &sanitized_path);
    assert_eq!(completed.status.code(), Some(0), "{completed:?}");
    let sanitized_text = fs::read_to_string(&sanitized_path).unwrap();
    for forbidden in [
        password,
        "structured_evidence",
        "source_sha256",
        "normalized_sha256",
        "database-password",
        "db.env",
        "db_user",
    ] {
        assert!(
            !sanitized_text.contains(forbidden),
            "sanitized report leaked {forbidden:?}"
        );
    }
}
