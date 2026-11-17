//! CP4 CLI behavior for explicit read-only history scans.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rnc"))
}

fn rules() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-synthetic-v1.json")
}

fn git(repo: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(arguments)
        .output()
        .expect("git executable");
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn build_repo(repo: &Path) -> (String, String) {
    fs::create_dir_all(repo).unwrap();
    git(repo, &["init", "-q", "-b", "main"]);
    git(repo, &["config", "user.email", "cp4-cli@example.invalid"]);
    git(repo, &["config", "user.name", "CP4 CLI Test"]);
    git(repo, &["config", "commit.gpgsign", "false"]);
    fs::write(repo.join("README.md"), "clean\n").unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", "clean"]);
    let clean = git(repo, &["rev-parse", "HEAD"]);
    fs::write(
        repo.join("app.env"),
        "KEY=RNC_SYNTH_KEY_GENERIC_CLI_HISTORY\n",
    )
    .unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", "introduce"]);
    let introduced = git(repo, &["rev-parse", "HEAD"]);
    fs::remove_file(repo.join("app.env")).unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", "remove"]);
    (clean, introduced)
}

fn run(repo: &Path, extra: &[&str], output: &Path) -> Output {
    let mut command = Command::new(binary());
    command.args([
        "scan",
        "--root",
        repo.to_str().unwrap(),
        "--rules",
        rules().to_str().unwrap(),
        "--format",
        "json",
        "--output",
        output.to_str().unwrap(),
        "--run-id",
        "cp4-cli-history",
    ]);
    command.args(extra);
    command.output().unwrap()
}

#[test]
fn history_mode_is_explicit_safe_and_attributed() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let (_clean, introduced) = build_repo(&repo);
    let reports = tempfile::tempdir().unwrap();
    let output = reports.path().join("private.json");
    let status_before = git(&repo, &["status", "--porcelain"]);
    let head_before = git(&repo, &["rev-parse", "HEAD"]);

    let completed = run(
        &repo,
        &["--history", "--mode", "whole", "--strategy", "regex"],
        &output,
    );
    assert_eq!(completed.status.code(), Some(10), "{completed:?}");
    let summary = String::from_utf8(completed.stdout).unwrap();
    assert!(summary.contains("Source: local-git-history"), "{summary}");
    assert!(summary.contains("History: 3 commits"), "{summary}");
    assert!(summary.contains("Findings: 1"), "{summary}");
    assert!(!summary.contains("RNC_SYNTH_KEY_"));
    assert!(!summary.contains(&introduced));
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(
        document["execution"]["source_adapter"]["id"],
        "local-git-history"
    );
    assert_eq!(document["history"]["commits"], 3);
    assert_eq!(document["history"]["deleted_paths"], 1);
    assert_eq!(document["execution"]["units"].as_array().unwrap().len(), 2);
    assert_eq!(document["findings"].as_array().unwrap().len(), 1);
    let finding = &document["findings"][0];
    let unit_id = finding["unit_id"].as_str().unwrap();
    let unit = document["execution"]["units"]
        .as_array()
        .unwrap()
        .iter()
        .find(|unit| unit["unit_id"] == unit_id)
        .unwrap();
    assert_eq!(unit["source_kind"], "git_commit_blob");
    assert_eq!(unit["locator"], format!("commit/{introduced}/app.env"));
    assert_eq!(status_before, git(&repo, &["status", "--porcelain"]));
    assert_eq!(head_before, git(&repo, &["rev-parse", "HEAD"]));

    let exempted = reports.path().join("exempted.json");
    let completed = run(
        &repo,
        &[
            "--history",
            "--exempt",
            "path:commit/*/app.env",
            "--mode",
            "whole",
        ],
        &exempted,
    );
    assert_eq!(completed.status.code(), Some(0), "{completed:?}");
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&exempted).unwrap()).unwrap();
    assert_eq!(document["result"]["result_code"], 2);
    assert_eq!(document["result"]["counts"]["exempted"], 1);
    assert_eq!(document["findings"].as_array().unwrap().len(), 1);

    let working = Command::new(binary())
        .args([
            "scan",
            "--root",
            repo.to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--format",
            "summary",
            "--mode",
            "whole",
        ])
        .output()
        .unwrap();
    assert_eq!(working.status.code(), Some(0), "{working:?}");
    assert!(String::from_utf8(working.stdout)
        .unwrap()
        .contains("Result: CLEAN (1)"));
}

#[test]
fn explicit_refs_limits_and_errors_are_visible() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let (clean, introduced) = build_repo(&repo);
    let reports = tempfile::tempdir().unwrap();

    let selected = reports.path().join("selected.json");
    let completed = run(
        &repo,
        &[
            "--history",
            "--ref",
            &introduced,
            "--mode",
            "whole",
            "--strategy",
            "regexset",
        ],
        &selected,
    );
    assert_eq!(completed.status.code(), Some(10), "{completed:?}");
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&selected).unwrap()).unwrap();
    assert_eq!(document["history"]["scope"], "selected-refs");
    assert_eq!(document["history"]["commits"], 2);
    assert_eq!(document["findings"].as_array().unwrap().len(), 1);

    let clean_ref = reports.path().join("clean.json");
    let completed = run(
        &repo,
        &["--history", "--ref", &clean, "--mode", "whole"],
        &clean_ref,
    );
    assert_eq!(completed.status.code(), Some(0), "{completed:?}");
    let document: serde_json::Value =
        serde_json::from_slice(&fs::read(&clean_ref).unwrap()).unwrap();
    assert_eq!(document["result"]["result_code"], 1);
    assert_eq!(document["history"]["commits"], 1);

    let bounded = reports.path().join("bounded.json");
    let completed = run(
        &repo,
        &["--history", "--max-history-commits", "1", "--mode", "whole"],
        &bounded,
    );
    assert_eq!(completed.status.code(), Some(30), "{completed:?}");
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&bounded).unwrap()).unwrap();
    assert_eq!(document["result"]["result_code"], 5);
    assert!(document["execution"]["fatal_errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "GIT_COMMIT_LIMIT"));

    let bad_ref = reports.path().join("bad-ref.json");
    let completed = run(&repo, &["--history", "--ref", "HEAD:README.md"], &bad_ref);
    assert_eq!(completed.status.code(), Some(64));
    assert!(!bad_ref.exists());

    let missing_history = Command::new(binary())
        .args([
            "scan",
            "--root",
            repo.to_str().unwrap(),
            "--rules",
            rules().to_str().unwrap(),
            "--ref",
            "HEAD",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_history.status.code(), Some(64));

    let inside = repo.join("private.json");
    let completed = run(&repo, &["--history"], &inside);
    assert_eq!(completed.status.code(), Some(64));
    assert!(!inside.exists());
}
