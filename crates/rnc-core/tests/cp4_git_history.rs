//! CP4 read-only Git-history acquisition and occurrence attribution.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use rnc_core::policy::PolicyOrigin;
use rnc_core::{
    scan, BackendRequest, ExecutionState, GitHistoryOptions, GitHistorySource, LoadedBundle,
    PolicySpec, RunConfig, ScanLimits, ScanMode,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn provider_rules() -> LoadedBundle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-providers-v1.json");
    LoadedBundle::load(&path).expect("provider rules")
}

fn git(repo: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo)
        .args(arguments)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
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

fn init_repo(path: &Path) {
    init_repo_with_branch(path, "main");
}

fn init_repo_with_branch(path: &Path, branch: &str) {
    git(path, &["init", "-q", "-b", branch]);
    git(path, &["config", "user.email", "cp4@example.invalid"]);
    git(path, &["config", "user.name", "CP4 History Test"]);
    git(path, &["config", "commit.gpgsign", "false"]);
}

fn commit(repo: &Path, message: &str) -> String {
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", message]);
    git(repo, &["rev-parse", "HEAD"])
}

fn config(mode: ScanMode, strategy: BackendRequest) -> RunConfig {
    RunConfig {
        run_id: "cp4-history-test".to_string(),
        limits: ScanLimits {
            max_total_bytes: 8 * 1024 * 1024,
            ..ScanLimits::default()
        },
        mode,
        stream_threshold_bytes: 1,
        stream_chunk_bytes: 32,
        strategy,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![3],
        config_source: "cp4-history".to_string(),
        config_provenance: BTreeMap::new(),
        deadline: Some(Instant::now() + Duration::from_secs(30)),
    }
}

fn scan_history(repo: &Path, mode: ScanMode, strategy: BackendRequest) -> rnc_core::ScanReport {
    let source = GitHistorySource::open(
        repo.to_path_buf(),
        &GitHistoryOptions {
            max_commits: 100,
            max_units: 1000,
            ..GitHistoryOptions::default()
        },
    )
    .expect("open history");
    let discovery = source.discover_until(Instant::now() + Duration::from_secs(20));
    scan(discovery, &provider_rules(), &config(mode, strategy)).expect("history scan")
}

fn evidence(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn findings(report: &rnc_core::ScanReport) -> Vec<(String, String, String, String, String)> {
    let units: BTreeMap<&str, &str> = report
        .execution
        .units
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit.locator.as_str()))
        .collect();
    report
        .findings
        .iter()
        .map(|finding| {
            (
                units[finding.unit_id.as_str()].to_string(),
                finding.rule_id.clone(),
                finding.evidence_digest.clone(),
                finding.finding_id.clone(),
                finding.unit_id.clone(),
            )
        })
        .collect()
}

fn repo_content_digest(repo: &Path) -> String {
    fn walk(root: &Path, current: &Path, output: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(current)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                walk(root, &path, output);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                output.push((relative, std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut entries = Vec::new();
    walk(&repo.join(".git"), &repo.join(".git"), &mut entries);
    let mut hasher = Sha256::new();
    for (path, bytes) in entries {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

fn build_history(repo: &Path) -> (String, String, String, String, String, String) {
    init_repo(repo);
    std::fs::write(repo.join("README.md"), "initial clean repository\n").unwrap();
    let clean = commit(repo, "initial clean commit");
    let first = format!("AKIA{}", "Q7Z3K5M2N4P6R8T0");
    let second = format!("AKIA{}", "R8T4M2N6P0Q3S5V7");
    std::fs::write(repo.join("app.env"), format!("AWS_ACCESS_KEY_ID={first}\n")).unwrap();
    let introduced = commit(repo, "introduce credential");
    std::fs::write(
        repo.join("app.env"),
        format!("AWS_ACCESS_KEY_ID={second}\n"),
    )
    .unwrap();
    let modified = commit(repo, "modify credential");
    std::fs::remove_file(repo.join("app.env")).unwrap();
    let removed = commit(repo, "remove credential");
    std::fs::write(
        repo.join("restored.env"),
        format!("AWS_ACCESS_KEY_ID={first}\n"),
    )
    .unwrap();
    std::fs::write(
        repo.join("other.env"),
        format!("AWS_ACCESS_KEY_ID={second}\n"),
    )
    .unwrap();
    let repeated = commit(repo, "repeat credentials in separate paths");
    std::fs::rename(repo.join("restored.env"), repo.join("renamed.env")).unwrap();
    let renamed = commit(repo, "rename credential path");
    (clean, introduced, modified, removed, repeated, renamed)
}

#[test]
fn history_reports_commit_path_occurrences_without_mutating_repository() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let (clean, introduced, modified, removed, repeated, renamed) = build_history(&repo);
    let first = format!("AKIA{}", "Q7Z3K5M2N4P6R8T0");
    let second = format!("AKIA{}", "R8T4M2N6P0Q3S5V7");
    let head_before = git(&repo, &["rev-parse", "HEAD"]);
    let status_before = git(&repo, &["status", "--porcelain"]);
    let before = repo_content_digest(&repo);

    let report = scan_history(&repo, ScanMode::Whole, BackendRequest::Regex);
    assert_eq!(report.execution.state, ExecutionState::Completed);
    assert_eq!(report.execution.source_adapter.id, "local-git-history");
    assert_eq!(report.execution.required_uninspected_count(), 0);
    let history = report.history.as_ref().expect("history metadata");
    assert_eq!(history.commits, 6);
    assert_eq!(history.deleted_paths, 2);
    assert!(history.scope.contains("all-reachable"));
    let observed = findings(&report);
    let expected = BTreeSet::from([
        (
            format!("commit/{introduced}/app.env"),
            "aws-access-key-id".to_string(),
            evidence(&first),
        ),
        (
            format!("commit/{modified}/app.env"),
            "aws-access-key-id".to_string(),
            evidence(&second),
        ),
        (
            format!("commit/{repeated}/restored.env"),
            "aws-access-key-id".to_string(),
            evidence(&first),
        ),
        (
            format!("commit/{repeated}/other.env"),
            "aws-access-key-id".to_string(),
            evidence(&second),
        ),
        (
            format!("commit/{renamed}/renamed.env"),
            "aws-access-key-id".to_string(),
            evidence(&first),
        ),
    ]);
    let actual: BTreeSet<_> = observed
        .iter()
        .map(|(locator, rule, digest, _, _)| (locator.clone(), rule.clone(), digest.clone()))
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(observed.len(), 5);
    assert_eq!(
        observed
            .iter()
            .map(|(_, _, digest, _, _)| digest)
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    assert!(observed
        .iter()
        .all(|(locator, _, _, _, _)| { !locator.contains(&clean) && !locator.contains(&removed) }));
    assert!(
        observed
            .iter()
            .map(|(_, _, _, finding_id, _)| finding_id)
            .collect::<BTreeSet<_>>()
            .len()
            == 5
    );

    assert_eq!(before, repo_content_digest(&repo));
    assert_eq!(head_before, git(&repo, &["rev-parse", "HEAD"]));
    assert_eq!(status_before, git(&repo, &["status", "--porcelain"]));
    assert!(!repo.join("app.env").exists());
}

#[test]
fn history_is_equivalent_across_modes_and_strategies() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    build_history(&repo);
    let mut baseline = None;
    for mode in [ScanMode::Whole, ScanMode::Stream] {
        for strategy in [
            BackendRequest::Regex,
            BackendRequest::RegexSet,
            BackendRequest::Prefilter,
            BackendRequest::Auto,
        ] {
            let report = scan_history(&repo, mode, strategy);
            let keys: Vec<_> = findings(&report);
            if let Some(reference) = &baseline {
                assert_eq!(&keys, reference, "{mode:?}/{strategy:?}");
            } else {
                baseline = Some(keys);
            }
        }
    }
}

#[test]
fn history_pre_scan_policy_blocks_before_blob_read() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let (_, introduced, _, _, repeated, _) = build_history(&repo);
    let first = format!("AKIA{}", "Q7Z3K5M2N4P6R8T0");
    let source = GitHistorySource::open(repo.clone(), &GitHistoryOptions::default()).unwrap();
    let mut discovery = source.discover_until(Instant::now() + Duration::from_secs(20));
    let mut policy = PolicySpec::empty();
    policy
        .add_block(
            "HISTORY-BLOCK",
            PolicyOrigin::Cli,
            &format!("commit/{repeated}/restored.env"),
            "operator block for history fixture",
            "1",
            false,
        )
        .unwrap();
    rnc_core::LocalSource::apply_policy_to_discovery(&mut discovery, &policy);
    let blocked = discovery
        .units
        .iter()
        .find(|unit| unit.locator == format!("commit/{repeated}/restored.env"))
        .unwrap();
    assert_eq!(blocked.scope, rnc_core::input::PreScanScope::Blocked);
    let mut run = config(ScanMode::Whole, BackendRequest::Regex);
    run.policy = policy;
    run.accepted_result_codes = vec![2, 3];
    let report = scan(discovery, &provider_rules(), &run).unwrap();
    assert_eq!(report.execution.blocked_count(), 1);
    let observed = findings(&report);
    assert!(observed.iter().any(|(locator, _, digest, _, _)| {
        locator == &format!("commit/{introduced}/app.env") && digest == &evidence(&first)
    }));
    assert!(!observed
        .iter()
        .any(|(locator, _, _, _, _)| locator == &format!("commit/{repeated}/restored.env")));
    assert_eq!(observed.len(), 4);
}

#[test]
fn merge_occurrences_remain_distinct_and_bare_repositories_are_supported() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(repo.join("README.md"), "base\n").unwrap();
    commit(&repo, "base");
    git(&repo, &["checkout", "-qb", "feature"]);
    let token = format!("AKIA{}", "M4P8R2T6V0W3Y5B7");
    std::fs::write(
        repo.join("branch.env"),
        format!("AWS_ACCESS_KEY_ID={token}\n"),
    )
    .unwrap();
    let branch_commit = commit(&repo, "feature credential");
    git(&repo, &["checkout", "-q", "main"]);
    std::fs::write(repo.join("main.txt"), "main only\n").unwrap();
    commit(&repo, "main change");
    git(
        &repo,
        &["merge", "-q", "--no-ff", "-m", "merge feature", "feature"],
    );
    let merge_commit = git(&repo, &["rev-parse", "HEAD"]);

    let report = scan_history(&repo, ScanMode::Whole, BackendRequest::Regex);
    let observed = findings(&report);
    let expected = BTreeSet::from([
        (
            format!("commit/{branch_commit}/branch.env"),
            "aws-access-key-id".to_string(),
            evidence(&token),
        ),
        (
            format!("commit/{merge_commit}/branch.env"),
            "aws-access-key-id".to_string(),
            evidence(&token),
        ),
    ]);
    let actual: BTreeSet<_> = observed
        .iter()
        .map(|(locator, rule, digest, _, _)| (locator.clone(), rule.clone(), digest.clone()))
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(
        observed
            .iter()
            .map(|(_, _, _, finding_id, _)| finding_id)
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );

    let bare = temp.path().join("bare.git");
    let clone = Command::new("git")
        .args(["clone", "-q", "--bare"])
        .arg(&repo)
        .arg(&bare)
        .output()
        .unwrap();
    assert!(
        clone.status.success(),
        "bare clone failed: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    let bare_report = scan_history(&bare, ScanMode::Stream, BackendRequest::Prefilter);
    let bare_occurrences: BTreeSet<_> = findings(&bare_report)
        .into_iter()
        .map(|(locator, rule, digest, _, _)| (locator, rule, digest))
        .collect();
    let repo_occurrences: BTreeSet<_> = observed
        .into_iter()
        .map(|(locator, rule, digest, _, _)| (locator, rule, digest))
        .collect();
    assert_eq!(bare_occurrences, repo_occurrences);
}

#[test]
fn submodule_gitlinks_are_uninspected_and_detached_head_is_traversed() {
    let temp = tempdir().unwrap();
    let submodule_repo = temp.path().join("submodule");
    std::fs::create_dir(&submodule_repo).unwrap();
    init_repo(&submodule_repo);
    std::fs::write(submodule_repo.join("README.md"), "base\n").unwrap();
    commit(&submodule_repo, "base");
    let gitlink = git(&submodule_repo, &["rev-parse", "HEAD"]);
    let cache = format!("160000,{gitlink},vendor-library");
    git(
        &submodule_repo,
        &["update-index", "--add", "--cacheinfo", &cache],
    );
    git(&submodule_repo, &["commit", "-qm", "declared submodule"]);
    let submodule_commit = git(&submodule_repo, &["rev-parse", "HEAD"]);
    let report = scan_history(&submodule_repo, ScanMode::Whole, BackendRequest::Regex);
    assert_eq!(report.result.result_code, 4);
    let unit = report
        .execution
        .units
        .iter()
        .find(|unit| unit.locator == format!("commit/{submodule_commit}/vendor-library"))
        .expect("gitlink unit");
    assert_eq!(unit.disposition, "UNINSPECTED");
    assert!(unit
        .reason_codes
        .iter()
        .any(|code| code == "GIT_SUBMODULE_NOT_TRAVERSED"));

    let detached = temp.path().join("detached");
    std::fs::create_dir(&detached).unwrap();
    init_repo(&detached);
    std::fs::write(detached.join("README.md"), "base\n").unwrap();
    let base = commit(&detached, "base");
    git(&detached, &["checkout", "-q", "--detach", &base]);
    git(&detached, &["branch", "-D", "main"]);
    let token = format!("AKIA{}", "T6V0W3Y5B7M4P8R2");
    std::fs::write(
        detached.join("detached.env"),
        format!("AWS_ACCESS_KEY_ID={token}\n"),
    )
    .unwrap();
    let detached_commit = commit(&detached, "detached credential");
    let report = scan_history(&detached, ScanMode::Whole, BackendRequest::Regex);
    assert_eq!(report.execution.state, ExecutionState::Completed);
    assert!(findings(&report).iter().any(|(locator, _, digest, _, _)| {
        locator == &format!("commit/{detached_commit}/detached.env") && digest == &evidence(&token)
    }));
}

#[test]
fn binary_and_non_utf8_blobs_preserve_original_byte_offsets() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("binary");
    std::fs::create_dir(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(repo.join("README.md"), "base\n").unwrap();
    commit(&repo, "base");
    let token = format!("AKIA{}", "B7M4P8R2T6V0W3Y5");
    let mut content = vec![0xff, 0x00];
    content.extend_from_slice(token.as_bytes());
    content.extend_from_slice(&[0xfe, 0x00]);
    std::fs::write(repo.join("binary.dat"), &content).unwrap();
    let binary_commit = commit(&repo, "binary credential");
    let report = scan_history(&repo, ScanMode::Whole, BackendRequest::Regex);
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "aws-access-key-id")
        .expect("binary finding");
    let unit = report
        .execution
        .units
        .iter()
        .find(|unit| unit.unit_id == finding.unit_id)
        .unwrap();
    assert_eq!(unit.locator, format!("commit/{binary_commit}/binary.dat"));
    assert_eq!(finding.start_byte, 2);
    assert_eq!(finding.end_byte, 2 + token.len());
    assert_eq!(finding.line, 1);
    assert_eq!(finding.evidence_digest, evidence(&token));
}

#[test]
#[allow(clippy::permissions_set_readonly_false)]
fn empty_bounded_shallow_and_corrupt_histories_fail_or_account_explicitly() {
    let temp = tempdir().unwrap();
    let empty = temp.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    init_repo(&empty);
    let report = scan_history(&empty, ScanMode::Whole, BackendRequest::Regex);
    assert_eq!(report.execution.state, ExecutionState::Completed);
    assert_eq!(report.history.as_ref().unwrap().commits, 0);
    assert_eq!(report.result.result_code, 4);
    assert!(report
        .result
        .reason_codes
        .iter()
        .any(|code| code == "NO_REQUIRED_SCOPE"));
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning == "EMPTY_GIT_HISTORY"));

    let repo = temp.path().join("bounded");
    std::fs::create_dir(&repo).unwrap();
    build_history(&repo);
    let source = GitHistorySource::open(
        repo.clone(),
        &GitHistoryOptions {
            max_commits: 2,
            ..GitHistoryOptions::default()
        },
    )
    .unwrap();
    let discovery = source.discover_until(Instant::now() + Duration::from_secs(20));
    assert!(discovery
        .fatal_errors
        .iter()
        .any(|error| error == "GIT_COMMIT_LIMIT"));
    let bounded = scan(
        discovery,
        &provider_rules(),
        &config(ScanMode::Whole, BackendRequest::Regex),
    )
    .unwrap();
    assert_eq!(bounded.result.result_code, 5);

    let shallow = temp.path().join("shallow");
    std::fs::create_dir(&shallow).unwrap();
    build_history(&shallow);
    let shallow_path = git(&shallow, &["rev-parse", "--git-path", "shallow"]);
    let shallow_path = PathBuf::from(shallow_path);
    let shallow_path = if shallow_path.is_absolute() {
        shallow_path
    } else {
        shallow.join(shallow_path)
    };
    std::fs::write(
        &shallow_path,
        format!("{}\n", git(&shallow, &["rev-parse", "HEAD"])),
    )
    .unwrap();
    assert!(GitHistorySource::open(shallow, &GitHistoryOptions::default()).is_err());

    let partial = temp.path().join("partial");
    std::fs::create_dir(&partial).unwrap();
    build_history(&partial);
    git(
        &partial,
        &["config", "--local", "extensions.partialClone", "origin"],
    );
    assert!(GitHistorySource::open(partial, &GitHistoryOptions::default()).is_err());

    let alternate = temp.path().join("alternate");
    std::fs::create_dir(&alternate).unwrap();
    build_history(&alternate);
    let alternate_path = git(
        &alternate,
        &["rev-parse", "--git-path", "objects/info/alternates"],
    );
    let alternate_path = PathBuf::from(alternate_path);
    let alternate_path = if alternate_path.is_absolute() {
        alternate_path
    } else {
        alternate.join(alternate_path)
    };
    std::fs::create_dir_all(alternate_path.parent().unwrap()).unwrap();
    std::fs::write(&alternate_path, "../../outside/objects\n").unwrap();
    assert!(GitHistorySource::open(alternate, &GitHistoryOptions::default()).is_err());

    let corrupt = temp.path().join("corrupt");
    std::fs::create_dir(&corrupt).unwrap();
    build_history(&corrupt);
    let blob = git(&corrupt, &["rev-parse", "HEAD:renamed.env"]);
    let object = corrupt
        .join(".git")
        .join("objects")
        .join(&blob[..2])
        .join(&blob[2..]);
    #[cfg(windows)]
    {
        let mut permissions = std::fs::metadata(&object).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&object, permissions).unwrap();
    }
    std::fs::remove_file(&object).unwrap();
    let source = GitHistorySource::open(corrupt.clone(), &GitHistoryOptions::default()).unwrap();
    let discovery = source.discover_until(Instant::now() + Duration::from_secs(20));
    let corrupt_report = scan(
        discovery,
        &provider_rules(),
        &config(ScanMode::Whole, BackendRequest::Regex),
    )
    .unwrap();
    assert_eq!(corrupt_report.result.result_code, 5);
    assert!(corrupt_report
        .execution
        .fatal_errors
        .iter()
        .any(|error| error == "GIT_OBJECT_UNAVAILABLE"));
}

#[test]
fn history_components_keep_commit_path_attribution() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(repo.join("README.md"), "clean\n").unwrap();
    commit(&repo, "initial");
    let password = "GiT9pL2mN8xR4tW";
    let data = format!("DATABASE_URL=postgresql://db_user:{password}@db.example.invalid/app\r\n");
    std::fs::write(repo.join("db.env"), &data).unwrap();
    let introduced = commit(&repo, "introduce database credential");

    let report = scan_history(&repo, ScanMode::Whole, BackendRequest::Regex);
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.rule_id == "database-connection-credential")
        .expect("database finding");
    let component = report
        .structured_evidence
        .components
        .iter()
        .find(|component| component.finding_id == finding.finding_id)
        .expect("component");
    let unit = report
        .execution
        .units
        .iter()
        .find(|unit| unit.unit_id == finding.unit_id)
        .expect("source unit");
    assert_eq!(unit.locator, format!("commit/{introduced}/db.env"));
    assert_eq!(component.unit_id, finding.unit_id);
    assert_eq!(
        &data.as_bytes()[component.start_byte..component.end_byte],
        password.as_bytes()
    );
    assert_eq!(component.line, 1);
    assert_eq!(component.normalized_sha256, evidence(password));
}
