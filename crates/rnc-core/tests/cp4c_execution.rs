//! CP4C execution-model, Git strategy and profiler regression.
//!
//! These fixtures are synthetic. They verify canonical equivalence and exact
//! evidence, not external accuracy.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use rnc_core::git::{GitHistoryMode, GitHistoryOptions, GitHistorySource, GitIoMode};
use rnc_core::profile::Profiler;
use rnc_core::{
    scan_with_options, BackendRequest, LoadedBundle, LocalSource, PolicySpec, RunConfig,
    ScanExecutionOptions, ScanLimits, ScanMode,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn provider_rules() -> LoadedBundle {
    LoadedBundle::load(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-providers-v1.json"),
    )
    .expect("provider rules")
}

fn config(mode: ScanMode, strategy: BackendRequest) -> RunConfig {
    RunConfig {
        run_id: "cp4c-execution-test".to_string(),
        limits: ScanLimits::default(),
        mode,
        stream_threshold_bytes: 1,
        stream_chunk_bytes: 32,
        strategy,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![3],
        config_source: "cp4c-test".to_string(),
        config_provenance: BTreeMap::new(),
        deadline: None,
    }
}

fn scan_root(
    root: &Path,
    mode: ScanMode,
    strategy: BackendRequest,
    workers: usize,
    profiler: Option<std::sync::Arc<Profiler>>,
) -> rnc_core::ScanReport {
    let source = LocalSource::new_with_policy(root.to_path_buf(), &PolicySpec::empty()).unwrap();
    scan_with_options(
        source.discover(),
        &provider_rules(),
        &config(mode, strategy),
        &ScanExecutionOptions { workers, profiler },
    )
    .expect("scan")
}

fn digest(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Observed {
    locator: String,
    rule_id: String,
    start: usize,
    end: usize,
    line: usize,
    value: Vec<u8>,
    evidence_digest: String,
    finding_id: String,
}

fn git_blob(repo: &Path, locator: &str) -> Vec<u8> {
    let mut parts = locator.splitn(3, '/');
    assert_eq!(parts.next(), Some("commit"));
    let commit = parts.next().expect("commit oid");
    let path = parts.next().expect("path");
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("show")
        .arg(format!("{commit}:{path}"))
        .output()
        .expect("git show");
    assert!(output.status.success(), "git show failed: {locator}");
    output.stdout
}

fn observed(report: &rnc_core::ScanReport, root: &Path) -> Vec<Observed> {
    let units: BTreeMap<&str, &str> = report
        .execution
        .units
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit.locator.as_str()))
        .collect();
    let mut values: Vec<Observed> = report
        .findings
        .iter()
        .map(|finding| {
            let locator = units[finding.unit_id.as_str()].to_string();
            let data = if locator.starts_with("commit/") {
                git_blob(root, &locator)
            } else {
                std::fs::read(root.join(&locator)).unwrap()
            };
            Observed {
                locator,
                rule_id: finding.rule_id.clone(),
                start: finding.start_byte,
                end: finding.end_byte,
                line: finding.line,
                value: data[finding.start_byte..finding.end_byte].to_vec(),
                evidence_digest: finding.evidence_digest.clone(),
                finding_id: finding.finding_id.clone(),
            }
        })
        .collect();
    values.sort();
    values
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
    git(path, &["init", "-q", "-b", "main"]);
    git(path, &["config", "user.email", "cp4c@example.invalid"]);
    git(path, &["config", "user.name", "CP4C Test"]);
    git(path, &["config", "commit.gpgsign", "false"]);
}

fn commit(repo: &Path, message: &str) -> String {
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", message]);
    git(repo, &["rev-parse", "HEAD"])
}

fn history_config(
    io: GitIoMode,
    history_mode: GitHistoryMode,
    context_lines: usize,
) -> GitHistoryOptions {
    GitHistoryOptions {
        refs: Vec::new(),
        max_commits: 100,
        max_units: 1000,
        io,
        history_mode,
        context_lines,
        profiler: None,
    }
}

fn scan_history(
    repo: &Path,
    mode: ScanMode,
    strategy: BackendRequest,
    workers: usize,
    options: GitHistoryOptions,
) -> rnc_core::ScanReport {
    let source = GitHistorySource::open(repo.to_path_buf(), &options).unwrap();
    let discovery = source.discover_until(Instant::now() + Duration::from_secs(30));
    scan_with_options(
        discovery,
        &provider_rules(),
        &config(mode, strategy),
        &ScanExecutionOptions {
            workers,
            profiler: None,
        },
    )
    .expect("history scan")
}

fn build_repo(repo: &Path) -> (String, String, String) {
    init_repo(repo);
    std::fs::write(repo.join("README.md"), "clean\n").unwrap();
    commit(repo, "clean");
    std::fs::write(
        repo.join("app.env"),
        "API_KEY=Qp7mN2xR9tW4yZ8aB3cD6eF1\nDB_PASSWORD=Kq7mN2xR9tW4yZ8aB3cD6eF1\n",
    )
    .unwrap();
    let initial = commit(repo, "initial credentials");
    std::fs::write(
        repo.join("app.env"),
        "API_KEY=Qp7mN2xR9tW4yZ8aB3cD6eF2\nDB_PASSWORD=Kq7mN2xR9tW4yZ8aB3cD6eF1\n",
    )
    .unwrap();
    let changed = commit(repo, "change api key");
    std::fs::write(
        repo.join("rails.yml"),
        "secret_key_base: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
    )
    .unwrap();
    let rails = commit(repo, "add rails secret");
    (initial, changed, rails)
}

#[test]
fn worker_counts_are_canonically_equivalent() {
    let root = tempdir().unwrap();
    for index in 0..6 {
        std::fs::write(
            root.path().join(format!("app{index}.env")),
            format!(
                "API_KEY=Qp7mN2xR9tW4yZ8aB3cD6eF{index}\nDB_PASSWORD=Kq7mN2xR9tW4yZ8aB3cD6eF{index}\n"
            ),
        )
        .unwrap();
    }
    let mut baseline: Option<Vec<Observed>> = None;
    for workers in [1, 2, 4, 8] {
        for mode in [ScanMode::Whole, ScanMode::Stream] {
            for strategy in [
                BackendRequest::Regex,
                BackendRequest::RegexSet,
                BackendRequest::Prefilter,
                BackendRequest::Auto,
            ] {
                let report = scan_root(root.path(), mode, strategy, workers, None);
                let current = observed(&report, root.path());
                assert_eq!(current.len(), 12);
                if let Some(expected) = &baseline {
                    assert_eq!(
                        &current, expected,
                        "workers={workers} {mode:?}/{strategy:?}"
                    );
                } else {
                    baseline = Some(current);
                }
            }
        }
    }
}

#[test]
fn worker_limits_preserve_accounting_and_evidence() {
    let root = tempdir().unwrap();
    for index in 0..6 {
        std::fs::write(
            root.path().join(format!("app{index}.env")),
            format!(
                "API_KEY=Qp7mN2xR9tW4yZ8aB3cD6eF{index}\nDB_PASSWORD=Kq7mN2xR9tW4yZ8aB3cD6eF{index}\n"
            ),
        )
        .unwrap();
    }
    let source =
        LocalSource::new_with_policy(root.path().to_path_buf(), &PolicySpec::empty()).unwrap();
    let discovery = source.discover();
    let mut run = config(ScanMode::Whole, BackendRequest::Regex);
    run.limits.max_findings = 3;
    let one = scan_with_options(
        discovery.clone(),
        &provider_rules(),
        &run,
        &ScanExecutionOptions::default(),
    )
    .unwrap();
    let four = scan_with_options(
        discovery,
        &provider_rules(),
        &run,
        &ScanExecutionOptions {
            workers: 4,
            profiler: None,
        },
    )
    .unwrap();
    assert_eq!(one.result.result_code, four.result.result_code);
    assert_eq!(one.findings.len(), four.findings.len());
    assert_eq!(observed(&one, root.path()), observed(&four, root.path()));
    let one_units: Vec<_> = one
        .execution
        .units
        .iter()
        .map(|unit| (&unit.unit_id, &unit.disposition, &unit.reason_codes))
        .collect();
    let four_units: Vec<_> = four
        .execution
        .units
        .iter()
        .map(|unit| (&unit.unit_id, &unit.disposition, &unit.reason_codes))
        .collect();
    assert_eq!(one_units, four_units);
}

#[test]
fn worker_total_byte_limit_is_order_independent() {
    let root = tempdir().unwrap();
    for index in 0..8 {
        std::fs::write(
            root.path().join(format!("app{index}.env")),
            format!(
                "API_KEY=Qp7mN2xR9tW4yZ8aB3cD6eF{index}\nDB_PASSWORD=Kq7mN2xR9tW4yZ8aB3cD6eF{index}\n"
            ),
        )
        .unwrap();
    }
    let source =
        LocalSource::new_with_policy(root.path().to_path_buf(), &PolicySpec::empty()).unwrap();
    let discovery = source.discover();
    let mut run = config(ScanMode::Whole, BackendRequest::Regex);
    run.limits.max_file_bytes = 128;
    run.limits.max_total_bytes = 220;
    let one = scan_with_options(
        discovery.clone(),
        &provider_rules(),
        &run,
        &ScanExecutionOptions::default(),
    )
    .unwrap();
    let four = scan_with_options(
        discovery,
        &provider_rules(),
        &run,
        &ScanExecutionOptions {
            workers: 4,
            profiler: None,
        },
    )
    .unwrap();
    assert_eq!(one.result.result_code, four.result.result_code);
    assert_eq!(observed(&one, root.path()), observed(&four, root.path()));
    let one_units: Vec<_> = one
        .execution
        .units
        .iter()
        .map(|unit| (&unit.unit_id, &unit.disposition, &unit.reason_codes))
        .collect();
    let four_units: Vec<_> = four
        .execution
        .units
        .iter()
        .map(|unit| (&unit.unit_id, &unit.disposition, &unit.reason_codes))
        .collect();
    assert_eq!(one_units, four_units);
}

#[test]
fn git_process_and_batch_are_exactly_equivalent() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    build_repo(&repo);
    let mut baseline: Option<Vec<Observed>> = None;
    for io in [GitIoMode::Process, GitIoMode::Batch] {
        for workers in [1, 2] {
            for mode in [ScanMode::Whole, ScanMode::Stream] {
                let report = scan_history(
                    &repo,
                    mode,
                    BackendRequest::Regex,
                    workers,
                    history_config(io, GitHistoryMode::Whole, 0),
                );
                let current = observed(&report, &repo);
                assert_eq!(current.len(), 5);
                if let Some(expected) = &baseline {
                    assert_eq!(&current, expected, "{io:?}/{workers}/{mode:?}");
                } else {
                    baseline = Some(current);
                }
            }
        }
    }
}

#[test]
fn batch_and_process_fail_large_objects_closed() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_repo(&repo);
    let value = "Q".repeat(200);
    std::fs::write(repo.join("large.env"), format!("API_KEY={value}\n")).unwrap();
    commit(&repo, "large object");
    let mut run = config(ScanMode::Whole, BackendRequest::Regex);
    run.limits.max_file_bytes = 64;
    run.limits.max_total_bytes = 1024;
    for io in [GitIoMode::Process, GitIoMode::Batch] {
        let source =
            GitHistorySource::open(repo.clone(), &history_config(io, GitHistoryMode::Whole, 0))
                .unwrap();
        let discovery = source.discover_until(Instant::now() + Duration::from_secs(20));
        let report = scan_with_options(
            discovery,
            &provider_rules(),
            &run,
            &ScanExecutionOptions::default(),
        )
        .unwrap();
        assert_eq!(report.result.result_code, 4, "{io:?}");
        assert!(report.execution.units.iter().any(|unit| unit
            .reason_codes
            .iter()
            .any(|reason| reason == "FILE_SIZE_LIMIT")));
    }
}

#[test]
fn missing_objects_are_rejected_in_both_git_io_modes() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(repo.join("app.env"), "clean\n").unwrap();
    commit(&repo, "clean");
    let oid = "0".repeat(40);
    for io in [GitIoMode::Process, GitIoMode::Batch] {
        let source =
            GitHistorySource::open(repo.clone(), &history_config(io, GitHistoryMode::Whole, 0))
                .unwrap();
        let result = source.read_blob(&oid, 1024, Instant::now() + Duration::from_secs(10));
        assert!(
            matches!(result, Err(rnc_core::GitReadError::ObjectUnavailable)),
            "{io:?}: {result:?}"
        );
    }
}

#[test]
fn diff_scanning_uses_introduced_lines_and_context() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let (_initial, changed, _rails) = build_repo(&repo);
    let whole = scan_history(
        &repo,
        ScanMode::Whole,
        BackendRequest::Regex,
        1,
        history_config(GitIoMode::Process, GitHistoryMode::Whole, 0),
    );
    assert_eq!(observed(&whole, &repo).len(), 5);
    for context in [0, 1, 3, 5] {
        let report = scan_history(
            &repo,
            ScanMode::Whole,
            BackendRequest::Regex,
            2,
            history_config(GitIoMode::Process, GitHistoryMode::Diff, context),
        );
        let findings = observed(&report, &repo);
        assert_eq!(findings.len(), 4, "context={context}: {findings:?}");
        assert!(
            !findings.iter().any(|finding| {
                finding.locator == format!("commit/{changed}/app.env")
                    && finding.value == b"Kq7mN2xR9tW4yZ8aB3cD6eF1"
            }),
            "unchanged context credential was emitted in diff mode"
        );
        for finding in &findings {
            let bytes = &finding.value;
            assert_eq!(finding.evidence_digest, digest(bytes));
        }
    }
}

#[test]
fn deletion_only_history_change_is_not_a_coverage_gap() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(repo.join("app.env"), "API_KEY=Qp7mN2xR9tW4yZ8aB3cD6eF1\n").unwrap();
    commit(&repo, "credential");
    std::fs::remove_file(repo.join("app.env")).unwrap();
    commit(&repo, "delete credential");
    let report = scan_history(
        &repo,
        ScanMode::Whole,
        BackendRequest::Regex,
        1,
        history_config(GitIoMode::Process, GitHistoryMode::Diff, 3),
    );
    assert_eq!(report.result.result_code, 3);
    assert_eq!(observed(&report, &repo).len(), 1);
    assert_eq!(report.execution.required_uninspected_count(), 0);
}

#[test]
fn binary_diff_is_explicitly_incomplete() {
    let temp = tempdir().unwrap();
    let repo = temp.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_repo(&repo);
    std::fs::write(repo.join("data.bin"), [0u8, 1, 2, 0, 3]).unwrap();
    commit(&repo, "binary");
    let report = scan_history(
        &repo,
        ScanMode::Whole,
        BackendRequest::Regex,
        1,
        history_config(GitIoMode::Process, GitHistoryMode::Diff, 3),
    );
    assert_eq!(report.result.result_code, 4);
    assert!(report.execution.units.iter().any(|unit| unit
        .reason_codes
        .iter()
        .any(|reason| reason == "GIT_DIFF_BINARY_UNSUPPORTED")));
}

#[test]
fn profiler_is_secret_free_and_does_not_change_findings() {
    let root = tempdir().unwrap();
    let value = "Qp7mN2xR9tW4yZ8aB3cD6eF1";
    std::fs::write(root.path().join("app.env"), format!("API_KEY={value}\n")).unwrap();
    let profiler = std::sync::Arc::new(Profiler::new());
    let profiled = scan_root(
        root.path(),
        ScanMode::Whole,
        BackendRequest::Regex,
        2,
        Some(profiler.clone()),
    );
    let plain = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex, 2, None);
    assert_eq!(
        observed(&profiled, root.path()),
        observed(&plain, root.path())
    );
    let document = profiler.finish("profile-test");
    let payload = serde_json::to_string(&document).unwrap();
    assert!(!payload.contains(value));
    assert!(!payload.contains("app.env"));
    assert_eq!(document.schema_version, "1");
    assert!(document.phases.contains_key("execution"));
    assert!(document.phases.contains_key("scan"));
    assert!(document.worker_phases.contains_key("matching.regex"));
    assert!(document.worker_phases.contains_key("scan.validation"));
    assert!(document.counters["candidates"] >= 1);
}
