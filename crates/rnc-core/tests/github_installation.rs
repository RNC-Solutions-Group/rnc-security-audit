//! GitHub App installation-token format coverage.
//!
//! The modern `ghs_APPID_JWT` token is treated as an opaque client credential.
//! Tests assert bounded structural recognition, not JWT signature or issuer
//! validation, and never contact GitHub.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rnc_core::{
    scan, BackendRequest, ExecutionState, LoadedBundle, LocalSource, PolicySpec, RunConfig,
    ScanLimits, ScanMode,
};
use tempfile::{tempdir, TempDir};

fn provider_rules() -> LoadedBundle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-providers-v1.json");
    LoadedBundle::load(&path).expect("provider rules")
}

fn config(mode: ScanMode, strategy: BackendRequest) -> RunConfig {
    RunConfig {
        run_id: "cp3-github-installation-test".to_string(),
        limits: ScanLimits::default(),
        mode,
        stream_threshold_bytes: 1,
        stream_chunk_bytes: 17,
        strategy,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![3],
        config_source: "cp3-github-installation-test".to_string(),
        config_provenance: BTreeMap::new(),
        deadline: None,
    }
}

fn legacy(seed: &str) -> String {
    let alphabet = b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9";
    let start = seed.bytes().map(usize::from).sum::<usize>() % alphabet.len();
    let body: String = (0..36)
        .map(|offset| alphabet[(start + offset * 7) % alphabet.len()] as char)
        .collect();
    format!("ghs_{body}")
}

fn modern(app_id: &str, segment: usize) -> String {
    let fill = |length: usize| "A1b2C3d4E5f6G7h8".repeat(length / 16 + 1)[..length].to_string();
    format!(
        "ghs_{app_id}_{}.{}.{}",
        fill(segment),
        fill(segment),
        fill(segment)
    )
}

fn fixture() -> (TempDir, BTreeMap<String, String>) {
    let root = tempdir().expect("GitHub installation tempdir");
    let legacy_value = legacy("legacy-one");
    let legacy_punct = legacy("legacy-two");
    let warm = modern("1234567890", 70);
    let steady = modern("9876543210", 170);
    let steady_punct = modern("5555555555", 140);
    let docs_segment = format!("example{}", "A1b2C3d4".repeat(8));
    let docs = format!("ghs_123_{}.{}.{}", docs_segment, docs_segment, docs_segment);
    let malformed_one_dot = format!(
        "ghs_1234567890_{}.{}",
        "A1b2C3d4".repeat(20),
        "E5f6G7h8".repeat(20)
    );
    let malformed_no_app = format!(
        "ghs_{}.{}.{}",
        "A1b2C3d4".repeat(20),
        "E5f6G7h8".repeat(20),
        "I9j0K1l2".repeat(20)
    );
    let malformed_short = "ghs_short".to_string();
    let oversized = format!(
        "ghs_1234567890_{}.{}.{}",
        "A1b2C3d4".repeat(300),
        "A1b2C3d4".repeat(300),
        "A1b2C3d4".repeat(300)
    );
    let files = [
        ("legacy.txt", format!("token = {legacy_value}\n")),
        ("modern.txt", format!("token = {steady}\n")),
        ("modern-short.txt", format!("token = {warm}\n")),
        (
            "punctuation.txt",
            format!("one=\"{legacy_punct}\",two=\"{steady_punct}\"\n"),
        ),
        (
            "malformed.txt",
            format!("{malformed_one_dot}\n{malformed_no_app}\n{malformed_short}\n"),
        ),
        ("documentation.txt", format!("{docs}\n")),
        ("oversized.txt", oversized),
    ];
    for (name, value) in files {
        std::fs::write(root.path().join(name), value.as_bytes()).unwrap();
    }
    let mut expected = BTreeMap::new();
    for value in [legacy_value, legacy_punct, warm, steady, steady_punct] {
        expected.insert(value, "github-app-installation-token".to_string());
    }
    (root, expected)
}

fn scan_case(root: &Path, mode: ScanMode, strategy: BackendRequest) -> rnc_core::ScanReport {
    let source = LocalSource::new_with_policy(root.to_path_buf(), &PolicySpec::empty()).unwrap();
    let discovery = source.discover();
    scan(discovery, &provider_rules(), &config(mode, strategy)).expect("scan")
}

fn actual(
    root: &Path,
    report: &rnc_core::ScanReport,
) -> BTreeMap<String, (String, String, Vec<String>)> {
    let units: BTreeMap<&str, String> = report
        .execution
        .units
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit.locator.clone()))
        .collect();
    report
        .findings
        .iter()
        .map(|finding| {
            let data = std::fs::read(root.join(&units[finding.unit_id.as_str()])).unwrap();
            let value = String::from_utf8(data[finding.start_byte..finding.end_byte].to_vec())
                .expect("ASCII fixture");
            (
                value,
                (
                    finding.rule_id.clone(),
                    finding.confidence.clone(),
                    finding.validation.clone(),
                ),
            )
        })
        .collect()
}

#[test]
fn legacy_and_stateless_installation_tokens_are_equivalent_across_backends() {
    let (root, expected) = fixture();
    for mode in [ScanMode::Whole, ScanMode::Stream] {
        for strategy in [
            BackendRequest::Regex,
            BackendRequest::RegexSet,
            BackendRequest::Prefilter,
            BackendRequest::Auto,
        ] {
            let report = scan_case(root.path(), mode, strategy);
            assert_eq!(report.execution.state, ExecutionState::Completed);
            assert_eq!(report.result.result_code, 3);
            let found = actual(root.path(), &report);
            assert_eq!(
                found
                    .iter()
                    .map(|(value, (rule, _, _))| (value.clone(), rule.clone()))
                    .collect::<BTreeMap<_, _>>(),
                expected,
                "{mode:?}/{strategy:?}"
            );
            assert_eq!(found.len(), 5);
            for (value, (rule, confidence, validation)) in &found {
                assert_eq!(rule, "github-app-installation-token");
                assert!(!value.chars().any(|character| character.is_whitespace()));
                assert!(value.starts_with("ghs_"));
                let modern = value.matches('.').count() == 2;
                let expected_status = if modern {
                    "PLAUSIBLE_UNVERIFIED"
                } else {
                    "FORMAT_VALID"
                };
                let expected_confidence = if modern { "medium" } else { "high" };
                assert_eq!(confidence, expected_confidence, "{value}");
                assert!(
                    validation.iter().any(|item| item == expected_status),
                    "{value}: {validation:?}"
                );
            }
            assert!(report
                .findings
                .iter()
                .all(|finding| finding.rule_id == "github-app-installation-token"));
        }
    }
}

#[test]
fn malformed_and_oversized_stateless_tokens_do_not_establish_coverage() {
    let (root, expected) = fixture();
    let report = scan_case(root.path(), ScanMode::Whole, BackendRequest::Regex);
    let found = actual(root.path(), &report);
    assert_eq!(found.len(), expected.len());
    assert!(!found.keys().any(|value| value == "ghs_short"));
    assert!(!found.keys().any(|value| value.contains("example")));
    assert!(!found.keys().any(|value| value.len() > 7000));
}
