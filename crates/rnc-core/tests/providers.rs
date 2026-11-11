//! CP3 provider-catalog integration over independent, harmless fixtures.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rnc_core::{
    scan, BackendRequest, ExecutionState, LoadedBundle, LocalSource, PolicySpec, RunConfig,
    ScanLimits, ScanMode,
};
use serde_json::Value;
use tempfile::{tempdir, TempDir};

fn provider_rules() -> LoadedBundle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-providers-v1.json");
    LoadedBundle::load(&path).expect("provider rules")
}

fn materialize(tier: &str) -> TempDir {
    let bundle_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/providers/bundle.json");
    let bundle: Value =
        serde_json::from_slice(&std::fs::read(bundle_path).expect("fixture bundle")).unwrap();
    let files = bundle["tiers"][tier]
        .as_object()
        .unwrap_or_else(|| panic!("missing fixture tier {tier}"));
    let root = tempdir().expect("fixture tempdir");
    for (relative, encoded) in files {
        let destination = root.path().join(relative);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::write(destination, hex::decode(encoded.as_str().unwrap()).unwrap()).unwrap();
    }
    root
}

fn truth() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/cp3/provider-truth-tier2.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn config(mode: ScanMode, strategy: BackendRequest) -> RunConfig {
    RunConfig {
        run_id: "cp3-provider-test".to_string(),
        limits: ScanLimits::default(),
        mode,
        stream_threshold_bytes: 1,
        stream_chunk_bytes: 64,
        strategy,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![3],
        config_source: "cp3-test".to_string(),
        config_provenance: BTreeMap::new(),
        deadline: None,
    }
}

fn scan_tier2(root: &Path, mode: ScanMode, strategy: BackendRequest) -> rnc_core::ScanReport {
    let source = LocalSource::new_with_policy(root.to_path_buf(), &PolicySpec::empty()).unwrap();
    let discovery = source.discover();
    scan(discovery, &provider_rules(), &config(mode, strategy)).expect("scan")
}

fn expected_keys() -> BTreeSet<(String, usize, usize, String)> {
    truth()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            (
                item["path"].as_str().unwrap().to_string(),
                item["start_byte"].as_u64().unwrap() as usize,
                item["end_byte"].as_u64().unwrap() as usize,
                item["expected_rule_id"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn actual_keys(report: &rnc_core::ScanReport) -> BTreeSet<(String, usize, usize, String)> {
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
                finding.start_byte,
                finding.end_byte,
                finding.rule_id.clone(),
            )
        })
        .collect()
}

#[test]
fn provider_catalog_detects_exactly_the_independent_truth() {
    let root = materialize("tier2");
    let report = scan_tier2(root.path(), ScanMode::Whole, BackendRequest::Regex);
    assert_eq!(report.execution.state, ExecutionState::Completed);
    assert_eq!(report.result.result_code, 3);
    assert_eq!(report.execution.required_uninspected_count(), 0);
    assert_eq!(report.findings.len(), 27);
    assert_eq!(actual_keys(&report), expected_keys());
    assert!(report.findings.iter().all(|finding| {
        finding.rule_id.starts_with("aws-")
            || finding.rule_id.starts_with("github-")
            || finding.rule_id.starts_with("google-")
            || finding.rule_id.starts_with("gitlab-")
            || finding.rule_id.starts_with("stripe-")
            || finding.rule_id.starts_with("slack-")
            || finding.rule_id.starts_with("sendgrid-")
            || finding.rule_id.starts_with("npm-")
            || finding.rule_id.starts_with("pem-")
            || finding.rule_id.starts_with("jwt-")
            || finding.rule_id.starts_with("database-")
            || finding.rule_id.starts_with("generic-")
    }));
    assert!(report.findings.iter().all(|finding| finding
        .validation
        .iter()
        .any(|value| { value == "FORMAT_VALID" || value == "PLAUSIBLE_UNVERIFIED" })));
}

#[test]
fn provider_findings_are_identical_across_modes_and_strategies() {
    let root = materialize("tier2");
    let mut baseline = None;
    for mode in [ScanMode::Whole, ScanMode::Stream] {
        for strategy in [
            BackendRequest::Regex,
            BackendRequest::RegexSet,
            BackendRequest::Prefilter,
            BackendRequest::Auto,
        ] {
            let report = scan_tier2(root.path(), mode, strategy);
            let keys: Vec<_> = report
                .findings
                .iter()
                .map(|finding| {
                    (
                        finding.unit_id.clone(),
                        finding.rule_id.clone(),
                        finding.start_byte,
                        finding.end_byte,
                        finding.evidence_digest.clone(),
                        finding.finding_id.clone(),
                        finding.confidence.clone(),
                        finding.validation.clone(),
                    )
                })
                .collect();
            assert_eq!(
                actual_keys(&report),
                expected_keys(),
                "{mode:?}/{strategy:?}"
            );
            if let Some(reference) = &baseline {
                assert_eq!(&keys, reference, "{mode:?}/{strategy:?}");
            } else {
                baseline = Some(keys);
            }
        }
    }
}

#[test]
fn malformed_public_and_certificate_containers_are_not_private_key_findings() {
    let root = materialize("tier2");
    let report = scan_tier2(root.path(), ScanMode::Whole, BackendRequest::Regex);
    for forbidden in ["pem/public.pem", "pem/certificate.pem"] {
        assert!(
            !report.findings.iter().any(|finding| report
                .execution
                .units
                .iter()
                .any(|unit| { unit.unit_id == finding.unit_id && unit.locator == forbidden })),
            "unexpected finding in {forbidden}"
        );
    }
}

#[test]
fn provider_catalog_has_documented_bounds() {
    let rules = provider_rules();
    assert_eq!(rules.rule_count(), 19);
    assert_eq!(rules.provider_rule_count(), 19);
    assert_eq!(rules.family_count(), 12);
    assert!(rules.max_match_bytes >= 31_000);
    assert!(rules.max_match_bytes <= 65_536);
}
