//! AWS identifier taxonomy and GitHub installation-token format integration.
//!
//! These fixtures are constructed at test time from documented prefixes and
//! harmless synthetic bodies. The independent taxonomy file is not produced by
//! the detector and records which prefixes are credentials, which are ordinary
//! IAM resource identifiers, and which are deliberately unsupported.

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

fn taxonomy() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/cp3/aws-identifier-taxonomy.json");
    serde_json::from_slice(&std::fs::read(path).expect("AWS taxonomy")).unwrap()
}

fn body(serial: usize, length: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut value = serial + 1000;
    let mut output = Vec::with_capacity(length);
    for _ in 0..4.min(length) {
        output.push(ALPHABET[value % ALPHABET.len()]);
        value /= ALPHABET.len();
    }
    while output.len() < length {
        let offset = output.len();
        output.push(ALPHABET[(serial * 13 + offset * 7) % ALPHABET.len()]);
    }
    String::from_utf8(output).unwrap()
}

fn token(prefix: &str, serial: usize) -> String {
    format!("{prefix}{}", body(serial, 16))
}

fn case_tokens(case: &Value, serial: usize) -> (String, Vec<(String, Option<String>)>) {
    let format = case.get("format").and_then(Value::as_str);
    if let Some(prefixes) = case.get("prefixes").and_then(Value::as_array) {
        let tokens: Vec<(String, Option<String>)> = prefixes
            .iter()
            .enumerate()
            .map(|(offset, prefix)| {
                let value = token(prefix.as_str().unwrap(), serial + offset);
                (value, None)
            })
            .collect();
        let expected_rules: Vec<String> = case
            .get("expected_rule_ids")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let source = if format == Some("iam-json") {
            let principals = tokens
                .iter()
                .map(|(value, _)| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\
                 \"Principal\":{{\"AWS\":[\"arn:aws:iam::111122223333:root\",{principals}]}},\
                 \"Action\":\"s3:GetObject\",\"Resource\":\"*\"}}]}}\n"
            )
        } else {
            tokens
                .iter()
                .map(|(value, _)| value.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
                + "\n"
        };
        let mut rule_iter = expected_rules.iter();
        let expected = tokens
            .iter()
            .filter_map(|(value, _)| {
                let credential = value.starts_with("AKIA")
                    || value.starts_with("ASIA")
                    || value.starts_with("ABIA")
                    || value.starts_with("ACCA");
                credential.then(|| (value.clone(), Some(rule_iter.next().unwrap().clone())))
            })
            .collect();
        return (source, expected);
    }

    let prefix = case["prefix"].as_str().unwrap();
    let value = if let Some(suffix) = case.get("body_suffix").and_then(Value::as_str) {
        format!("{prefix}{suffix}")
    } else {
        let length = case
            .get("body_length")
            .and_then(Value::as_u64)
            .unwrap_or(16) as usize;
        format!("{prefix}{}", body(serial, length))
    };
    let source = if format == Some("iam-json") {
        format!(
            "{{\"Version\":\"2012-10-17\",\"Statement\":[{{\"Effect\":\"Allow\",\
             \"Principal\":{{\"AWS\":[\"arn:aws:iam::111122223333:root\",\"{value}\"]}},\
             \"Action\":\"s3:GetObject\",\"Resource\":\"*\"}}]}}\n"
        )
    } else if format == Some("boundary") {
        format!("key={value}! trailing\n")
    } else {
        format!("record = {value};\n")
    };
    let expected_rule = case
        .get("expected_rule_id")
        .and_then(Value::as_str)
        .map(str::to_string);
    (source, vec![(value, expected_rule)])
}

fn build_fixture() -> (TempDir, BTreeMap<String, String>, BTreeSet<String>) {
    let document = taxonomy();
    let root = tempdir().expect("AWS taxonomy tempdir");
    let mut expected = BTreeMap::new();
    let mut forbidden = BTreeSet::new();
    let mut serial = 0usize;
    for case in document["cases"].as_array().unwrap() {
        let step = case
            .get("prefixes")
            .and_then(Value::as_array)
            .map_or(1, |values| values.len());
        let (source, tokens) = case_tokens(case, serial);
        serial += step + 1;
        let path = format!("{}.txt", case["case_id"].as_str().unwrap());
        std::fs::write(root.path().join(&path), source.as_bytes()).unwrap();
        for (value, rule) in tokens {
            if let Some(rule) = rule {
                expected.insert(value, rule);
            } else {
                forbidden.insert(value);
            }
        }
    }
    (root, expected, forbidden)
}

fn config(mode: ScanMode, strategy: BackendRequest) -> RunConfig {
    RunConfig {
        run_id: "cp3-aws-taxonomy-test".to_string(),
        limits: ScanLimits::default(),
        mode,
        stream_threshold_bytes: 1,
        stream_chunk_bytes: 32,
        strategy,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![3],
        config_source: "cp3-aws-taxonomy-test".to_string(),
        config_provenance: BTreeMap::new(),
        deadline: None,
    }
}

fn scan_case(root: &Path, mode: ScanMode, strategy: BackendRequest) -> rnc_core::ScanReport {
    let source = LocalSource::new_with_policy(root.to_path_buf(), &PolicySpec::empty()).unwrap();
    let discovery = source.discover();
    scan(discovery, &provider_rules(), &config(mode, strategy)).expect("scan")
}

fn findings_by_token(report: &rnc_core::ScanReport, root: &Path) -> BTreeMap<String, String> {
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
            (value, finding.rule_id.clone())
        })
        .collect()
}

#[test]
fn aws_identifier_taxonomy_is_enforced_on_every_mode_and_strategy() {
    let document = taxonomy();
    assert_eq!(document["cases"].as_array().unwrap().len(), 20);
    let (root, expected, forbidden) = build_fixture();
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
            let actual = findings_by_token(&report, root.path());
            assert_eq!(actual, expected, "{mode:?}/{strategy:?}");
            assert!(
                forbidden.iter().all(|value| !actual.contains_key(value)),
                "ordinary IAM identifier was reported as a credential: {mode:?}/{strategy:?}"
            );
            assert_eq!(actual.len(), 10);
            for (value, rule) in &actual {
                match rule.as_str() {
                    "aws-access-key-id" => {
                        assert!(
                            value.starts_with("AKIA") || value.starts_with("ASIA"),
                            "{value}"
                        )
                    }
                    "aws-sts-service-bearer-token-id" => assert!(value.starts_with("ABIA")),
                    "aws-context-specific-credential-id" => assert!(value.starts_with("ACCA")),
                    other => panic!("unexpected AWS credential rule {other} for {value}"),
                }
            }
        }
    }
}

#[test]
fn aws_catalog_does_not_reintroduce_resource_prefixes() {
    let rules = provider_rules();
    let text = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-providers-v1.json"),
    )
    .unwrap();
    for prefix in [
        "AIDA", "AGPA", "AIPA", "ANPA", "ANVA", "APKA", "AROA", "ASCA",
    ] {
        assert!(
            !text.contains(&format!("\"({prefix}\"")),
            "resource prefix {prefix} appears in a credential pattern"
        );
    }
    assert_eq!(rules.rule_count(), 19);
    assert_eq!(rules.family_count(), 12);
}
