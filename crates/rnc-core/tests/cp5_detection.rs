//! CP5 detection-recovery regressions.
//!
//! These fixtures are independently authored synthetic values. Assertions use
//! exact source byte spans and digests so a finding with the right identifier
//! but the wrong captured value cannot pass.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rnc_core::backend::{BackendRequest as Strategy, MatchPlan};
use rnc_core::stream::{scan_content, ScanContentConfig};
use rnc_core::{
    scan, BackendRequest, LoadedBundle, LocalSource, PolicySpec, RunConfig, ScanLimits, ScanMode,
};
use tempfile::tempdir;

fn provider_rules() -> LoadedBundle {
    LoadedBundle::load(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-providers-v1.json"),
    )
    .expect("provider rules")
}

fn scan_root(root: &Path) -> rnc_core::ScanReport {
    let source = LocalSource::new_with_policy(root.to_path_buf(), &PolicySpec::empty()).unwrap();
    let config = RunConfig {
        run_id: "cp5-detection-test".to_string(),
        limits: ScanLimits::default(),
        mode: ScanMode::Whole,
        stream_threshold_bytes: 1024 * 1024,
        strategy: BackendRequest::Prefilter,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![3],
        config_source: "cp5-test".to_string(),
        config_provenance: BTreeMap::new(),
        deadline: None,
        ..RunConfig::default()
    };
    scan(source.discover(), &provider_rules(), &config).expect("scan")
}

fn unit_locator(report: &rnc_core::ScanReport, unit_id: &str) -> String {
    report
        .execution
        .units
        .iter()
        .find(|unit| unit.unit_id == unit_id)
        .map(|unit| unit.locator.clone())
        .unwrap_or_else(|| panic!("missing unit {unit_id}"))
}

fn observed(report: &rnc_core::ScanReport, root: &Path) -> Vec<(String, String, usize, Vec<u8>)> {
    report
        .findings
        .iter()
        .map(|finding| {
            let locator = unit_locator(report, &finding.unit_id);
            let data = std::fs::read(root.join(&locator)).unwrap();
            (
                locator,
                finding.rule_id.clone(),
                finding.line,
                data[finding.start_byte..finding.end_byte].to_vec(),
            )
        })
        .collect()
}

fn assert_exact_value(observed: &[(String, String, usize, Vec<u8>)], value: &str) {
    assert!(
        observed
            .iter()
            .any(|(_, _, _, captured)| captured.as_slice() == value.as_bytes()),
        "missing exact value {value:?}; observed={observed:?}"
    );
}

#[test]
fn wordpress_authentication_material_is_captured_across_representations() {
    let root = tempdir().unwrap();
    let php_value = "Wp5!xQ#7@Lm2$Rt9%Uv4^Yb8&Nc3*Hd6(Jf1)Kg0_Ps+Ze=Ab-Cd/Ef{Gh}Ij<K>Lm?No";
    let env_value = "P9qL2vN7xR4mT8sK1dF6hJ3cW5bZ0yE7uA2iO9gS4pQ8rV1nM6kD3fH5jL0cB7";
    let base64_value =
        "Q3hpQVllRjNaNGwtSkVZc3RNN3oxSFFNdDNVT0pSYWxmNHU5Qmh1Wl83ejJrWEZHaVV1aEFtQWxDWUYxMmkxRQ==";
    std::fs::write(
        root.path().join("wp-config.php"),
        format!(
            "<?php\n\
             define( 'AUTH_KEY',         '{php_value}' );\n\
             define('NONCE_SALT', '{env_value}');\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join(".env"),
        format!("WP_SALT_3={env_value}\nWP_SALT_10={env_value}\n"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("secret.yaml"),
        format!("apiVersion: v1\ndata:\n  auth-key: {base64_value}\n"),
    )
    .unwrap();

    let report = scan_root(root.path());
    let findings = observed(&report, root.path());
    let wordpress: Vec<_> = findings
        .iter()
        .filter(|(_, rule, _, _)| rule == "wordpress-auth-key-salt")
        .collect();
    assert_eq!(
        wordpress.len(),
        5,
        "expected exactly the five authored WordPress values: {findings:?}"
    );
    assert_exact_value(&findings, php_value);
    assert_exact_value(&findings, env_value);
    assert_exact_value(&findings, base64_value);
    assert!(wordpress.iter().any(|(_, _, line, _)| *line == 2));
}

#[test]
fn wordpress_rule_rejects_placeholders_and_non_credential_identifiers() {
    let root = tempdir().unwrap();
    std::fs::write(
        root.path().join("negatives.env"),
        "AUTH_KEY=changeme\n\
         AUTH_KEY=${AUTH_KEY}\n\
         AUTH_KEY_HINT=this-is-not-a-credential-000000000000000000000000\n\
         SECURE_AUTH_KEY=short\n\
         WP_SALT_1=replace_with_generated_value\n",
    )
    .unwrap();
    let report = scan_root(root.path());
    let findings = observed(&report, root.path());
    assert!(
        findings.is_empty(),
        "placeholder and boundary negatives produced findings: {findings:?}"
    );
}

#[test]
fn hmac_and_signing_identifiers_are_recognized_with_exact_values() {
    let root = tempdir().unwrap();
    let signing = "nP4vB8xQ2rT7mW9cL5hJ1sK6dF3gY0zA8uE2iO4p";
    let jwt_signing = "Q7mZ2xV9pL4nR8tK1sD6fH3jW5cB0yE7uA2iO9gS4";
    let hmac_secret = "rT5nY8kM3xQ7vL2pD9sF4hJ6cW1bZ0uE8iO5aG2";
    let payments = "Z9kQ3vN7xT1mR5pL8sD2fH6jW4cB0yE3uA7iO9gS";
    let camel = "M2sD7fH1jL5cB9yE3uA6iO0gS4pQ8rV2nK6xT1mW5";
    let k8s = "T8nR2xL6mK0pD4fH7jW1cB5yE9uA3iO6gS2pQ8rV1nM5kD9fH3";
    std::fs::write(
        root.path().join("signing.env"),
        format!(
            "SIGNING_KEY={signing}\n\
             JWT_SIGNING_KEY={jwt_signing}\n\
             HMAC_SECRET={hmac_secret}\n\
             PAYMENTS_SIGNING_KEY={payments}\n\
             SESSION_SECRET={signing}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("signing.json"),
        format!("{{\"SigningKey\": \"{camel}\"}}\n"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("signing.yaml"),
        format!("data:\n  jwt-signing-key: {k8s}\n"),
    )
    .unwrap();

    let report = scan_root(root.path());
    let findings = observed(&report, root.path());
    for value in [signing, jwt_signing, hmac_secret, payments, camel, k8s] {
        assert_exact_value(&findings, value);
    }
    assert_eq!(
        findings
            .iter()
            .filter(|(_, rule, _, _)| rule == "generic-secret-assignment")
            .count(),
        7,
        "SESSION_SECRET control and all six signing values must be retained: {findings:?}"
    );
}

#[test]
fn signing_identifier_aliases_do_not_match_algorithm_or_identifier_fields() {
    let root = tempdir().unwrap();
    std::fs::write(
        root.path().join("aliases.env"),
        "SIGNING_KEY_ALGORITHM=HS256\n\
         HMAC_KEY_ID=identifier-only-not-a-secret\n\
         JWT_SIGNING_KEY_KID=key-id-only-not-a-secret\n\
         HMAC_SECRET_NAME=metadata-only-not-a-secret\n",
    )
    .unwrap();
    let report = scan_root(root.path());
    let findings = observed(&report, root.path());
    assert!(
        findings.is_empty(),
        "algorithm/metadata aliases produced findings: {findings:?}"
    );
}

#[test]
fn wordpress_and_signing_rules_are_equivalent_across_backends() {
    let value = "Wp5!xQ#7@Lm2$Rt9%Uv4^Yb8&Nc3*Hd6(Jf1)Kg0_Ps+Ze=Ab-Cd/Ef{Gh}Ij<K>Lm?No";
    let content = format!(
        "<?php\ndefine('AUTH_KEY', '{value}');\nSIGNING_KEY=Q7mZ2xV9pL4nR8tK1sD6fH3jW5cB0yE7uA2iO9gS4\n"
    );
    let rules = provider_rules();
    let baseline = {
        let plan = MatchPlan::new(&rules, Strategy::Regex).unwrap();
        scan_content(
            content.as_bytes(),
            "u-cp5-equivalence",
            "cp5-equivalence",
            &plan,
            &ScanContentConfig {
                mode: ScanMode::Whole,
                stream_chunk_bytes: 64,
                max_findings: 10,
                deadline: Instant::now() + std::time::Duration::from_secs(5),
            },
        )
        .unwrap()
    };
    let baseline: Vec<_> = baseline
        .findings
        .iter()
        .map(|finding| {
            (
                finding.rule_id.clone(),
                finding.start_byte,
                finding.end_byte,
                finding.evidence_digest.clone(),
            )
        })
        .collect();
    for strategy in [Strategy::RegexSet, Strategy::Prefilter, Strategy::Auto] {
        let plan = MatchPlan::new(&rules, strategy).unwrap();
        let result = scan_content(
            content.as_bytes(),
            "u-cp5-equivalence",
            "cp5-equivalence",
            &plan,
            &ScanContentConfig {
                mode: ScanMode::Whole,
                stream_chunk_bytes: 64,
                max_findings: 10,
                deadline: Instant::now() + std::time::Duration::from_secs(5),
            },
        )
        .unwrap();
        let observed: Vec<_> = result
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.rule_id.clone(),
                    finding.start_byte,
                    finding.end_byte,
                    finding.evidence_digest.clone(),
                )
            })
            .collect();
        assert_eq!(baseline, observed, "strategy {strategy:?} diverged");
    }
}
