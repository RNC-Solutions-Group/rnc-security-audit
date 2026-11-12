//! CP4B contextual candidate validation regression.
//!
//! Fixtures are independently authored synthetic values. Assertions compare
//! exact source bytes, offsets and digests rather than finding counts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rnc_core::backend::{BackendRequest as Strategy, MatchPlan};
use rnc_core::finding::finding_id;
use rnc_core::stream::{scan_content, ScanContentConfig};
use rnc_core::{
    scan, BackendRequest, LoadedBundle, LocalSource, PolicySpec, RunConfig, ScanLimits, ScanMode,
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
        run_id: "cp4b-contextual-test".to_string(),
        limits: ScanLimits::default(),
        mode,
        stream_threshold_bytes: 1,
        stream_chunk_bytes: 48,
        strategy,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![3],
        config_source: "cp4b-test".to_string(),
        config_provenance: BTreeMap::new(),
        deadline: None,
    }
}

fn scan_root(root: &Path, mode: ScanMode, strategy: BackendRequest) -> rnc_core::ScanReport {
    let source = LocalSource::new_with_policy(root.to_path_buf(), &PolicySpec::empty()).unwrap();
    scan(
        source.discover(),
        &provider_rules(),
        &config(mode, strategy),
    )
    .expect("scan")
}

fn digest(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observed {
    locator: String,
    unit_id: String,
    rule_id: String,
    rule_version: String,
    start: usize,
    end: usize,
    line: usize,
    value: Vec<u8>,
    evidence_digest: String,
    finding_id: String,
    confidence: String,
    validation: Vec<String>,
}

fn observed(report: &rnc_core::ScanReport, root: &Path) -> Vec<Observed> {
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
            let locator = units[finding.unit_id.as_str()].to_string();
            let data = std::fs::read(root.join(&locator)).unwrap();
            Observed {
                locator,
                unit_id: finding.unit_id.clone(),
                rule_id: finding.rule_id.clone(),
                rule_version: finding.rule_version.clone(),
                start: finding.start_byte,
                end: finding.end_byte,
                line: finding.line,
                value: data[finding.start_byte..finding.end_byte].to_vec(),
                evidence_digest: finding.evidence_digest.clone(),
                finding_id: finding.finding_id.clone(),
                confidence: finding.confidence.clone(),
                validation: finding.validation.clone(),
            }
        })
        .collect()
}

fn value_bytes<'a>(observed: &'a [Observed], value: &str) -> &'a Observed {
    observed
        .iter()
        .find(|finding| finding.value.as_slice() == value.as_bytes())
        .unwrap_or_else(|| panic!("missing exact value {value:?}: {observed:?}"))
}

fn assert_exact_offsets(data: &[u8], finding: &Observed) {
    assert_eq!(
        &data[finding.start..finding.end],
        finding.value.as_slice(),
        "{}",
        finding.rule_id
    );
    assert_eq!(finding.evidence_digest, digest(&finding.value));
    assert_eq!(
        finding.finding_id,
        finding_id(
            &finding.unit_id,
            &finding.rule_id,
            &finding.rule_version,
            finding.start,
            finding.end,
            &finding.evidence_digest,
        ),
        "finding identity is calculated from exact source evidence"
    );
}

#[test]
fn hex_lengths_and_qualified_names_are_contextually_classified() {
    let root = tempdir().unwrap();
    let hex32 = "0123456789abcdef0123456789abcdef";
    let hex40 = format!("{hex32}01234567");
    let hex64 = format!("{hex32}{hex32}");
    let hex96 = format!("{hex64}{hex32}");
    let hex128 = format!("{hex64}{hex64}");
    let password32 = "fedcba9876543210fedcba9876543210";
    let data = format!(
        "api_key = {hex32}\n\
         oauth_token = \"{hex40}\"\n\
         api_key = {hex64}\n\
         api_key = {hex96}\n\
         secret_key_base: {hex128}\n\
         secretKeyBase: {hex128}\n\
         password = {password32}\n\
         sha256_password = {hex64}\n\
         hash_password = {hex64}\n\
         password_hash = {hex32}\n\
         password_hint = {hex32}\n\
         checksum = {hex32}\n\
         timePasswordChanged: 1515902314887\n\
         api_key = \"$2b$12$0123456789abcdef0123456789abcdef0123456789abcdef01234567\"\n\
         api_key = \"sha256:{hex64}\"\n\
         request_id = {hex32}\n\
         uuid = 550e8400-e29b-41d4-a716-446655440000\n"
    );
    std::fs::write(root.path().join("hex.env"), &data).unwrap();

    let report = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex);
    assert_eq!(report.result.result_code, 3);
    let findings = observed(&report, root.path());
    assert_eq!(findings.len(), 7, "{findings:?}");
    for value in [
        hex32,
        hex40.as_str(),
        hex64.as_str(),
        hex96.as_str(),
        hex128.as_str(),
        password32,
    ] {
        let finding = value_bytes(&findings, value);
        assert_eq!(finding.rule_id, "generic-secret-assignment");
        assert_eq!(finding.rule_version, "2026.11.5");
        assert_eq!(finding.confidence, "low");
        assert!(finding
            .validation
            .iter()
            .any(|item| item == "HEX_CREDENTIAL_SHAPE"));
        assert!(finding
            .validation
            .iter()
            .any(|item| item == "PLAUSIBLE_UNVERIFIED"));
        assert_exact_offsets(data.as_bytes(), finding);
    }
    // Lines 8-17 are digest-named, hint, checksum, timestamp, explicit-hash,
    // identifier and UUID controls.
    assert!(
        !findings
            .iter()
            .any(|finding| (8..=17).contains(&finding.line)),
        "negative control emitted a finding: {findings:?}"
    );
}

#[test]
fn callback_and_prose_are_rejected_while_real_assignments_are_preserved() {
    let root = tempdir().unwrap();
    let password = "Kq7mN2xR9tW4yZ8aB3cD6eF1";
    let define = "Mq7mN2xR9tW4yZ8aB3cD6eF1";
    let php = "Nq7mN2xR9tW4yZ8aB3cD6eF1";
    let array = "Oq7mN2xR9tW4yZ8aB3cD6eF1";
    let xml = "Pq7mN2xR9tW4yZ8aB3cD6eF1";
    let django = "django-insecure-A(b[c]D)eF9gH2jK4mN6pQ8rS0tU2vW4xY6z";
    let data = format!(
        "conn.login('user@example.com', 'examplepassword', function(err, res) {{\n\
         # Risk: userPassword, sshPassphrase, sshUserPassword\n\
         Risk: userPassword, sshPassphrase\n\
         userPassword,sshPassphrase\n\
         password = function(err)\n\
         # password = \"{password}\"\n\
         define('DB_PASSWORD', '{define}');\n\
         $password = '{php}';\n\
         $config['password'] = '{array}';\n\
         <password>{xml}</password>\n\
         SECRET_KEY = '{django}'\n"
    );
    std::fs::write(root.path().join("mixed.txt"), &data).unwrap();

    let report = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex);
    let findings = observed(&report, root.path());
    assert_eq!(findings.len(), 6, "{findings:?}");
    for value in [password, define, php, array, xml, django] {
        let finding = value_bytes(&findings, value);
        assert!(matches!(
            finding.rule_id.as_str(),
            "generic-secret-assignment" | "generic-array-assignment" | "generic-xml-assignment"
        ));
        assert_exact_offsets(data.as_bytes(), finding);
    }
    for forbidden in [
        "function(err",
        "sshPassphrase",
        "examplepassword",
        "userPassword",
    ] {
        assert!(
            !findings
                .iter()
                .any(|finding| finding.value.as_slice() == forbidden.as_bytes()),
            "emitted callback/prose token {forbidden:?}"
        );
    }
}

#[test]
fn every_quoted_and_unquoted_value_alternative_has_exact_offsets() {
    let root = tempdir().unwrap();
    let values = [
        "Dq7mN2xR9tW4yZ8aB3cD6eF1",
        "Sq7mN2xR9tW4yZ8aB3cD6eF1",
        "Bq7mN2xR9tW4yZ8aB3cD6eF1",
        "Uq7mN2xR9tW4yZ8aB3cD6eF1",
        "Aq7mN2xR9tW4yZ8aB3cD6eF1",
        "Cq7mN2xR9tW4yZ8aB3cD6eF1",
        "Eq7mN2xR9tW4yZ8aB3cD6eF1",
        "Fq7mN2xR9tW4yZ8aB3cD6eF1",
    ];
    let data = format!(
        "password = \"{}\"\n\
         password = '{}'\n\
         password = `{}`\n\
         password = {}\n\
         $config['password'] = \"{}\"\n\
         $config['password'] = '{}'\n\
         $config['password'] = `{}`\n\
         $config['password'] = {}\n",
        values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7]
    );
    std::fs::write(root.path().join("groups.txt"), &data).unwrap();

    let report = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex);
    let findings = observed(&report, root.path());
    assert_eq!(findings.len(), 8, "{findings:?}");
    for value in values {
        let finding = value_bytes(&findings, value);
        assert_exact_offsets(data.as_bytes(), finding);
        assert_eq!(finding.confidence, "low");
    }
}

#[test]
fn hex_context_applies_to_array_xml_and_sql_forms() {
    let root = tempdir().unwrap();
    let hex32 = "0123456789abcdef0123456789abcdef";
    let hex64 = format!("{hex32}{hex32}");
    let data = format!(
        "$config['api_key'] = {hex32};\n\
         <api_key>{hex32}</api_key>\n\
         CREATE USER rnc_user WITH PASSWORD '{hex64}';\n"
    );
    std::fs::write(root.path().join("contexts.txt"), &data).unwrap();
    let report = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex);
    let findings = observed(&report, root.path());
    assert_eq!(findings.len(), 3, "{findings:?}");
    for (rule, value) in [
        ("generic-array-assignment", hex32),
        ("generic-xml-assignment", hex32),
        ("generic-sql-password", hex64.as_str()),
    ] {
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == rule && finding.value.as_slice() == value.as_bytes())
            .unwrap_or_else(|| panic!("missing {rule} {value:?}: {findings:?}"));
        assert_eq!(finding.confidence, "low");
        assert!(finding
            .validation
            .iter()
            .any(|item| item == "HEX_CREDENTIAL_SHAPE"));
        assert_exact_offsets(data.as_bytes(), finding);
    }
}

#[test]
fn contextual_findings_are_equivalent_across_modes_and_strategies() {
    let root = tempdir().unwrap();
    let data = "api_key = 0123456789abcdef0123456789abcdef\n\
                secret_key_base: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\
                # password = \"Kq7mN2xR9tW4yZ8aB3cD6eF1\"\n\
                sha256_password = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    std::fs::write(root.path().join("equivalence.env"), data).unwrap();

    let mut baseline: Option<Vec<Observed>> = None;
    for mode in [ScanMode::Whole, ScanMode::Stream, ScanMode::Auto] {
        for strategy in [
            BackendRequest::Regex,
            BackendRequest::RegexSet,
            BackendRequest::Prefilter,
            BackendRequest::Auto,
        ] {
            let report = scan_root(root.path(), mode, strategy);
            let current = observed(&report, root.path());
            assert!(!current.is_empty());
            if let Some(expected) = &baseline {
                assert_eq!(&current, expected, "{mode:?}/{strategy:?}");
            } else {
                baseline = Some(current);
            }
        }
    }
}

#[test]
fn contextual_values_cross_streaming_overlap_without_identity_change() {
    let rules = provider_rules();
    let plan = MatchPlan::new(&rules, Strategy::Regex).unwrap();
    let value = "0123456789abcdef0123456789abcdef";
    let mut data = vec![b'x'; 65_580];
    data.push(b'\n');
    data.extend_from_slice(format!("api_key = {value}\n").as_bytes());
    let deadline = Instant::now() + Duration::from_secs(30);
    let scan = |mode| {
        scan_content(
            &data,
            "u-boundary",
            "r-boundary",
            &plan,
            &ScanContentConfig {
                mode,
                stream_chunk_bytes: 48,
                max_findings: 10,
                deadline,
            },
        )
        .unwrap()
    };
    let whole = scan(ScanMode::Whole);
    let streamed = scan(ScanMode::Stream);
    assert_eq!(whole.findings.len(), 1);
    assert_eq!(streamed.findings.len(), 1);
    let start = 65_581 + "api_key = ".len();
    for report in [&whole, &streamed] {
        assert_eq!(report.findings[0].start_byte, start);
        assert_eq!(report.findings[0].end_byte, start + value.len());
        assert_eq!(report.findings[0].evidence_digest, digest(value.as_bytes()));
    }
    assert_eq!(
        whole.findings[0].finding_id,
        streamed.findings[0].finding_id
    );
}

#[test]
fn private_and_sanitized_reports_preserve_component_isolation() {
    let root = tempdir().unwrap();
    let password = "GiT9pL2mN8xR4tW";
    let data = format!(
        "DATABASE_URL=postgresql://db_user:{password}@db.example.invalid/app\n\
         api_key = 0123456789abcdef0123456789abcdef\n"
    );
    std::fs::write(root.path().join("db.env"), &data).unwrap();
    let report = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex);
    let findings = observed(&report, root.path());
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "database-connection-credential"));
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "generic-secret-assignment"));

    let private = report.private_value().unwrap();
    let private_text = serde_json::to_string(&private).unwrap();
    assert!(!private_text.contains("identifier_capture_group"));
    assert!(!private_text.contains(password));
    let component = report
        .structured_evidence
        .components
        .iter()
        .find(|component| component.kind == "database-password")
        .expect("database component");
    assert_eq!(
        &data.as_bytes()[component.start_byte..component.end_byte],
        password.as_bytes()
    );
    assert_eq!(component.source_sha256, digest(password.as_bytes()));

    let sanitized = serde_json::to_string(&report.sanitized_value()).unwrap();
    for forbidden in [
        "structured_evidence",
        "database-password",
        password,
        "0123456789abcdef0123456789abcdef",
        "db.env",
    ] {
        assert!(
            !sanitized.contains(forbidden),
            "sanitized leaked {forbidden}"
        );
    }
}
