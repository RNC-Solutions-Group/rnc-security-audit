//! CP4A structured credential-component evidence regression.
//!
//! These fixtures are synthetic and generated in the test process. The primary
//! database finding remains the contextual userinfo span; component evidence is
//! private supplementary data.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rnc_core::{
    scan, BackendRequest, LoadedBundle, LocalSource, PolicySpec, RunConfig, ScanLimits, ScanMode,
    StructuredComponent,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn provider_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-providers-v1.json")
}

fn provider_rules() -> LoadedBundle {
    LoadedBundle::load(&provider_path()).expect("provider rules")
}

fn config(mode: ScanMode, strategy: BackendRequest) -> RunConfig {
    RunConfig {
        run_id: "cp4a-structured-test".to_string(),
        limits: ScanLimits::default(),
        mode,
        stream_threshold_bytes: 1,
        stream_chunk_bytes: 64,
        strategy,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![3],
        config_source: "cp4a-test".to_string(),
        config_provenance: BTreeMap::new(),
        deadline: None,
    }
}

fn scan_root(
    root: &Path,
    rules: &LoadedBundle,
    mode: ScanMode,
    strategy: BackendRequest,
) -> rnc_core::ScanReport {
    let source = LocalSource::new_with_policy(root.to_path_buf(), &PolicySpec::empty()).unwrap();
    let discovery = source.discover();
    scan(discovery, rules, &config(mode, strategy)).expect("scan")
}

fn digest(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn component_for<'a>(
    report: &'a rnc_core::ScanReport,
    finding: &rnc_core::Finding,
) -> &'a StructuredComponent {
    report
        .structured_evidence
        .components
        .iter()
        .find(|component| component.finding_id == finding.finding_id)
        .expect("database finding has a component")
}

fn fixture() -> (tempfile::TempDir, Vec<u8>) {
    let root = tempdir().unwrap();
    let plain = "rnc_user:kR9d2mQ7xL4pN8sT1vW6yZ3";
    let ansi = "\x1b[31mcolor_user:zX8cV6bN4mQ2wE9r\x1b[0m";
    let internal = "svc_user:pa\x1b[1mss\x1b[0m";
    let percent = "pct_user:p%40ss%3Aword";
    let ipv6 = "v6_user:V6pQ2mN8xR4tW7yZ";
    let colon = "colon_user:pa:ss:word9";
    let mysql = "my_user:MyQ7pL2mN8xR4tW";
    let redis = "redis_user:ReD9sQ2mN8xR4tW";
    let amqp = "amqp_user:AmQ9pL2mN8xR4tW";
    let empty = "empty_user:@db.example.invalid/app";
    let oversized = format!("over_user:{}", "A".repeat(129));
    let unicode = "unicode_user:pässword9";
    let malformed = "\x1b]0;title\x07bad_user:BaD9pL2mN8xR";
    let data = format!(
        "postgresql://{plain}@db.example.invalid:5432/app\r\n\
         \x1b[32mmongodb://{mongodb}\x1b[0m\r\n\
         mongodb://{ansi}@db.example.invalid/app\r\n\
         mongodb://{internal}@db.example.invalid/app\r\n\
         postgresql://{percent}@db.example.invalid/app\r\n\
         mongodb+srv://{ipv6}@[2001:db8::1]/app\r\n\
         mysql://{colon}@mysql.example.invalid/app\r\n\
         mysql://{mysql}@mysql.example.invalid/app\r\n\
         redis://{redis}@redis.example.invalid/0\r\n\
         amqps://{amqp}@amqp.example.invalid/vhost\r\n\
         postgresql://{empty}\r\n\
         postgresql://{oversized}@db.example.invalid/app\r\n\
         postgresql://{unicode}@db.example.invalid/app\r\n\
         postgresql://{malformed}@db.example.invalid/app\r\n",
        mongodb = "mongo_user:M0ng0Q7pL2mN8xR4tW",
        ansi = ansi,
        internal = internal,
        percent = percent,
        ipv6 = ipv6,
        colon = colon,
        mysql = mysql,
        redis = redis,
        amqp = amqp,
        empty = empty,
        oversized = oversized,
        unicode = unicode,
        malformed = malformed,
    );
    std::fs::write(root.path().join("uris.txt"), &data).unwrap();
    (root, data.into_bytes())
}

#[test]
fn database_components_are_exact_for_uri_edge_cases() {
    let (root, data) = fixture();
    let report = scan_root(
        root.path(),
        &provider_rules(),
        ScanMode::Whole,
        BackendRequest::Regex,
    );
    let units: BTreeMap<&str, &str> = report
        .execution
        .units
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit.locator.as_str()))
        .collect();
    let database_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.rule_id == "database-connection-credential")
        .collect();
    assert!(database_findings.len() >= 10, "{database_findings:?}");
    // The malformed-escape finding is deliberately retained without a
    // component; every other database finding must have one.
    assert_eq!(
        report.structured_evidence.components.len(),
        database_findings.len() - 1
    );
    let malformed_finding = database_findings
        .iter()
        .find(|finding| {
            data[finding.start_byte..finding.end_byte]
                .windows(12)
                .any(|window| window == b"bad_user:BaD")
        })
        .copied()
        .expect("malformed-escape database finding");
    let mut seen = BTreeSet::new();
    for finding in &database_findings {
        if finding.finding_id == malformed_finding.finding_id {
            continue;
        }
        let component = component_for(&report, finding);
        assert!(seen.insert(component.finding_id.clone()));
        assert_eq!(component.unit_id, finding.unit_id);
        assert_eq!(component.kind, "database-password");
        assert_eq!(component.line, finding.line);
        assert_eq!(component.line_end, Some(component.line));
        let locator = units[finding.unit_id.as_str()];
        assert_eq!(
            component.source_sha256,
            digest(&data[component.start_byte..component.end_byte])
        );
        assert_eq!(locator, "uris.txt");
    }

    let by_password = |visible: &str| {
        report
            .findings
            .iter()
            .filter(|finding| finding.rule_id == "database-connection-credential")
            .map(|finding| (finding, component_for(&report, finding)))
            .find(|(_, component)| {
                &data[component.start_byte..component.end_byte] == visible.as_bytes()
            })
            .unwrap_or_else(|| panic!("missing visible password {visible:?}"))
    };
    let (_, plain) = by_password("kR9d2mQ7xL4pN8sT1vW6yZ3");
    assert_eq!(plain.ansi, "NONE");
    assert!(plain.normalization.is_none());
    assert_eq!(plain.normalized_sha256, digest(b"kR9d2mQ7xL4pN8sT1vW6yZ3"));

    let (_, ansi) = by_password("zX8cV6bN4mQ2wE9r");
    assert_eq!(ansi.ansi, "TRIMMED");
    assert_eq!(ansi.normalization.as_deref(), Some("ansi-sgr-v1"));
    assert_eq!(ansi.normalized_sha256, digest(b"zX8cV6bN4mQ2wE9r"));

    let (_, internal) = by_password("pa\x1b[1mss");
    assert_eq!(internal.ansi, "INTERNAL");
    assert_eq!(internal.normalized_sha256, digest(b"pass"));
    assert_eq!(internal.source_sha256, digest(b"pa\x1b[1mss"));

    let (_, percent) = by_password("p%40ss%3Aword");
    assert_eq!(percent.normalized_sha256, digest(b"p%40ss%3Aword"));
    assert_eq!(percent.ansi, "NONE");

    let (_, ipv6) = by_password("V6pQ2mN8xR4tW7yZ");
    assert_eq!(ipv6.normalized_sha256, digest(b"V6pQ2mN8xR4tW7yZ"));

    let (_, colon) = by_password("pa:ss:word9");
    assert_eq!(colon.normalized_sha256, digest(b"pa:ss:word9"));

    assert!(!report.findings.iter().any(|finding| {
        finding.rule_id == "database-connection-credential"
            && (&data[finding.start_byte..finding.end_byte] == b"empty_user:")
    }));
    assert!(!report.findings.iter().any(|finding| {
        finding.rule_id == "database-connection-credential"
            && data[finding.start_byte..finding.end_byte]
                .windows(9)
                .any(|window| window == b"over_user")
    }));
    assert!(!report.findings.iter().any(|finding| {
        finding.rule_id == "database-connection-credential"
            && data[finding.start_byte..finding.end_byte]
                .windows(12)
                .any(|window| window == b"unicode_user")
    }));
    assert!(!report
        .structured_evidence
        .components
        .iter()
        .any(|component| component.finding_id == malformed_finding.finding_id));
}

#[test]
fn component_evidence_is_equivalent_across_modes_and_strategies() {
    let (root, _) = fixture();
    let rules = provider_rules();
    let mut baseline: Option<(Vec<u8>, Vec<StructuredComponent>)> = None;
    for mode in [ScanMode::Whole, ScanMode::Stream, ScanMode::Auto] {
        for strategy in [
            BackendRequest::Regex,
            BackendRequest::RegexSet,
            BackendRequest::Prefilter,
            BackendRequest::Auto,
        ] {
            let report = scan_root(root.path(), &rules, mode, strategy);
            let mut findings = report.findings.clone();
            findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
            let findings = serde_json::to_vec(&findings).unwrap();
            let mut components = report.structured_evidence.components.clone();
            components.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
            if let Some((expected_findings, expected_components)) = &baseline {
                assert_eq!(&findings, expected_findings, "{mode:?}/{strategy:?}");
                assert_eq!(&components, expected_components, "{mode:?}/{strategy:?}");
            } else {
                baseline = Some((findings, components));
            }
        }
    }
}

#[test]
fn component_metadata_does_not_change_primary_findings() {
    let (root, _) = fixture();
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(provider_path()).unwrap()).unwrap();
    let mut without_extractor = document.clone();
    for rule in without_extractor["rules"].as_array_mut().unwrap() {
        rule.as_object_mut().unwrap().remove("component_extractor");
    }
    let without_rules: rnc_core::RuleBundle = serde_json::from_value(without_extractor).unwrap();
    let without_rules = LoadedBundle::from_bundle(without_rules).unwrap();
    let with_report = scan_root(
        root.path(),
        &provider_rules(),
        ScanMode::Whole,
        BackendRequest::Regex,
    );
    let without_report = scan_root(
        root.path(),
        &without_rules,
        ScanMode::Whole,
        BackendRequest::Regex,
    );
    let with_findings = serde_json::to_value(&with_report.findings).unwrap();
    let without_findings = serde_json::to_value(&without_report.findings).unwrap();
    assert_eq!(with_findings, without_findings);
    assert!(without_report.structured_evidence.components.is_empty());
    assert!(!with_report.structured_evidence.components.is_empty());
}

#[test]
fn private_and_sanitized_reports_keep_component_evidence_isolated() {
    let (root, _) = fixture();
    let report = scan_root(
        root.path(),
        &provider_rules(),
        ScanMode::Whole,
        BackendRequest::Regex,
    );
    let private = report.private_value().unwrap();
    assert_eq!(private["structured_evidence"]["version"], "1");
    let components = private["structured_evidence"]["components"]
        .as_array()
        .unwrap();
    assert!(!components.is_empty());
    assert!(components.iter().all(|component| {
        component.get("source_sha256").is_some()
            && component.get("normalized_sha256").is_some()
            && component.get("finding_id").is_some()
            && component.get("unit_id").is_some()
            && component.get("start_byte").is_some()
            && component.get("end_byte").is_some()
    }));
    let private_text = serde_json::to_string(&private).unwrap();
    for raw in [
        "kR9d2mQ7xL4pN8sT1vW6yZ3",
        "zX8cV6bN4mQ2wE9r",
        "p%40ss%3Aword",
        "pa:ss:word9",
    ] {
        assert!(!private_text.contains(raw), "private report leaked {raw}");
    }
    let sanitized = report.sanitized_value();
    let sanitized_text = serde_json::to_string(&sanitized).unwrap();
    assert!(!sanitized_text.contains("structured_evidence"));
    assert!(!sanitized_text.contains("source_sha256"));
    assert!(!sanitized_text.contains("database-password"));
    assert!(!sanitized_text.contains("uris.txt"));
}
