//! CP4 filesystem detection regression: generic values, structured keys and
//! newly documented provider families.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rnc_core::{
    scan, BackendRequest, LoadedBundle, LocalSource, PolicySpec, RunConfig, ScanLimits, ScanMode,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn provider_rules() -> LoadedBundle {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules/rnc-providers-v1.json");
    LoadedBundle::load(&path).expect("provider rules")
}

fn synthetic(seed: &str, length: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut output = String::new();
    let mut material = Sha256::digest(seed.as_bytes()).to_vec();
    while output.len() < length {
        for byte in &material {
            output.push(ALPHABET[*byte as usize % ALPHABET.len()] as char);
            if output.len() == length {
                break;
            }
        }
        material = Sha256::digest(&material).to_vec();
    }
    output
}

fn config(mode: ScanMode, strategy: BackendRequest) -> RunConfig {
    RunConfig {
        run_id: "cp4-filesystem-test".to_string(),
        limits: ScanLimits::default(),
        mode,
        stream_threshold_bytes: 1,
        stream_chunk_bytes: 48,
        strategy,
        policy: PolicySpec::empty(),
        accepted_result_codes: vec![3],
        config_source: "cp4-test".to_string(),
        config_provenance: BTreeMap::new(),
        deadline: None,
    }
}

fn scan_root(root: &Path, mode: ScanMode, strategy: BackendRequest) -> rnc_core::ScanReport {
    let source = LocalSource::new_with_policy(root.to_path_buf(), &PolicySpec::empty()).unwrap();
    let discovery = source.discover();
    scan(discovery, &provider_rules(), &config(mode, strategy)).expect("scan")
}

fn values(report: &rnc_core::ScanReport, root: &Path) -> Vec<(String, String, Vec<u8>, usize)> {
    let units: BTreeMap<&str, &str> = report
        .execution
        .units
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit.locator.as_str()))
        .collect();
    let mut output = Vec::new();
    for finding in &report.findings {
        let locator = units[finding.unit_id.as_str()];
        let data = std::fs::read(root.join(locator)).unwrap();
        output.push((
            locator.to_string(),
            finding.rule_id.clone(),
            data[finding.start_byte..finding.end_byte].to_vec(),
            finding.line,
        ));
    }
    output
}

fn assert_contains(
    observed: &[(String, String, Vec<u8>, usize)],
    rule: &str,
    value: &str,
    locator: &str,
) {
    assert!(
        observed.iter().any(|(path, id, bytes, _)| {
            path == locator && id == rule && bytes.as_slice() == value.as_bytes()
        }),
        "missing {rule} {value:?} in {locator}; observed {observed:?}"
    );
}

#[test]
fn generic_assignment_formats_and_negative_controls() {
    let root = tempdir().unwrap();
    let a = synthetic("env-a", 28);
    let b = synthetic("env-b", 28);
    let e = synthetic("env-e", 28);
    let f = synthetic("json-f", 28);
    let g = synthetic("json-g", 28);
    let h = synthetic("yaml-h", 28);
    let i = synthetic("yaml-i", 28);
    let j1 = synthetic("yaml-j1", 22);
    let j2 = synthetic("yaml-j2", 22);
    let k = synthetic("toml-k", 28);
    let l = synthetic("toml-l", 28);
    let m = synthetic("php-m", 28);
    let n = synthetic("php-n", 28);
    let o = synthetic("php-o", 28);
    let p = synthetic("xml-p", 28);
    let sql = synthetic("sql-password", 28);
    let xml_db = synthetic("xml-db-password", 28);
    let q = synthetic("crlf-q", 28);
    let r = synthetic("escape-r", 12);
    let s = synthetic("escape-s", 12);
    let t = synthetic("unicode-t", 28);
    let u = synthetic("invalid-u", 28);
    let phrase = "correct horse battery staple";
    let quoted = format!("{r}\\\"{s}");

    std::fs::write(
        root.path().join("assignments.env"),
        format!(
            "# ordinary configuration\n\
             DB_PASSWORD=\"{a}\"\n\
             API_TOKEN={b}\n\
             EMPTY_PASSWORD=\n\
             PASSWORD=${{DB_PASSWORD}}\n\
             PASSWORD=\"password\"\n\
             PASSWORD_HINT=\"enter your password\"\n\
             PUBLIC_KEY=\"not-private\"\n\
             NORMAL_SETTING=\"utf-8\"\n\
             APP_PASSWORD=\"{phrase}\"\n\
             export CLIENT_SECRET='{e}'\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("config.json"),
        format!(
            "{{\"password\": \"{f}\", \"api_key\": \"{g}\", \"note\": \"not-a-secret-value\"}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("config.yaml"),
        format!(
            "password: \"{h}\"\nclient_secret: '{i}'\nauth_token: ${{AUTH_TOKEN}}\n\
             multiline_secret: |\n  {j1}\n  {j2}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("config.toml"),
        format!("password = \"{k}\"\napi_key = \"{l}\"\n"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("php.php"),
        format!(
            "<?php\ndefine('DB_PASSWORD', '{m}');\n$password = '{n}';\n$config['password'] = '{o}';\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("config.xml"),
        format!("<config><password>{p}</password><db_password>{xml_db}</db_password></config>\n"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("schema.sql"),
        format!("CREATE USER rnc_user WITH PASSWORD '{sql}';\n"),
    )
    .unwrap();
    std::fs::write(root.path().join("crlf.ini"), format!("password={q}\r\n")).unwrap();
    std::fs::write(
        root.path().join("escaped.conf"),
        format!("password = \"{quoted}\"\n"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("unicode.txt"),
        format!("héllo — ordinary text\npassword={t}\n"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("invalid.bin"),
        [b"\xff\xfe password=".as_slice(), u.as_bytes(), b"\n"].concat(),
    )
    .unwrap();
    let oversized = "A".repeat(600);
    std::fs::write(
        root.path().join("large.txt"),
        format!("password={oversized}\n"),
    )
    .unwrap();

    let report = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex);
    assert_eq!(report.execution.required_uninspected_count(), 0);
    let observed = values(&report, root.path());
    assert_contains(
        &observed,
        "generic-secret-assignment",
        &a,
        "assignments.env",
    );
    assert_contains(
        &observed,
        "generic-secret-assignment",
        &b,
        "assignments.env",
    );
    assert_contains(
        &observed,
        "generic-secret-assignment",
        phrase,
        "assignments.env",
    );
    assert_contains(
        &observed,
        "generic-secret-assignment",
        &e,
        "assignments.env",
    );
    assert_contains(&observed, "generic-secret-assignment", &f, "config.json");
    assert_contains(&observed, "generic-secret-assignment", &g, "config.json");
    assert_contains(&observed, "generic-secret-assignment", &h, "config.yaml");
    assert_contains(&observed, "generic-secret-assignment", &i, "config.yaml");
    assert_contains(&observed, "generic-secret-assignment", &k, "config.toml");
    assert_contains(&observed, "generic-secret-assignment", &l, "config.toml");
    assert_contains(&observed, "generic-secret-assignment", &m, "php.php");
    assert_contains(&observed, "generic-secret-assignment", &n, "php.php");
    assert_contains(&observed, "generic-array-assignment", &o, "php.php");
    assert_contains(&observed, "generic-xml-assignment", &p, "config.xml");
    assert_contains(&observed, "generic-xml-assignment", &xml_db, "config.xml");
    assert_contains(&observed, "generic-sql-password", &sql, "schema.sql");
    assert_contains(&observed, "generic-secret-assignment", &q, "crlf.ini");
    assert_contains(
        &observed,
        "generic-secret-assignment",
        &quoted,
        "escaped.conf",
    );
    assert_contains(&observed, "generic-secret-assignment", &t, "unicode.txt");
    assert_contains(&observed, "generic-secret-assignment", &u, "invalid.bin");
    assert!(observed.iter().any(|(path, rule, bytes, _)| {
        path == "config.yaml"
            && rule == "generic-multiline-assignment"
            && bytes
                .windows(j1.len())
                .any(|window| window == j1.as_bytes())
            && bytes
                .windows(j2.len())
                .any(|window| window == j2.as_bytes())
    }));
    assert_eq!(
        observed
            .iter()
            .filter(|(_, rule, _, _)| rule.starts_with("generic-"))
            .count(),
        21
    );
    for forbidden in [
        "password",
        "utf-8",
        "not-a-secret-value",
        "enter your password",
    ] {
        assert!(
            !observed
                .iter()
                .any(|(_, _, bytes, _)| bytes.as_slice() == forbidden.as_bytes()),
            "emitted benign value {forbidden:?}"
        );
    }
    assert!(!observed.iter().any(|(path, _, _, _)| path == "large.txt"));
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if content.len() < 128 {
        output.push(content.len() as u8);
    } else {
        output.push(0x81);
        output.push(content.len() as u8);
    }
    output.extend_from_slice(content);
    output
}

fn dummy_pkcs8() -> Vec<u8> {
    let oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    let algorithm = der(0x30, &[der(0x06, &oid), der(0x05, &[])].concat());
    let payload = b"rnc-cp4-not-a-real-private-key".to_vec();
    der(
        0x30,
        &[der(0x02, &[0]), algorithm, der(0x04, &payload)].concat(),
    )
}

fn pem(private_key: bool) -> String {
    let (label, payload) = if private_key {
        ("PRIVATE KEY", dummy_pkcs8())
    } else {
        ("PUBLIC KEY", dummy_pkcs8())
    };
    let encoded = base64(&payload);
    let body: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----",
        body.join("\n")
    )
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in data.chunks(3) {
        let value = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        output.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        output.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn crc24(data: &[u8]) -> u32 {
    let mut crc = 0x00b7_04ceu32;
    for byte in data {
        crc ^= (*byte as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0xff_ffff
}

fn pgp_private_block() -> String {
    let packet = [0x95u8, 0x20]
        .iter()
        .copied()
        .chain([7u8; 32])
        .collect::<Vec<_>>();
    let encoded = base64(&packet);
    let checksum = crc24(&packet);
    let checksum = base64(&checksum.to_be_bytes()[1..]);
    format!(
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: RNC test\n\n{encoded}\n={checksum}\n-----END PGP PRIVATE KEY BLOCK-----"
    )
}

#[test]
fn private_key_representations_and_malformed_controls() {
    let root = tempdir().unwrap();
    let private = pem(true);
    let public = pem(false);
    std::fs::write(
        root.path().join("plain.pem"),
        format!("2026-11-11 INFO loaded\n{private}\n"),
    )
    .unwrap();
    std::fs::write(
        root.path().join("escaped.json"),
        format!(
            "{{\"private_key\": \"{}\"}}\n",
            private.replace('\n', "\\n")
        ),
    )
    .unwrap();
    let wrapped = base64(private.as_bytes());
    std::fs::write(
        root.path().join("wrapped.txt"),
        format!("prefix {wrapped} suffix\n"),
    )
    .unwrap();
    std::fs::write(root.path().join("pgp.asc"), pgp_private_block()).unwrap();
    std::fs::write(root.path().join("public.pem"), format!("{public}\n")).unwrap();
    std::fs::write(
        root.path().join("pgp-public.asc"),
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("truncated.pem"),
        "-----BEGIN PRIVATE KEY-----\nAAAA\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("wrapped-public.txt"),
        base64(public.as_bytes()),
    )
    .unwrap();
    let bad_checksum = {
        let block = pgp_private_block();
        let checksum_start = block.rfind("\n=").unwrap();
        format!(
            "{}\n=AAAA\n-----END PGP PRIVATE KEY BLOCK-----",
            &block[..checksum_start]
        )
    };
    std::fs::write(root.path().join("pgp-bad-checksum.asc"), bad_checksum).unwrap();

    let report = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex);
    let observed = values(&report, root.path());
    assert!(observed.iter().any(|(path, rule, bytes, _)| {
        path == "plain.pem"
            && rule == "pem-private-key"
            && bytes.starts_with(b"-----BEGIN PRIVATE KEY-----")
            && bytes.ends_with(b"-----END PRIVATE KEY-----")
    }));
    assert!(observed.iter().any(|(path, rule, bytes, _)| {
        path == "escaped.json"
            && rule == "pem-private-key-escaped"
            && bytes.starts_with(b"-----BEGIN PRIVATE KEY-----\\n")
            && bytes.ends_with(b"-----END PRIVATE KEY-----")
    }));
    assert!(observed.iter().any(|(path, rule, bytes, _)| {
        path == "wrapped.txt" && rule == "pem-private-key-base64" && bytes == wrapped.as_bytes()
    }));
    assert!(observed
        .iter()
        .any(|(path, rule, _, _)| { path == "pgp.asc" && rule == "pem-private-key-pgp" }));
    assert_eq!(
        observed
            .iter()
            .filter(|(_, rule, _, _)| rule.starts_with("pem-"))
            .count(),
        4
    );
    for forbidden in [
        "public.pem",
        "pgp-public.asc",
        "truncated.pem",
        "wrapped-public.txt",
        "pgp-bad-checksum.asc",
    ] {
        assert!(!observed.iter().any(|(path, _, _, _)| path == forbidden));
    }
    let baseline: BTreeSet<_> = observed.into_iter().collect();
    for mode in [ScanMode::Whole, ScanMode::Stream] {
        for strategy in [
            BackendRequest::Regex,
            BackendRequest::RegexSet,
            BackendRequest::Prefilter,
            BackendRequest::Auto,
        ] {
            let report = scan_root(root.path(), mode, strategy);
            let current: BTreeSet<_> = values(&report, root.path()).into_iter().collect();
            assert_eq!(current, baseline, "{mode:?}/{strategy:?}");
        }
    }
}

#[test]
fn documented_provider_families_accept_and_reject() {
    let root = tempdir().unwrap();
    let azure_bytes: Vec<u8> = (0..64)
        .map(|index| ((index * 37 + 11) % 251) as u8)
        .collect();
    let azure = base64(&azure_bytes);
    let tailscale = format!(
        "tskey-api-{}-{}",
        synthetic("tailscale-body", 32),
        synthetic("tailscale-tail", 8)
    );
    let groq = format!("gsk_{}", synthetic("groq-body", 32));
    let xai = format!("xai-{}", synthetic("xai-body", 80));
    let perplexity = format!("pplx-{}", synthetic("perplexity-body", 32));
    let doppler = format!("dp.st.prd.{}", synthetic("doppler-body", 32));
    let slack_host = ["hooks", "slack", "com"].join(".");
    let slack = format!(
        "https://{}/{}/T{}/B{}/{}",
        slack_host,
        "services",
        synthetic("slack-team", 9),
        synthetic("slack-channel", 9),
        synthetic("slack-secret", 24)
    );
    let openai = format!("sk-{}", synthetic("openai-body", 40));
    std::fs::write(
        root.path().join("providers.env"),
        format!(
            "AZURE_CONNECTION=DefaultEndpointsProtocol=https;AccountName=rncstorage;AccountKey={azure};EndpointSuffix=core.windows.net\n\
             TAILSCALE_KEY={tailscale}\nGROQ_API_KEY={groq}\nXAI_API_KEY={xai}\n\
             PERPLEXITY_API_KEY={perplexity}\nDOPPLER_TOKEN={doppler}\n\
             SLACK_WEBHOOK={slack}\nOPENAI_API_KEY={openai}\n"
        ),
    )
    .unwrap();
    let slack_host = ["hooks", "slack", "com"].join(".");
    let slack_placeholder = format!(
        "https://{}/{}/T{}/B{}/{}",
        slack_host,
        "services",
        "0".repeat(8),
        "0".repeat(8),
        "X".repeat(24)
    );
    std::fs::write(
        root.path().join("negatives.env"),
        format!(
            "AccountKey={};TAILSCALE_KEY=tskey-other-{};GROQ_API_KEY=gsk_short;\
             XAI_API_KEY=xai-{};PERPLEXITY_API_KEY=pplx-{};DOPPLER_TOKEN=dp.st.prd.short;\
             SLACK_WEBHOOK={slack_placeholder};\
             OPENAI_API_KEY=sk-short\n",
            "A".repeat(88),
            synthetic("wrong-tailscale", 32),
            "A".repeat(79),
            "A".repeat(12),
        ),
    )
    .unwrap();

    let report = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex);
    let observed = values(&report, root.path());
    let expected = BTreeSet::from([
        "azure-storage-account-key",
        "tailscale-key",
        "groq-api-key",
        "xai-api-key",
        "perplexity-api-key",
        "doppler-service-token",
        "slack-incoming-webhook",
        "openai-api-key",
    ]);
    let actual: BTreeSet<&str> = observed
        .iter()
        .filter(|(path, _, _, _)| path == "providers.env")
        .map(|(_, rule, _, _)| rule.as_str())
        .collect();
    assert_eq!(actual, expected, "{observed:?}");
    assert_eq!(
        observed
            .iter()
            .filter(|(path, _, _, _)| path == "providers.env")
            .count(),
        8
    );
    assert!(!observed
        .iter()
        .any(|(path, _, _, _)| path == "negatives.env"));
    let baseline: BTreeSet<_> = observed.into_iter().collect();
    for mode in [ScanMode::Whole, ScanMode::Stream] {
        for strategy in [
            BackendRequest::Regex,
            BackendRequest::RegexSet,
            BackendRequest::Prefilter,
            BackendRequest::Auto,
        ] {
            let report = scan_root(root.path(), mode, strategy);
            let current: BTreeSet<_> = values(&report, root.path()).into_iter().collect();
            assert_eq!(current, baseline, "{mode:?}/{strategy:?}");
        }
    }
}

#[test]
fn authorization_headers_and_url_userinfo_are_classified() {
    let root = tempdir().unwrap();
    let basic_password = synthetic("basic-password", 24);
    let basic = base64(format!("rnc-service:{basic_password}").as_bytes());
    let bearer = synthetic("opaque-bearer", 36);
    let url_user = synthetic("url-user", 12);
    let url_password = synthetic("url-password", 24);
    let header = synthetic("header-key", 28);
    std::fs::write(
        root.path().join("auth.txt"),
        format!(
            "Authorization: Basic {basic}\n\
             Authorization: Bearer {bearer}\n\
             DATABASE_URL=postgresql://{url_user}:{url_password}@db.example.invalid/app\n\
             X-API-Key: {header}\n\
             Authorization: Basic dXNlcjpwYXNzd29yZA==\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("url.txt"),
        format!("https://{url_user}:{url_password}@example.invalid/path\n"),
    )
    .unwrap();
    let report = scan_root(root.path(), ScanMode::Whole, BackendRequest::Regex);
    let observed = values(&report, root.path());
    assert_contains(&observed, "http-basic-authorization", &basic, "auth.txt");
    assert_contains(&observed, "http-bearer-opaque", &bearer, "auth.txt");
    assert_contains(&observed, "generic-secret-assignment", &header, "auth.txt");
    assert!(observed.iter().any(|(path, rule, bytes, _)| {
        path == "url.txt"
            && rule == "credential-url-userinfo"
            && bytes.as_slice() == format!("{url_user}:{url_password}").as_bytes()
    }));
    // The URL form and database URI both contain the same userinfo; the latter
    // is expected to capture only the database credential once.
    assert!(observed.iter().any(|(path, rule, bytes, _)| {
        path == "auth.txt"
            && rule == "database-connection-credential"
            && bytes.as_slice() == format!("{url_user}:{url_password}").as_bytes()
    }));
    assert!(!observed
        .iter()
        .any(|(_, _, bytes, _)| { bytes.as_slice() == b"dXNlcjpwYXNzd29yZA==" }));
}

#[test]
fn bounded_content_streaming_finds_a_secret_across_the_overlap_boundary() {
    use rnc_core::backend::{BackendRequest as Strategy, MatchPlan};
    use rnc_core::stream::{scan_content, ScanContentConfig};
    let rules = provider_rules();
    let plan = MatchPlan::new(&rules, Strategy::Regex).unwrap();
    let value = synthetic("boundary-value", 28);
    let prefix = 65_580usize;
    let mut data = vec![b'x'; prefix];
    data.push(b'\n');
    data.extend_from_slice(format!("DB_PASSWORD={value}\n").as_bytes());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let streamed = scan_content(
        &data,
        "u-content",
        "r-content",
        &plan,
        &ScanContentConfig {
            mode: ScanMode::Stream,
            stream_chunk_bytes: 48,
            max_findings: 10,
            deadline,
        },
    )
    .unwrap();
    assert_eq!(streamed.findings.len(), 1);
    let start = prefix + 1 + "DB_PASSWORD=".len();
    assert_eq!(streamed.findings[0].start_byte, start);
    assert_eq!(streamed.findings[0].end_byte, start + value.len());
    let whole = scan_content(
        &data,
        "u-content",
        "r-content",
        &plan,
        &ScanContentConfig {
            mode: ScanMode::Whole,
            stream_chunk_bytes: 48,
            max_findings: 10,
            deadline,
        },
    )
    .unwrap();
    assert_eq!(
        streamed.findings[0].finding_id,
        whole.findings[0].finding_id
    );
}

#[test]
fn cp4_findings_are_equivalent_across_modes_and_strategies() {
    let root = tempdir().unwrap();
    let password = synthetic("equivalence-password", 28);
    let key = synthetic("equivalence-key", 28);
    std::fs::write(
        root.path().join("a.env"),
        format!("DB_PASSWORD={password}\nAPI_KEY={key}\n"),
    )
    .unwrap();
    std::fs::write(root.path().join("key.pem"), format!("{}\n", pem(true))).unwrap();
    let baseline = None;
    let mut baseline = baseline;
    for mode in [ScanMode::Whole, ScanMode::Stream] {
        for strategy in [
            BackendRequest::Regex,
            BackendRequest::RegexSet,
            BackendRequest::Prefilter,
            BackendRequest::Auto,
        ] {
            let report = scan_root(root.path(), mode, strategy);
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
            assert!(!keys.is_empty());
            if let Some(reference) = &baseline {
                assert_eq!(&keys, reference, "{mode:?}/{strategy:?}");
            } else {
                baseline = Some(keys);
            }
        }
    }
}
