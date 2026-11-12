//! Deterministic, offline candidate validation.
//!
//! Validators return one of three observable outcomes:
//! - the candidate has the declared structural format;
//! - the candidate is structurally plausible but cannot be verified offline;
//! - the candidate is invalid or a known benign placeholder and is not emitted.
//!
//! No validator performs network access, provider authentication, token
//! redemption, or any operation that could activate or disclose a credential.

use serde::{Deserialize, Serialize};

use crate::context::CandidateContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Validator {
    MarkerFormat,
    MarkerSuffix,
    AsciiOnly,
    NotPlaceholder,
    #[serde(rename = "ENTROPY_MIN_3_5")]
    EntropyMin3_5,
    #[serde(rename = "BASE64URL")]
    Base64Url,
    Hex,
    AwsAccessKeyId,
    AwsServiceBearerTokenId,
    AwsContextSpecificCredentialId,
    AwsSecretAccessKey,
    GoogleApiKey,
    #[serde(rename = "GITHUB_CLASSIC_PAT")]
    GitHubClassicPat,
    #[serde(rename = "GITHUB_FINE_GRAINED_PAT")]
    GitHubFineGrainedPat,
    #[serde(rename = "GITHUB_OAUTH_TOKEN")]
    GitHubOAuthToken,
    #[serde(rename = "GITHUB_APP_INSTALLATION_TOKEN")]
    GitHubAppInstallationToken,
    #[serde(rename = "GITLAB_PAT")]
    GitLabPat,
    StripeSecretKey,
    SlackToken,
    #[serde(rename = "SENDGRID_API_KEY")]
    SendGridApiKey,
    NpmToken,
    AzureStorageAccountKey,
    TailscaleKey,
    GroqApiKey,
    XaiApiKey,
    PerplexityApiKey,
    DopplerServiceToken,
    SlackWebhook,
    #[serde(rename = "OPENAI_API_KEY")]
    OpenAiApiKey,
    PemPrivateKey,
    EscapedPemPrivateKey,
    PgpPrivateKey,
    Base64PemPrivateKey,
    JwtBearer,
    HttpBasicAuth,
    HttpBearerOpaque,
    #[serde(rename = "URL_USERINFO")]
    UrlUserInfo,
    DatabaseUri,
    GenericSecretAssignment,
    GenericAssignedSecret,
    MultilineAssignedSecret,
    SqlPassword,
}

impl Validator {
    pub fn name(self) -> &'static str {
        match self {
            Self::MarkerFormat => "MARKER_FORMAT",
            Self::MarkerSuffix => "MARKER_SUFFIX",
            Self::AsciiOnly => "ASCII_ONLY",
            Self::NotPlaceholder => "NOT_PLACEHOLDER",
            Self::EntropyMin3_5 => "ENTROPY_MIN_3_5",
            Self::Base64Url => "BASE64URL",
            Self::Hex => "HEX",
            Self::AwsAccessKeyId => "AWS_ACCESS_KEY_ID",
            Self::AwsServiceBearerTokenId => "AWS_SERVICE_BEARER_TOKEN_ID",
            Self::AwsContextSpecificCredentialId => "AWS_CONTEXT_SPECIFIC_CREDENTIAL_ID",
            Self::AwsSecretAccessKey => "AWS_SECRET_ACCESS_KEY",
            Self::GoogleApiKey => "GOOGLE_API_KEY",
            Self::GitHubClassicPat => "GITHUB_CLASSIC_PAT",
            Self::GitHubFineGrainedPat => "GITHUB_FINE_GRAINED_PAT",
            Self::GitHubOAuthToken => "GITHUB_OAUTH_TOKEN",
            Self::GitHubAppInstallationToken => "GITHUB_APP_INSTALLATION_TOKEN",
            Self::GitLabPat => "GITLAB_PAT",
            Self::StripeSecretKey => "STRIPE_SECRET_KEY",
            Self::SlackToken => "SLACK_TOKEN",
            Self::SendGridApiKey => "SENDGRID_API_KEY",
            Self::NpmToken => "NPM_TOKEN",
            Self::AzureStorageAccountKey => "AZURE_STORAGE_ACCOUNT_KEY",
            Self::TailscaleKey => "TAILSCALE_KEY",
            Self::GroqApiKey => "GROQ_API_KEY",
            Self::XaiApiKey => "XAI_API_KEY",
            Self::PerplexityApiKey => "PERPLEXITY_API_KEY",
            Self::DopplerServiceToken => "DOPPLER_SERVICE_TOKEN",
            Self::SlackWebhook => "SLACK_WEBHOOK",
            Self::OpenAiApiKey => "OPENAI_API_KEY",
            Self::PemPrivateKey => "PEM_PRIVATE_KEY",
            Self::EscapedPemPrivateKey => "ESCAPED_PEM_PRIVATE_KEY",
            Self::PgpPrivateKey => "PGP_PRIVATE_KEY",
            Self::Base64PemPrivateKey => "BASE64_PEM_PRIVATE_KEY",
            Self::JwtBearer => "JWT_BEARER",
            Self::HttpBasicAuth => "HTTP_BASIC_AUTH",
            Self::HttpBearerOpaque => "HTTP_BEARER_OPAQUE",
            Self::UrlUserInfo => "URL_USERINFO",
            Self::DatabaseUri => "DATABASE_URI",
            Self::GenericSecretAssignment => "GENERIC_SECRET_ASSIGNMENT",
            Self::GenericAssignedSecret => "GENERIC_ASSIGNED_SECRET",
            Self::MultilineAssignedSecret => "MULTILINE_ASSIGNED_SECRET",
            Self::SqlPassword => "SQL_PASSWORD",
        }
    }

    pub(crate) fn apply(
        self,
        candidate: &[u8],
        context: Option<&CandidateContext<'_>>,
    ) -> Result<ValidatorVerdict, ValidationError> {
        match self {
            Self::MarkerFormat => {
                validate_marker_format(candidate).map(|_| ValidatorVerdict::valid())
            }
            Self::MarkerSuffix => {
                validate_marker_suffix(candidate).map(|_| ValidatorVerdict::valid())
            }
            Self::AsciiOnly => {
                if candidate.is_ascii() {
                    Ok(ValidatorVerdict::valid())
                } else {
                    Err(ValidationError::invalid(self, "candidate is not ASCII"))
                }
            }
            Self::NotPlaceholder => {
                if is_known_placeholder(candidate) {
                    Err(ValidationError::benign(
                        self,
                        "candidate is a known placeholder or documentation value",
                    ))
                } else {
                    Ok(ValidatorVerdict::valid())
                }
            }
            Self::EntropyMin3_5 => {
                if shannon_entropy(candidate) < 3.5 {
                    Err(ValidationError::invalid(
                        self,
                        "candidate entropy is below the declared threshold",
                    ))
                } else {
                    Ok(ValidatorVerdict::valid())
                }
            }
            Self::Base64Url => {
                if decode_base64(candidate, true).is_some() {
                    Ok(ValidatorVerdict::valid())
                } else {
                    Err(ValidationError::invalid(
                        self,
                        "candidate is not valid base64url",
                    ))
                }
            }
            Self::Hex => {
                if !candidate.is_empty() && candidate.iter().all(u8::is_ascii_hexdigit) {
                    Ok(ValidatorVerdict::valid())
                } else {
                    Err(ValidationError::invalid(
                        self,
                        "candidate is not valid hexadecimal",
                    ))
                }
            }
            Self::AwsAccessKeyId => validate_aws_access_key_id(candidate),
            Self::AwsServiceBearerTokenId => validate_aws_service_bearer_token_id(candidate),
            Self::AwsContextSpecificCredentialId => {
                validate_aws_context_specific_credential_id(candidate)
            }
            Self::AwsSecretAccessKey => validate_aws_secret(candidate),
            Self::GoogleApiKey => validate_google_api_key(candidate),
            Self::GitHubClassicPat => validate_github_classic(candidate),
            Self::GitHubFineGrainedPat => validate_github_fine_grained(candidate),
            Self::GitHubOAuthToken => validate_github_oauth(candidate),
            Self::GitHubAppInstallationToken => validate_github_app_installation(candidate),
            Self::GitLabPat => validate_gitlab_pat(candidate),
            Self::StripeSecretKey => validate_stripe(candidate),
            Self::SlackToken => validate_slack(candidate),
            Self::SendGridApiKey => validate_sendgrid(candidate),
            Self::NpmToken => validate_npm(candidate),
            Self::AzureStorageAccountKey => validate_azure_storage_account_key(candidate),
            Self::TailscaleKey => validate_tailscale_key(candidate),
            Self::GroqApiKey => validate_groq_api_key(candidate),
            Self::XaiApiKey => validate_xai_api_key(candidate),
            Self::PerplexityApiKey => validate_perplexity_api_key(candidate),
            Self::DopplerServiceToken => validate_doppler_service_token(candidate),
            Self::SlackWebhook => validate_slack_webhook(candidate),
            Self::OpenAiApiKey => validate_openai_api_key(candidate),
            Self::PemPrivateKey => validate_pem_private_key(candidate),
            Self::EscapedPemPrivateKey => validate_escaped_pem_private_key(candidate),
            Self::PgpPrivateKey => validate_pgp_private_key(candidate),
            Self::Base64PemPrivateKey => validate_base64_pem_private_key(candidate),
            Self::JwtBearer => validate_jwt(candidate),
            Self::HttpBasicAuth => validate_http_basic(candidate),
            Self::HttpBearerOpaque => validate_http_bearer(candidate),
            Self::UrlUserInfo => validate_url_userinfo(candidate),
            Self::DatabaseUri => validate_database_uri(candidate),
            Self::GenericSecretAssignment => validate_generic_assignment(candidate),
            Self::GenericAssignedSecret => validate_generic_assigned_secret(candidate, context),
            Self::MultilineAssignedSecret => validate_multiline_assigned_secret(candidate),
            Self::SqlPassword => validate_sql_password(candidate, context),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
    FormatValid,
    PlausibleUnverified,
}

impl ValidationStatus {
    pub fn name(self) -> &'static str {
        match self {
            Self::FormatValid => "FORMAT_VALID",
            Self::PlausibleUnverified => "PLAUSIBLE_UNVERIFIED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationOutcome {
    pub status: ValidationStatus,
    pub applied: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorVerdict {
    pub plausible: bool,
    pub note: Option<&'static str>,
}

impl ValidatorVerdict {
    fn valid() -> Self {
        Self {
            plausible: false,
            note: None,
        }
    }

    fn plausible(note: &'static str) -> Self {
        Self {
            plausible: true,
            note: Some(note),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationError {
    pub validator: Validator,
    pub reason: &'static str,
    pub benign: bool,
}

impl ValidationError {
    fn invalid(validator: Validator, reason: &'static str) -> Self {
        Self {
            validator,
            reason,
            benign: false,
        }
    }

    fn benign(validator: Validator, reason: &'static str) -> Self {
        Self {
            validator,
            reason,
            benign: true,
        }
    }
}

pub fn validate_candidate(
    candidate: &[u8],
    validators: &[Validator],
) -> Result<ValidationOutcome, ValidationError> {
    validate_candidate_with_context_bytes(candidate, validators, None)
}

pub(crate) fn validate_candidate_with_context(
    context: &CandidateContext<'_>,
    validators: &[Validator],
) -> Result<ValidationOutcome, ValidationError> {
    validate_candidate_with_context_bytes(context.value, validators, Some(context))
}

fn validate_candidate_with_context_bytes(
    candidate: &[u8],
    validators: &[Validator],
    context: Option<&CandidateContext<'_>>,
) -> Result<ValidationOutcome, ValidationError> {
    let mut applied = Vec::with_capacity(validators.len());
    let mut notes = Vec::new();
    let mut plausible = false;
    for validator in validators {
        let verdict = validator.apply(candidate, context)?;
        applied.push(validator.name().to_string());
        plausible |= verdict.plausible;
        if let Some(note) = verdict.note {
            if !notes.iter().any(|existing: &String| existing == note) {
                notes.push(note.to_string());
            }
        }
    }
    Ok(ValidationOutcome {
        status: if plausible {
            ValidationStatus::PlausibleUnverified
        } else {
            ValidationStatus::FormatValid
        },
        applied,
        notes,
    })
}

/// Bounded syntax gate for generic assignment rules.
///
/// Comma is not an assignment operator in the supported configuration syntax.
/// The one intentional exception is the explicit `define(...)` call form.
/// Unquoted call expressions are also rejected when the delimiter is an
/// assignment/colon operator. XML element values use `>` and are intentionally
/// outside this gate, so literal parentheses remain valid there.
pub(crate) fn validate_assignment_syntax(
    context: &CandidateContext<'_>,
) -> Result<(), ValidationError> {
    let _ = context.identifier;
    if context.delimiter == Some(b',') && !context.define_call {
        return Err(ValidationError::benign(
            Validator::GenericAssignedSecret,
            "comma-delimited text is not a supported assignment",
        ));
    }
    if matches!(context.delimiter, Some(b'=') | Some(b':'))
        && context.value_quote.is_none()
        && context.value.contains(&b'(')
    {
        return Err(ValidationError::benign(
            Validator::GenericAssignedSecret,
            "unquoted call expression is not an assigned value",
        ));
    }
    Ok(())
}

const MARKER_PREFIX: &[u8] = b"RNC_SYNTH_KEY_";

fn validate_marker_format(candidate: &[u8]) -> Result<(), ValidationError> {
    if !(16..=128).contains(&candidate.len()) || !candidate.starts_with(MARKER_PREFIX) {
        return Err(ValidationError::invalid(
            Validator::MarkerFormat,
            "synthetic marker format is invalid",
        ));
    }
    if !candidate
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(ValidationError::invalid(
            Validator::MarkerFormat,
            "synthetic marker contains unsupported characters",
        ));
    }
    Ok(())
}

fn validate_marker_suffix(candidate: &[u8]) -> Result<(), ValidationError> {
    let suffix = candidate.strip_prefix(MARKER_PREFIX).ok_or_else(|| {
        ValidationError::invalid(Validator::MarkerSuffix, "synthetic marker prefix is absent")
    })?;
    let final_segment = suffix
        .rsplit(|byte| *byte == b'_')
        .next()
        .unwrap_or_default();
    if suffix.len() < 4 || suffix.ends_with(b"_") || final_segment.len() < 4 {
        return Err(ValidationError::invalid(
            Validator::MarkerSuffix,
            "synthetic marker suffix is too short",
        ));
    }
    if suffix.windows(5).any(|window| window == b"DECOY")
        || suffix.windows(4).any(|window| window == b"FAKE")
    {
        return Err(ValidationError::invalid(
            Validator::MarkerSuffix,
            "synthetic marker is a declared decoy",
        ));
    }
    Ok(())
}

fn validate_aws_identifier(
    candidate: &[u8],
    prefixes: &[&[u8; 4]],
    validator: Validator,
    label: &'static str,
) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() != 20
        || !prefixes.iter().any(|prefix| candidate.starts_with(*prefix))
        || !candidate[4..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(ValidationError::invalid(
            validator,
            "AWS credential identifier has an unrecognized prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            validator,
            "AWS credential identifier is a known documentation example",
        ));
    }
    if shannon_entropy(&candidate[4..]) < 3.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    if validator != Validator::AwsAccessKeyId {
        return Ok(ValidatorVerdict::plausible(label));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_aws_access_key_id(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    const PREFIXES: [&[u8; 4]; 2] = [b"AKIA", b"ASIA"];
    validate_aws_identifier(
        candidate,
        &PREFIXES,
        Validator::AwsAccessKeyId,
        "AWS access key ID",
    )
}

fn validate_aws_service_bearer_token_id(
    candidate: &[u8],
) -> Result<ValidatorVerdict, ValidationError> {
    const PREFIXES: [&[u8; 4]; 1] = [b"ABIA"];
    validate_aws_identifier(
        candidate,
        &PREFIXES,
        Validator::AwsServiceBearerTokenId,
        "SERVICE_BEARER_TOKEN_IDENTIFIER_ONLY",
    )
}

fn validate_aws_context_specific_credential_id(
    candidate: &[u8],
) -> Result<ValidatorVerdict, ValidationError> {
    const PREFIXES: [&[u8; 4]; 1] = [b"ACCA"];
    validate_aws_identifier(
        candidate,
        &PREFIXES,
        Validator::AwsContextSpecificCredentialId,
        "CONTEXT_SPECIFIC_CREDENTIAL_IDENTIFIER_ONLY",
    )
}

fn validate_aws_secret(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() != 40 || !candidate.iter().all(|byte| is_base64_byte(*byte, false)) {
        return Err(ValidationError::invalid(
            Validator::AwsSecretAccessKey,
            "AWS secret access key has an invalid length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::AwsSecretAccessKey,
            "AWS secret access key is a known documentation example",
        ));
    }
    if shannon_entropy(candidate) < 3.5 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_google_api_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() != 39
        || !candidate.starts_with(b"AIza")
        || !candidate[4..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
    {
        return Err(ValidationError::invalid(
            Validator::GoogleApiKey,
            "Google API key has an invalid prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::GoogleApiKey,
            "Google API key is a known documentation example",
        ));
    }
    if shannon_entropy(&candidate[4..]) < 3.5 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_github_classic(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() != 40
        || !candidate.starts_with(b"ghp_")
        || !candidate[4..].iter().all(u8::is_ascii_alphanumeric)
    {
        return Err(ValidationError::invalid(
            Validator::GitHubClassicPat,
            "GitHub classic token has an invalid prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::GitHubClassicPat,
            "GitHub classic token is a known documentation example",
        ));
    }
    if shannon_entropy(&candidate[4..]) < 3.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_github_fine_grained(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() != 93
        || !candidate.starts_with(b"github_pat_")
        || !candidate[11..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        return Err(ValidationError::invalid(
            Validator::GitHubFineGrainedPat,
            "GitHub fine-grained token has an invalid prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::GitHubFineGrainedPat,
            "GitHub fine-grained token is a known documentation example",
        ));
    }
    if shannon_entropy(&candidate[11..]) < 3.5 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_github_oauth(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let prefix = candidate.get(..4).unwrap_or_default();
    if !(prefix == b"gho_" || prefix == b"ghu_" || prefix == b"ghr_")
        || !(40..=512).contains(&candidate.len())
        || !candidate[4..].iter().all(u8::is_ascii_alphanumeric)
    {
        return Err(ValidationError::invalid(
            Validator::GitHubOAuthToken,
            "GitHub OAuth/user/refresh token has an invalid prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::GitHubOAuthToken,
            "GitHub OAuth/user/refresh token is a known documentation example",
        ));
    }
    if candidate.len() > 40 {
        return Ok(ValidatorVerdict::plausible("GITHUB_LONG_TOKEN_VARIANT"));
    }
    if shannon_entropy(&candidate[4..]) < 3.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn github_base64url(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
}

fn validate_github_app_installation(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if !candidate.starts_with(b"ghs_") {
        return Err(ValidationError::invalid(
            Validator::GitHubAppInstallationToken,
            "GitHub App installation token lacks the ghs_ prefix",
        ));
    }
    let body = &candidate[4..];
    let legacy = candidate.len() == 40 && body.iter().all(u8::is_ascii_alphanumeric);
    let modern = if legacy {
        false
    } else {
        // Modern stateless installation tokens are documented as ghs_APPID_JWT.
        // The JWT is treated as opaque: only segment framing and the documented
        // base64url alphabet are checked. No signature, issuer or claim is trusted.
        (100..=6144).contains(&candidate.len())
            && body
                .iter()
                .position(|byte| *byte == b'_')
                .is_some_and(|separator| {
                    let app_id = &body[..separator];
                    let jwt = &body[separator + 1..];
                    (1..=32).contains(&app_id.len())
                        && app_id.iter().all(u8::is_ascii_alphanumeric)
                        && jwt.split(|byte| *byte == b'.').count() == 3
                        && jwt.split(|byte| *byte == b'.').all(|segment| {
                            (8..=2048).contains(&segment.len()) && github_base64url(segment)
                        })
                })
    };
    if !legacy && !modern {
        return Err(ValidationError::invalid(
            Validator::GitHubAppInstallationToken,
            "GitHub App installation token has an invalid legacy or stateless structure",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::GitHubAppInstallationToken,
            "GitHub App installation token is a known documentation example",
        ));
    }
    if shannon_entropy(body) < 3.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    if modern {
        return Ok(ValidatorVerdict::plausible(
            "GITHUB_STATELESS_INSTALLATION_TOKEN_STRUCTURE_ONLY",
        ));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_gitlab_pat(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() != 26
        || !candidate.starts_with(b"glpat-")
        || !candidate[6..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
    {
        return Err(ValidationError::invalid(
            Validator::GitLabPat,
            "GitLab personal access token has an invalid prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::GitLabPat,
            "GitLab token is a known documentation example",
        ));
    }
    if shannon_entropy(&candidate[6..]) < 3.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_stripe(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let prefix_ok = candidate.starts_with(b"sk_live_")
        || candidate.starts_with(b"sk_test_")
        || candidate.starts_with(b"rk_live_")
        || candidate.starts_with(b"rk_test_");
    if !prefix_ok
        || !(24..=247).contains(&candidate.len())
        || !candidate[8..].iter().all(u8::is_ascii_alphanumeric)
    {
        return Err(ValidationError::invalid(
            Validator::StripeSecretKey,
            "Stripe secret key has an invalid prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::StripeSecretKey,
            "Stripe key is a known documentation example",
        ));
    }
    if shannon_entropy(&candidate[8..]) < 3.5 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_slack(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let prefix_ok = candidate.get(..5).is_some_and(|prefix| {
        prefix == b"xoxb-"
            || prefix == b"xoxp-"
            || prefix == b"xoxa-"
            || prefix == b"xoxr-"
            || prefix == b"xoxs-"
            || prefix == b"xapp-"
    });
    if !prefix_ok
        || !(20..=256).contains(&candidate.len())
        || candidate.ends_with(b"-")
        || !candidate[5..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return Err(ValidationError::invalid(
            Validator::SlackToken,
            "Slack token has an invalid prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::SlackToken,
            "Slack token is a known documentation example",
        ));
    }
    if shannon_entropy(&candidate[5..]) < 2.5 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_sendgrid(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let parts: Vec<&[u8]> = candidate.split(|byte| *byte == b'.').collect();
    if candidate.len() != 69
        || !candidate.starts_with(b"SG.")
        || parts.len() != 3
        || parts[1].len() != 22
        || parts[2].len() != 43
        || !parts[1]
            .iter()
            .chain(parts[2].iter())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
    {
        return Err(ValidationError::invalid(
            Validator::SendGridApiKey,
            "SendGrid API key has an invalid prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::SendGridApiKey,
            "SendGrid API key is a known documentation example",
        ));
    }
    if shannon_entropy(&candidate[3..]) < 3.5 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_npm(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() != 40
        || !candidate.starts_with(b"npm_")
        || !candidate[4..].iter().all(u8::is_ascii_alphanumeric)
    {
        return Err(ValidationError::invalid(
            Validator::NpmToken,
            "npm token has an invalid prefix, length or character set",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::NpmToken,
            "npm token is a known documentation example",
        ));
    }
    if shannon_entropy(&candidate[4..]) < 3.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_azure_storage_account_key(
    candidate: &[u8],
) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() != 88
        || !candidate
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return Err(ValidationError::invalid(
            Validator::AzureStorageAccountKey,
            "Azure storage account key has an invalid length or base64 alphabet",
        ));
    }
    let decoded = decode_base64(candidate, false).ok_or_else(|| {
        ValidationError::invalid(
            Validator::AzureStorageAccountKey,
            "Azure storage account key is not valid base64",
        )
    })?;
    if decoded.len() != 64
        || decoded.iter().all(|byte| *byte == decoded[0])
        || shannon_entropy(&decoded) < 3.0
    {
        return Err(ValidationError::invalid(
            Validator::AzureStorageAccountKey,
            "Azure storage account key does not decode to a plausible 512-bit key",
        ));
    }
    if is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::AzureStorageAccountKey,
            "Azure storage account key is a known placeholder",
        ));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_tailscale_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let text = std::str::from_utf8(candidate).map_err(|_| {
        ValidationError::invalid(Validator::TailscaleKey, "Tailscale key is not UTF-8")
    })?;
    let Some(rest) = text.strip_prefix("tskey-") else {
        return Err(ValidationError::invalid(
            Validator::TailscaleKey,
            "Tailscale key lacks the documented tskey- prefix",
        ));
    };
    let Some((kind, body)) = rest.split_once('-') else {
        return Err(ValidationError::invalid(
            Validator::TailscaleKey,
            "Tailscale key has no documented type prefix",
        ));
    };
    if !matches!(kind, "api" | "auth" | "client" | "scim" | "webhook")
        || !(16..=384).contains(&body.len())
        || body.starts_with('-')
        || body.ends_with('-')
        || body.contains("--")
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ValidationError::invalid(
            Validator::TailscaleKey,
            "Tailscale key has an invalid type, body or character set",
        ));
    }
    if is_known_placeholder(candidate) || shannon_entropy(body.as_bytes()) < 3.0 {
        return Err(ValidationError::invalid(
            Validator::TailscaleKey,
            "Tailscale key is a placeholder or has implausible entropy",
        ));
    }
    Ok(ValidatorVerdict::plausible(
        "TAILSCALE_DOCUMENTED_PREFIX_FAMILY_ONLY",
    ))
}

fn validate_groq_api_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if !(24..=160).contains(&candidate.len())
        || !candidate.starts_with(b"gsk_")
        || !candidate[4..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        || is_known_placeholder(candidate)
        || shannon_entropy(&candidate[4..]) < 3.5
    {
        return Err(ValidationError::invalid(
            Validator::GroqApiKey,
            "Groq API key has an invalid prefix, length, alphabet or entropy",
        ));
    }
    Ok(ValidatorVerdict::plausible("GROQ_DOCUMENTED_PREFIX_ONLY"))
}

fn validate_xai_api_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() != 84
        || !candidate.starts_with(b"xai-")
        || !candidate[4..].iter().all(u8::is_ascii_alphanumeric)
        || is_known_placeholder(candidate)
        || shannon_entropy(&candidate[4..]) < 3.5
    {
        return Err(ValidationError::invalid(
            Validator::XaiApiKey,
            "xAI API key does not match the documented example shape",
        ));
    }
    Ok(ValidatorVerdict::plausible(
        "XAI_DOCUMENTED_EXAMPLE_SHAPE_ONLY",
    ))
}

fn validate_perplexity_api_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if !(30..=160).contains(&candidate.len())
        || !candidate.starts_with(b"pplx-")
        || !candidate[5..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        || is_known_placeholder(candidate)
        || shannon_entropy(&candidate[5..]) < 3.5
    {
        return Err(ValidationError::invalid(
            Validator::PerplexityApiKey,
            "Perplexity API key has an invalid prefix, length, alphabet or entropy",
        ));
    }
    Ok(ValidatorVerdict::plausible(
        "PERPLEXITY_DOCUMENTED_PREFIX_ONLY",
    ))
}

fn validate_doppler_service_token(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let text = std::str::from_utf8(candidate).map_err(|_| {
        ValidationError::invalid(
            Validator::DopplerServiceToken,
            "Doppler service token is not UTF-8",
        )
    })?;
    let Some(rest) = text.strip_prefix("dp.st.") else {
        return Err(ValidationError::invalid(
            Validator::DopplerServiceToken,
            "Doppler service token lacks the documented dp.st. prefix",
        ));
    };
    let segments: Vec<&str> = rest.split('.').collect();
    if !(2..=4).contains(&segments.len())
        || segments.iter().any(|segment| {
            segment.is_empty()
                || segment.len() > 128
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        || segments.last().is_some_and(|segment| segment.len() < 16)
        || is_known_placeholder(candidate)
        || shannon_entropy(rest.as_bytes()) < 3.0
    {
        return Err(ValidationError::invalid(
            Validator::DopplerServiceToken,
            "Doppler service token has an invalid segment structure",
        ));
    }
    Ok(ValidatorVerdict::plausible(
        "DOPPLER_SERVICE_TOKEN_STRUCTURE_ONLY",
    ))
}

fn validate_slack_webhook(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let text = std::str::from_utf8(candidate).map_err(|_| {
        ValidationError::invalid(Validator::SlackWebhook, "Slack webhook is not UTF-8")
    })?;
    let Some(rest) = text.strip_prefix("https://hooks.slack.com/services/") else {
        return Err(ValidationError::invalid(
            Validator::SlackWebhook,
            "Slack webhook lacks the documented host and path prefix",
        ));
    };
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.len() != 3
        || !segments[0].starts_with('T')
        || !segments[1].starts_with('B')
        || !(9..=13).contains(&segments[0].len())
        || !(9..=13).contains(&segments[1].len())
        || !(20..=64).contains(&segments[2].len())
        || segments
            .iter()
            .any(|segment| !segment.bytes().all(|byte| byte.is_ascii_alphanumeric()))
        || is_known_placeholder(candidate)
        || segments[2].bytes().all(|byte| matches!(byte, b'0' | b'X'))
        || shannon_entropy(segments[2].as_bytes()) < 3.0
    {
        return Err(ValidationError::invalid(
            Validator::SlackWebhook,
            "Slack webhook has an invalid T/B/secret structure or is a placeholder",
        ));
    }
    Ok(ValidatorVerdict::plausible(
        "SLACK_WEBHOOK_URL_STRUCTURE_ONLY",
    ))
}

fn validate_openai_api_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if !(23..=256).contains(&candidate.len())
        || !candidate.starts_with(b"sk-")
        || !candidate[3..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        || is_known_placeholder(candidate)
        || shannon_entropy(&candidate[3..]) < 3.5
    {
        return Err(ValidationError::invalid(
            Validator::OpenAiApiKey,
            "OpenAI API key has an invalid prefix, length, alphabet or entropy",
        ));
    }
    Ok(ValidatorVerdict::plausible("OPENAI_DOCUMENTED_PREFIX_ONLY"))
}

#[derive(Debug)]
struct DerItem {
    tag: u8,
    content_start: usize,
    content_end: usize,
    next: usize,
}

fn der_item(data: &[u8], position: usize) -> Option<DerItem> {
    if position + 2 > data.len() {
        return None;
    }
    let tag = data[position];
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = data[position + 1];
    let (length, content_start) = if first < 0x80 {
        (first as usize, position + 2)
    } else {
        let length_bytes = (first & 0x7f) as usize;
        if length_bytes == 0 || length_bytes > 4 || position + 2 + length_bytes > data.len() {
            return None;
        }
        let mut length = 0usize;
        for byte in &data[position + 2..position + 2 + length_bytes] {
            length = length.checked_mul(256)?.checked_add(*byte as usize)?;
        }
        (length, position + 2 + length_bytes)
    };
    let content_end = content_start.checked_add(length)?;
    if content_end > data.len() {
        return None;
    }
    Some(DerItem {
        tag,
        content_start,
        content_end,
        next: content_end,
    })
}

fn der_children(data: &[u8], item: &DerItem) -> Option<Vec<DerItem>> {
    if item.tag != 0x30 {
        return None;
    }
    let mut children = Vec::new();
    let mut position = item.content_start;
    while position < item.content_end {
        let child = der_item(data, position)?;
        if child.next <= position || child.next > item.content_end {
            return None;
        }
        position = child.next;
        children.push(child);
    }
    if position == item.content_end {
        Some(children)
    } else {
        None
    }
}

fn pem_label<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.strip_prefix(marker)?.strip_suffix("-----")
}

fn validate_pem_private_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    validate_pem_text(candidate, Validator::PemPrivateKey)
}

fn validate_escaped_pem_private_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let decoded = decode_escaped_string(candidate).ok_or_else(|| {
        ValidationError::invalid(
            Validator::EscapedPemPrivateKey,
            "escaped PEM container has unsupported or truncated escaping",
        )
    })?;
    validate_pem_text(&decoded, Validator::EscapedPemPrivateKey)
}

fn validate_base64_pem_private_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let decoded = decode_base64(candidate, false).ok_or_else(|| {
        ValidationError::invalid(
            Validator::Base64PemPrivateKey,
            "base64-wrapped PEM container is not valid base64",
        )
    })?;
    validate_pem_text(&decoded, Validator::Base64PemPrivateKey)
}

fn validate_pem_text(
    candidate: &[u8],
    validator: Validator,
) -> Result<ValidatorVerdict, ValidationError> {
    let text = std::str::from_utf8(candidate).map_err(|_| {
        ValidationError::invalid(validator, "PEM container is not valid UTF-8 text")
    })?;
    if text.contains('\0') {
        return Err(ValidationError::invalid(
            validator,
            "PEM container contains a NUL byte",
        ));
    }
    let mut lines = text.lines();
    let begin = lines.next().unwrap_or_default().trim();
    let begin_label = pem_label(begin, "-----BEGIN ").ok_or_else(|| {
        ValidationError::invalid(validator, "PEM container has no valid BEGIN line")
    })?;
    if !begin_label.ends_with("PRIVATE KEY") {
        return Err(ValidationError::invalid(
            validator,
            "PEM container is not a private key",
        ));
    }
    let mut end_label = None;
    let mut body = String::new();
    let mut saw_end = false;
    for line in lines {
        if let Some(label) = pem_label(line.trim(), "-----END ") {
            end_label = Some(label);
            saw_end = true;
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        body.push_str(line.trim());
    }
    if !saw_end {
        return Err(ValidationError::invalid(
            validator,
            "PEM container has no END line",
        ));
    }
    let end_label = end_label.unwrap_or_default();
    if begin_label != end_label {
        return Err(ValidationError::invalid(
            validator,
            "PEM BEGIN and END labels do not match",
        ));
    }
    if body.len() < 32 {
        return Err(ValidationError::invalid(
            validator,
            "PEM private key body is too short",
        ));
    }
    let decoded = decode_base64(body.as_bytes(), false).ok_or_else(|| {
        ValidationError::invalid(validator, "PEM private key body is not valid base64")
    })?;
    if decoded.len() < 32 {
        return Err(ValidationError::invalid(
            validator,
            "decoded PEM private key is too short",
        ));
    }
    if decoded.iter().all(|byte| *byte == decoded[0]) {
        return Err(ValidationError::benign(
            validator,
            "PEM private key body is a repeated placeholder",
        ));
    }
    if begin_label == "OPENSSH PRIVATE KEY" {
        if decoded.starts_with(b"openssh-key-v1\0") {
            return Ok(ValidatorVerdict::plausible("PEM_OPENSSH_STRUCTURE_ONLY"));
        }
        return Err(ValidationError::invalid(
            validator,
            "OpenSSH private key has no openssh-key-v1 header",
        ));
    }
    let outer = match der_item(&decoded, 0) {
        Some(item) if item.tag == 0x30 && item.next == decoded.len() => item,
        _ => return Ok(ValidatorVerdict::plausible("PEM_DER_STRUCTURE_UNVERIFIED")),
    };
    let children = match der_children(&decoded, &outer) {
        Some(children) => children,
        None => return Ok(ValidatorVerdict::plausible("PEM_DER_STRUCTURE_UNVERIFIED")),
    };
    let recognized = match begin_label {
        "RSA PRIVATE KEY" => {
            children.len() >= 9
                && children[0].tag == 0x02
                && children[1].tag == 0x02
                && children[2].tag == 0x02
        }
        "EC PRIVATE KEY" => {
            children.len() >= 3 && children[0].tag == 0x02 && children[1].tag == 0x04
        }
        "DSA PRIVATE KEY" => children.len() >= 6 && children[0].tag == 0x02,
        "PRIVATE KEY" => children.len() >= 3 && children[0].tag == 0x02 && children[1].tag == 0x30,
        "ENCRYPTED PRIVATE KEY" => children.len() >= 2 && children[1].tag == 0x30,
        _ => false,
    };
    if recognized {
        Ok(ValidatorVerdict::valid())
    } else {
        Ok(ValidatorVerdict::plausible("PEM_DER_STRUCTURE_UNVERIFIED"))
    }
}

fn validate_pgp_private_key(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let text = std::str::from_utf8(candidate).map_err(|_| {
        ValidationError::invalid(
            Validator::PgpPrivateKey,
            "PGP armored block is not valid UTF-8 text",
        )
    })?;
    if text.contains('\0') {
        return Err(ValidationError::invalid(
            Validator::PgpPrivateKey,
            "PGP armored block contains a NUL byte",
        ));
    }
    let mut lines = text.lines();
    let begin = lines.next().unwrap_or_default().trim();
    if begin != "-----BEGIN PGP PRIVATE KEY BLOCK-----" {
        return Err(ValidationError::invalid(
            Validator::PgpPrivateKey,
            "PGP armored block does not begin a private key block",
        ));
    }
    let mut headers = 0usize;
    let mut body = String::new();
    let mut checksum = None;
    let mut saw_end = false;
    let mut saw_body = false;
    for line in lines {
        let line = line.trim();
        if line == "-----END PGP PRIVATE KEY BLOCK-----" {
            saw_end = true;
            break;
        }
        if line.is_empty() {
            continue;
        }
        if !saw_body && line.contains(':') && body.is_empty() {
            headers += 1;
            if headers > 8 || line.len() > 256 {
                return Err(ValidationError::invalid(
                    Validator::PgpPrivateKey,
                    "PGP armor header block is unbounded",
                ));
            }
            continue;
        }
        if let Some(checksum_text) = line.strip_prefix('=') {
            if checksum.is_some() {
                return Err(ValidationError::invalid(
                    Validator::PgpPrivateKey,
                    "PGP armor contains more than one checksum line",
                ));
            }
            checksum = Some(checksum_text.as_bytes().to_vec());
            continue;
        }
        if checksum.is_some() {
            return Err(ValidationError::invalid(
                Validator::PgpPrivateKey,
                "PGP armor contains data after the checksum",
            ));
        }
        if line.len() > 76
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(ValidationError::invalid(
                Validator::PgpPrivateKey,
                "PGP armor body contains an invalid line",
            ));
        }
        saw_body = true;
        body.push_str(line);
    }
    if !saw_end || !saw_body {
        return Err(ValidationError::invalid(
            Validator::PgpPrivateKey,
            "PGP armored block is incomplete",
        ));
    }
    let decoded = decode_base64(body.as_bytes(), false).ok_or_else(|| {
        ValidationError::invalid(
            Validator::PgpPrivateKey,
            "PGP armor body is not valid base64",
        )
    })?;
    if decoded.len() < 32 {
        return Err(ValidationError::invalid(
            Validator::PgpPrivateKey,
            "decoded PGP secret-key block is too short",
        ));
    }
    if let Some(checksum) = checksum {
        let expected = decode_base64(&checksum, false).ok_or_else(|| {
            ValidationError::invalid(
                Validator::PgpPrivateKey,
                "PGP armor checksum is not valid base64",
            )
        })?;
        if expected.len() != 3
            || crc24(&decoded) != u32::from_be_bytes([0, expected[0], expected[1], expected[2]])
        {
            return Err(ValidationError::invalid(
                Validator::PgpPrivateKey,
                "PGP armor checksum does not match the decoded body",
            ));
        }
    }
    let first = decoded[0];
    if first & 0x80 == 0 {
        return Err(ValidationError::invalid(
            Validator::PgpPrivateKey,
            "PGP secret-key body has no valid packet header",
        ));
    }
    let new_format = first & 0x40 != 0;
    let tag = if new_format {
        first & 0x3f
    } else {
        (first >> 2) & 0x0f
    };
    if !matches!(tag, 5 | 7) {
        return Err(ValidationError::invalid(
            Validator::PgpPrivateKey,
            "PGP block does not begin with a secret-key or secret-subkey packet",
        ));
    }
    Ok(ValidatorVerdict::plausible("PGP_SECRET_KEY_STRUCTURE_ONLY"))
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
    crc & 0x00ff_ffff
}

fn validate_http_basic(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let decoded = decode_base64(candidate, false).ok_or_else(|| {
        ValidationError::invalid(
            Validator::HttpBasicAuth,
            "HTTP Basic credentials are not base64",
        )
    })?;
    if !(3..=4096).contains(&decoded.len()) {
        return Err(ValidationError::invalid(
            Validator::HttpBasicAuth,
            "decoded HTTP Basic credentials are outside the supported bounds",
        ));
    }
    let Some(separator) = decoded.iter().position(|byte| *byte == b':') else {
        return Err(ValidationError::invalid(
            Validator::HttpBasicAuth,
            "HTTP Basic credentials have no user/password separator",
        ));
    };
    let user = &decoded[..separator];
    let password = &decoded[separator + 1..];
    if user.is_empty()
        || user.len() > 256
        || password.is_empty()
        || password.len() > 1024
        || user.iter().any(|byte| byte.is_ascii_control())
        || password.iter().any(|byte| byte.is_ascii_control())
    {
        return Err(ValidationError::invalid(
            Validator::HttpBasicAuth,
            "HTTP Basic user or password is empty, unbounded or contains controls",
        ));
    }
    let password_text = std::str::from_utf8(password).map_err(|_| {
        ValidationError::invalid(
            Validator::HttpBasicAuth,
            "HTTP Basic password is not valid UTF-8",
        )
    })?;
    if is_variable_reference(password_text)
        || is_placeholder_wrapper(password_text)
        || is_common_benign_value(password_text)
        || is_known_placeholder(password)
    {
        return Err(ValidationError::benign(
            Validator::HttpBasicAuth,
            "HTTP Basic password is a placeholder or unresolved reference",
        ));
    }
    Ok(ValidatorVerdict::plausible(
        "HTTP_BASIC_CREDENTIALS_STRUCTURE_ONLY",
    ))
}

fn validate_http_bearer(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    if !(12..=4096).contains(&candidate.len())
        || !candidate.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(*byte, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=')
        })
    {
        return Err(ValidationError::invalid(
            Validator::HttpBearerOpaque,
            "Bearer token has an invalid length or character set",
        ));
    }
    if candidate.starts_with(b"eyJ") || is_known_placeholder(candidate) {
        return Err(ValidationError::benign(
            Validator::HttpBearerOpaque,
            "Bearer token is covered by a structured rule or is a known placeholder",
        ));
    }
    if looks_like_provider_token(candidate) {
        return Err(ValidationError::benign(
            Validator::HttpBearerOpaque,
            "Bearer token is handled by a provider-specific rule",
        ));
    }
    if shannon_entropy(candidate) < 3.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::plausible(
        "HTTP_BEARER_OPAQUE_STRUCTURE_ONLY",
    ))
}

fn validate_url_userinfo(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let text = std::str::from_utf8(candidate).map_err(|_| {
        ValidationError::invalid(Validator::UrlUserInfo, "URL userinfo is not valid UTF-8")
    })?;
    let Some((user, password)) = text.split_once(':') else {
        return Err(ValidationError::invalid(
            Validator::UrlUserInfo,
            "URL userinfo has no password separator",
        ));
    };
    if user.is_empty()
        || user.len() > 128
        || password.is_empty()
        || password.len() > 512
        || user.contains('@')
        || password.contains('@')
        || !valid_percent_encoding(user)
        || !valid_percent_encoding(password)
    {
        return Err(ValidationError::invalid(
            Validator::UrlUserInfo,
            "URL userinfo is empty, unbounded or malformed",
        ));
    }
    if is_variable_reference(user)
        || is_variable_reference(password)
        || is_placeholder_wrapper(password)
        || is_common_benign_value(password)
        || is_known_placeholder(password.as_bytes())
    {
        return Err(ValidationError::benign(
            Validator::UrlUserInfo,
            "URL userinfo is a placeholder or unresolved reference",
        ));
    }
    if shannon_entropy(password.as_bytes()) < 2.5 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::plausible("URL_USERINFO_STRUCTURE_ONLY"))
}

fn validate_multiline_assigned_secret(
    candidate: &[u8],
) -> Result<ValidatorVerdict, ValidationError> {
    if candidate.len() > 4096 {
        return Err(ValidationError::invalid(
            Validator::MultilineAssignedSecret,
            "multiline assigned value exceeds the supported bound",
        ));
    }
    let text = std::str::from_utf8(candidate).map_err(|_| {
        ValidationError::invalid(
            Validator::MultilineAssignedSecret,
            "multiline assigned value is not valid UTF-8",
        )
    })?;
    let mut lines: Vec<&str> = text
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return Err(ValidationError::invalid(
            Validator::MultilineAssignedSecret,
            "multiline assigned value has no content",
        ));
    }
    let indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    for line in &mut lines {
        if line.len() >= indent {
            *line = &line[indent..];
        }
    }
    let joined = lines.join("\n");
    if !(6..=4096).contains(&joined.len())
        || joined
            .chars()
            .any(|character| character != '\n' && character.is_control())
        || joined.contains('\0')
    {
        return Err(ValidationError::invalid(
            Validator::MultilineAssignedSecret,
            "multiline assigned content is outside the literal bounds",
        ));
    }
    if is_variable_reference(&joined)
        || is_placeholder_wrapper(&joined)
        || is_common_benign_value(&joined)
        || is_known_placeholder(joined.as_bytes())
        || looks_like_nonsecret_setting(&joined)
    {
        return Err(ValidationError::benign(
            Validator::MultilineAssignedSecret,
            "multiline assigned content is a placeholder or benign setting",
        ));
    }
    if looks_like_provider_token(joined.as_bytes()) {
        return Err(ValidationError::benign(
            Validator::MultilineAssignedSecret,
            "multiline assigned content is handled by a provider-specific rule",
        ));
    }
    if shannon_entropy(joined.as_bytes()) < 2.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::plausible(
        "MULTILINE_ASSIGNMENT_STRUCTURE_ONLY",
    ))
}

fn validate_sql_password(
    candidate: &[u8],
    context: Option<&CandidateContext<'_>>,
) -> Result<ValidatorVerdict, ValidationError> {
    validate_generic_assigned_secret(candidate, context).map_err(|error| ValidationError {
        validator: Validator::SqlPassword,
        reason: error.reason,
        benign: error.benign,
    })
}

fn validate_generic_assigned_secret(
    candidate: &[u8],
    context: Option<&CandidateContext<'_>>,
) -> Result<ValidatorVerdict, ValidationError> {
    let decoded = decode_escaped_string(candidate).ok_or_else(|| {
        ValidationError::invalid(
            Validator::GenericAssignedSecret,
            "assigned value has unsupported or truncated escaping",
        )
    })?;
    let text = std::str::from_utf8(&decoded).map_err(|_| {
        ValidationError::invalid(
            Validator::GenericAssignedSecret,
            "assigned value is not valid UTF-8",
        )
    })?;
    if !(6..=512).contains(&text.len())
        || text.trim() != text
        || text.chars().any(char::is_control)
        || text.contains('\r')
        || text.contains('\n')
    {
        return Err(ValidationError::invalid(
            Validator::GenericAssignedSecret,
            "assigned value is outside the literal bounds",
        ));
    }
    if is_variable_reference(text)
        || is_placeholder_wrapper(text)
        || is_common_benign_value(text)
        || is_known_placeholder(&decoded)
    {
        return Err(ValidationError::benign(
            Validator::GenericAssignedSecret,
            "assigned value is a placeholder, variable or common benign value",
        ));
    }
    if looks_like_provider_token(&decoded) {
        return Err(ValidationError::benign(
            Validator::GenericAssignedSecret,
            "assigned value is handled by a provider-specific rule",
        ));
    }
    if text.contains("://")
        || text.contains('{')
        || text.contains('}')
        || text.contains('<')
        || text.contains('>')
        || text.ends_with('/')
    {
        return Err(ValidationError::invalid(
            Validator::GenericAssignedSecret,
            "assigned value has non-literal or URI structure",
        ));
    }
    let _ = context;
    if looks_like_password_hash(text) || looks_like_nonsecret_setting(text) {
        return Err(ValidationError::benign(
            Validator::GenericAssignedSecret,
            "assigned value is a hash, setting or nonsecret value",
        ));
    }
    if all_same_char(text) || shannon_entropy(&decoded) < 2.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::plausible(
        "ASSIGNMENT_CONTEXT_AND_VALUE_STRUCTURE_ONLY",
    ))
}

fn validate_jwt(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let text = std::str::from_utf8(candidate)
        .map_err(|_| ValidationError::invalid(Validator::JwtBearer, "JWT is not valid UTF-8"))?;
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 3 || parts[0].len() > 4096 || parts[1].len() > 8192 || parts[2].len() > 4096 {
        return Err(ValidationError::invalid(
            Validator::JwtBearer,
            "JWT does not have three bounded segments",
        ));
    }
    let header = decode_base64(parts[0].as_bytes(), true).ok_or_else(|| {
        ValidationError::invalid(Validator::JwtBearer, "JWT header is not valid base64url")
    })?;
    let payload = decode_base64(parts[1].as_bytes(), true).ok_or_else(|| {
        ValidationError::invalid(Validator::JwtBearer, "JWT payload is not valid base64url")
    })?;
    let header_value: serde_json::Value = serde_json::from_slice(&header).map_err(|_| {
        ValidationError::invalid(Validator::JwtBearer, "JWT header is not valid JSON")
    })?;
    let payload_value: serde_json::Value = serde_json::from_slice(&payload).map_err(|_| {
        ValidationError::invalid(Validator::JwtBearer, "JWT payload is not valid JSON")
    })?;
    let header_object = header_value.as_object().ok_or_else(|| {
        ValidationError::invalid(Validator::JwtBearer, "JWT header is not a JSON object")
    })?;
    if !payload_value.is_object() {
        return Err(ValidationError::invalid(
            Validator::JwtBearer,
            "JWT payload is not a JSON object",
        ));
    }
    let algorithm = header_object.get("alg").and_then(|value| value.as_str());
    if algorithm.is_none() {
        return Err(ValidationError::invalid(
            Validator::JwtBearer,
            "JWT header has no string alg field",
        ));
    }
    if !parts[2].is_empty() && decode_base64(parts[2].as_bytes(), true).is_none() {
        return Err(ValidationError::invalid(
            Validator::JwtBearer,
            "JWT signature is not valid base64url",
        ));
    }
    if algorithm == Some("none") || parts[2].is_empty() {
        return Ok(ValidatorVerdict::plausible("JWT_UNSIGNED"));
    }
    Ok(ValidatorVerdict::plausible("JWT_STRUCTURE_ONLY"))
}

fn validate_database_uri(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let text = std::str::from_utf8(candidate).map_err(|_| {
        ValidationError::invalid(Validator::DatabaseUri, "database credentials are not UTF-8")
    })?;
    let Some((user, password)) = text.split_once(':') else {
        return Err(ValidationError::invalid(
            Validator::DatabaseUri,
            "database connection credentials have no password separator",
        ));
    };
    if user.is_empty()
        || user.len() > 64
        || password.is_empty()
        || password.len() > 128
        || user.contains('/')
        || user.contains('@')
        || password.contains('@')
        || password.contains('/')
    {
        return Err(ValidationError::invalid(
            Validator::DatabaseUri,
            "database user or password is empty, unbounded or malformed",
        ));
    }
    if is_variable_reference(user) || is_variable_reference(password) {
        return Err(ValidationError::benign(
            Validator::DatabaseUri,
            "database credential is an unresolved variable or placeholder",
        ));
    }
    if is_placeholder_wrapper(password) || is_common_benign_value(password) {
        return Err(ValidationError::benign(
            Validator::DatabaseUri,
            "database password is a placeholder or common benign value",
        ));
    }
    if !valid_percent_encoding(user) || !valid_percent_encoding(password) {
        return Err(ValidationError::invalid(
            Validator::DatabaseUri,
            "database credential contains invalid percent encoding",
        ));
    }
    if is_known_placeholder(password.as_bytes()) {
        return Err(ValidationError::benign(
            Validator::DatabaseUri,
            "database password is a known placeholder",
        ));
    }
    if all_same_char(password) || shannon_entropy(password.as_bytes()) < 2.5 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::valid())
}

fn validate_generic_assignment(candidate: &[u8]) -> Result<ValidatorVerdict, ValidationError> {
    let text = std::str::from_utf8(candidate).map_err(|_| {
        ValidationError::invalid(
            Validator::GenericSecretAssignment,
            "generic assignment value is not UTF-8",
        )
    })?;
    if !(8..=128).contains(&text.len()) {
        return Err(ValidationError::invalid(
            Validator::GenericSecretAssignment,
            "generic assignment value length is outside the declared bounds",
        ));
    }
    if text.chars().any(char::is_whitespace)
        || text.contains("://")
        || text.contains('(')
        || text.contains(')')
        || text.contains('{')
        || text.contains('}')
        || text.contains('<')
        || text.contains('>')
        || text.contains('\\')
        || text.contains("...")
    {
        return Err(ValidationError::invalid(
            Validator::GenericSecretAssignment,
            "generic assignment value has unsafe or non-literal structure",
        ));
    }
    if is_variable_reference(text) {
        return Err(ValidationError::benign(
            Validator::GenericSecretAssignment,
            "generic assignment is an unresolved variable",
        ));
    }
    if is_placeholder_wrapper(text) || is_common_benign_value(text) {
        return Err(ValidationError::benign(
            Validator::GenericSecretAssignment,
            "generic assignment is a placeholder or common benign value",
        ));
    }
    if looks_like_provider_token(candidate) {
        return Err(ValidationError::benign(
            Validator::GenericSecretAssignment,
            "generic assignment value is handled by a provider-specific rule",
        ));
    }
    if is_known_placeholder(candidate) || is_common_benign_value(text) {
        return Err(ValidationError::benign(
            Validator::GenericSecretAssignment,
            "generic assignment is a known benign value",
        ));
    }
    if all_same_char(text) || shannon_entropy(candidate) < 3.0 {
        return Ok(ValidatorVerdict::plausible("LOW_ENTROPY"));
    }
    Ok(ValidatorVerdict::plausible(
        "GENERIC_ASSIGNMENT_STRUCTURE_ONLY",
    ))
}

fn decode_escaped_string(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() > 256 * 1024 {
        return None;
    }
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0usize;
    while index < input.len() {
        if input[index] != b'\\' {
            output.push(input[index]);
            index += 1;
            continue;
        }
        index += 1;
        let escaped = *input.get(index)?;
        index += 1;
        match escaped {
            b'n' => output.push(b'\n'),
            b'r' => output.push(b'\r'),
            b't' => output.push(b'\t'),
            b'b' => output.push(8),
            b'f' => output.push(12),
            b'\\' => output.push(b'\\'),
            b'"' => output.push(b'"'),
            b'\'' => output.push(b'\''),
            b'/' => output.push(b'/'),
            b'u' => {
                if index + 4 > input.len() {
                    return None;
                }
                let digits = std::str::from_utf8(&input[index..index + 4]).ok()?;
                let value = u16::from_str_radix(digits, 16).ok()?;
                let character = char::from_u32(value as u32)?;
                let mut encoded = [0u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                index += 4;
            }
            _ => {
                output.push(b'\\');
                output.push(escaped);
            }
        }
        if output.len() > 512 * 1024 {
            return None;
        }
    }
    Some(output)
}

fn looks_like_password_hash(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("$2a$")
        || lower.starts_with("$2b$")
        || lower.starts_with("$2y$")
        || lower.starts_with("$argon2")
        || lower.starts_with("$pbkdf2")
        || lower.starts_with("$scrypt")
        || lower.starts_with("sha1:")
        || lower.starts_with("sha256:")
        || lower.starts_with("sha512:")
        || lower.starts_with("md5:")
        || lower.starts_with("{sha}")
        || lower.starts_with("{ssha}")
    {
        return true;
    }
    let hex_only = text.bytes().all(|byte| byte.is_ascii_hexdigit());
    hex_only && matches!(text.len(), 32 | 40 | 64 | 96 | 128)
}

fn looks_like_nonsecret_setting(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "localhost"
            | "127.0.0.1"
            | "0.0.0.0"
            | "::1"
            | "default"
            | "development"
            | "staging"
            | "production"
            | "debug"
            | "info"
            | "warning"
            | "error"
            | "utf-8"
            | "utf8"
            | "application/json"
            | "text/plain"
            | "read-only"
            | "readonly"
            | "read/write"
            | "readwrite"
            | "no-password"
            | "not-set"
            | "unset"
    ) || lower.ends_with(".example.com")
        || lower.ends_with(".invalid")
        || lower.ends_with(".local")
        || lower.ends_with(".test")
}

fn is_base64_byte(byte: u8, url: bool) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'+' | b'/' | b'=')
        || (url && matches!(byte, b'-' | b'_'))
}

fn base64_value(byte: u8, url: bool) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' if !url => Some(62),
        b'/' if !url => Some(63),
        b'-' if url => Some(62),
        b'_' if url => Some(63),
        _ => None,
    }
}

/// Small bounded base64/base64url decoder used by offline validators.
pub fn decode_base64(input: &[u8], url: bool) -> Option<Vec<u8>> {
    let mut symbols = Vec::with_capacity(input.len());
    let mut padding = 0usize;
    let mut saw_padding = false;
    for byte in input {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if *byte == b'=' {
            saw_padding = true;
            padding += 1;
            if padding > 2 {
                return None;
            }
            continue;
        }
        if saw_padding {
            return None;
        }
        symbols.push(base64_value(*byte, url)?);
    }
    if symbols.is_empty() || symbols.len() % 4 == 1 {
        return None;
    }
    if padding > 0 && (symbols.len() + padding) % 4 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(symbols.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for symbol in symbols {
        buffer = (buffer << 6) | symbol as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(output)
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let length = data.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn is_known_placeholder(candidate: &[u8]) -> bool {
    const EXACT: [&str; 4] = [
        concat!("AKIA", "IOSFODNN7EXAMPLE"),
        concat!("wJalrXUtn", "FEMI/K7MDENG", "/bPxRfiCY", "EXAMPLEKEY"),
        concat!("ghp_", "1234567890abcdefghijklmnopqrstuvwxyz"),
        concat!("AIza", "SyA1234567890abcdefghijklmnopqrstuv"),
    ];
    if EXACT.iter().any(|value| candidate == value.as_bytes()) {
        return true;
    }
    const MARKERS: [&[u8]; 13] = [
        b"example",
        b"sample",
        b"placeholder",
        b"changeme",
        b"notreal",
        b"not-real",
        b"your_key",
        b"your-key",
        b"insert_",
        b"replace_",
        b"redacted",
        b"xxxxxxxx",
        b"00000000",
    ];
    MARKERS
        .iter()
        .any(|marker| contains_ascii_ci(candidate, marker))
        || (candidate.len() >= 8
            && (candidate.iter().all(|byte| *byte == candidate[0])
                || shannon_entropy(candidate) < 2.0))
}

fn is_variable_reference(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("${")
        || lower.contains("{{")
        || lower.contains("$(")
        || lower.contains("os.getenv")
        || lower.contains("process.env")
        || lower.contains("system.getenv")
        || lower.contains("vault:")
        || lower.contains("secretref")
        || lower.contains("<secret")
        || lower.starts_with('$')
        || lower.starts_with('%')
}

fn looks_like_provider_token(candidate: &[u8]) -> bool {
    const PREFIXES: [&[u8]; 39] = [
        b"AKIA",
        b"ASIA",
        b"ABIA",
        b"ACCA",
        b"AIDA",
        b"AGPA",
        b"AIPA",
        b"ANPA",
        b"ANVA",
        b"APKA",
        b"AROA",
        b"ASCA",
        b"AIza",
        b"ghp_",
        b"github_pat_",
        b"gho_",
        b"ghu_",
        b"ghs_",
        b"ghr_",
        b"glpat-",
        b"sk_live_",
        b"sk_test_",
        b"rk_live_",
        b"rk_test_",
        b"xoxb-",
        b"xoxp-",
        b"xoxa-",
        b"xoxr-",
        b"xoxs-",
        b"xapp-",
        b"SG.",
        b"npm_",
        b"tskey-",
        b"gsk_",
        b"xai-",
        b"pplx-",
        b"dp.st.",
        b"https://hooks.slack.com/services/",
        b"sk-",
    ];
    if PREFIXES.iter().any(|prefix| candidate.starts_with(prefix)) {
        return true;
    }
    candidate.starts_with(b"-----BEGIN ") && candidate.ends_with(b"PRIVATE KEY-----")
}

fn is_placeholder_wrapper(text: &str) -> bool {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    (trimmed.starts_with("__") && trimmed.ends_with("__"))
        || (trimmed.starts_with('<') && trimmed.ends_with('>'))
        || (trimmed.starts_with("{{") && trimmed.ends_with("}}"))
        || (trimmed.starts_with("${") && trimmed.ends_with('}'))
        || lower.contains("your_key")
        || lower.contains("your-key")
        || lower.contains("your_token")
        || lower.contains("your-token")
        || lower.contains("change_me")
        || lower.contains("change-me")
}

fn all_same_char(text: &str) -> bool {
    let mut characters = text.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    characters.all(|character| character == first)
}

fn is_common_benign_value(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "password"
            | "passwd"
            | "secret"
            | "changeme"
            | "admin"
            | "letmein"
            | "qwerty"
            | "12345678"
            | "123456789"
            | "1234567890"
            | "password1"
            | "password123"
            | "test"
            | "testing"
            | "none"
            | "null"
            | "undefined"
            | "true"
            | "false"
    )
}

fn valid_percent_encoding(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_valid(value: &[u8], validators: &[Validator]) {
        assert!(validate_candidate(value, validators).is_ok(), "{value:?}");
    }

    fn assert_invalid(value: &[u8], validators: &[Validator]) {
        assert!(validate_candidate(value, validators).is_err(), "{value:?}");
    }

    #[test]
    fn accepts_harmless_marker() {
        let validators = [Validator::MarkerFormat, Validator::MarkerSuffix];
        assert_eq!(
            validate_candidate(b"RNC_SYNTH_KEY_GENERIC_ALPHA", &validators)
                .unwrap()
                .applied,
            vec!["MARKER_FORMAT", "MARKER_SUFFIX"]
        );
    }

    #[test]
    fn rejects_decoys_and_malformed_values() {
        for value in [
            b"NOT_A_MARKER".as_slice(),
            b"RNC_SYNTH_KEY_".as_slice(),
            b"RNC_SYNTH_KEY_lower".as_slice(),
            b"RNC_SYNTH_KEY_DECOY_ALPHA".as_slice(),
            b"RNC_SYNTH_KEY_TRAILING_".as_slice(),
            b"RNC_SYNTH_KEY_AWS_12".as_slice(),
        ] {
            assert_invalid(value, &[Validator::MarkerFormat, Validator::MarkerSuffix]);
        }
    }

    #[test]
    fn base64_and_hex_validation_is_bounded() {
        assert!(decode_base64(b"SGVsbG8=", false).is_some());
        assert!(decode_base64(b"SGVsbG8", true).is_some());
        assert!(decode_base64(b"!!!!", false).is_none());
        assert!(decode_base64(b"A", false).is_none());
        assert_valid(b"deadBEEF", &[Validator::Hex]);
        assert_invalid(b"not-hex", &[Validator::Hex]);
    }

    #[test]
    fn aws_access_key_id_accepts_documented_prefix_and_rejects_lookalikes() {
        assert_valid(
            concat!("AKIA", "Q7Z3K5M2N4P6R8T0").as_bytes(),
            &[Validator::AwsAccessKeyId],
        );
        assert_valid(
            concat!("ASIA", "Q7Z3K5M2N4P6R8T0").as_bytes(),
            &[Validator::AwsAccessKeyId],
        );
        assert_invalid(
            concat!("AKIA", "IOSFODNN7EXAMPLE").as_bytes(),
            &[Validator::AwsAccessKeyId],
        );
        assert_invalid(
            concat!("AKIA", "Q7Z3K5M2N4P6R8T").as_bytes(),
            &[Validator::AwsAccessKeyId],
        );
        assert_invalid(
            concat!("ZZZA", "Q7Z3K5M2N4P6R8T0").as_bytes(),
            &[Validator::AwsAccessKeyId],
        );
        for resource_prefix in [
            b"AIDA", b"AGPA", b"AIPA", b"ANPA", b"ANVA", b"APKA", b"AROA", b"ASCA",
        ] {
            let mut value = resource_prefix.to_vec();
            value.extend_from_slice(b"Q7Z3K5M2N4P6R8T0");
            assert_invalid(&value, &[Validator::AwsAccessKeyId]);
        }
    }

    #[test]
    fn aws_sensitive_identifiers_have_distinct_validators() {
        assert_valid(
            concat!("ABIA", "Q7Z3K5M2N4P6R8T0").as_bytes(),
            &[Validator::AwsServiceBearerTokenId],
        );
        assert_valid(
            concat!("ACCA", "Q7Z3K5M2N4P6R8T0").as_bytes(),
            &[Validator::AwsContextSpecificCredentialId],
        );
        assert_invalid(
            concat!("ABIA", "Q7Z3K5M2N4P6R8T0").as_bytes(),
            &[Validator::AwsAccessKeyId],
        );
        assert_invalid(
            concat!("ACCA", "Q7Z3K5M2N4P6R8T0").as_bytes(),
            &[Validator::AwsAccessKeyId],
        );
        assert_invalid(
            concat!("AKIA", "Q7Z3K5M2N4P6R8T0").as_bytes(),
            &[Validator::AwsServiceBearerTokenId],
        );
        let bearer = validate_candidate(
            concat!("ABIA", "Q7Z3K5M2N4P6R8T0").as_bytes(),
            &[Validator::AwsServiceBearerTokenId],
        )
        .expect("bearer identifier");
        assert_eq!(bearer.status, ValidationStatus::PlausibleUnverified);
        assert!(bearer
            .notes
            .iter()
            .any(|note| note == "SERVICE_BEARER_TOKEN_IDENTIFIER_ONLY"));
    }

    #[test]
    fn github_oauth_prefix_does_not_claim_installation_tokens() {
        assert_invalid(
            concat!("ghs_", "0123456789abcdefghijklmnopqrstuvwxyz").as_bytes(),
            &[Validator::GitHubOAuthToken],
        );
        assert_valid(
            concat!("gho_", "0123456789abcdefghijklmnopqrstuvwxyz").as_bytes(),
            &[Validator::GitHubOAuthToken],
        );
    }

    #[test]
    fn github_installation_tokens_cover_legacy_and_stateless_formats() {
        let legacy = concat!("ghs_", "0123456789abcdefghijklmnopqrstuvwxyz");
        let legacy_outcome =
            validate_candidate(legacy.as_bytes(), &[Validator::GitHubAppInstallationToken])
                .expect("legacy installation token");
        assert_eq!(legacy_outcome.status, ValidationStatus::FormatValid);
        assert_invalid(
            concat!("ghs_", "0123456789abcdefghijklmnopqrstuvwxy").as_bytes(),
            &[Validator::GitHubAppInstallationToken],
        );

        let modern = format!(
            "ghs_1234567890_{}.{}.{}",
            "A1b2C3d4".repeat(15),
            "e5F6g7H8".repeat(15),
            "C9d0E1f2".repeat(6)
        );
        let modern_outcome =
            validate_candidate(modern.as_bytes(), &[Validator::GitHubAppInstallationToken])
                .expect("stateless installation token");
        assert_eq!(modern_outcome.status, ValidationStatus::PlausibleUnverified);
        assert!(modern_outcome
            .notes
            .iter()
            .any(|note| note == "GITHUB_STATELESS_INSTALLATION_TOKEN_STRUCTURE_ONLY"));

        for malformed in [
            "ghs_1234567890_".to_string() + &"A".repeat(120) + "." + &"b".repeat(120),
            format!(
                "ghs_1234567890_{}.{}.{}",
                "A".repeat(120),
                "b".repeat(120),
                ""
            ),
            format!(
                "ghs_{}.{}.{}",
                "A".repeat(120),
                "b".repeat(120),
                "C".repeat(43)
            ),
            format!(
                "ghs_1234567890_{}.{}.{}",
                "A".repeat(2049),
                "b".repeat(120),
                "C".repeat(43)
            ),
            "ghs_short".to_string(),
        ] {
            assert_invalid(
                malformed.as_bytes(),
                &[Validator::GitHubAppInstallationToken],
            );
        }
    }

    #[test]
    fn aws_secret_requires_full_base64_and_rejects_docs_example() {
        assert_valid(
            concat!("kR9d2mQ7xL4pN8sT1vW6yZ3aB5cD0eF7gH2jK9mP").as_bytes(),
            &[Validator::AwsSecretAccessKey],
        );
        assert_invalid(
            concat!("wJalrXUtn", "FEMI/K7MDENG", "/bPxRfiCY", "EXAMPLEKEY").as_bytes(),
            &[Validator::AwsSecretAccessKey],
        );
        assert_invalid(
            concat!("kR9d2mQ7xL4pN8sT1vW6yZ3aB5cD0eF7gH2jK9m").as_bytes(),
            &[Validator::AwsSecretAccessKey],
        );
    }

    #[test]
    fn provider_prefix_validators_accept_and_reject() {
        assert_valid(
            concat!("AIza", "SyD4mQ7xL4pN8sT1vW6yZ3aB5cD0eF7gH2X").as_bytes(),
            &[Validator::GoogleApiKey],
        );
        assert_valid(
            concat!("ghp_", "0123456789abcdefghijklmnopqrstuvwxyz").as_bytes(),
            &[Validator::GitHubClassicPat],
        );
        assert_valid(
            concat!("glpat-", "0123456789abcdefghij").as_bytes(),
            &[Validator::GitLabPat],
        );
        assert_valid(
            concat!("npm_", "0123456789abcdefghijklmnopqrstuvwxyz").as_bytes(),
            &[Validator::NpmToken],
        );
        assert_invalid(b"ghp_short", &[Validator::GitHubClassicPat]);
        assert_invalid(
            concat!("glpat-", "0123456789abcdefghij").as_bytes(),
            &[Validator::GitHubClassicPat],
        );
    }

    #[test]
    fn jwt_is_structurally_parsed_but_marked_plausible() {
        let value = concat!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJzdWIiOiJybmMtdGVzdCJ9.",
            "c2lnbmF0dXJl"
        );
        let outcome = validate_candidate(value.as_bytes(), &[Validator::JwtBearer]).unwrap();
        assert_eq!(outcome.status, ValidationStatus::PlausibleUnverified);
        assert!(outcome
            .notes
            .iter()
            .any(|note| note == "JWT_STRUCTURE_ONLY"));
        assert_invalid(
            concat!("eyJhbGciOiJIUzI1NiJ9.", "not-json.", "signature").as_bytes(),
            &[Validator::JwtBearer],
        );
    }

    #[test]
    fn database_uri_validates_credential_fields() {
        assert_valid(
            b"rnc_user:kR9d2mQ7xL4pN8sT1vW6yZ3aB5cD0eF7",
            &[Validator::DatabaseUri],
        );
        assert_invalid(b"rnc_user:${DB_PASSWORD}", &[Validator::DatabaseUri]);
        assert_invalid(b"rnc_user:", &[Validator::DatabaseUri]);
    }

    #[test]
    fn generic_assignment_is_plausible_not_verified() {
        let outcome = validate_candidate(
            b"kR9d2mQ7xL4pN8sT1vW6yZ3",
            &[Validator::GenericSecretAssignment],
        )
        .unwrap();
        assert_eq!(outcome.status, ValidationStatus::PlausibleUnverified);
        assert_invalid(
            b"password",
            &[
                Validator::GenericSecretAssignment,
                Validator::NotPlaceholder,
            ],
        );
        assert_invalid(b"${DB_PASSWORD}", &[Validator::GenericSecretAssignment]);
    }

    #[test]
    fn database_placeholder_wrappers_are_not_emitted() {
        for value in [
            b"app:__PASSWORD__".as_slice(),
            b"app:<password>".as_slice(),
            b"app:${DB_PASSWORD}".as_slice(),
            b"app:password".as_slice(),
        ] {
            assert_invalid(value, &[Validator::DatabaseUri]);
        }
    }

    #[test]
    fn slack_app_level_tokens_are_in_scope() {
        assert_valid(
            b"xapp-1-AC4EJLPN86E-0626629748879-d2e9a329b652bc14dbe0a96092c9cd6e3c16631965706f2",
            &[Validator::SlackToken],
        );
    }

    #[test]
    fn generic_assignment_does_not_duplicate_provider_shaped_values() {
        assert_invalid(
            b"SG.0123456789012345678901.0123456789012345678901234567890123456789012",
            &[Validator::GenericSecretAssignment],
        );
        assert_invalid(
            concat!("ghp_", "0123456789abcdefghijklmnopqrstuvwxyz").as_bytes(),
            &[Validator::GenericSecretAssignment],
        );
        for resource_prefix in [
            b"AIDA", b"AGPA", b"AIPA", b"ANPA", b"ANVA", b"APKA", b"AROA", b"ASCA",
        ] {
            let mut value = resource_prefix.to_vec();
            value.extend_from_slice(b"Q7Z3K5M2N4P6R8T0");
            assert_invalid(&value, &[Validator::GenericSecretAssignment]);
        }
    }

    #[test]
    fn entropy_threshold_is_measured_not_assumed() {
        assert!(shannon_entropy(b"aaaaaaaa") < 1.0);
        assert!(shannon_entropy(b"0123456789abcdef") >= 3.5);
        assert_invalid(b"aaaaaaaa", &[Validator::EntropyMin3_5]);
    }
}
