# Gitleaks Scan Harness — Detection Report

> **DETECTION REPORT.**

This file contains no raw matched values, no expected secret text, and no raw scanner report.

| Field | Value |
| --- | --- |
| Overall status | **COMPLETED** |
| Gitleaks integration | EXECUTED |
| Gitleaks execution | EXECUTED |
| Detection accuracy | MEASURED |
| Scanner kind | gitleaks |
| Harness / scenario | 0.2.0 / cp1a-v1 |
| Generated (UTC) | 2026-11-09T20:54:57Z |

## Dataset

| Field | Value |
| --- | --- |
| Name | Levain FP Corpus (negative and positive fixtures) |
| Source | https://github.com/levainbot/fp-corpus |
| Revision | c130c321aa9046af17a6c876cb97e2ed71397110 |
| Tag | v1 |
| License | MIT |
| Manifest SHA-256 | c456d2a4943494dea0ac3e5161193d91a77250c700c23e5113de12b2a311af3e |
| Counting unit | individual labeled case: negative corpus counts sections (expected secrets are zero); positive corpus counts planted credentials |

| Corpus | Sections | Lines | Credentials | Hard sections |
| --- | --- | --- | --- | --- |
| Negative | 116 | 866 | 0 | 0 |
| Positive | 45 | 368 | 85 | 3 |

## Target

| Field | Value |
| --- | --- |
| Scanner kind | gitleaks |
| Binary path | `C:\Dev\gitleaks-cp1a-build\bin\gitleaks.exe` |
| Binary SHA-256 | `54dd670dda5f6a84b9b195a2fab33a766ed5976b60dbd73e4b15eb6ffc2aff8a` |
| Gitleaks source revision | 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c |
| Integration status | EXECUTED |
| Scan mode | dir |
| Configuration mode | builtin-default |
| Configuration path | built-in default |
| Configuration SHA-256 | not applicable |

## Execution

### Negative corpus

| Field | Value |
| --- | --- |
| Status | **COMPLETED** |
| Command | `C:\Dev\gitleaks-cp1a-build\bin\gitleaks.exe dir <corpus-dir> --report-format json --report-path <report> --no-banner` |
| Exit code | 1 |
| Timed out | no |
| Timeout limit (s) | 300.0 |
| Duration (s) | 0.237 |
| Positive control reported | yes |
| Control file encountered | yes |
| Control findings on file | 2 |
| Control credential findings | 2 |
| Control kinds detected | aws-access-key-id, github-token |
| Control kinds echoed in raw output | aws-access-key-id, github-token |
| Unmatched control-file findings | 0 |
| Scanner report SHA-256 | `c22f47491ab73bf8aa71f6762f3b8976be86e36ede8c5aad79ca32b0234d5422` |
| Stderr (redacted) | [stderr present; raw content withheld] |

| Metric | Value |
| --- | --- |
| Sections scanned | 116 |
| Expected credentials | 0 |
| Findings parsed | 3 |
| False positives | 3 |
| Duplicate findings | 0 |
| Personal-data matches (not counted) | 0 |
| Findings without extracted evidence | 0 |
| Sections tripped | 1 |
| Clean | no |

True negatives are **not** inferred from line counts; this corpus has no per-line oracle. A clean run means no unexpected finding was reported.

| Section | Findings |
| --- | --- |
| tailscale and wireguard status | 3 |

### Positive corpus

| Field | Value |
| --- | --- |
| Status | **COMPLETED** |
| Command | `C:\Dev\gitleaks-cp1a-build\bin\gitleaks.exe dir <corpus-dir> --report-format json --report-path <report> --no-banner` |
| Exit code | 1 |
| Timed out | no |
| Timeout limit (s) | 300.0 |
| Duration (s) | 0.186 |
| Positive control reported | yes |
| Control file encountered | yes |
| Control findings on file | 2 |
| Control credential findings | 2 |
| Control kinds detected | github-token, aws-access-key-id |
| Control kinds echoed in raw output | aws-access-key-id, github-token |
| Unmatched control-file findings | 0 |
| Scanner report SHA-256 | `b39cff6e9199863aea814fe254f3598337ade4844f9a2c162a320ef8d71427db` |
| Stderr (redacted) | [stderr present; raw content withheld] |

| Metric | Value |
| --- | --- |
| Sections scanned | 45 |
| Expected credentials | 85 (82 core, 3 hard) |
| True positives | 47 |
| False negatives | 38 |
| Core recall | 57.32% |
| Hard recall | 0.0% |
| Overall recall | 55.29% |
| Unexpected findings | 0 |
| Partial matches (not credited) | 1 |
| Ambiguous findings (not credited) | 0 |
| False positives | 1 |
| Duplicate findings | 2 |
| Personal-data matches (not counted) | 0 |
| Findings without extracted evidence | 0 |

| Match classification | Count |
| --- | --- |
| Complete | 46 |
| Normalized | 1 |
| Partial | 1 |
| Ambiguous | 0 |
| Miss | 38 |

Missed credentials (kind only; values omitted):

| Section | Kind | Tier | Classification | Partial evidence |
| --- | --- | --- | --- | --- |
| env-file | aws_access_key_id | core | miss | 0 |
| curl-verbose-basic-auth | http_basic_auth | core | miss | 0 |
| hardhat-deploy-failure | wallet_seed_phrase | core | miss | 0 |
| wallet-restore-env | wallet_seed_phrase | core | miss | 0 |
| axios-error-dump | bearer_token | core | miss | 0 |
| postgres-connection-failure | url_password | core | miss | 0 |
| mongodb-uri | url_password | core | miss | 0 |
| cloudsql-iam-dsn | url_password | core | miss | 0 |
| cloudsql-iam-dsn | email | core | miss | 0 |
| payment-processing-log | payment_card | core | miss | 0 |
| payment-processing-log | payment_card | core | miss | 0 |
| terraform-apply-output | aws_access_key_id | core | miss | 0 |
| pip-index-url-with-password | url_password | core | miss | 0 |
| ai-gateway-upstream-errors | xai_api_key | core | miss | 0 |
| platform-cli-auth-failures | doppler_token | core | miss | 0 |
| platform-cli-auth-failures | supabase_access_token | core | miss | 0 |
| platform-cli-auth-failures | netlify_pat | core | miss | 0 |
| platform-cli-auth-failures | tailscale_auth_key | core | miss | 0 |
| ci-publish-step-output | nuget_api_key | core | miss | 0 |
| ci-publish-step-output | sentry_org_auth_token | core | miss | 0 |
| webhook-and-oauth-callback-dump | discord_webhook_url | core | miss | 0 |
| webhook-and-oauth-callback-dump | google_oauth_client_secret | core | miss | 0 |
| webhook-and-oauth-callback-dump | resend_api_key | core | miss | 0 |
| webhook-and-oauth-callback-dump | airtable_pat | core | miss | 0 |
| edge-aws-secret-ends-in-plus | aws_access_key_id | core | miss | 0 |
| edge-github-tokens-containing-placeholder-words | github_pat_classic | core | miss | 0 |
| edge-github-tokens-containing-placeholder-words | github_pat_classic | core | miss | 0 |
| edge-openai-project-key-ends-in-hyphen | openai_project_key | core | partial | 1 |
| ansi-github-actions-raw-log | aws_access_key_id | core | miss | 0 |
| ansi-github-actions-raw-log | aws_secret_access_key | core | miss | 0 |
| ... | 8 more | ... | ... | ... |

Partial matches (locations only; not credited):

| Section | Line | Rule | Candidate kinds | Relation |
| --- | --- | --- | --- | --- |
| edge-openai-project-key-ends-in-hyphen | 4 | generic-api-key | openai_project_key | finding_contains_expected |

## Detection scope

Scope annotation is separate from TP/FN scoring and applies only to the pinned default configuration. It is a conservative manual mapping to the default rule IDs, not a scanner result.

| Scope class | Missed cases |
| --- | --- |
| Out of scope | 15 |
| Unknown | 7 |
| In scope but missed | 16 |

Out-of-scope cases:

| Section | Kind | Basis |
| --- | --- | --- |
| hardhat-deploy-failure | wallet_seed_phrase | no default seed-phrase rule |
| wallet-restore-env | wallet_seed_phrase | no default seed-phrase rule |
| cloudsql-iam-dsn | email | not a secret; no default email rule |
| payment-processing-log | payment_card | no default payment-card rule |
| payment-processing-log | payment_card | no default payment-card rule |
| ai-gateway-upstream-errors | xai_api_key | no default xAI rule |
| platform-cli-auth-failures | supabase_access_token | no default Supabase rule |
| platform-cli-auth-failures | tailscale_auth_key | no default Tailscale rule |
| webhook-and-oauth-callback-dump | discord_webhook_url | no default Discord webhook rule |
| webhook-and-oauth-callback-dump | google_oauth_client_secret | no default Google OAuth client-secret rule |
| webhook-and-oauth-callback-dump | resend_api_key | no default Resend rule |
| ansi-github-actions-raw-log | aws_secret_access_key | no default rule for the paired secret key |
| hard-shapeless-password | shapeless_password | hard tier; no shape-based rule |
| hard-capability-url | capability_url_segment | hard tier; no shape-based rule |
| hard-token-split-across-lines | wrapped_token | hard tier; token is split across lines |

Unknown-scope cases:

| Section | Kind | Basis |
| --- | --- | --- |
| axios-error-dump | bearer_token | no direct bearer rule; generic or JWT rules may apply |
| postgres-connection-failure | url_password | no direct rule; generic or curl rules may apply |
| mongodb-uri | url_password | no direct rule; generic or curl rules may apply |
| cloudsql-iam-dsn | url_password | no direct rule; generic or curl rules may apply |
| pip-index-url-with-password | url_password | no direct rule; generic or curl rules may apply |
| ansi-docker-compose-logs | url_password | no direct rule; generic or curl rules may apply |
| ansi-docker-compose-logs | bearer_token | no direct bearer rule; generic or JWT rules may apply |

In-scope cases still missed:

| Section | Kind | Tier |
| --- | --- | --- |
| env-file | aws_access_key_id | core |
| curl-verbose-basic-auth | http_basic_auth | core |
| terraform-apply-output | aws_access_key_id | core |
| platform-cli-auth-failures | doppler_token | core |
| platform-cli-auth-failures | netlify_pat | core |
| ci-publish-step-output | nuget_api_key | core |
| ci-publish-step-output | sentry_org_auth_token | core |
| webhook-and-oauth-callback-dump | airtable_pat | core |
| edge-aws-secret-ends-in-plus | aws_access_key_id | core |
| edge-github-tokens-containing-placeholder-words | github_pat_classic | core |
| edge-github-tokens-containing-placeholder-words | github_pat_classic | core |
| edge-openai-project-key-ends-in-hyphen | openai_project_key | core |
| ansi-github-actions-raw-log | aws_access_key_id | core |
| ansi-pytest-npm-publish-failure | npm_token | core |
| ansi-terraform-plan-diff | sendgrid_api_key | core |
| ansi-terraform-plan-diff | generic_assignment | core |

## Limitations

- Only the CP1 detection lane is implemented; functional conformance, performance, and Go race testing are not part of this report.
- The corpus is synthetic and finite; it does not measure real-world repository or credential prevalence.
- Negative-corpus true negatives are not inferred from line counts; the oracle is 'expected secrets are zero'.
- Three hard-tier credentials are reported separately and are not included in the core recall percentage.
- Partial, ambiguous, and line-only findings are not credited as true positives; they are reported separately.
- The real Gitleaks CLI and JSON parser were exercised at the pinned source revision; other versions and configurations are untested.
- Detection-scope annotation is a conservative manual mapping to the pinned default rule IDs, not a scanner result; it does not alter TP/FN counts.

## Reproduction

```sh
python -m harness prepare
python -m harness run --gitleaks <path-to-gitleaks> --corpus both \
  --gitleaks-source-revision <40-char-sha> --out-dir reports --name <name>
```

The scan target directory and raw report are temporary. See `docs/checkpoints/CP1A-report.md` for the CP1A checkpoint record.
