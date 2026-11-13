# Scanner Harness Report

> Overall: **COMPLETE_WITH_LIMITATIONS**

> Matrix status: **PASS**

> Scanner: **gitleaks**

| Field | Value |
| --- | --- |
| Harness version | 0.4.0 |
| Run ID | `20261110T185938Z` |
| Generated (UTC) | 2026-11-10T19:01:58Z |
| Source repository | https://github.com/RNC-Solutions-Group/gitleaks |
| Source branch | master |
| Resolved commit | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Scanner version | v8.0.0-rnc.5f6ec56cfa6f |
| Suites | gitleaks, levain, leaky-repo |

## Builds

| Platform | Kind | Build | Version | Artifact |
| --- | --- | --- | --- | --- |
| windows-amd64 | executable | PASS | v8.0.0-rnc.5f6ec56cfa6f | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |
| docker-linux-amd64 | docker | PASS | v8.0.0-rnc.5f6ec56cfa6f | `sha256:c18f30b566db4b12d695a19941ae6d375d3b00e7f6b043d7cf6a3d3fd7b0c4ed` |
| docker-linux-arm64 | docker | PASS | v8.0.0-rnc.5f6ec56cfa6f | `sha256:a0d2e186253047de0051819ba2ebeb67fa37c72b60cbbef170804bc37b031a4f` |

## Datasets

| Dataset | Revision | Checksum |
| --- | --- | --- |
| gitleaks-fixtures | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | `cd7f05e76b4590ee738d4573f3ddb3c493142ecd1204bc15754a21d0e66f7345` |
| levain | `c130c321aa9046af17a6c876cb97e2ed71397110` | `21782e59ddf95c4aedc88aa7a56f03aa9577b4d3e742c5b2adad7463eb533107` |
| leaky-repo | `2e951359cac53addbee56437da3ffb546e3dfe24` | `146df5e25fa987a0b5c5610a958941e5416a29c9f72eadaa3677abc620b281ce` |

## Suites

| Suite | Status | Applicable | Metrics |
| --- | --- | --- | --- |
| gitleaks | PASS | True | scenario total=69; scenario passed=68; assertion total=435; assertion passed=435 |
| levain | PASS | True | true positives=47; expected secrets=85; false positives=3; duplicates=2 |
| leaky-repo | PASS | True | expected count=175; covered count=22; count coverage percent=12.57; files covered=13; files covered percent=29.55; excess findings=0 |

## Suite details

### gitleaks

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- docker-linux-arm64: **PASS**
- scenario total: 69
- scenario passed: 68
- assertion total: 435
- assertion passed: 435
- Limitation: One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- Limitation: Docker coverage remains INCOMPLETE until every INTERNAL_GO contract is evidenced.
- Limitation: The legacy fixture lane retains hashed reports rather than raw scanner report bytes.

### levain

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- docker-linux-arm64: **PASS**
- true positives: 47
- expected secrets: 85
- false positives: 3
- duplicates: 2
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

### leaky-repo

- windows-amd64: **PASS**
- docker-linux-amd64: **PASS**
- docker-linux-arm64: **PASS**
- expected count: 175
- covered count: 22
- count coverage percent: 12.57
- files covered: 13
- files covered percent: 29.55
- excess findings: 0
- unlisted findings: 0
- rich score status: COMPLETED
- rich matched count: 22
- rich missed count: 153
- rich unexpected count: 0
- rich duplicate count: 0
- rich detection recall percent: 12.57
- rich category conflict items: 31
- Limitation: Legacy Leaky Repo score preserves the upstream line-count methodology.
- Limitation: RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Limitation: Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Limitation: Git-history benchmarking is not enabled in this checkpoint.

## Leaky Repo dual scores

| Methodology | Expected | Covered / matched | Files / misses | Exceptions |
| --- | ---: | ---: | ---: | ---: |
| Legacy upstream count | 175 | 22 (12.57%) | 13/44 files | excess=0, unlisted=0 |
| RNC line-level rich | 175 | 22 (12.57%) | missed=153 | duplicates=0, unexpected=0, category_conflicts=31 |

The rich score is detection-only: no precision, F1, or verified false-positive claim is made without a negative oracle.

## Exceptions

| Suite | Classification | Expected ID | Path | Line | Reason |
| --- | --- | --- | --- | --- | --- |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 4 | negative corpus finding rule generic-api-key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 5 | negative corpus finding rule generic-api-key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 8 | negative corpus finding rule generic-api-key |
| levain | MISSED_EXPECTATION | - | env-file | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | curl-verbose-basic-auth | - | credential kind http_basic_auth not detected |
| levain | MISSED_EXPECTATION | - | hardhat-deploy-failure | - | credential kind wallet_seed_phrase not detected |
| levain | MISSED_EXPECTATION | - | wallet-restore-env | - | credential kind wallet_seed_phrase not detected |
| levain | MISSED_EXPECTATION | - | axios-error-dump | - | credential kind bearer_token not detected |
| levain | MISSED_EXPECTATION | - | postgres-connection-failure | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | mongodb-uri | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | cloudsql-iam-dsn | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | cloudsql-iam-dsn | - | credential kind email not detected |
| levain | MISSED_EXPECTATION | - | payment-processing-log | - | credential kind payment_card not detected |
| levain | MISSED_EXPECTATION | - | payment-processing-log | - | credential kind payment_card not detected |
| levain | MISSED_EXPECTATION | - | terraform-apply-output | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | pip-index-url-with-password | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | ai-gateway-upstream-errors | - | credential kind xai_api_key not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind doppler_token not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind supabase_access_token not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind netlify_pat not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind tailscale_auth_key not detected |
| levain | MISSED_EXPECTATION | - | ci-publish-step-output | - | credential kind nuget_api_key not detected |
| levain | MISSED_EXPECTATION | - | ci-publish-step-output | - | credential kind sentry_org_auth_token not detected |
| levain | MISSED_EXPECTATION | - | webhook-and-oauth-callback-dump | - | credential kind discord_webhook_url not detected |
| levain | MISSED_EXPECTATION | - | webhook-and-oauth-callback-dump | - | credential kind google_oauth_client_secret not detected |
| levain | MISSED_EXPECTATION | - | webhook-and-oauth-callback-dump | - | credential kind resend_api_key not detected |
| levain | MISSED_EXPECTATION | - | webhook-and-oauth-callback-dump | - | credential kind airtable_pat not detected |
| levain | MISSED_EXPECTATION | - | edge-aws-secret-ends-in-plus | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | edge-github-tokens-containing-placeholder-words | - | credential kind github_pat_classic not detected |
| levain | MISSED_EXPECTATION | - | edge-github-tokens-containing-placeholder-words | - | credential kind github_pat_classic not detected |
| levain | MISSED_EXPECTATION | - | edge-openai-project-key-ends-in-hyphen | - | credential kind openai_project_key not detected |
| levain | MISSED_EXPECTATION | - | ansi-github-actions-raw-log | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | ansi-github-actions-raw-log | - | credential kind aws_secret_access_key not detected |
| levain | MISSED_EXPECTATION | - | ansi-docker-compose-logs | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | ansi-docker-compose-logs | - | credential kind bearer_token not detected |
| levain | MISSED_EXPECTATION | - | ansi-pytest-npm-publish-failure | - | credential kind npm_token not detected |
| levain | MISSED_EXPECTATION | - | ansi-terraform-plan-diff | - | credential kind sendgrid_api_key not detected |
| levain | MISSED_EXPECTATION | - | ansi-terraform-plan-diff | - | credential kind generic_assignment not detected |
| levain | MISSED_EXPECTATION | - | hard-shapeless-password | - | credential kind shapeless_password not detected |
| levain | MISSED_EXPECTATION | - | hard-capability-url | - | credential kind capability_url_segment not detected |
| levain | MISSED_EXPECTATION | - | hard-token-split-across-lines | - | credential kind wrapped_token not detected |
| levain | PARTIAL_MATCH | - | edge-openai-project-key-ends-in-hyphen | 4 | partial evidence for openai_project_key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 4 | negative corpus finding rule generic-api-key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 5 | negative corpus finding rule generic-api-key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 8 | negative corpus finding rule generic-api-key |
| levain | MISSED_EXPECTATION | - | env-file | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | curl-verbose-basic-auth | - | credential kind http_basic_auth not detected |
| levain | MISSED_EXPECTATION | - | hardhat-deploy-failure | - | credential kind wallet_seed_phrase not detected |
| levain | MISSED_EXPECTATION | - | wallet-restore-env | - | credential kind wallet_seed_phrase not detected |
| levain | MISSED_EXPECTATION | - | axios-error-dump | - | credential kind bearer_token not detected |
| levain | MISSED_EXPECTATION | - | postgres-connection-failure | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | mongodb-uri | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | cloudsql-iam-dsn | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | cloudsql-iam-dsn | - | credential kind email not detected |
| levain | MISSED_EXPECTATION | - | payment-processing-log | - | credential kind payment_card not detected |
| levain | MISSED_EXPECTATION | - | payment-processing-log | - | credential kind payment_card not detected |
| levain | MISSED_EXPECTATION | - | terraform-apply-output | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | pip-index-url-with-password | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | ai-gateway-upstream-errors | - | credential kind xai_api_key not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind doppler_token not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind supabase_access_token not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind netlify_pat not detected |
| levain | MISSED_EXPECTATION | - | platform-cli-auth-failures | - | credential kind tailscale_auth_key not detected |
| levain | MISSED_EXPECTATION | - | ci-publish-step-output | - | credential kind nuget_api_key not detected |
| levain | MISSED_EXPECTATION | - | ci-publish-step-output | - | credential kind sentry_org_auth_token not detected |
| levain | MISSED_EXPECTATION | - | webhook-and-oauth-callback-dump | - | credential kind discord_webhook_url not detected |
| levain | MISSED_EXPECTATION | - | webhook-and-oauth-callback-dump | - | credential kind google_oauth_client_secret not detected |
| levain | MISSED_EXPECTATION | - | webhook-and-oauth-callback-dump | - | credential kind resend_api_key not detected |
| levain | MISSED_EXPECTATION | - | webhook-and-oauth-callback-dump | - | credential kind airtable_pat not detected |
| levain | MISSED_EXPECTATION | - | edge-aws-secret-ends-in-plus | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | edge-github-tokens-containing-placeholder-words | - | credential kind github_pat_classic not detected |
| levain | MISSED_EXPECTATION | - | edge-github-tokens-containing-placeholder-words | - | credential kind github_pat_classic not detected |
| levain | MISSED_EXPECTATION | - | edge-openai-project-key-ends-in-hyphen | - | credential kind openai_project_key not detected |
| levain | MISSED_EXPECTATION | - | ansi-github-actions-raw-log | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | ansi-github-actions-raw-log | - | credential kind aws_secret_access_key not detected |
| levain | MISSED_EXPECTATION | - | ansi-docker-compose-logs | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | ansi-docker-compose-logs | - | credential kind bearer_token not detected |
| levain | MISSED_EXPECTATION | - | ansi-pytest-npm-publish-failure | - | credential kind npm_token not detected |
| levain | MISSED_EXPECTATION | - | ansi-terraform-plan-diff | - | credential kind sendgrid_api_key not detected |
| levain | MISSED_EXPECTATION | - | ansi-terraform-plan-diff | - | credential kind generic_assignment not detected |
| levain | MISSED_EXPECTATION | - | hard-shapeless-password | - | credential kind shapeless_password not detected |
| levain | MISSED_EXPECTATION | - | hard-capability-url | - | credential kind capability_url_segment not detected |
| levain | MISSED_EXPECTATION | - | hard-token-split-across-lines | - | credential kind wrapped_token not detected |
| levain | PARTIAL_MATCH | - | edge-openai-project-key-ends-in-hyphen | 4 | partial evidence for openai_project_key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 4 | negative corpus finding rule generic-api-key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 5 | negative corpus finding rule generic-api-key |
| levain | UNEXPECTED_FINDING | - | tailscale and wireguard status | 8 | negative corpus finding rule generic-api-key |
| levain | MISSED_EXPECTATION | - | env-file | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | curl-verbose-basic-auth | - | credential kind http_basic_auth not detected |
| levain | MISSED_EXPECTATION | - | hardhat-deploy-failure | - | credential kind wallet_seed_phrase not detected |
| levain | MISSED_EXPECTATION | - | wallet-restore-env | - | credential kind wallet_seed_phrase not detected |
| levain | MISSED_EXPECTATION | - | axios-error-dump | - | credential kind bearer_token not detected |
| levain | MISSED_EXPECTATION | - | postgres-connection-failure | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | mongodb-uri | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | cloudsql-iam-dsn | - | credential kind url_password not detected |
| levain | MISSED_EXPECTATION | - | cloudsql-iam-dsn | - | credential kind email not detected |
| levain | MISSED_EXPECTATION | - | payment-processing-log | - | credential kind payment_card not detected |
| levain | MISSED_EXPECTATION | - | payment-processing-log | - | credential kind payment_card not detected |
| levain | MISSED_EXPECTATION | - | terraform-apply-output | - | credential kind aws_access_key_id not detected |
| levain | MISSED_EXPECTATION | - | pip-index-url-with-password | - | credential kind url_password not detected |
| ... | 485 more exceptions | | | | |

## Cross-platform comparisons

| Suite | Comparison | Result | Details |
| --- | --- | --- | --- |
| gitleaks | windows-amd64_vs_docker-linux-amd64 | PASS |  |
| gitleaks | windows-amd64_vs_docker-linux-arm64 | PASS |  |
| gitleaks | docker-linux-amd64_vs_docker-linux-arm64 | PASS |  |
| levain | windows-amd64_vs_docker-linux-amd64 | PASS |  |
| levain | windows-amd64_vs_docker-linux-arm64 | PASS |  |
| levain | docker-linux-amd64_vs_docker-linux-arm64 | PASS |  |
| leaky-repo | windows-amd64_vs_docker-linux-amd64 | PASS | 0 legacy metric differences; 0 per-file differences; 0 rich finding differences |
| leaky-repo | windows-amd64_vs_docker-linux-arm64 | PASS | 0 legacy metric differences; 0 per-file differences; 0 rich finding differences |
| leaky-repo | docker-linux-amd64_vs_docker-linux-arm64 | PASS | 0 legacy metric differences; 0 per-file differences; 0 rich finding differences |


## Baseline comparison

- Status: **METRIC_ONLY**
- gitleaks: METRIC_ONLY — baseline has no normalized scoring evaluations for this suite
- levain: METRIC_ONLY — baseline has no normalized scoring evaluations for this suite
- leaky-repo: METRIC_ONLY — baseline has no normalized scoring evaluations for this suite

## Reports

- Sanitized: reports\cp1d\cp1d-baseline.json, reports\cp1d\cp1d-baseline.md
- Raw: not generated

## Limitations

- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- Raw reports are opt-in and never printed in ordinary console summaries.
- Gitleaks fixture coverage is incomplete until every INTERNAL_GO contract is evidenced.
- Leaky Repo count coverage is 12.57% (13/44 files); this is a count benchmark, not a completeness claim.
- One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- Docker coverage remains INCOMPLETE until every INTERNAL_GO contract is evidenced.
- The legacy fixture lane retains hashed reports rather than raw scanner report bytes.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Git-history benchmarking is not enabled in this checkpoint.
- Baseline comparison status: METRIC_ONLY.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
A built artifact is not counted as tested unless an applicable suite actually executed it.
