# Scanner Experiment Report

> **Outcome: COMPLETE**

## Identity

| Field | Value |
| --- | --- |
| Scanner | Gitleaks (`gitleaks`) |
| Registered build | `gitleaks-local` |
| Scanner version | 8.25.0-local |
| Artifact manifest | `run/manifest.toml` |
| Artifact manifest SHA-256 | `e56066972ecc5e81eb6a1809e71ab874694e687bc97fd94c82192e3a5ee8b53c` |
| Source commit (manifest metadata) | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Source commit verification | NOT VERIFIED — operator-supplied metadata; no source checkout or build |
| Registered executable | `gitleaks.exe` |
| Registered executable SHA-256 | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |
| Registered Docker image | `—` |
| Registered Docker image ID | `—` |
| Rules/configuration file | `—` |
| Rules/configuration SHA-256 | `—` |
| Adapter | `gitleaks` / Gitleaks |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261113T171808Z-085c06ac` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-13T17:18:10Z |

The executed scanner identity is the operator-provided executable SHA-256 or Docker image ID above. The source commit is retained as operator metadata only; it is never acquired or compiled by this harness.

## Configuration profile

| Setting | Value |
| --- | --- |
| profile | DEFAULT |
| scanner_config_argument | None |
| working_directory | empty run-owned scanner-cwd |
| cleared_environment | ['BETTERLEAKS_CONFIG', 'BETTERLEAKS_CONFIG_TOML', 'GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML', 'RNC_CONFIG', 'RNC_SCANNER_CONFIG'] |
| configuration_file_required | False |
| default isolation | {"config_argument": null, "isolated_working_directory": true, "limitations": ["DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.", "The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes."], "mode": "bundled-default", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "RNC_CONFIG", "RNC_SCANNER_CONFIG"], "verifiable": true} |
- Limitation: DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- Limitation: The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.

## Registered artifacts and products

| Product | Kind | Status | Build ID | Version | Artifact identity | Verified |
| --- | --- | --- | --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | `gitleaks-local` | 8.25.0-local | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` | True |

Toolchain: Docker `29.9.3`, Git `git version 2.45.2.windows.1`, Python `Python 3.13.5`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=47; expected credentials=85; false positives=3; partial matches=1; duplicates=2; precision %=94.0; recall %=55.29 |

### Product-level results

#### levain

- levain / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=None/None |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=47, FP=3, precision=94.0, recall=55.29, F1=69.63 |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** None/None (None%), rich line-truth matched=None/None |
| Leaky Repo history | **UNSCORED** — truth=None, execution=None, occurrences=None/None, unique=None/None, recall=None%, pending=None, unverified=None |
| RNC Lab v3 filesystem | TP=None/None, unique=None/None, recall=None%, duplicates=None, FP alerts=None, pending=None, precision=NOT CERTIFIED |
| RNC Lab v3 Git | NOT_APPLICABLE; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 1 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads: `levain-filesystem` (163 files / 85581 bytes)

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `levain-filesystem` | 0.135 | 0.135/0.135 | 0.0 | 0.296875 | 47.46 | 163/163 | STABLE |


- `windows-amd64` `levain-filesystem` run 0: 0.135 s, exit=1, telemetry=windows_process_times

## Scanner invocations

Every row records the actual executed argument vector (not a reconstructed command), in execution order. Credential-bearing argument values are redacted only when a sensitive flag such as `--password` or `--token` is present; the original argv digest is retained in the JSON report.

| # | Type | Suite | Workload | Platform | Build | Artifact identity | Exit | Duration (s) | Timeout/error | Command |
| ---: | --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |
| 1 | detection | `levain` | `levain-negative` | `windows-amd64` | `gitleaks-local` | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` | 1 | 0.257 | none | `C:\Dev\rnc-benchmark-harness\run\gitleaks.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171808Z-085c06ac\evidence\levain\windows-amd64\negative --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171808Z-085c06ac\evidence\levain\windows-amd64\negative-report.json --no-banner --exit-code 1` |
| 2 | detection | `levain` | `levain-positive` | `windows-amd64` | `gitleaks-local` | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` | 1 | 0.087 | none | `C:\Dev\rnc-benchmark-harness\run\gitleaks.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171808Z-085c06ac\evidence\levain\windows-amd64\positive --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171808Z-085c06ac\evidence\levain\windows-amd64\positive-report.json --no-banner --exit-code 1` |
| 3 | warmup | `levain` | `levain-filesystem` | `windows-amd64` | `gitleaks-local` | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` | 1 | 0.126 | none | `C:\Dev\rnc-benchmark-harness\run\gitleaks.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171808Z-085c06ac\evidence\performance\levain --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171808Z-085c06ac\evidence\performance\windows-amd64\levain-filesystem\warmup\0\report.json --no-banner --exit-code 1` |
| 4 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `gitleaks-local` | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` | 1 | 0.135 | none | `C:\Dev\rnc-benchmark-harness\run\gitleaks.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171808Z-085c06ac\evidence\performance\levain --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171808Z-085c06ac\evidence\performance\windows-amd64\levain-filesystem\measured\0\report.json --no-banner --exit-code 1` |

Invocation types: `detection`, `warmup`, `measured`, and `verification` for artifact/ruleset validation. Detection and performance commands use the same registered executable or image.

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker artifact was executed; no container cleanup was required.
- Removed run-owned benchmark workspace, generated datasets, and evidence.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `levain` | filesystem | UNEXPECTED_FINDING | tailscale and wireguard status | negative corpus finding rule generic-api-key |
| `levain` | filesystem | UNEXPECTED_FINDING | tailscale and wireguard status | negative corpus finding rule generic-api-key |
| `levain` | filesystem | UNEXPECTED_FINDING | tailscale and wireguard status | negative corpus finding rule generic-api-key |
| `levain` | filesystem | MISSED_EXPECTATION | env-file | credential kind aws_access_key_id not detected |
| `levain` | filesystem | MISSED_EXPECTATION | curl-verbose-basic-auth | credential kind http_basic_auth not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hardhat-deploy-failure | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | wallet-restore-env | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | axios-error-dump | credential kind bearer_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | postgres-connection-failure | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | mongodb-uri | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind email not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | terraform-apply-output | credential kind aws_access_key_id not detected |
| `levain` | filesystem | MISSED_EXPECTATION | pip-index-url-with-password | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind xai_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind doppler_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind supabase_access_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind netlify_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind tailscale_auth_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind nuget_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind sentry_org_auth_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind discord_webhook_url not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind google_oauth_client_secret not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind resend_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind airtable_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-aws-secret-ends-in-plus | credential kind aws_access_key_id not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-github-tokens-containing-placeholder-words | credential kind github_pat_classic not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-github-tokens-containing-placeholder-words | credential kind github_pat_classic not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-openai-project-key-ends-in-hyphen | credential kind openai_project_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-github-actions-raw-log | credential kind aws_access_key_id not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-github-actions-raw-log | credential kind aws_secret_access_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind bearer_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-pytest-npm-publish-failure | credential kind npm_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-terraform-plan-diff | credential kind sendgrid_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-terraform-plan-diff | credential kind generic_assignment not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-shapeless-password | credential kind shapeless_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-capability-url | credential kind capability_url_segment not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-token-split-across-lines | credential kind wrapped_token not detected |
| `levain` | filesystem | PARTIAL_MATCH | edge-openai-project-key-ends-in-hyphen | partial evidence for openai_project_key |

## Limitations

- Source commit is operator-supplied manifest metadata; the harness did not clone, check out, or compile scanner source.
- The registered executable SHA-256 and Docker image ID are the executed artifact identities; they are verified before every run.
- A verified artifact is not counted as tested unless an applicable suite executed it.
- Registered Docker images and run/ executables are never deleted or modified by the harness.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
