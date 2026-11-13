# Scanner Experiment Report

> **Outcome: COMPLETE**

## Identity

| Field | Value |
| --- | --- |
| Scanner | RNC Scanner (`rnc`) |
| Registered build | `rnc-cp3` |
| Scanner version | 0.1.0 |
| Artifact manifest | `run/manifest.toml` |
| Artifact manifest SHA-256 | `6aef0938ab5ef6917b13c2f3250cf3be5ab1529f00daa01ad5e61e4ba79106ad` |
| Source commit (manifest metadata) | `5391d8457ea091c45733920078a7f714ec61f678` |
| Source commit verification | NOT VERIFIED — operator-supplied metadata; no source checkout or build |
| Registered executable | `rnc-cp3.exe` |
| Registered executable SHA-256 | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` |
| Registered Docker image | `rnc-scanner:cp3-amd64` |
| Registered Docker image ID | `sha256:469d9f1d33c1e30e534993d9540c81fe445ac6d55f99f21ff5b99548eb774d1d` |
| Rules/configuration file | `rules/rnc-cp3-providers-v1.json` |
| Rules/configuration SHA-256 | `0d21dfe17107e61292bc6eb2f8ff975021851cc27dcbf627e6eeef05a3bd0eb4` |
| Adapter | `rnc` / RNC Scanner |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261113T190843Z-1f07120a` |
| Harness version | 0.6.0 |
| Generated (UTC) | 2026-11-13T19:08:46Z |

The executed scanner identity is the operator-provided executable SHA-256 or Docker image ID above. The source commit is retained as operator metadata only; it is never acquired or compiled by this harness.

## Configuration profile

| Setting | Value |
| --- | --- |
| profile | DEFAULT |
| scanner_config_argument | None |
| working_directory | empty run-owned scanner-cwd |
| cleared_environment | ['BETTERLEAKS_CONFIG', 'BETTERLEAKS_CONFIG_TOML', 'GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML', 'RNC_CONFIG', 'RNC_SCANNER_CONFIG'] |
| configuration_file_required | False |
| rules_sha256 | 0d21dfe17107e61292bc6eb2f8ff975021851cc27dcbf627e6eeef05a3bd0eb4 |
| default isolation | {"config_argument": "--rules", "config_isolation": "empty repository configuration passed as --config to suppress target auto-discovery", "history_mode": {"argument": "--history", "capability_source": "operator-provided manifest capabilities", "limitations": ["History scope is the pinned HEAD's reachable history, selected with --ref HEAD.", "Submodules, symlinks and other uninspected units are never treated as covered."], "read_only": true, "ref": "HEAD", "ref_argument": "--ref", "runtime_dependency": "git executable in the native host or container image", "scope": "selected-refs"}, "isolated_working_directory": true, "limitations": ["The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.", "The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.", "Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed."], "mode": "operator-registered-provider-rules", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "RNC_CONFIG", "RNC_SCANNER_CONFIG"], "rules_hash_recorded_from_manifest": true, "rules_path": "rules/rnc-providers-v1.json", "rules_sha256": null, "rules_source": "operator-provided rules_file in run/manifest.toml", "verifiable": true} |
- Limitation: The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.
- Limitation: The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Limitation: Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed.

## Registered artifacts and products

| Product | Kind | Status | Build ID | Version | Artifact identity | Verified |
| --- | --- | --- | --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | `rnc-cp3` | 0.1.0 | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | True |

Toolchain: Docker `29.9.3`, Git `git version 2.45.2.windows.1`, Python `Python 3.13.5`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `synthetic-filesystem` | **COMPLETED_AND_SCORED** | PASS | False | precision %=100.0; F1 %=100.0; expected=4; value-verified=4; line-only=0 |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=32; expected credentials=85; false positives=0; partial matches=0; duplicates=0; precision %=100.0; recall %=37.65 |

### Product-level results

#### synthetic-filesystem

- controlled-filesystem / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**

#### levain

- levain / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=4/4 |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=32, FP=0, precision=100.0, recall=37.65, F1=54.7 |
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
| `windows-amd64` | `levain-filesystem` | 0.13 | 0.13/0.13 | 0.0 | 0.125 | 27.02 | 163/163 | STABLE |


- `windows-amd64` `levain-filesystem` run 0: 0.13 s, exit=10, telemetry=windows_process_times

## Scanner invocations

Every row records the actual executed argument vector (not a reconstructed command), in execution order. Credential-bearing argument values are redacted only when a sensitive flag such as `--password` or `--token` is present; the original argv digest is retained in the JSON report.

| # | Type | Suite | Workload | Platform | Build | Artifact identity | Exit | Duration (s) | Timeout/error | Command |
| ---: | --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |
| 1 | verification | `—` | `ruleset-validation` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 0 | 0.073 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe rules validate --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --strategy auto` |
| 2 | detection | `synthetic-filesystem` | `synthetic-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.047 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\synthetic-filesystem\target --rules C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\synthetic-filesystem\scanner-config.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\synthetic-filesystem\lanes\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\synthetic-filesystem\lanes\windows-amd64\report.json --format private --run-id 20261113T190843Z-1f07120a` |
| 3 | detection | `levain` | `levain-negative` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.705 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\levain\windows-amd64\negative --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\levain\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\levain\windows-amd64\negative-report.json --format private --run-id 20261113T190843Z-1f07120a` |
| 4 | detection | `levain` | `levain-positive` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.128 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\levain\windows-amd64\positive --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\levain\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\levain\windows-amd64\positive-report.json --format private --run-id 20261113T190843Z-1f07120a` |
| 5 | warmup | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.282 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\performance\windows-amd64\levain-filesystem\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\performance\windows-amd64\levain-filesystem\warmup\0\report.json --format private --run-id 20261113T190843Z-1f07120a` |
| 6 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.13 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\performance\windows-amd64\levain-filesystem\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T190843Z-1f07120a\evidence\performance\windows-amd64\levain-filesystem\measured\0\report.json --format private --run-id 20261113T190843Z-1f07120a` |

Invocation types: `detection`, `warmup`, `measured`, and `verification` for artifact/ruleset validation. Detection and performance commands use the same registered executable or image.

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker artifact was executed; no container cleanup was required.
- Removed run-owned benchmark workspace, generated datasets, and evidence.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `levain` | filesystem | MISSED_EXPECTATION | curl-verbose-basic-auth | credential kind http_basic_auth not detected |
| `levain` | filesystem | MISSED_EXPECTATION | gpg-secret-key-export | credential kind pgp_private_key_block not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hardhat-deploy-failure | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | wallet-restore-env | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | axios-error-dump | credential kind bearer_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | postgres-connection-failure | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | mongodb-uri | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind email not detected |
| `levain` | filesystem | MISSED_EXPECTATION | slack-integration-error | credential kind slack_webhook_url not detected |
| `levain` | filesystem | MISSED_EXPECTATION | mailgun-delivery-log | credential kind mailgun_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | azure-storage-connection-string | credential kind azure_storage_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ssh-private-key-in-log | credential kind private_key_pem not detected |
| `levain` | filesystem | MISSED_EXPECTATION | gcp-service-account-json | credential kind private_key_escaped_json not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | pip-index-url-with-password | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind groq_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind xai_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind perplexity_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind fireworks_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | inference-worker-traceback | credential kind replicate_api_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | inference-worker-traceback | credential kind pinecone_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | inference-worker-traceback | credential kind elevenlabs_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind doppler_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind databricks_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind grafana_service_account_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind planetscale_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind supabase_access_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind netlify_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind tailscale_auth_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind rubygems_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind nuget_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind sonarqube_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind sentry_org_auth_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind newrelic_user_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind dynatrace_api_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind terraform_cloud_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind discord_webhook_url not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind google_oauth_client_secret not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind resend_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind postman_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind airtable_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-openai-project-key-ends-in-hyphen | credential kind openai_project_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-confluent-secret-ends-in-slash | credential kind confluent_cloud_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-confluent-secret-ends-in-slash | credential kind confluent_cloud_secret not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-vault-token-with-letter-prefixed-body | credential kind vault_service_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | custom-vendor-prefix-convention | credential kind custom_internal_format not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind bearer_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-shapeless-password | credential kind shapeless_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-capability-url | credential kind capability_url_segment not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-token-split-across-lines | credential kind wrapped_token not detected |

## Limitations

- Source commit is operator-supplied manifest metadata; the harness did not clone, check out, or compile scanner source.
- The registered executable SHA-256 and Docker image ID are the executed artifact identities; they are verified before every run.
- A verified artifact is not counted as tested unless an applicable suite executed it.
- Registered Docker images and run/ executables are never deleted or modified by the harness.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.
- The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
