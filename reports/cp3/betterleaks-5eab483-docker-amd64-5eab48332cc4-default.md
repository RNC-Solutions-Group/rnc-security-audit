# Scanner Experiment Report

> **Outcome: COMPLETE_WITH_LIMITATIONS**

## Identity

| Field | Value |
| --- | --- |
| Scanner | Betterleaks (`betterleaks`) |
| Scanner build version | v1.8.1 |
| Source repository | https://github.com/betterleaks/betterleaks |
| Requested source commit | `5eab48332cc48565864514e3bc6de89df091a7c4` |
| Checkout HEAD | `5eab48332cc48565864514e3bc6de89df091a7c4` |
| Checkout HEAD verified | True |
| Adapter | `betterleaks` / Betterleaks |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261111T185254Z-2299d1f1` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-11T18:54:50Z |

The source commit is the primary experiment identity. Build hashes and image IDs below are supporting provenance, not substitutes for it.

## Configuration profile

| Setting | Value |
| --- | --- |
| profile | DEFAULT |
| scanner_config_argument | None |
| working_directory | empty run-owned scanner-cwd |
| cleared_environment | ['BETTERLEAKS_CONFIG', 'BETTERLEAKS_CONFIG_TOML', 'GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML'] |
| configuration_file_required | False |
| default isolation | {"config_argument": null, "isolated_working_directory": true, "limitations": ["DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.", "The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes."], "mode": "bundled-default", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"], "verifiable": true} |
- Limitation: DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- Limitation: The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.

## Builds and products

| Product | Kind | Build | Version | Artifact identity |
| --- | --- | --- | --- | --- |
| `docker-linux-amd64` | docker | PASS | v1.8.1 | `sha256:cb65a5ea0d70a7b2b0d582cc83d7e81eb9c72b923ddbfe9755b72ccde6c983c8` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `synthetic-filesystem` | **COMPLETED_AND_SCORED** | PASS | False | precision %=100.0; F1 %=100.0; expected=4; value-verified=4; line-only=0 |
| `git-history` | **COMPLETED_AND_SCORED** | PASS | False | unique matched=3; unique expected=3; occurrences matched=5; occurrences expected=5 |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=48; expected credentials=85; false positives=5; partial matches=3; duplicates=2; precision %=90.57; recall %=56.47 |
| `leaky-repo` | **COMPLETED_AND_SCORED** | PASS | True | LEGACY COUNT COVERAGE %=21.14; rich line-truth recall %=21.14; expected=175; covered=37; files covered=22; rich matched=37; rich missed=138 |

### Product-level results

#### synthetic-filesystem

- controlled-filesystem / `docker-linux-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `docker-linux-amd64`: **PASS**

#### git-history

- controlled-history / `docker-linux-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `docker-linux-amd64`: **PASS**

#### levain

- levain / `docker-linux-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `docker-linux-amd64`: **PASS**
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

#### leaky-repo

- filesystem / `docker-linux-amd64`: **COMPLETED_AND_SCORED** (PASS)
- history / `docker-linux-amd64`: **COMPLETED_UNSCORED** (PASS)
- target `docker-linux-amd64`: **PASS**
- Limitation: Legacy Leaky Repo score preserves the upstream line-count methodology.
- Limitation: RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Limitation: Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Limitation: Leaky Repo Git-history observations are not scored: no independently verified historical truth manifest exists, so history truth is BLOCKED and the filesystem 175-item denominator is not applied.

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=4/4 |
| Synthetic history | unique=3/3, occurrences=5/5 |
| Levain | TP=48, FP=5, precision=90.57, recall=56.47, F1=69.57 |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** 37/175 (21.14%), rich line-truth matched=37/175 |
| Leaky Repo history | **UNSCORED** — truth=BLOCKED, execution=PASS, findings=41, unique fingerprints=29 |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history has no defensible denominator and is never scored against the 175 filesystem items.

## Performance (separate from detection)

Workload: 610 files / 5888020 bytes; 5 warm-up(s), 7 measured run(s).

| Product | Median s | Min/max s | CV | CPU s | Peak MiB | Stability |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `docker-linux-amd64` | 2.196 | 1.829/2.904 | 0.150993 | unavailable | unavailable | STABLE |

- `docker-linux-amd64` run 0: 2.218 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` run 1: 1.971 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` run 2: 1.829 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` run 3: 1.952 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` run 4: 2.371 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` run 5: 2.904 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` run 6: 2.196 s, exit=1, telemetry=docker_stats

## Cleanup

- Status: **PASS**
- Retained by request: False
- No run-owned containers found.
- Removed 1 run-owned image(s).
- Removed image tag rnc-betterleaks-20261111t185254z-2299d1f1-5eab48332cc4-docker-linux-amd64.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Classification | Path | Reason |
| --- | --- | --- | --- |
| `levain` | UNEXPECTED_FINDING | config file (placeholders) | negative corpus finding rule generic-credential-uri |
| `levain` | UNEXPECTED_FINDING | docker compose masked env | negative corpus finding rule generic-password |
| `levain` | UNEXPECTED_FINDING | tailscale and wireguard status | negative corpus finding rule generic-api-key |
| `levain` | UNEXPECTED_FINDING | tailscale and wireguard status | negative corpus finding rule generic-api-key |
| `levain` | UNEXPECTED_FINDING | tailscale and wireguard status | negative corpus finding rule generic-api-key |
| `levain` | MISSED_EXPECTATION | env-file | credential kind aws_access_key_id not detected |
| `levain` | MISSED_EXPECTATION | curl-verbose-basic-auth | credential kind http_basic_auth not detected |
| `levain` | MISSED_EXPECTATION | hardhat-deploy-failure | credential kind wallet_seed_phrase not detected |
| `levain` | MISSED_EXPECTATION | wallet-restore-env | credential kind wallet_seed_phrase not detected |
| `levain` | MISSED_EXPECTATION | axios-error-dump | credential kind bearer_token not detected |
| `levain` | MISSED_EXPECTATION | mongodb-uri | credential kind url_password not detected |
| `levain` | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind url_password not detected |
| `levain` | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind email not detected |
| `levain` | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | MISSED_EXPECTATION | terraform-apply-output | credential kind aws_access_key_id not detected |
| `levain` | MISSED_EXPECTATION | pip-index-url-with-password | credential kind url_password not detected |
| `levain` | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind xai_api_key not detected |
| `levain` | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind doppler_token not detected |
| `levain` | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind planetscale_token not detected |
| `levain` | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind netlify_pat not detected |
| `levain` | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind tailscale_auth_key not detected |
| `levain` | MISSED_EXPECTATION | ci-publish-step-output | credential kind nuget_api_key not detected |
| `levain` | MISSED_EXPECTATION | ci-publish-step-output | credential kind sentry_org_auth_token not detected |
| `levain` | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind discord_webhook_url not detected |
| `levain` | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind google_oauth_client_secret not detected |
| `levain` | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind resend_api_key not detected |
| `levain` | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind airtable_pat not detected |
| `levain` | MISSED_EXPECTATION | edge-aws-secret-ends-in-plus | credential kind aws_access_key_id not detected |
| `levain` | MISSED_EXPECTATION | edge-github-tokens-containing-placeholder-words | credential kind github_pat_classic not detected |
| `levain` | MISSED_EXPECTATION | edge-github-tokens-containing-placeholder-words | credential kind github_pat_classic not detected |
| `levain` | MISSED_EXPECTATION | edge-openai-project-key-ends-in-hyphen | credential kind openai_project_key not detected |
| `levain` | MISSED_EXPECTATION | ansi-github-actions-raw-log | credential kind aws_access_key_id not detected |
| `levain` | MISSED_EXPECTATION | ansi-github-actions-raw-log | credential kind aws_secret_access_key not detected |
| `levain` | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind url_password not detected |
| `levain` | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind bearer_token not detected |
| `levain` | MISSED_EXPECTATION | ansi-pytest-npm-publish-failure | credential kind npm_token not detected |
| `levain` | MISSED_EXPECTATION | ansi-terraform-plan-diff | credential kind sendgrid_api_key not detected |
| `levain` | MISSED_EXPECTATION | ansi-terraform-plan-diff | credential kind generic_assignment not detected |
| `levain` | MISSED_EXPECTATION | hard-shapeless-password | credential kind shapeless_password not detected |
| `levain` | MISSED_EXPECTATION | hard-capability-url | credential kind capability_url_segment not detected |
| `levain` | MISSED_EXPECTATION | hard-token-split-across-lines | credential kind wrapped_token not detected |
| `levain` | PARTIAL_MATCH | mongodb-uri | partial evidence for url_password |
| `levain` | PARTIAL_MATCH | ansi-docker-compose-logs | partial evidence for url_password |
| `levain` | PARTIAL_MATCH | edge-openai-project-key-ends-in-hyphen | partial evidence for openai_project_key |
| `leaky-repo` | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bashrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bashrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bashrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/config.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/config.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .esmtprc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .esmtprc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .esmtprc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .git-credentials | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .idea/WebServers.xml | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .idea/WebServers.xml | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .netrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .netrc | no observed finding matched this expected item |

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- LEGACY COUNT COVERAGE for Leaky Repo is 21.14% (22/44 files); this is an upstream count metric, not verified detection recall.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo Git-history observations are not scored: no independently verified historical truth manifest exists, so history truth is BLOCKED and the filesystem 175-item denominator is not applied.
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
