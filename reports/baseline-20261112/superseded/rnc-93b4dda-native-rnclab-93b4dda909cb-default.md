# Scanner Experiment Report

> **Outcome: INCOMPLETE**

## Identity

| Field | Value |
| --- | --- |
| Scanner | RNC Scanner (`rnc`) |
| Scanner build version | 0.1.0 |
| Source repository | C:\Dev\rnc-security-audit |
| Requested source commit | `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` |
| Checkout HEAD | `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` |
| Checkout HEAD verified | True |
| Adapter | `rnc` / RNC Scanner |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261112T233929Z-d229bba6` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-12T23:43:19Z |

The source commit is the primary experiment identity. Build hashes and image IDs below are supporting provenance, not substitutes for it.

## Configuration profile

| Setting | Value |
| --- | --- |
| profile | DEFAULT |
| scanner_config_argument | None |
| working_directory | empty run-owned scanner-cwd |
| cleared_environment | ['BETTERLEAKS_CONFIG', 'BETTERLEAKS_CONFIG_TOML', 'GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML', 'RNC_CONFIG', 'RNC_SCANNER_CONFIG'] |
| configuration_file_required | False |
| rules_sha256 | 87d7f9051ae41df34df29a0d5447ee8c9d71854ada46b789c9b7a00e4320a73a |
| default isolation | {"config_argument": "--rules", "config_isolation": "empty repository configuration passed as --config to suppress target auto-discovery", "history_mode": {"argument": "--history", "limitations": ["History scope is the pinned HEAD's reachable history, selected with --ref HEAD.", "Submodules, symlinks and other uninspected units are never treated as covered."], "read_only": true, "ref": "HEAD", "ref_argument": "--ref", "runtime_dependency": "git executable in the native host or container image", "scope": "selected-refs"}, "isolated_working_directory": true, "limitations": ["The rule bundle is read from the pinned source checkout and hashed after the source build.", "The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.", "Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed."], "mode": "bundled-provider-rules", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "RNC_CONFIG", "RNC_SCANNER_CONFIG"], "rules_hash_recorded_after_build": true, "rules_path": "rules/rnc-providers-v1.json", "rules_sha256": null, "verifiable": true} |
- Limitation: The rule bundle is read from the pinned source checkout and hashed after the source build.
- Limitation: The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Limitation: Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed.

## Builds and products

| Product | Kind | Build | Version | Artifact identity |
| --- | --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | 0.1.0 | `deaded803e5941f18151454400b18dcf3ad58bbc7ef8b3dc243368acf38b3c56` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `rnclab` | **BLOCKED** | BLOCKED | True | — |

### Product-level results

#### rnclab

- target `windows-amd64`: **BLOCKED** — scanner invocation problem: INCOMPLETE
- Limitation: RNC Lab negative references are source-adjudicated within the frozen corpus; findings not present in the oracle remain pending review and precision/F1 are not certified.
- Limitation: Filesystem (1,282) and Git-history (320) denominators are separate and are never combined.
- Limitation: Private-key credit requires private-key material; public-key-only, SPKI-only, filename-only and encrypted-container-only evidence is not a true positive.
- Limitation: The frozen lab is verified before and after scanning; a hash change blocks the run.

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=None/None |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=None, FP=None, precision=None, recall=None, F1=None |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** None/None (None%), rich line-truth matched=None/None |
| Leaky Repo history | **UNSCORED** — truth=None, execution=None, occurrences=None/None, unique=None/None, recall=None%, pending=None, unverified=None |
| RNC Lab v3 filesystem | TP=0/640, unique=0/366, recall=0.0%, duplicates=0, FP alerts=0, pending=0, precision=NOT CERTIFIED |
| RNC Lab v3 Git | supported; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 5 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads:

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `rnclab-filesystem` | None | None/None | None | unavailable | unavailable | 360/360 | INCOMPLETE |
| `windows-amd64` | `rnclab-git` | 6.312 | 6.276/6.372 | 0.005574 | 0.671875 | 84.16 | 102/102 | STABLE |
| `windows-amd64` | `rnclab-legacy-5x` | None | None/None | None | unavailable | unavailable | 1810/1810 | INCOMPLETE |
| `windows-amd64` | `rnclab-legacy-10x` | None | None/None | None | unavailable | unavailable | 3610/3610 | INCOMPLETE |

### RNC Lab load scaling

| Product | Profile | Files | Bytes | Runtime scaling | Memory scaling | Accuracy scored |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `legacy-5x` | 1810 | 68402295 | None | None | false (performance only) |
| `windows-amd64` | `legacy-10x` | 3610 | 69695167 | None | None | false (performance only) |

- `windows-amd64` `rnclab-filesystem` run 0: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-filesystem` run 1: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-filesystem` run 2: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-filesystem` run 3: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-filesystem` run 4: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-git` run 0: 6.28 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 1: 6.312 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 2: 6.329 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 3: 6.372 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 4: 6.276 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 0: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-legacy-5x` run 1: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-legacy-5x` run 2: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-legacy-10x` run 0: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-legacy-10x` run 1: 0.0 s, exit=None, telemetry=unavailable
- `windows-amd64` `rnclab-legacy-10x` run 2: 0.0 s, exit=None, telemetry=unavailable

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker product was built or invoked; no container cleanup was required.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/checkout/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/risk/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/pricing/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | FALSE_POSITIVE | docs/integration-guide.md | exact path and value identity |
| `rnclab` | git:windows-amd64 | FALSE_POSITIVE | docs/integration-guide.md | exact path and value identity |
| `rnclab` | git:windows-amd64 | FALSE_POSITIVE | docs/integration-guide.md | exact path and value identity |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/giftcards/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/billing/config/payments.yml | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/billing/config/payments.yml | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/reporting/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/notify/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/orders/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/promo/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/subscription/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | UNMATCHED_PENDING_REVIEW | services/identity/keys/deploy.pem | no exact source value identity at the finding path |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/analytics/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/billing/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/catalog/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/checkout/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/checkout/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/compliance/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/fraud/.env | password/database_password in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/fraud/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/giftcards/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/giftcards/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/identity/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/identity/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/inventory/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/invoice/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/invoice/config/app.yml | provider_token/twilio_auth_token in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/locator/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/loyalty/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/loyalty/config/app.yml | provider_token/twilio_auth_token in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/media/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/media/config/app.yml | provider_token/twilio_auth_token in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/mobile/.env | password/database_password in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/mobile/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/mobile/config/app.yml | password/database_password in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/mobile/config/app.yml | provider_token/twilio_auth_token in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/notify/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/notify/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/orders/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/orders/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/payment/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/payment/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/payment/config/v2.yml | provider_token/stripe_webhook_secret in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/pricing/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/pricing/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/promo/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/promo/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/reporting/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/reporting/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/returns/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/review/.env | password/database_password in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/review/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/review/config/app.yml | password/database_password in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/risk/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/risk/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/search/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/shipping/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/shipping/config/app.yml | provider_token/twilio_auth_token in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/storefront/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/subscription/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/subscription/keys/deploy.pem | private_key/rsa_private_key_pkcs1 in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/suppliers/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/suppliers/config/app.yml | provider_token/sendgrid_api_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/tax/.env | password/database_password in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/tax/.env | hmac_secret/application_signing_key in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/tax/config/app.yml | password/database_password in git |
| `rnclab` | git:windows-amd64 | MISSED_EXPECTATION | services/wishlist/.env | hmac_secret/application_signing_key in git |

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- RNC Lab negative references are source-adjudicated within the frozen corpus; findings not present in the oracle remain pending review and precision/F1 are not certified.
- Filesystem (1,282) and Git-history (320) denominators are separate and are never combined.
- Private-key credit requires private-key material; public-key-only, SPKI-only, filename-only and encrypted-container-only evidence is not a true positive.
- The frozen lab is verified before and after scanning; a hash change blocks the run.
- The rule bundle is read from the pinned source checkout and hashed after the source build.
- The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
