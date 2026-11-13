# Scanner Experiment Report

> **Outcome: COMPLETE**

## Identity

| Field | Value |
| --- | --- |
| Scanner | RNC Scanner (`rnc`) |
| Scanner build version | 0.1.0 |
| Source repository | C:\Dev\rnc-security-audit |
| Requested source commit | `5391d8457ea091c45733920078a7f714ec61f678` |
| Checkout HEAD | `5391d8457ea091c45733920078a7f714ec61f678` |
| Checkout HEAD verified | True |
| Adapter | `rnc` / RNC Scanner |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261112T235354Z-e51dcf4d` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-12T23:55:28Z |

The source commit is the primary experiment identity. Build hashes and image IDs below are supporting provenance, not substitutes for it.

## Configuration profile

| Setting | Value |
| --- | --- |
| profile | DEFAULT |
| scanner_config_argument | None |
| working_directory | empty run-owned scanner-cwd |
| cleared_environment | ['BETTERLEAKS_CONFIG', 'BETTERLEAKS_CONFIG_TOML', 'GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML', 'RNC_CONFIG', 'RNC_SCANNER_CONFIG'] |
| configuration_file_required | False |
| rules_sha256 | 0d21dfe17107e61292bc6eb2f8ff975021851cc27dcbf627e6eeef05a3bd0eb4 |
| default isolation | {"config_argument": "--rules", "config_isolation": "empty repository configuration passed as --config to suppress target auto-discovery", "history_mode": {"argument": "--history", "limitations": ["History scope is the pinned HEAD's reachable history, selected with --ref HEAD.", "Submodules, symlinks and other uninspected units are never treated as covered."], "read_only": true, "ref": "HEAD", "ref_argument": "--ref", "runtime_dependency": "git executable in the native host or container image", "scope": "selected-refs"}, "isolated_working_directory": true, "limitations": ["The rule bundle is read from the pinned source checkout and hashed after the source build.", "The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.", "Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed."], "mode": "bundled-provider-rules", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "RNC_CONFIG", "RNC_SCANNER_CONFIG"], "rules_hash_recorded_after_build": true, "rules_path": "rules/rnc-providers-v1.json", "rules_sha256": null, "verifiable": true} |
- Limitation: The rule bundle is read from the pinned source checkout and hashed after the source build.
- Limitation: The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Limitation: Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed.

## Builds and products

| Product | Kind | Build | Version | Artifact identity |
| --- | --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | 0.1.0 | `cc97f2e052475dbd16a722260591c9f6c2be0d568d141d90917cb6211401d586` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `rnclab` | **COMPLETED_AND_SCORED** | PASS | True | — |

### Product-level results

#### rnclab

- target `windows-amd64`: **PASS** — the pinned scanner source revision does not expose Git-history scanning
- Limitation: RNC Lab negative references are source-adjudicated within the frozen corpus; findings not present in the oracle remain pending review and precision/F1 are not certified.
- Limitation: Filesystem (1,282) and Git-history (320) denominators are separate and are never combined.
- Limitation: Private-key credit requires private-key material; public-key-only, SPKI-only, filename-only and encrypted-container-only evidence is not a true positive.
- Limitation: The frozen lab is verified before and after scanning; a hash change blocks the run.
- Limitation: Git-history mode is NOT_APPLICABLE for this pinned scanner source revision; no zero score or fabricated occurrences were emitted.

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=None/None |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=None, FP=None, precision=None, recall=None, F1=None |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** None/None (None%), rich line-truth matched=None/None |
| Leaky Repo history | **UNSCORED** — truth=None, execution=None, occurrences=None/None, unique=None/None, recall=None%, pending=None, unverified=None |
| RNC Lab v3 filesystem | TP=260/640, unique=171/366, recall=40.62%, duplicates=0, FP alerts=23, pending=56, precision=NOT CERTIFIED |
| RNC Lab v3 Git | NOT_APPLICABLE; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 5 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads:

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `rnclab-filesystem` | 0.296 | 0.285/0.304 | 0.022177 | 0.296875 | 28.33 | 360/371 | STABLE |
| `windows-amd64` | `rnclab-legacy-5x` | 1.988 | 1.973/2.29 | 0.070082 | 1.953125 | 44.19 | 1809/1810 | STABLE |
| `windows-amd64` | `rnclab-legacy-10x` | 3.469 | 3.31/3.531 | 0.027083 | 3.375 | 62.58 | 3609/3610 | STABLE |

### RNC Lab load scaling

| Product | Profile | Files | Bytes | Runtime scaling | Memory scaling | Accuracy scored |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `legacy-5x` | 1810 | 68402295 | 6.716216 | 1.55963 | false (performance only) |
| `windows-amd64` | `legacy-10x` | 3610 | 69695167 | 11.719595 | 2.208879 | false (performance only) |

- `windows-amd64` `rnclab-filesystem` run 0: 0.285 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 1: 0.291 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 2: 0.296 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 3: 0.299 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 4: 0.304 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 0: 2.29 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 1: 1.973 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 2: 1.988 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 0: 3.31 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 1: 3.531 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 2: 3.469 s, exit=20, telemetry=windows_process_times

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker product was built or invoked; no container cleanup was required.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | orbit-dashboard/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | lumen-lighting/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | fraud-scoring/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | fraud-scoring/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/infra/ssh/deploy_key | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | ops/inventory/provider-identifiers.json | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | ops/inventory/provider-identifiers.json | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | ops/inventory/provider-identifiers.json | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | ops/inventory/provider-identifiers.json | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | ops/inventory/provider-identifiers.json | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | ops/inventory/provider-identifiers.json | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | checkout-bff/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | store-locator/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pulse-analytics/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | supplier-hub/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | fleet-console/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | gift-cards/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | hr-portal/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-02.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | docs/integration-guide.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | docs/integration-guide.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-01.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-03.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | loyalty-portal/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | harbor-outfitters/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | pulse-analytics/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | store-locator/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | store-locator/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | loyalty-portal/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | gift-cards/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | summit-gear/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | acme-storefront/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/k8s/base/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/k8s/base/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | returns-center/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | loyalty-portal/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ledger-api/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ledger-api/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | vendor-onboarding/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | checkout-bff/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | returns-center/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | supplier-hub/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-03.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.pypirc | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | data/clients/mongosh-history.txt | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/ci/media-pipeline/ci/scripts/publish.sh | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | lumen-lighting/.env | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | orbit-dashboard/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | etl-warehouse/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | etl-warehouse/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | checkout-bff/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | supplier-hub/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/ci/platform-tools/ci/scripts/publish.sh | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/id_ed25519 | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | search-indexer/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | search-indexer/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pulse-analytics/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | pos-gateway/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | orbit-dashboard/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | northwind-catalog/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pricing-engine/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pricing-engine/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/id_rsa | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | bluebird-home/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | data/clients/warehouse.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | cedar-garden/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | returns-center/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/ci/checkout-bff/ci/scripts/publish.sh | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-04.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | notification-worker/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | notification-worker/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-02.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-01.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | warehouse-mobile/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | gift-cards/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-04.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | inventory-sync/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | inventory-sync/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | workstation/notes/secrets-rotation.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/deploy/k8s/secret.yaml | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/deploy/k8s/secret.yaml | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/deploy/k8s/secret.yaml | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/logs/deploy-2025-03-04.log | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- RNC Lab negative references are source-adjudicated within the frozen corpus; findings not present in the oracle remain pending review and precision/F1 are not certified.
- Filesystem (1,282) and Git-history (320) denominators are separate and are never combined.
- Private-key credit requires private-key material; public-key-only, SPKI-only, filename-only and encrypted-container-only evidence is not a true positive.
- The frozen lab is verified before and after scanning; a hash change blocks the run.
- Git-history mode is NOT_APPLICABLE for this pinned scanner source revision; no zero score or fabricated occurrences were emitted.
- The rule bundle is read from the pinned source checkout and hashed after the source build.
- The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
