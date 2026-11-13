# Scanner Experiment Report

> **Outcome: COMPLETE**

## Identity

| Field | Value |
| --- | --- |
| Scanner | Gitleaks (`gitleaks`) |
| Scanner build version | v8.0.0-rnc.5f6ec56cfa6f |
| Source repository | C:\Dev\gitleaks\gitleaks |
| Requested source commit | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Checkout HEAD | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Checkout HEAD verified | True |
| Adapter | `gitleaks` / Gitleaks |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261112T235937Z-0af1baad` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-13T00:00:18Z |

The source commit is the primary experiment identity. Build hashes and image IDs below are supporting provenance, not substitutes for it.

## Configuration profile

| Setting | Value |
| --- | --- |
| cleared_environment | ['BETTERLEAKS_CONFIG', 'BETTERLEAKS_CONFIG_TOML', 'GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML', 'RNC_CONFIG', 'RNC_SCANNER_CONFIG'] |
| configuration_file_required | False |
| profile | DEFAULT |
| scanner_config_argument | None |
| working_directory | empty run-owned scanner-cwd |
| default isolation | {"config_argument": null, "isolated_working_directory": true, "limitations": ["DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.", "The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes."], "mode": "bundled-default", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "RNC_CONFIG", "RNC_SCANNER_CONFIG"], "verifiable": true} |
- Limitation: DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- Limitation: The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.

## Builds and products

| Product | Kind | Build | Version | Artifact identity |
| --- | --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | v8.0.0-rnc.5f6ec56cfa6f | `c68865ea9cd5645e21c6bef2cfdc16a49b4d693b24028b5e4badfda593a913d1` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `rnclab` | **COMPLETED_AND_SCORED** | PASS | True | — |

### Product-level results

#### rnclab

- target `windows-amd64`: **PASS**
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
| RNC Lab v3 filesystem | TP=357/640, unique=220/366, recall=55.78%, duplicates=80, FP alerts=4, pending=34, precision=NOT CERTIFIED |
| RNC Lab v3 Git | supported; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 5 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads: `rnclab-filesystem` (371 files / 258574 bytes), `rnclab-git` (102 files / 41455 bytes)

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `rnclab-filesystem` | 0.23 | 0.228/0.276 | 0.07907 | 0.796875 | 53.0 | 360/371 | STABLE |
| `windows-amd64` | `rnclab-git` | 0.212 | 0.198/0.224 | 0.043851 | 0.125 | 39.55 | 102/102 | STABLE |
| `windows-amd64` | `rnclab-legacy-5x` | 1.484 | 1.331/1.862 | 0.143151 | 4.5 | 58.54 | 1810/1810 | STABLE |
| `windows-amd64` | `rnclab-legacy-10x` | 2.711 | 2.629/2.862 | 0.035297 | 8.59375 | 74.89 | 3610/3610 | STABLE |

### RNC Lab load scaling

| Product | Profile | Files | Bytes | Runtime scaling | Memory scaling | Accuracy scored |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `legacy-5x` | 1810 | 68402295 | 6.452174 | 1.104429 | false (performance only) |
| `windows-amd64` | `legacy-10x` | 3610 | 69695167 | 11.786957 | 1.413 | false (performance only) |

- `windows-amd64` `rnclab-filesystem` run 0: 0.23 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 1: 0.23 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 2: 0.228 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 3: 0.258 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 4: 0.276 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 0: 0.198 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 1: 0.202 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 2: 0.214 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 3: 0.212 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 4: 0.224 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 0: 1.862 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 1: 1.484 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 2: 1.331 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 0: 2.629 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 1: 2.862 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 2: 2.711 s, exit=1, telemetry=windows_process_times

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker product was built or invoked; no container cleanup was required.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | checkout-bff/README.md | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | fraud-scoring/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | gift-cards/README.md | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | inventory-sync/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ledger-api/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | loyalty-portal/README.md | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/infra/ssh/deploy_key | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | ops/inventory/provider-identifiers.json | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | ops/inventory/provider-identifiers.json | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | ops/inventory/provider-identifiers.json | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/k8s/base/deploy-ssh-secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-01.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-02.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-03.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-04.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | orbit-dashboard/README.md | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pricing-engine/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pulse-analytics/README.md | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pulse-analytics/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/k8s/workstation/kubeconfig-admin.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | returns-center/README.md | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | returns-center/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/k8s/base/tls-secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | store-locator/README.md | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | store-locator/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | summit-gear/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | supplier-hub/README.md | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.config/pki/client-01.p12 | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.config/pki/client-02.p12 | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.config/pki/client-03.p12 | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.config/pki/client-04.p12 | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-01.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-02.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-03.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/id_ed25519 | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-04.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | workstation/notes/secrets-rotation.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/id_rsa | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.github/workflows/deploy.yml | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/deploy/k8s/secret.yaml | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/docker-compose.yml | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/logs/deploy-2025-03-04.log | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/backups/ledger-full-2025-02.zip | password/database_password in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/backups/ledger-full-2025-02.zip | private_key/ed25519_private_key_pkcs8 in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/backups/orbit-dashboard-2025-03-01.zip | password/database_password in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/backups/orbit-dashboard-2025-03-01.zip | api_key/generic_api_key in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/backups/orbit-dashboard-2025-03-01.zip | private_key/tls_private_key_pkcs8 in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/builds/media-worker-2025.02.tar.bz2 | password/database_password in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/builds/platform-tools-2025.03.tar.xz | password/database_password in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/builds/platform-tools-2025.03.tar.xz | password/database_password in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/builds/platform-tools-2025.03.tar.xz | password/database_password in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | archive/logs/gateway-2025-03-01.log.gz | password/admin_password in archive |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | audit-log/.env | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | audit-log/.env | api_key/generic_api_key in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | audit-log/.env | password/smtp_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | audit-log/.github/workflows/build.yml | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | audit-log/docker-compose.yml | api_key/generic_api_key in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | audit-log/secrets/otp-provisioning.txt | otp_seed/totp_seed in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | audit-log/secrets/registry_password.txt | password/application_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/deploy/k8s/secret.yaml | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/logs/deploy-2025-03-04.log | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | bluebird-home/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/deploy/k8s/secret.yaml | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/logs/deploy-2025-03-04.log | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | cedar-garden/wp-config.php | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | checkout-bff/.env | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | checkout-bff/.env | password/application_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | checkout-bff/docker-compose.yml | password/application_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | checkout-bff/logs/app-2025-03-11.log | password/application_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | data/clients/.pgpass | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | data/clients/mongosh-history.txt | password/database_password in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | data/clients/redis.conf | password/application_password in file |

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- RNC Lab negative references are source-adjudicated within the frozen corpus; findings not present in the oracle remain pending review and precision/F1 are not certified.
- Filesystem (1,282) and Git-history (320) denominators are separate and are never combined.
- Private-key credit requires private-key material; public-key-only, SPKI-only, filename-only and encrypted-container-only evidence is not a true positive.
- The frozen lab is verified before and after scanning; a hash change blocks the run.
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
