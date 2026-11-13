# Scanner Experiment Report

> **Outcome: COMPLETE**

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
| Run ID | `20261112T235532Z-e747d019` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-12T23:59:15Z |

The source commit is the primary experiment identity. Build hashes and image IDs below are supporting provenance, not substitutes for it.

## Configuration profile

| Setting | Value |
| --- | --- |
| cleared_environment | ['BETTERLEAKS_CONFIG', 'BETTERLEAKS_CONFIG_TOML', 'GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML', 'RNC_CONFIG', 'RNC_SCANNER_CONFIG'] |
| configuration_file_required | False |
| profile | DEFAULT |
| rules_sha256 | 87d7f9051ae41df34df29a0d5447ee8c9d71854ada46b789c9b7a00e4320a73a |
| scanner_config_argument | None |
| working_directory | empty run-owned scanner-cwd |
| default isolation | {"config_argument": "--rules", "config_isolation": "empty repository configuration passed as --config to suppress target auto-discovery", "history_mode": {"argument": "--history", "limitations": ["History scope is the pinned HEAD's reachable history, selected with --ref HEAD.", "Submodules, symlinks and other uninspected units are never treated as covered."], "read_only": true, "ref": "HEAD", "ref_argument": "--ref", "runtime_dependency": "git executable in the native host or container image", "scope": "selected-refs"}, "isolated_working_directory": true, "limitations": ["The rule bundle is read from the pinned source checkout and hashed after the source build.", "The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.", "Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed."], "mode": "bundled-provider-rules", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "RNC_CONFIG", "RNC_SCANNER_CONFIG"], "rules_hash_recorded_after_build": true, "rules_path": "rules/rnc-providers-v1.json", "rules_sha256": null, "verifiable": true} |
- Limitation: The rule bundle is read from the pinned source checkout and hashed after the source build.
- Limitation: The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Limitation: Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed.

## Builds and products

| Product | Kind | Build | Version | Artifact identity |
| --- | --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | 0.1.0 | `fcaf448887484176ce712a15479fe848a2f397ee09df9de1a18590f730107e3a` |

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
| RNC Lab v3 filesystem | TP=297/640, unique=194/366, recall=46.41%, duplicates=0, FP alerts=23, pending=66, precision=NOT CERTIFIED |
| RNC Lab v3 Git | supported; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 5 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads: `rnclab-filesystem` (371 files / 258574 bytes), `rnclab-git` (102 files / 41455 bytes)

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `rnclab-filesystem` | 0.523 | 0.488/0.534 | 0.030658 | 0.515625 | 89.38 | 360/371 | STABLE |
| `windows-amd64` | `rnclab-git` | 6.975 | 6.707/7.153 | 0.020763 | 0.8125 | 84.48 | 102/102 | STABLE |
| `windows-amd64` | `rnclab-legacy-5x` | 11.675 | 11.549/11.928 | 0.01345 | 11.59375 | 104.4 | 1809/1810 | STABLE |
| `windows-amd64` | `rnclab-legacy-10x` | 12.938 | 12.883/12.943 | 0.002104 | 12.796875 | 124.07 | 3609/3610 | STABLE |

### RNC Lab load scaling

| Product | Profile | Files | Bytes | Runtime scaling | Memory scaling | Accuracy scored |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `legacy-5x` | 1810 | 68402294 | 22.323136 | 1.168043 | false (performance only) |
| `windows-amd64` | `legacy-10x` | 3610 | 69695167 | 24.73805 | 1.388139 | false (performance only) |

- `windows-amd64` `rnclab-filesystem` run 0: 0.525 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 1: 0.523 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 2: 0.512 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 3: 0.488 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 4: 0.534 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 0: 6.707 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 1: 6.943 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 2: 6.975 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 3: 7.153 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 4: 7.011 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 0: 11.928 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 1: 11.549 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 2: 11.675 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 0: 12.938 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 1: 12.943 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 2: 12.883 s, exit=20, telemetry=windows_process_times

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker product was built or invoked; no container cleanup was required.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.git-credentials | no exact source value identity at the finding path |
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
| `rnclab` | filesystem:windows-amd64 | UNVERIFIED_EVIDENCE | ops/k8s/workstation/kubeconfig-admin.yaml | private-key material is not evidenced |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | warehouse-mobile/Properties/PublishProfiles/prod.pubxml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | store-locator/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pulse-analytics/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | supplier-hub/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | fleet-console/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | etl-warehouse/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | vendor-onboarding/Properties/PublishProfiles/prod.pubxml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | hr-portal/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | checkout-bff/src/config.ts | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-02.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | docs/integration-guide.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | docs/integration-guide.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/ci/platform-tools/Jenkinsfile | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-01.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | loyalty-portal/src/config.ts | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-03.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | loyalty-portal/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pulse-analytics/src/config.ts | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/ci/checkout-bff/Jenkinsfile | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | harbor-outfitters/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | pulse-analytics/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | store-locator/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | gift-cards/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | summit-gear/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNVERIFIED_EVIDENCE | ops/k8s/base/deploy-ssh-secret.yaml | private-key material is not evidenced |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | acme-storefront/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/k8s/base/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/k8s/base/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | returns-center/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | orbit-dashboard/src/config.ts | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | loyalty-portal/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ledger-api/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ledger-api/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | vendor-onboarding/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/ci/media-pipeline/Jenkinsfile | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pricing-engine/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | fleet-console/Properties/PublishProfiles/prod.pubxml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | returns-center/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | supplier-hub/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-03.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | lumen-lighting/.env | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | orbit-dashboard/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | fraud-scoring/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | etl-warehouse/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | etl-warehouse/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | gift-cards/src/config.ts | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | checkout-bff/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/id_ed25519 | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | search-indexer/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | search-indexer/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | pos-gateway/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ledger-api/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | orbit-dashboard/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | northwind-catalog/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pricing-engine/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pricing-engine/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/id_rsa | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | search-indexer/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | bluebird-home/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | cedar-garden/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | supplier-hub/src/config.ts | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-04.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | returns-center/src/config.ts | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | pos-gateway/Properties/PublishProfiles/prod.pubxml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | notification-worker/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | notification-worker/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNVERIFIED_EVIDENCE | ops/k8s/base/tls-secret.yaml | private-key material is not evidenced |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | store-locator/src/config.ts | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-02.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | ops/keys/service-signing-01.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | warehouse-mobile/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | gift-cards/README.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | workstation/.ssh/encrypted/key-04.enc.pem | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | inventory-sync/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | inventory-sync/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | inventory-sync/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | hr-portal/Properties/PublishProfiles/prod.pubxml | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | UNMATCHED_PENDING_REVIEW | notification-worker/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:windows-amd64 | FALSE_POSITIVE | workstation/notes/secrets-rotation.md | exact path and value identity |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |
| `rnclab` | filesystem:windows-amd64 | MISSED_EXPECTATION | acme-storefront/.env | password/wordpress_salt in file |

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
