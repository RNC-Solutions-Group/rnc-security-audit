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
| Run ID | `20261112T233238Z-a090ed66` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-12T23:35:19Z |

The source commit is the primary experiment identity. Build hashes and image IDs below are supporting provenance, not substitutes for it.

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

## Builds and products

| Product | Kind | Build | Version | Artifact identity |
| --- | --- | --- | --- | --- |
| `docker-linux-amd64` | docker | PASS | v8.0.0-rnc.5f6ec56cfa6f | `sha256:d2f2b38b3fb08965a198654db2a3aead3b62d6fa65ae6d06e34b696ca83a85bd` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `rnclab` | **COMPLETED_AND_SCORED** | PASS | True | — |

### Product-level results

#### rnclab

- target `docker-linux-amd64`: **PASS**
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
| RNC Lab v3 filesystem | TP=0/640, unique=0/366, recall=0.0%, duplicates=0, FP alerts=0, pending=480, precision=NOT CERTIFIED |
| RNC Lab v3 Git | supported; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 5 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads:

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `docker-linux-amd64` | `rnclab-filesystem` | 1.547 | 1.499/1.627 | 0.027299 | unavailable | unavailable | 360/360 | STABLE |
| `docker-linux-amd64` | `rnclab-git` | 4.604 | 2.198/5.921 | 0.297549 | unavailable | unavailable | 102/102 | UNSTABLE |
| `docker-linux-amd64` | `rnclab-legacy-5x` | 6.627 | 6.557/6.708 | 0.009305 | unavailable | unavailable | 1810/1810 | STABLE |
| `docker-linux-amd64` | `rnclab-legacy-10x` | 12.348 | 12.242/12.436 | 0.006426 | unavailable | unavailable | 3610/3610 | STABLE |

### RNC Lab load scaling

| Product | Profile | Files | Bytes | Runtime scaling | Memory scaling | Accuracy scored |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `docker-linux-amd64` | `legacy-5x` | 1810 | 68402294 | 4.283775 | None | false (performance only) |
| `docker-linux-amd64` | `legacy-10x` | 3610 | 69695167 | 7.9819 | None | false (performance only) |

- `docker-linux-amd64` `rnclab-filesystem` run 0: 1.547 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-filesystem` run 1: 1.547 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-filesystem` run 2: 1.583 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-filesystem` run 3: 1.499 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-filesystem` run 4: 1.627 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-git` run 0: 2.198 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-git` run 1: 4.098 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-git` run 2: 4.604 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-git` run 3: 5.731 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-git` run 4: 5.921 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-legacy-5x` run 0: 6.557 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-legacy-5x` run 1: 6.708 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-legacy-5x` run 2: 6.627 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-legacy-10x` run 0: 12.242 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-legacy-10x` run 1: 12.348 s, exit=1, telemetry=docker_stats
- `docker-linux-amd64` `rnclab-legacy-10x` run 2: 12.436 s, exit=1, telemetry=docker_stats

## Cleanup

- Status: **PASS**
- Retained by request: False
- No run-owned containers found.
- Removed 1 run-owned image(s).
- Removed image tag rnc-gitleaks-20261112t233238z-a090ed66-5f6ec56cfa6f-docker-linux-amd64.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/.github/workflows/deploy.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/docker-compose.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/wp-content/plugins/acme-crm/config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/acme-storefront/wp-content/plugins/acme-crm/config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/audit-log/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/audit-log/config/docker/config.json | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/audit-log/docker-compose.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/.github/workflows/deploy.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/.github/workflows/deploy.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/docker-compose.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/docker-compose.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/wp-content/plugins/acme-crm/config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/bluebird-home/wp-content/plugins/acme-crm/config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/.github/workflows/deploy.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/.github/workflows/deploy.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/docker-compose.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/docker-compose.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/deploy/k8s/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/wp-config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/wp-content/plugins/acme-crm/config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/cedar-garden/wp-content/plugins/acme-crm/config.php | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/.github/workflows/ci.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/.github/workflows/ci.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/README.md | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/deploy/k8s/secrets.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/src/config.ts | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/checkout-bff/test/fixtures/tokens.json | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/data/clients/.my.cnf | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/docs-portal/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/docs-portal/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/docs-portal/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/docs-portal/.github/workflows/build.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/docs-portal/config/docker/config.json | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/docs-portal/docker-compose.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/.gitlab-ci.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/.gitlab-ci.yml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/config/settings.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/deploy/secret.yaml | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/etl-warehouse/tests/conftest.py | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/feature-flags/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/feature-flags/.env | no exact source value identity at the finding path |
| `rnclab` | filesystem:docker-linux-amd64 | UNMATCHED_PENDING_REVIEW | /scan/feature-flags/docker-compose.yml | no exact source value identity at the finding path |

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
