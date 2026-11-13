# Scanner Experiment Report

> **Outcome: COMPLETE_WITH_LIMITATIONS**

## Identity

| Field | Value |
| --- | --- |
| Scanner | RNC Scanner (`rnc`) |
| Scanner build version | 0.1.0 |
| Source repository | https://github.com/RNC-Solutions-Group/rnc-security-audit |
| Requested source commit | `5391d8457ea091c45733920078a7f714ec61f678` |
| Checkout HEAD | `5391d8457ea091c45733920078a7f714ec61f678` |
| Checkout HEAD verified | True |
| Adapter | `rnc` / RNC Scanner |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261111T231913Z-280f5bd1` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-11T23:23:19Z |

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
| default isolation | {"config_argument": "--rules", "config_isolation": "empty .rncscanner.toml passed as --config to suppress target auto-discovery", "isolated_working_directory": true, "limitations": ["The rule bundle is read from the pinned source checkout and hashed after the source build.", "The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.", "RNC history mode is not supported at this source commit and is reported NOT_APPLICABLE."], "mode": "bundled-provider-rules", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "RNC_CONFIG", "RNC_SCANNER_CONFIG"], "rules_hash_recorded_after_build": true, "rules_path": "rules/rnc-providers-v1.json", "rules_sha256": null, "verifiable": true} |
- Limitation: The rule bundle is read from the pinned source checkout and hashed after the source build.
- Limitation: The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Limitation: RNC history mode is not supported at this source commit and is reported NOT_APPLICABLE.

## Builds and products

| Product | Kind | Build | Version | Artifact identity |
| --- | --- | --- | --- | --- |
| `docker-linux-amd64` | docker | PASS | 0.1.0 | `sha256:5c42e2424ed6bd3cef98338bece00d10cf31ebcbe5cff522f03867039a90ebe7` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `git-history` | **NOT_APPLICABLE** | NOT_APPLICABLE | False | — |
| `gitleaks` | **NOT_APPLICABLE** | NOT_APPLICABLE | False | — |
| `leaky-repo` | **COMPLETED_AND_SCORED** | PASS | True | LEGACY COUNT COVERAGE %=18.86; rich line-truth recall %=18.29; expected=175; covered=33; files covered=18; rich matched=32; rich missed=143 |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=32; expected credentials=85; false positives=0; partial matches=0; duplicates=0; precision %=100.0; recall %=37.65 |
| `synthetic-filesystem` | **COMPLETED_AND_SCORED** | PASS | False | precision %=100.0; F1 %=100.0; expected=4; value-verified=4; line-only=0 |

### Product-level results

#### git-history

- Reason: scanner adapter 'rnc' does not support suite 'git-history'

#### gitleaks

- Reason: scanner adapter 'rnc' does not support suite 'gitleaks'

#### leaky-repo

- filesystem / `docker-linux-amd64`: **COMPLETED_AND_SCORED** (PASS)
- history / `None`: **NOT_APPLICABLE** (NOT_APPLICABLE) — scanner adapter does not support Git-history mode
- target `docker-linux-amd64`: **PASS**
- Limitation: Legacy Leaky Repo score preserves the upstream line-count methodology.
- Limitation: RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Limitation: Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Limitation: Leaky Repo Git-history capability is NOT_APPLICABLE for this scanner.

#### levain

- levain / `docker-linux-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `docker-linux-amd64`: **PASS**
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

#### synthetic-filesystem

- controlled-filesystem / `docker-linux-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `docker-linux-amd64`: **PASS**

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=4/4 |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=32, FP=0, precision=100.0, recall=37.65, F1=54.7 |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** 33/175 (18.86%), rich line-truth matched=32/175 |
| Leaky Repo history | **UNSCORED** — truth=None, execution=None, findings=None, unique fingerprints=None |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history has no defensible denominator and is never scored against the 175 filesystem items.

## Performance (separate from detection)

Workload: 610 files / 5888020 bytes; 3 warm-up(s), 5 measured run(s).

| Product | Median s | Min/max s | CV | CPU s | Peak MiB | Stability |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `docker-linux-amd64` | 19.214 | 6.865/31.202 | 0.456049 | unavailable | unavailable | UNSTABLE |

- `docker-linux-amd64` run 0: 12.466 s, exit=10, telemetry=docker_stats
- `docker-linux-amd64` run 1: 19.809 s, exit=10, telemetry=docker_stats
- `docker-linux-amd64` run 2: 19.214 s, exit=10, telemetry=docker_stats
- `docker-linux-amd64` run 3: 6.865 s, exit=10, telemetry=docker_stats
- `docker-linux-amd64` run 4: 31.202 s, exit=10, telemetry=docker_stats

## Cleanup

- Status: **PASS**
- Retained by request: False
- No run-owned containers found.
- Removed 1 run-owned image(s).
- Removed image tag rnc-scanner-20261111t231913z-280f5bd1-5391d8457ea0-docker-linux-amd64.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Classification | Path | Reason |
| --- | --- | --- | --- |
| `leaky-repo` | UNEXPECTED_FINDING | db/mongoid.yml | finding location does not match an expected line |
| `leaky-repo` | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
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
| `leaky-repo` | MISSED_EXPECTATION | .bashrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/config.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .docker/config.json | no observed finding matched this expected item |
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
| `leaky-repo` | MISSED_EXPECTATION | .netrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .netrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .npmrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .npmrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .npmrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .ssh/id_rsa.pub | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.s3cfg | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.s3cfg | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.tugboat | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.tugboat | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/heroku.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | config | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | config | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | config | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | config | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/.pgpass | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dbeaver-data-sources.xml | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/mongoid.yml | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | deployment-config.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | deployment-config.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | deployment-config.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | etc/shadow | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | filezilla/filezilla.xml | no observed finding matched this expected item |

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- LEGACY COUNT COVERAGE for Leaky Repo is 18.86% (18/44 files); this is an upstream count metric, not verified detection recall.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo Git-history capability is NOT_APPLICABLE for this scanner.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- The rule bundle is read from the pinned source checkout and hashed after the source build.
- The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- RNC history mode is not supported at this source commit and is reported NOT_APPLICABLE.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
