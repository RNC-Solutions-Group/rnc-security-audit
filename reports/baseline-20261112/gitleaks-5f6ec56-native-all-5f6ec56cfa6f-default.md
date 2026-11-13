# Scanner Experiment Report

> **Outcome: COMPLETE_WITH_LIMITATIONS**

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
| Run ID | `20261112T232931Z-10c3437d` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-12T23:29:58Z |

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
| `leaky-repo` | **COMPLETED_AND_SCORED** | PASS | True | LEGACY COUNT COVERAGE %=12.57; rich line-truth recall %=12.57; expected=175; covered=22; files covered=13; rich matched=22; rich missed=153 |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=47; expected credentials=85; false positives=3; partial matches=1; duplicates=2; precision %=94.0; recall %=55.29 |

### Product-level results

#### leaky-repo

- filesystem / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- history / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**
- Limitation: Legacy Leaky Repo score preserves the upstream line-count methodology.
- Limitation: RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Limitation: Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Limitation: Leaky Repo history uses the owner-approved 65-occurrence / 53-group source oracle; the filesystem 175-item denominator is not applied.
- Limitation: Reviewed negative references are not exhaustive; history precision and F1 are NOT CERTIFIED.
- Limitation: Informative history references are excluded from primary recall.
- Limitation: Every observed history finding is retained; unmatched and unverified findings require review.

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
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** 22/175 (12.57%), rich line-truth matched=22/175 |
| Leaky Repo history | **SCORED** — truth=APPROVED_SOURCE_ORACLE, execution=PASS, occurrences=21/65, unique=15/53, recall=32.31%, pending=0, unverified=0 |
| RNC Lab v3 filesystem | TP=None/None, unique=None/None, recall=None%, duplicates=None, FP alerts=None, pending=None, precision=NOT CERTIFIED |
| RNC Lab v3 Git | NOT_APPLICABLE; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 5 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads: `levain-filesystem` (163 files / 85581 bytes), `leaky-repo-filesystem` (610 files / 5888020 bytes), `leaky-repo-git` (None files / None bytes)

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `levain-filesystem` | 0.102 | 0.098/0.114 | 0.057234 | 0.28125 | 49.24 | 163/163 | STABLE |
| `windows-amd64` | `leaky-repo-filesystem` | 0.337 | 0.314/0.352 | 0.04677 | 1.453125 | 54.84 | 610/610 | STABLE |
| `windows-amd64` | `leaky-repo-git` | 0.155 | 0.149/0.173 | 0.054046 | 0.171875 | 38.87 | None/None | STABLE |


- `windows-amd64` `levain-filesystem` run 0: 0.114 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 1: 0.109 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 2: 0.1 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 3: 0.102 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 4: 0.098 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 0: 0.314 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 1: 0.348 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 2: 0.352 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 3: 0.337 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 4: 0.317 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 0: 0.151 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 1: 0.149 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 2: 0.157 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 3: 0.155 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 4: 0.173 s, exit=1, telemetry=windows_process_times

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker product was built or invoked; no container cleanup was required.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bashrc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bashrc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bashrc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bashrc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .docker/config.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .docker/config.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .esmtprc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .esmtprc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .esmtprc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .ftpconfig | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .git-credentials | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .idea/WebServers.xml | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .idea/WebServers.xml | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .mozilla/firefox/logins.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .netrc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .netrc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .npmrc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .npmrc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .ssh/id_rsa.pub | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.s3cfg | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.tugboat | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.tugboat | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/heroku.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | config | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | config | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | config | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | config | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/.pgpass | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dbeaver-data-sources.xml | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/dump.sql | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/mongoid.yml | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | deployment-config.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | deployment-config.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | deployment-config.json | no observed finding matched this expected item |

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- LEGACY COUNT COVERAGE for Leaky Repo is 12.57% (13/44 files); this is an upstream count metric, not verified detection recall.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo history uses the owner-approved 65-occurrence / 53-group source oracle; the filesystem 175-item denominator is not applied.
- Reviewed negative references are not exhaustive; history precision and F1 are NOT CERTIFIED.
- Informative history references are excluded from primary recall.
- Every observed history finding is retained; unmatched and unverified findings require review.
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
