# Scanner Experiment Report

> **Outcome: COMPLETE_WITH_LIMITATIONS**

## Identity

| Field | Value |
| --- | --- |
| Scanner | Gitleaks (`gitleaks`) |
| Scanner build version | v8.0.0-rnc.5f6ec56cfa6f |
| Source repository | https://github.com/RNC-Solutions-Group/gitleaks |
| Requested source commit | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Checkout HEAD | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Checkout HEAD verified | True |
| Adapter | `gitleaks` / Gitleaks |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261111T184816Z-f0da6499` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-11T18:49:09Z |

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
| `windows-amd64` | executable | PASS | v8.0.0-rnc.5f6ec56cfa6f | `c68865ea9cd5645e21c6bef2cfdc16a49b4d693b24028b5e4badfda593a913d1` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `git-history` | **COMPLETED_AND_SCORED** | PASS | False | unique matched=3; unique expected=3; occurrences matched=5; occurrences expected=5 |
| `gitleaks` | **COMPLETED_AND_SCORED** | PASS | False | scenarios passed=22; scenarios=23; assertions passed=141; assertions=141 |
| `leaky-repo` | **COMPLETED_AND_SCORED** | PASS | True | LEGACY COUNT COVERAGE %=12.57; rich line-truth recall %=12.57; expected=175; covered=22; files covered=13; rich matched=22; rich missed=153 |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=47; expected credentials=85; false positives=3; partial matches=1; duplicates=2; precision %=94.0; recall %=55.29 |
| `synthetic-filesystem` | **COMPLETED_AND_SCORED** | PASS | False | precision %=100.0; F1 %=100.0; expected=4; value-verified=4; line-only=0 |

### Product-level results

#### git-history

- controlled-history / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**

#### gitleaks

- functional-fixtures / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**
- Limitation: One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- Limitation: The legacy fixture lane retains hashed reports rather than raw scanner report bytes.

#### leaky-repo

- filesystem / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- history / `windows-amd64`: **COMPLETED_UNSCORED** (PASS)
- target `windows-amd64`: **PASS**
- Limitation: Legacy Leaky Repo score preserves the upstream line-count methodology.
- Limitation: RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Limitation: Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Limitation: Leaky Repo Git-history observations are not scored: no independently verified historical truth manifest exists, so history truth is BLOCKED and the filesystem 175-item denominator is not applied.

#### levain

- levain / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

#### synthetic-filesystem

- controlled-filesystem / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=4/4 |
| Synthetic history | unique=3/3, occurrences=5/5 |
| Levain | TP=47, FP=3, precision=94.0, recall=55.29, F1=69.63 |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** 22/175 (12.57%), rich line-truth matched=22/175 |
| Leaky Repo history | **UNSCORED** — truth=BLOCKED, execution=PASS, findings=26, unique fingerprints=16 |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history has no defensible denominator and is never scored against the 175 filesystem items.

## Performance (separate from detection)

Workload: 610 files / 5888020 bytes; 5 warm-up(s), 7 measured run(s).

| Product | Median s | Min/max s | CV | CPU s | Peak MiB | Stability |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | 0.699 | 0.482/0.912 | 0.214567 | 2.328125 | 67.9 | STABLE |

- `windows-amd64` run 0: 0.699 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 1: 0.482 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 2: 0.535 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 3: 0.618 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 4: 0.912 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 5: 0.855 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 6: 0.779 s, exit=1, telemetry=windows_process_times

## Cleanup

- Status: **PASS**
- Retained by request: False
- No run-owned containers found.
- No run-owned images found.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Classification | Path | Reason |
| --- | --- | --- | --- |
| `gitleaks` | NOT_APPLICABLE | testdata/repos/symlinks/ | Linux-native symlink staging is not available on Windows; the Docker lane preserves this scenario. |
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
| `leaky-repo` | MISSED_EXPECTATION | .npmrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .npmrc | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .ssh/id_rsa.pub | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
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
| `leaky-repo` | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | db/robomongo.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | deployment-config.json | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | deployment-config.json | no observed finding matched this expected item |

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- LEGACY COUNT COVERAGE for Leaky Repo is 12.57% (13/44 files); this is an upstream count metric, not verified detection recall.
- One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- The legacy fixture lane retains hashed reports rather than raw scanner report bytes.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo Git-history observations are not scored: no independently verified historical truth manifest exists, so history truth is BLOCKED and the filesystem 175-item denominator is not applied.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
