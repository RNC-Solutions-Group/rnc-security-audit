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
| Run ID | `20261111T185221Z-28cdb842` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-11T18:52:50Z |

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
| `windows-amd64` | executable | PASS | v1.8.1 | `18d1fb705b8545616c5c7ad14d5aa1c75dce93978b136cbb517875253438c1ee` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `git-history` | **COMPLETED_AND_SCORED** | PASS | False | unique matched=3; unique expected=3; occurrences matched=5; occurrences expected=5 |
| `gitleaks` | **NOT_APPLICABLE** | NOT_APPLICABLE | False | — |
| `leaky-repo` | **COMPLETED_AND_SCORED** | PASS | True | LEGACY COUNT COVERAGE %=21.14; rich line-truth recall %=21.14; expected=175; covered=37; files covered=22; rich matched=37; rich missed=138 |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=48; expected credentials=85; false positives=5; partial matches=3; duplicates=2; precision %=90.57; recall %=56.47 |
| `synthetic-filesystem` | **COMPLETED_AND_SCORED** | PASS | False | precision %=100.0; F1 %=100.0; expected=4; value-verified=4; line-only=0 |

### Product-level results

#### git-history

- controlled-history / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**

#### gitleaks

- Reason: scanner adapter 'betterleaks' does not support suite 'gitleaks'

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
| Levain | TP=48, FP=5, precision=90.57, recall=56.47, F1=69.57 |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** 37/175 (21.14%), rich line-truth matched=37/175 |
| Leaky Repo history | **UNSCORED** — truth=BLOCKED, execution=PASS, findings=41, unique fingerprints=29 |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history has no defensible denominator and is never scored against the 175 filesystem items.

## Performance (separate from detection)

Workload: 610 files / 5888020 bytes; 5 warm-up(s), 7 measured run(s).

| Product | Median s | Min/max s | CV | CPU s | Peak MiB | Stability |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | 0.666 | 0.516/0.819 | 0.16034 | 1.53125 | 119.4 | STABLE |

- `windows-amd64` run 0: 0.666 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 1: 0.621 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 2: 0.696 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 3: 0.788 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 4: 0.516 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 5: 0.541 s, exit=1, telemetry=windows_process_times
- `windows-amd64` run 6: 0.819 s, exit=1, telemetry=windows_process_times

## Cleanup

- Status: **PASS**
- Retained by request: False
- No run-owned containers found.
- No run-owned images found.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Classification | Path | Reason |
| --- | --- | --- | --- |
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
| `leaky-repo` | MISSED_EXPECTATION | filezilla/filezilla.xml | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | filezilla/filezilla.xml | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | filezilla/recentservers.xml | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | filezilla/recentservers.xml | no observed finding matched this expected item |
| `leaky-repo` | MISSED_EXPECTATION | filezilla/recentservers.xml | no observed finding matched this expected item |

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- LEGACY COUNT COVERAGE for Leaky Repo is 21.14% (22/44 files); this is an upstream count metric, not verified detection recall.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo Git-history observations are not scored: no independently verified historical truth manifest exists, so history truth is BLOCKED and the filesystem 175-item denominator is not applied.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
