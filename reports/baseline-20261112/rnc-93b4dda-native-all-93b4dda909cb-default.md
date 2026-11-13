# Scanner Experiment Report

> **Outcome: COMPLETE_WITH_LIMITATIONS**

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
| Run ID | `20261112T233709Z-a1e48c3d` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-12T23:39:17Z |

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
| `windows-amd64` | executable | PASS | 0.1.0 | `5c2642e226bac1d63aef19ece2a100e3cbc7325b0e857a3858fbef5a220214dc` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `leaky-repo` | **COMPLETED_AND_SCORED** | PASS | True | LEGACY COUNT COVERAGE %=15.43; rich line-truth recall %=14.29; expected=175; covered=27; files covered=18; rich matched=25; rich missed=150 |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=43; expected credentials=85; false positives=2; partial matches=0; duplicates=0; precision %=95.56; recall %=50.59 |

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
| Levain | TP=43, FP=2, precision=95.56, recall=50.59, F1=66.16 |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** 27/175 (15.43%), rich line-truth matched=25/175 |
| Leaky Repo history | **SCORED** — truth=APPROVED_SOURCE_ORACLE, execution=PASS, occurrences=21/65, unique=19/53, recall=32.31%, pending=0, unverified=0 |
| RNC Lab v3 filesystem | TP=None/None, unique=None/None, recall=None%, duplicates=None, FP alerts=None, pending=None, precision=NOT CERTIFIED |
| RNC Lab v3 Git | NOT_APPLICABLE; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 5 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads: `levain-filesystem` (163 files / 85581 bytes), `leaky-repo-filesystem` (610 files / 5888020 bytes), `leaky-repo-git` (None files / None bytes)

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `levain-filesystem` | 0.284 | 0.278/0.304 | 0.032282 | 0.28125 | 95.14 | 163/163 | STABLE |
| `windows-amd64` | `leaky-repo-filesystem` | 1.038 | 1.018/1.067 | 0.016047 | 1.03125 | 88.59 | 610/610 | STABLE |
| `windows-amd64` | `leaky-repo-git` | 7.127 | 7.01/7.453 | 0.021248 | 0.75 | 85.8 | None/None | STABLE |


- `windows-amd64` `levain-filesystem` run 0: 0.304 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 1: 0.293 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 2: 0.284 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 3: 0.278 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 4: 0.282 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 0: 1.018 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 1: 1.067 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 2: 1.05 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 3: 1.038 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 4: 1.031 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 0: 7.127 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 1: 7.078 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 2: 7.17 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 3: 7.01 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 4: 7.453 s, exit=10, telemetry=windows_process_times

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker product was built or invoked; no container cleanup was required.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `leaky-repo` | filesystem | UNVERIFIED_EVIDENCE | web/js/salesforce.js | correct location but extracted value is missing or conflicts with expected value; mandatory investigation |
| `leaky-repo` | filesystem | UNMATCHED_PENDING_REVIEW | .leaky-meta/secrets.csv | path absent from source oracle; mandatory investigation, not verified false positive |
| `leaky-repo` | filesystem | UNMATCHED_PENDING_REVIEW | .leaky-meta/secrets.csv | path absent from source oracle; mandatory investigation, not verified false positive |
| `leaky-repo` | filesystem | UNVERIFIED_EVIDENCE | db/mongoid.yml | correct location but extracted value is missing or conflicts with expected value; mandatory investigation |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .bash_profile | no observed finding matched this expected item |
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
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .docker/.dockercfg | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .docker/config.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .docker/config.json | no observed finding matched this expected item |
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
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .npmrc | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .remote-sync.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .ssh/id_rsa.pub | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | .vscode/sftp.json | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.credentials | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.s3cfg | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.s3cfg | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.tugboat | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.tugboat | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/.tugboat | no observed finding matched this expected item |
| `leaky-repo` | filesystem | MISSED_EXPECTATION | cloud/heroku.json | no observed finding matched this expected item |
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

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- LEGACY COUNT COVERAGE for Leaky Repo is 15.43% (18/44 files); this is an upstream count metric, not verified detection recall.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo history uses the owner-approved 65-occurrence / 53-group source oracle; the filesystem 175-item denominator is not applied.
- Reviewed negative references are not exhaustive; history precision and F1 are NOT CERTIFIED.
- Informative history references are excluded from primary recall.
- Every observed history finding is retained; unmatched and unverified findings require review.
- The rule bundle is read from the pinned source checkout and hashed after the source build.
- The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Git-history capability is verified from the pinned CLI source after build; unsupported source commits are reported rather than assumed.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
