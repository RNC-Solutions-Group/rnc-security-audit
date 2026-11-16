# Scanner Experiment Report

> **Outcome: COMPLETE_WITH_LIMITATIONS**

## Identity

| Field | Value |
| --- | --- |
| Scanner | RNC Scanner (`rnc`) |
| Registered build | `rnc-cp4a` |
| Scanner version | 0.1.0 |
| Artifact manifest | `run/manifest.toml` |
| Artifact manifest SHA-256 | `ef22463023d4aa2417a92e74074bb1a98eb85ce9cab6576878c3b047bf81a937` |
| Source commit (manifest metadata) | `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` |
| Source commit verification | NOT VERIFIED — operator-supplied metadata; no source checkout or build |
| Registered executable | `rnc-cp4a.exe` |
| Registered executable SHA-256 | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` |
| Registered Docker image | `rnc-scanner:cp4a-amd64` |
| Registered Docker image ID | `sha256:026f7a171ea0a45ac6a9845a6f4d59fc15f8797155ba77e6c626435d57cf410d` |
| Rules/configuration file | `rules/rnc-cp4a-providers-v1.json` |
| Rules/configuration SHA-256 | `87d7f9051ae41df34df29a0d5447ee8c9d71854ada46b789c9b7a00e4320a73a` |
| Adapter | `rnc` / RNC Scanner |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261116T000735Z-15e055f2` |
| Harness version | 0.6.0 |
| Generated (UTC) | 2026-11-16T00:13:14Z |

The executed scanner identity is the operator-provided executable SHA-256 or Docker image ID above. The source commit is retained as operator metadata only; it is never acquired or compiled by this harness.

## Configuration profile

| Setting | Value |
| --- | --- |
| profile | DEFAULT |
| scanner_config_argument | None |
| working_directory | empty run-owned scanner-cwd |
| cleared_environment | ['BETTERLEAKS_CONFIG', 'BETTERLEAKS_CONFIG_TOML', 'GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML', 'RNC_CONFIG', 'RNC_SCANNER_CONFIG'] |
| configuration_file_required | False |
| rules_sha256 | 87d7f9051ae41df34df29a0d5447ee8c9d71854ada46b789c9b7a00e4320a73a |
| default isolation | {"config_argument": "--rules", "config_isolation": "empty repository configuration passed as --config to suppress target auto-discovery", "history_mode": {"argument": "--history", "capability_source": "operator-provided manifest capabilities", "limitations": ["History scope is the pinned HEAD's reachable history, selected with --ref HEAD.", "Submodules, symlinks and other uninspected units are never treated as covered."], "read_only": true, "ref": "HEAD", "ref_argument": "--ref", "runtime_dependency": "git executable in the native host or container image", "scope": "selected-refs"}, "isolated_working_directory": true, "limitations": ["The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.", "The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.", "Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed."], "mode": "operator-registered-provider-rules", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "RNC_CONFIG", "RNC_SCANNER_CONFIG"], "rules_hash_recorded_from_manifest": true, "rules_path": "rules/rnc-providers-v1.json", "rules_sha256": null, "rules_source": "operator-provided rules_file in run/manifest.toml", "verifiable": true} |
- Limitation: The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.
- Limitation: The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Limitation: Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed.

## Registered artifacts and products

| Product | Kind | Status | Build ID | Version | Artifact identity | Verified |
| --- | --- | --- | --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | `rnc-cp4a` | 0.1.0 | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | True |

Toolchain: Docker `29.9.3`, Git `git version 2.45.2.windows.1`, Python `Python 3.13.5`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=43; expected credentials=85; false positives=2; partial matches=0; duplicates=0; precision %=95.56; recall %=50.59 |
| `leaky-repo` | **COMPLETED_AND_SCORED** | PASS | True | LEGACY COUNT COVERAGE %=15.43; rich line-truth recall %=14.29; expected=175; covered=27; files covered=18; rich matched=25; rich missed=150 |
| `rnclab` | **COMPLETED_AND_SCORED** | PASS | True | — |

### Product-level results

#### levain

- levain / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

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
| Levain | TP=43, FP=2, precision=95.56, recall=50.59, F1=66.16 |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** 27/175 (15.43%), rich line-truth matched=25/175 |
| Leaky Repo history | **SCORED** — truth=APPROVED_SOURCE_ORACLE, execution=PASS, occurrences=21/65, unique=19/53, recall=32.31%, pending=0, unverified=0 |
| RNC Lab v3 filesystem | TP=347/640, unique=208/366, recall=54.22%, duplicates=0, near-misses=0 (0 targets), unverified=21, pending=11, FP alerts=10, precision=NOT CERTIFIED |
| RNC Lab v3 Git | supported; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 3 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads: `levain-filesystem` (163 files / 85581 bytes), `leaky-repo-filesystem` (610 files / 5888020 bytes), `leaky-repo-git` (None files / None bytes), `rnclab-filesystem` (371 files / 258574 bytes), `rnclab-git` (102 files / 41455 bytes)

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `levain-filesystem` | 0.365 | 0.348/0.39 | 0.046917 | 0.328125 | 95.14 | 163/163 | STABLE |
| `windows-amd64` | `leaky-repo-filesystem` | 1.444 | 1.34/1.559 | 0.061785 | 1.359375 | 88.63 | 610/610 | STABLE |
| `windows-amd64` | `leaky-repo-git` | 12.716 | 10.487/15.924 | 0.171105 | 1.3125 | 85.72 | None/None | STABLE |
| `windows-amd64` | `rnclab-filesystem` | 0.752 | 0.725/0.818 | 0.051064 | 0.75 | 89.28 | 360/371 | STABLE |
| `windows-amd64` | `rnclab-git` | 9.76 | 9.43/9.838 | 0.018276 | 1.140625 | 84.14 | 102/102 | STABLE |
| `windows-amd64` | `rnclab-legacy-5x` | 17.018 | 15.876/19.224 | 0.07999 | 16.046875 | 104.62 | 1809/1810 | STABLE |
| `windows-amd64` | `rnclab-legacy-10x` | 16.546 | 16.528/16.711 | 0.004963 | 15.90625 | 124.11 | 3609/3610 | STABLE |

### RNC Lab load scaling

| Product | Profile | Files | Bytes | Runtime scaling | Memory scaling | Accuracy scored |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `legacy-5x` | 1810 | 68402295 | 22.630319 | 1.171771 | false (performance only) |
| `windows-amd64` | `legacy-10x` | 3610 | 69695167 | 22.00266 | 1.390051 | false (performance only) |

- `windows-amd64` `levain-filesystem` run 0: 0.365 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 1: 0.348 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 2: 0.39 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 0: 1.559 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 1: 1.444 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 2: 1.34 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 0: 15.924 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 1: 12.716 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 2: 10.487 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 0: 0.818 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 1: 0.752 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 2: 0.725 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 0: 9.43 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 1: 9.838 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 2: 9.76 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 0: 19.224 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 1: 15.876 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 2: 17.018 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 0: 16.528 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 1: 16.546 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 2: 16.711 s, exit=20, telemetry=windows_process_times

## Scanner invocations

Every row records the actual executed argument vector (not a reconstructed command), in execution order. Credential-bearing argument values are redacted only when a sensitive flag such as `--password` or `--token` is present; the original argv digest is retained in the JSON report.

| # | Type | Suite | Workload | Platform | Build | Artifact identity | Exit | Duration (s) | Timeout/error | Command |
| ---: | --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |
| 1 | verification | `—` | `ruleset-validation` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 0 | 0.419 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe rules validate --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --strategy auto` |
| 2 | detection | `levain` | `levain-negative` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 0.74 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\levain\windows-amd64\negative --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\levain\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\levain\windows-amd64\negative-report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 3 | detection | `levain` | `levain-positive` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 0.509 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\levain\windows-amd64\positive --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\levain\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\levain\windows-amd64\positive-report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 4 | detection | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 0.643 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\leaky-repo\windows-amd64\scan --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\leaky-repo\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\leaky-repo\windows-amd64\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 5 | detection | `leaky-repo` | `leaky-repo-history` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 11.001 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\leaky-history\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\leaky-history\windows-amd64\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 6 | detection | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 0.65 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\rnclab\windows-amd64\filesystem\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\rnclab\windows-amd64\filesystem\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 7 | detection | `rnclab` | `rnclab-history` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 8.391 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\rnclab\windows-amd64\git\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\rnclab\windows-amd64\git\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 8 | warmup | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 0.517 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\levain-filesystem\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\levain-filesystem\warmup\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 9 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 0.365 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\levain-filesystem\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\levain-filesystem\measured\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 10 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 0.348 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\levain-filesystem\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\levain-filesystem\measured\1\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 11 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 0.39 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\levain-filesystem\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\levain-filesystem\measured\2\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 12 | warmup | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 1.874 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\leaky-target --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-filesystem\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-filesystem\warmup\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 13 | measured | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 1.559 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\leaky-target --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 14 | measured | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 1.444 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\leaky-target --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\1\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 15 | measured | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 1.34 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\leaky-target --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\2\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 16 | warmup | `leaky-repo` | `leaky-repo-git` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 11.792 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-git\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-git\warmup\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 17 | measured | `leaky-repo` | `leaky-repo-git` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 15.924 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-git\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-git\measured\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 18 | measured | `leaky-repo` | `leaky-repo-git` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 12.716 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-git\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-git\measured\1\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 19 | measured | `leaky-repo` | `leaky-repo-git` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 10.487 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-git\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\leaky-repo-git\measured\2\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 20 | warmup | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 0.75 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-filesystem\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-filesystem\warmup\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 21 | measured | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 0.818 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-filesystem\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-filesystem\measured\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 22 | measured | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 0.752 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-filesystem\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-filesystem\measured\1\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 23 | measured | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 0.725 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-filesystem\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-filesystem\measured\2\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 24 | warmup | `rnclab` | `rnclab-git` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 9.438 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-git\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-git\warmup\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 25 | measured | `rnclab` | `rnclab-git` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 9.43 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-git\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-git\measured\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 26 | measured | `rnclab` | `rnclab-git` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 9.838 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-git\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-git\measured\1\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 27 | measured | `rnclab` | `rnclab-git` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 10 | 9.76 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --history --ref HEAD --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-git\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\rnclab-git\measured\2\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 28 | warmup | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 24.106 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-5x\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-5x\warmup\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 29 | measured | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 19.224 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 30 | measured | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 15.876 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\1\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 31 | measured | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 17.018 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\2\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 32 | warmup | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 22.603 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-10x\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-10x\warmup\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 33 | measured | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 16.528 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\0\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 34 | measured | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 16.546 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\1\report.json --format private --run-id 20261116T000735Z-15e055f2` |
| 35 | measured | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `rnc-cp4a` | `6ec71c0b815b8d500d9e5a77e299a01d7a5e8728e811c0ab89b4a8770758517b` | 20 | 16.711 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp4a.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp4a-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000735Z-15e055f2\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\2\report.json --format private --run-id 20261116T000735Z-15e055f2` |

Invocation types: `detection`, `warmup`, `measured`, and `verification` for artifact/ruleset validation. Detection and performance commands use the same registered executable or image.

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker artifact was executed; no container cleanup was required.
- Removed run-owned benchmark workspace, generated datasets, and evidence.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `levain` | filesystem | UNEXPECTED_FINDING | docker compose masked env | negative corpus finding rule generic-secret-assignment |
| `levain` | filesystem | UNEXPECTED_FINDING | signed bot traffic access log | negative corpus finding rule credential-url-userinfo |
| `levain` | filesystem | MISSED_EXPECTATION | gpg-secret-key-export | credential kind pgp_private_key_block not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hardhat-deploy-failure | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | wallet-restore-env | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind email not detected |
| `levain` | filesystem | MISSED_EXPECTATION | twilio-sdk-error | credential kind twilio_api_key_sid not detected |
| `levain` | filesystem | MISSED_EXPECTATION | mailgun-delivery-log | credential kind mailgun_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ssh-private-key-in-log | credential kind private_key_pem not detected |
| `levain` | filesystem | MISSED_EXPECTATION | gcp-service-account-json | credential kind private_key_escaped_json not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | pip-index-url-with-password | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind xai_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind fireworks_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | inference-worker-traceback | credential kind elevenlabs_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind doppler_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind databricks_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind grafana_service_account_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind planetscale_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind supabase_access_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind netlify_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind rubygems_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind nuget_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind sonarqube_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind sentry_org_auth_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind dynatrace_api_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind terraform_cloud_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind discord_webhook_url not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind google_oauth_client_secret not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind resend_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind postman_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind airtable_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-openai-project-key-ends-in-hyphen | credential kind openai_project_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-confluent-secret-ends-in-slash | credential kind confluent_cloud_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-confluent-secret-ends-in-slash | credential kind confluent_cloud_secret not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-vault-token-with-letter-prefixed-body | credential kind vault_service_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | custom-vendor-prefix-convention | credential kind custom_internal_format not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind bearer_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-terraform-plan-diff | credential kind generic_assignment not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-shapeless-password | credential kind shapeless_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-capability-url | credential kind capability_url_segment not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-token-split-across-lines | credential kind wrapped_token not detected |
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

## Limitations

- Source commit is operator-supplied manifest metadata; the harness did not clone, check out, or compile scanner source.
- The registered executable SHA-256 and Docker image ID are the executed artifact identities; they are verified before every run.
- A verified artifact is not counted as tested unless an applicable suite executed it.
- Registered Docker images and run/ executables are never deleted or modified by the harness.
- LEGACY COUNT COVERAGE for Leaky Repo is 15.43% (18/44 files); this is an upstream count metric, not verified detection recall.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo history uses the owner-approved 65-occurrence / 53-group source oracle; the filesystem 175-item denominator is not applied.
- Reviewed negative references are not exhaustive; history precision and F1 are NOT CERTIFIED.
- Informative history references are excluded from primary recall.
- Every observed history finding is retained; unmatched and unverified findings require review.
- RNC Lab negative references are source-adjudicated within the frozen corpus; findings not present in the oracle remain pending review and precision/F1 are not certified.
- Filesystem (1,282) and Git-history (320) denominators are separate and are never combined.
- Private-key credit requires private-key material; public-key-only, SPKI-only, filename-only and encrypted-container-only evidence is not a true positive.
- The frozen lab is verified before and after scanning; a hash change blocks the run.
- The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.
- The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
