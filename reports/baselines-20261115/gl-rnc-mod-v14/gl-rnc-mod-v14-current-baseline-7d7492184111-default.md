# Scanner Experiment Report

> **Outcome: COMPLETE_WITH_LIMITATIONS**

## Identity

| Field | Value |
| --- | --- |
| Scanner | Gitleaks (`gitleaks`) |
| Registered build | `gl-rnc-mod-v14` |
| Scanner version | v8.25.0+dev.7d7492184111 |
| Artifact manifest | `run/manifest.toml` |
| Artifact manifest SHA-256 | `ef22463023d4aa2417a92e74074bb1a98eb85ce9cab6576878c3b047bf81a937` |
| Source commit (manifest metadata) | `7d74921841114be7677a423cf60620210e832bf7` |
| Source commit verification | NOT VERIFIED — operator-supplied metadata; no source checkout or build |
| Registered executable | `gl-rnc-mod-v14.exe` |
| Registered executable SHA-256 | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` |
| Registered Docker image | `—` |
| Registered Docker image ID | `—` |
| Rules/configuration file | `—` |
| Rules/configuration SHA-256 | `—` |
| Adapter | `gitleaks` / Gitleaks |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261116T000424Z-080efee1` |
| Harness version | 0.6.0 |
| Generated (UTC) | 2026-11-16T00:06:02Z |

The executed scanner identity is the operator-provided executable SHA-256 or Docker image ID above. The source commit is retained as operator metadata only; it is never acquired or compiled by this harness.

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

## Registered artifacts and products

| Product | Kind | Status | Build ID | Version | Artifact identity | Verified |
| --- | --- | --- | --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | `gl-rnc-mod-v14` | v8.25.0+dev.7d7492184111 | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | True |

Toolchain: Docker `29.9.3`, Git `git version 2.45.2.windows.1`, Python `Python 3.13.5`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=49; expected credentials=85; false positives=3; partial matches=1; duplicates=2; precision %=94.23; recall %=57.65 |
| `leaky-repo` | **COMPLETED_AND_SCORED** | PASS | True | LEGACY COUNT COVERAGE %=12.57; rich line-truth recall %=12.57; expected=175; covered=22; files covered=13; rich matched=22; rich missed=153 |
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
| Levain | TP=49, FP=3, precision=94.23, recall=57.65, F1=71.53 |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** 22/175 (12.57%), rich line-truth matched=22/175 |
| Leaky Repo history | **SCORED** — truth=APPROVED_SOURCE_ORACLE, execution=PASS, occurrences=21/65, unique=15/53, recall=32.31%, pending=0, unverified=0 |
| RNC Lab v3 filesystem | TP=369/640, unique=231/366, recall=57.66%, duplicates=82, near-misses=0 (0 targets), unverified=13, pending=8, FP alerts=4, precision=NOT CERTIFIED |
| RNC Lab v3 Git | supported; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 3 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads: `levain-filesystem` (163 files / 85581 bytes), `leaky-repo-filesystem` (610 files / 5888020 bytes), `leaky-repo-git` (None files / None bytes), `rnclab-filesystem` (371 files / 258574 bytes), `rnclab-git` (102 files / 41455 bytes)

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `levain-filesystem` | 0.246 | 0.245/0.715 | 0.550559 | 0.484375 | 49.84 | 163/163 | UNSTABLE |
| `windows-amd64` | `leaky-repo-filesystem` | 0.659 | 0.621/0.923 | 0.182896 | 2.0 | 58.53 | 610/610 | STABLE |
| `windows-amd64` | `leaky-repo-git` | 0.461 | 0.434/0.501 | 0.059148 | 0.359375 | 40.55 | None/None | STABLE |
| `windows-amd64` | `rnclab-filesystem` | 0.494 | 0.481/0.495 | 0.013014 | 1.0625 | 53.52 | 360/371 | STABLE |
| `windows-amd64` | `rnclab-git` | 0.488 | 0.474/0.511 | 0.031066 | 0.265625 | 39.66 | 102/102 | STABLE |
| `windows-amd64` | `rnclab-legacy-5x` | 2.556 | 2.312/2.591 | 0.049912 | 6.109375 | 74.36 | 1810/1810 | STABLE |
| `windows-amd64` | `rnclab-legacy-10x` | 4.294 | 4.243/4.47 | 0.022429 | 10.484375 | 96.81 | 3610/3610 | STABLE |

### RNC Lab load scaling

| Product | Profile | Files | Bytes | Runtime scaling | Memory scaling | Accuracy scored |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `legacy-5x` | 1810 | 68402295 | 5.174089 | 1.389359 | false (performance only) |
| `windows-amd64` | `legacy-10x` | 3610 | 69695167 | 8.692308 | 1.808787 | false (performance only) |

- `windows-amd64` `levain-filesystem` run 0: 0.246 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 1: 0.245 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 2: 0.715 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 0: 0.923 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 1: 0.621 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 2: 0.659 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 0: 0.501 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 1: 0.434 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-git` run 2: 0.461 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 0: 0.481 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 1: 0.494 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 2: 0.495 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 0: 0.488 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 1: 0.511 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-git` run 2: 0.474 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 0: 2.556 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 1: 2.591 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 2: 2.312 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 0: 4.294 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 1: 4.243 s, exit=1, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 2: 4.47 s, exit=1, telemetry=windows_process_times

## Scanner invocations

Every row records the actual executed argument vector (not a reconstructed command), in execution order. Credential-bearing argument values are redacted only when a sensitive flag such as `--password` or `--token` is present; the original argv digest is retained in the JSON report.

| # | Type | Suite | Workload | Platform | Build | Artifact identity | Exit | Duration (s) | Timeout/error | Command |
| ---: | --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |
| 1 | detection | `levain` | `levain-negative` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.31 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\levain\windows-amd64\negative --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\levain\windows-amd64\negative-report.json --no-banner --exit-code 1` |
| 2 | detection | `levain` | `levain-positive` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.212 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\levain\windows-amd64\positive --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\levain\windows-amd64\positive-report.json --no-banner --exit-code 1` |
| 3 | detection | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.214 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\leaky-repo\windows-amd64\scan --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\leaky-repo\windows-amd64\report.json --no-banner --exit-code 1` |
| 4 | detection | `leaky-repo` | `leaky-repo-history` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.45 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\leaky-history\windows-amd64\report.json --no-banner --exit-code 1` |
| 5 | detection | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.5 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\rnclab\windows-amd64\filesystem\report.json --no-banner --exit-code 1` |
| 6 | detection | `rnclab` | `rnclab-history` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.546 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\rnclab\windows-amd64\git\report.json --no-banner --exit-code 1` |
| 7 | warmup | `levain` | `levain-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.464 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\levain --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\levain-filesystem\warmup\0\report.json --no-banner --exit-code 1` |
| 8 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.246 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\levain --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\levain-filesystem\measured\0\report.json --no-banner --exit-code 1` |
| 9 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.245 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\levain --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\levain-filesystem\measured\1\report.json --no-banner --exit-code 1` |
| 10 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.715 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\levain --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\levain-filesystem\measured\2\report.json --no-banner --exit-code 1` |
| 11 | warmup | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 1.019 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\leaky-target --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\leaky-repo-filesystem\warmup\0\report.json --no-banner --exit-code 1` |
| 12 | measured | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.923 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\leaky-target --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\0\report.json --no-banner --exit-code 1` |
| 13 | measured | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.621 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\leaky-target --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\1\report.json --no-banner --exit-code 1` |
| 14 | measured | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.659 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\leaky-target --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\2\report.json --no-banner --exit-code 1` |
| 15 | warmup | `leaky-repo` | `leaky-repo-git` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.423 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\leaky-repo-git\warmup\0\report.json --no-banner --exit-code 1` |
| 16 | measured | `leaky-repo` | `leaky-repo-git` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.501 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\leaky-repo-git\measured\0\report.json --no-banner --exit-code 1` |
| 17 | measured | `leaky-repo` | `leaky-repo-git` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.434 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\leaky-repo-git\measured\1\report.json --no-banner --exit-code 1` |
| 18 | measured | `leaky-repo` | `leaky-repo-git` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.461 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\leaky-repo\2e951359cac53addbee56437da3ffb546e3dfe24\source --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\leaky-repo-git\measured\2\report.json --no-banner --exit-code 1` |
| 19 | warmup | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.573 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\rnclab-filesystem\warmup\0\report.json --no-banner --exit-code 1` |
| 20 | measured | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.481 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\rnclab-filesystem\measured\0\report.json --no-banner --exit-code 1` |
| 21 | measured | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.494 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\rnclab-filesystem\measured\1\report.json --no-banner --exit-code 1` |
| 22 | measured | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.495 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\rnclab-filesystem\measured\2\report.json --no-banner --exit-code 1` |
| 23 | warmup | `rnclab` | `rnclab-git` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.539 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\rnclab-git\warmup\0\report.json --no-banner --exit-code 1` |
| 24 | measured | `rnclab` | `rnclab-git` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.488 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\rnclab-git\measured\0\report.json --no-banner --exit-code 1` |
| 25 | measured | `rnclab` | `rnclab-git` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.511 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\rnclab-git\measured\1\report.json --no-banner --exit-code 1` |
| 26 | measured | `rnclab` | `rnclab-git` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 0.474 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe git C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\history --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\rnclab-git\measured\2\report.json --no-banner --exit-code 1` |
| 27 | warmup | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 3.195 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\load-measure\legacy-5x\warmup\0\report.json --no-banner --exit-code 1` |
| 28 | measured | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 2.556 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\0\report.json --no-banner --exit-code 1` |
| 29 | measured | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 2.591 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\1\report.json --no-banner --exit-code 1` |
| 30 | measured | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 2.312 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\2\report.json --no-banner --exit-code 1` |
| 31 | warmup | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 5.917 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\load-measure\legacy-10x\warmup\0\report.json --no-banner --exit-code 1` |
| 32 | measured | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 4.294 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\0\report.json --no-banner --exit-code 1` |
| 33 | measured | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 4.243 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\1\report.json --no-banner --exit-code 1` |
| 34 | measured | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `gl-rnc-mod-v14` | `7f1c9bd6f61c3ae414ab7df7688aeef04bd03312ac624127a13d39aa15238bfb` | 1 | 4.47 | none | `C:\Dev\rnc-benchmark-harness\run\gl-rnc-mod-v14.exe dir C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --report-format json --report-path C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000424Z-080efee1\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\2\report.json --no-banner --exit-code 1` |

Invocation types: `detection`, `warmup`, `measured`, and `verification` for artifact/ruleset validation. Detection and performance commands use the same registered executable or image.

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker artifact was executed; no container cleanup was required.
- Removed run-owned benchmark workspace, generated datasets, and evidence.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `levain` | filesystem | UNEXPECTED_FINDING | tailscale and wireguard status | negative corpus finding rule generic-api-key |
| `levain` | filesystem | UNEXPECTED_FINDING | tailscale and wireguard status | negative corpus finding rule generic-api-key |
| `levain` | filesystem | UNEXPECTED_FINDING | tailscale and wireguard status | negative corpus finding rule generic-api-key |
| `levain` | filesystem | MISSED_EXPECTATION | env-file | credential kind aws_access_key_id not detected |
| `levain` | filesystem | MISSED_EXPECTATION | curl-verbose-basic-auth | credential kind http_basic_auth not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hardhat-deploy-failure | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | wallet-restore-env | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | axios-error-dump | credential kind bearer_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | postgres-connection-failure | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | mongodb-uri | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind email not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | terraform-apply-output | credential kind aws_access_key_id not detected |
| `levain` | filesystem | MISSED_EXPECTATION | pip-index-url-with-password | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind xai_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind doppler_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind supabase_access_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind netlify_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind tailscale_auth_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind nuget_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind sentry_org_auth_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind discord_webhook_url not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind google_oauth_client_secret not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind resend_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | webhook-and-oauth-callback-dump | credential kind airtable_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-aws-secret-ends-in-plus | credential kind aws_access_key_id not detected |
| `levain` | filesystem | MISSED_EXPECTATION | edge-openai-project-key-ends-in-hyphen | credential kind openai_project_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-github-actions-raw-log | credential kind aws_access_key_id not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-github-actions-raw-log | credential kind aws_secret_access_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind bearer_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-pytest-npm-publish-failure | credential kind npm_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-terraform-plan-diff | credential kind sendgrid_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-terraform-plan-diff | credential kind generic_assignment not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-shapeless-password | credential kind shapeless_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-capability-url | credential kind capability_url_segment not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-token-split-across-lines | credential kind wrapped_token not detected |
| `levain` | filesystem | PARTIAL_MATCH | edge-openai-project-key-ends-in-hyphen | partial evidence for openai_project_key |
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

## Limitations

- Source commit is operator-supplied manifest metadata; the harness did not clone, check out, or compile scanner source.
- The registered executable SHA-256 and Docker image ID are the executed artifact identities; they are verified before every run.
- A verified artifact is not counted as tested unless an applicable suite executed it.
- Registered Docker images and run/ executables are never deleted or modified by the harness.
- LEGACY COUNT COVERAGE for Leaky Repo is 12.57% (13/44 files); this is an upstream count metric, not verified detection recall.
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
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
