# Scanner Experiment Report

> **Outcome: COMPLETE_WITH_LIMITATIONS**

## Identity

| Field | Value |
| --- | --- |
| Scanner | RNC Scanner (`rnc`) |
| Registered build | `rnc-cp3` |
| Scanner version | 0.1.0 |
| Artifact manifest | `run/manifest.toml` |
| Artifact manifest SHA-256 | `ef22463023d4aa2417a92e74074bb1a98eb85ce9cab6576878c3b047bf81a937` |
| Source commit (manifest metadata) | `5391d8457ea091c45733920078a7f714ec61f678` |
| Source commit verification | NOT VERIFIED — operator-supplied metadata; no source checkout or build |
| Registered executable | `rnc-cp3.exe` |
| Registered executable SHA-256 | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` |
| Registered Docker image | `rnc-scanner:cp3-amd64` |
| Registered Docker image ID | `sha256:469d9f1d33c1e30e534993d9540c81fe445ac6d55f99f21ff5b99548eb774d1d` |
| Rules/configuration file | `rules/rnc-cp3-providers-v1.json` |
| Rules/configuration SHA-256 | `0d21dfe17107e61292bc6eb2f8ff975021851cc27dcbf627e6eeef05a3bd0eb4` |
| Adapter | `rnc` / RNC Scanner |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261116T000603Z-2706e99f` |
| Harness version | 0.6.0 |
| Generated (UTC) | 2026-11-16T00:07:34Z |

The executed scanner identity is the operator-provided executable SHA-256 or Docker image ID above. The source commit is retained as operator metadata only; it is never acquired or compiled by this harness.

## Configuration profile

| Setting | Value |
| --- | --- |
| profile | DEFAULT |
| scanner_config_argument | None |
| working_directory | empty run-owned scanner-cwd |
| cleared_environment | ['BETTERLEAKS_CONFIG', 'BETTERLEAKS_CONFIG_TOML', 'GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML', 'RNC_CONFIG', 'RNC_SCANNER_CONFIG'] |
| configuration_file_required | False |
| rules_sha256 | 0d21dfe17107e61292bc6eb2f8ff975021851cc27dcbf627e6eeef05a3bd0eb4 |
| default isolation | {"config_argument": "--rules", "config_isolation": "empty repository configuration passed as --config to suppress target auto-discovery", "history_mode": {"argument": "--history", "capability_source": "operator-provided manifest capabilities", "limitations": ["History scope is the pinned HEAD's reachable history, selected with --ref HEAD.", "Submodules, symlinks and other uninspected units are never treated as covered."], "read_only": true, "ref": "HEAD", "ref_argument": "--ref", "runtime_dependency": "git executable in the native host or container image", "scope": "selected-refs"}, "isolated_working_directory": true, "limitations": ["The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.", "The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.", "Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed."], "mode": "operator-registered-provider-rules", "removed_environment": ["BETTERLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "RNC_CONFIG", "RNC_SCANNER_CONFIG"], "rules_hash_recorded_from_manifest": true, "rules_path": "rules/rnc-providers-v1.json", "rules_sha256": null, "rules_source": "operator-provided rules_file in run/manifest.toml", "verifiable": true} |
- Limitation: The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.
- Limitation: The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Limitation: Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed.

## Registered artifacts and products

| Product | Kind | Status | Build ID | Version | Artifact identity | Verified |
| --- | --- | --- | --- | --- | --- | --- |
| `windows-amd64` | executable | PASS | `rnc-cp3` | 0.1.0 | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | True |

Toolchain: Docker `29.9.3`, Git `git version 2.45.2.windows.1`, Python `Python 3.13.5`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `levain` | **COMPLETED_AND_SCORED** | PASS | True | true positives=32; expected credentials=85; false positives=0; partial matches=0; duplicates=0; precision %=100.0; recall %=37.65 |
| `leaky-repo` | **COMPLETED_AND_SCORED** | PASS | True | LEGACY COUNT COVERAGE %=18.86; rich line-truth recall %=18.29; expected=175; covered=33; files covered=18; rich matched=32; rich missed=143 |
| `rnclab` | **COMPLETED_AND_SCORED** | PASS | True | — |

### Product-level results

#### levain

- levain / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `windows-amd64`: **PASS**
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.

#### leaky-repo

- filesystem / `windows-amd64`: **COMPLETED_AND_SCORED** (PASS)
- history / `None`: **NOT_APPLICABLE** (NOT_APPLICABLE) — scanner adapter does not support Git-history mode
- target `windows-amd64`: **PASS**
- Limitation: Legacy Leaky Repo score preserves the upstream line-count methodology.
- Limitation: RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Limitation: Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Limitation: Leaky Repo Git-history capability is NOT_APPLICABLE for this scanner.

#### rnclab

- target `windows-amd64`: **PASS** — the pinned scanner source revision does not expose Git-history scanning
- Limitation: RNC Lab negative references are source-adjudicated within the frozen corpus; findings not present in the oracle remain pending review and precision/F1 are not certified.
- Limitation: Filesystem (1,282) and Git-history (320) denominators are separate and are never combined.
- Limitation: Private-key credit requires private-key material; public-key-only, SPKI-only, filename-only and encrypted-container-only evidence is not a true positive.
- Limitation: The frozen lab is verified before and after scanning; a hash change blocks the run.
- Limitation: Git-history mode is NOT_APPLICABLE for this pinned scanner source revision; no zero score or fabricated occurrences were emitted.

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=None/None |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=32, FP=0, precision=100.0, recall=37.65, F1=54.7 |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** 33/175 (18.86%), rich line-truth matched=32/175 |
| Leaky Repo history | **UNSCORED** — truth=NOT_APPLICABLE, execution=NOT_APPLICABLE, occurrences=None/None, unique=None/None, recall=None%, pending=None, unverified=None |
| RNC Lab v3 filesystem | TP=302/640, unique=183/366, recall=47.19%, duplicates=0, near-misses=0 (0 targets), unverified=27, pending=0, FP alerts=10, precision=NOT CERTIFIED |
| RNC Lab v3 Git | NOT_APPLICABLE; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Canonical plan: 1 warm-up(s), 3 measured run(s); load plan: 1 warm-up, 3 measured runs; environment=DEV, stress=none.

Workloads: `levain-filesystem` (163 files / 85581 bytes), `leaky-repo-filesystem` (610 files / 5888020 bytes), `rnclab-filesystem` (371 files / 258574 bytes)

| Product | Workload | Median s | Min/max s | CV | CPU s | Peak MiB | Files | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `levain-filesystem` | 0.178 | 0.174/0.191 | 0.040095 | 0.15625 | 27.07 | 163/163 | STABLE |
| `windows-amd64` | `leaky-repo-filesystem` | 0.517 | 0.51/0.574 | 0.053709 | 0.515625 | 28.82 | 610/610 | STABLE |
| `windows-amd64` | `rnclab-filesystem` | 0.398 | 0.395/0.409 | 0.015021 | 0.390625 | 28.34 | 360/371 | STABLE |
| `windows-amd64` | `rnclab-legacy-5x` | 3.96 | 3.795/4.963 | 0.121747 | 3.390625 | 44.14 | 1809/1810 | STABLE |
| `windows-amd64` | `rnclab-legacy-10x` | 4.796 | 4.789/4.878 | 0.008381 | 4.625 | 62.25 | 3609/3610 | STABLE |

### RNC Lab load scaling

| Product | Profile | Files | Bytes | Runtime scaling | Memory scaling | Accuracy scored |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `windows-amd64` | `legacy-5x` | 1810 | 68402295 | 9.949749 | 1.557761 | false (performance only) |
| `windows-amd64` | `legacy-10x` | 3610 | 69695166 | 12.050251 | 2.196719 | false (performance only) |

- `windows-amd64` `levain-filesystem` run 0: 0.178 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 1: 0.191 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `levain-filesystem` run 2: 0.174 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 0: 0.51 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 1: 0.517 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `leaky-repo-filesystem` run 2: 0.574 s, exit=10, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 0: 0.409 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 1: 0.395 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-filesystem` run 2: 0.398 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 0: 4.963 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 1: 3.96 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-5x` run 2: 3.795 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 0: 4.878 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 1: 4.796 s, exit=20, telemetry=windows_process_times
- `windows-amd64` `rnclab-legacy-10x` run 2: 4.789 s, exit=20, telemetry=windows_process_times

## Scanner invocations

Every row records the actual executed argument vector (not a reconstructed command), in execution order. Credential-bearing argument values are redacted only when a sensitive flag such as `--password` or `--token` is present; the original argv digest is retained in the JSON report.

| # | Type | Suite | Workload | Platform | Build | Artifact identity | Exit | Duration (s) | Timeout/error | Command |
| ---: | --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |
| 1 | verification | `—` | `ruleset-validation` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 0 | 0.211 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe rules validate --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --strategy auto` |
| 2 | detection | `levain` | `levain-negative` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.344 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\levain\windows-amd64\negative --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\levain\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\levain\windows-amd64\negative-report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 3 | detection | `levain` | `levain-positive` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.21 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\levain\windows-amd64\positive --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\levain\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\levain\windows-amd64\positive-report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 4 | detection | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.267 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\leaky-repo\windows-amd64\scan --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\leaky-repo\windows-amd64\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\leaky-repo\windows-amd64\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 5 | detection | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 0.43 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\rnclab\windows-amd64\filesystem\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\rnclab\windows-amd64\filesystem\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 6 | warmup | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.512 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\levain-filesystem\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\levain-filesystem\warmup\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 7 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.178 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\levain-filesystem\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\levain-filesystem\measured\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 8 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.191 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\levain-filesystem\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\levain-filesystem\measured\1\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 9 | measured | `levain` | `levain-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.174 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\levain --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\levain-filesystem\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\levain-filesystem\measured\2\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 10 | warmup | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.898 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\leaky-target --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\leaky-repo-filesystem\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\leaky-repo-filesystem\warmup\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 11 | measured | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.51 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\leaky-target --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 12 | measured | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.517 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\leaky-target --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\1\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 13 | measured | `leaky-repo` | `leaky-repo-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 10 | 0.574 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\leaky-target --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\leaky-repo-filesystem\measured\2\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 14 | warmup | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 0.374 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\rnclab-filesystem\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\rnclab-filesystem\warmup\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 15 | measured | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 0.409 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\rnclab-filesystem\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\rnclab-filesystem\measured\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 16 | measured | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 0.395 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\rnclab-filesystem\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\rnclab-filesystem\measured\1\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 17 | measured | `rnclab` | `rnclab-filesystem` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 0.398 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Dev\rnc-benchmark-harness\datasets\cache\rnc-synth-lab\corpus\filesystem --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\rnclab-filesystem\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\rnclab-filesystem\measured\2\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 18 | warmup | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 7.904 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-5x\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-5x\warmup\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 19 | measured | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 4.963 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 20 | measured | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 3.96 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\1\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 21 | measured | `rnclab` | `rnclab-legacy-5x` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 3.795 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\loads\legacy-5x\lab\stress-runs\factor-5 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-5x\measured\2\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 22 | warmup | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 10.418 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-10x\warmup\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-10x\warmup\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 23 | measured | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 4.878 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\0\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\0\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 24 | measured | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 4.796 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\1\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\1\report.json --format private --run-id 20261116T000603Z-2706e99f` |
| 25 | measured | `rnclab` | `rnclab-legacy-10x` | `windows-amd64` | `rnc-cp3` | `284c4c981401b8328648290f8d24b5e788669dbf1e5f995638427ae352b9a8c3` | 20 | 4.789 | none | `C:\Dev\rnc-benchmark-harness\run\rnc-cp3.exe scan --root C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\loads\legacy-10x\lab\stress-runs\factor-10 --rules C:\Dev\rnc-benchmark-harness\run\rules\rnc-cp3-providers-v1.json --config C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\2\rnc-isolation.toml --output C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261116T000603Z-2706e99f\evidence\performance\windows-amd64\load-measure\legacy-10x\measured\2\report.json --format private --run-id 20261116T000603Z-2706e99f` |

Invocation types: `detection`, `warmup`, `measured`, and `verification` for artifact/ruleset validation. Detection and performance commands use the same registered executable or image.

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker artifact was executed; no container cleanup was required.
- Removed run-owned benchmark workspace, generated datasets, and evidence.

## Exceptions

| Suite | Dimension | Classification | Path | Reason |
| --- | --- | --- | --- | --- |
| `levain` | filesystem | MISSED_EXPECTATION | curl-verbose-basic-auth | credential kind http_basic_auth not detected |
| `levain` | filesystem | MISSED_EXPECTATION | gpg-secret-key-export | credential kind pgp_private_key_block not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hardhat-deploy-failure | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | wallet-restore-env | credential kind wallet_seed_phrase not detected |
| `levain` | filesystem | MISSED_EXPECTATION | axios-error-dump | credential kind bearer_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | postgres-connection-failure | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | mongodb-uri | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | cloudsql-iam-dsn | credential kind email not detected |
| `levain` | filesystem | MISSED_EXPECTATION | slack-integration-error | credential kind slack_webhook_url not detected |
| `levain` | filesystem | MISSED_EXPECTATION | mailgun-delivery-log | credential kind mailgun_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | azure-storage-connection-string | credential kind azure_storage_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ssh-private-key-in-log | credential kind private_key_pem not detected |
| `levain` | filesystem | MISSED_EXPECTATION | gcp-service-account-json | credential kind private_key_escaped_json not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | payment-processing-log | credential kind payment_card not detected |
| `levain` | filesystem | MISSED_EXPECTATION | pip-index-url-with-password | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind groq_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind xai_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind perplexity_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ai-gateway-upstream-errors | credential kind fireworks_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | inference-worker-traceback | credential kind replicate_api_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | inference-worker-traceback | credential kind pinecone_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | inference-worker-traceback | credential kind elevenlabs_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind doppler_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind databricks_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind grafana_service_account_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind planetscale_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind supabase_access_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind netlify_pat not detected |
| `levain` | filesystem | MISSED_EXPECTATION | platform-cli-auth-failures | credential kind tailscale_auth_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind rubygems_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind nuget_api_key not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind sonarqube_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind sentry_org_auth_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ci-publish-step-output | credential kind newrelic_user_key not detected |
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
| `levain` | filesystem | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind url_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | ansi-docker-compose-logs | credential kind bearer_token not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-shapeless-password | credential kind shapeless_password not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-capability-url | credential kind capability_url_segment not detected |
| `levain` | filesystem | MISSED_EXPECTATION | hard-token-split-across-lines | credential kind wrapped_token not detected |
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

## Limitations

- Source commit is operator-supplied manifest metadata; the harness did not clone, check out, or compile scanner source.
- The registered executable SHA-256 and Docker image ID are the executed artifact identities; they are verified before every run.
- A verified artifact is not counted as tested unless an applicable suite executed it.
- Registered Docker images and run/ executables are never deleted or modified by the harness.
- LEGACY COUNT COVERAGE for Leaky Repo is 18.86% (18/44 files); this is an upstream count metric, not verified detection recall.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo Git-history capability is NOT_APPLICABLE for this scanner.
- RNC Lab negative references are source-adjudicated within the frozen corpus; findings not present in the oracle remain pending review and precision/F1 are not certified.
- Filesystem (1,282) and Git-history (320) denominators are separate and are never combined.
- Private-key credit requires private-key material; public-key-only, SPKI-only, filename-only and encrypted-container-only evidence is not a true positive.
- The frozen lab is verified before and after scanning; a hash change blocks the run.
- Git-history mode is NOT_APPLICABLE for this pinned scanner source revision; no zero score or fabricated occurrences were emitted.
- The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.
- The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
