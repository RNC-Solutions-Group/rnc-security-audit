# Scanner Experiment Report

> **Outcome: INCOMPLETE**

## Identity

| Field | Value |
| --- | --- |
| Scanner | Gitleaks (`gitleaks`) |
| Registered build | `gitleaks-bad` |
| Scanner version | test |
| Artifact manifest | `run/manifest-blocked.toml` |
| Artifact manifest SHA-256 | `b38ec3ed1c1d7267dc3483c19d4139190685b4c868b097de1aba9124507fa6e6` |
| Source commit (manifest metadata) | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Source commit verification | NOT VERIFIED — operator-supplied metadata; no source checkout or build |
| Registered executable | `gitleaks.exe` |
| Registered executable SHA-256 | `0000000000000000000000000000000000000000000000000000000000000000` |
| Registered Docker image | `—` |
| Registered Docker image ID | `—` |
| Rules/configuration file | `—` |
| Rules/configuration SHA-256 | `—` |
| Adapter | `gitleaks` / Gitleaks |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261113T171853Z-7bcf1aa4` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-13T17:18:58Z |

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
| `windows-amd64` | executable | BLOCKED | `gitleaks-bad` | test | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` | False |

- Artifact `windows-amd64` problem: executable SHA-256 mismatch for gitleaks.exe: manifest=0000000000000000000000000000000000000000000000000000000000000000 actual=e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2

Toolchain: Docker `29.9.3`, Git `git version 2.45.2.windows.1`, Python `Python 3.13.5`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `levain` | **BLOCKED** | BLOCKED | True | — |
| `leaky-repo` | **BLOCKED** | BLOCKED | True | history score status=NOT_READY |

### Product-level results

#### levain

- target `windows-amd64`: **BLOCKED** — target build failed
- Limitation: Levain is a synthetic corpus; counts are not real-world prevalence.
- Limitation: The Levain negative-corpus control was not detected, so precision, false-positive counts and F1 are UNSCORED; positive-corpus recall remains observable.

#### leaky-repo

- history / `windows-amd64`: **BLOCKED** (BLOCKED)
- target `windows-amd64`: **BLOCKED** — target build failed
- Limitation: Legacy Leaky Repo score preserves the upstream line-count methodology.
- Limitation: RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Limitation: Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Limitation: Leaky Repo Git-history execution completed but could not be scored: target build failed.

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=None/None |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=None, FP=None, precision=None, recall=None, F1=None |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** None/None (None%), rich line-truth matched=None/None |
| Leaky Repo history | **UNSCORED** — truth=BLOCKED, execution=BLOCKED, occurrences=None/None, unique=None/None, recall=None%, pending=None, unverified=None |
| RNC Lab v3 filesystem | TP=None/None, unique=None/None, recall=None%, duplicates=None, FP alerts=None, pending=None, precision=NOT CERTIFIED |
| RNC Lab v3 Git | NOT_APPLICABLE; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Not available: not reached

## Cleanup

- Status: **PASS**
- Retained by request: False
- No Docker artifact was executed; no container cleanup was required.
- Removed run-owned benchmark workspace, generated datasets, and evidence.

## Limitations

- Source commit is operator-supplied manifest metadata; the harness did not clone, check out, or compile scanner source.
- The registered executable SHA-256 and Docker image ID are the executed artifact identities; they are verified before every run.
- A verified artifact is not counted as tested unless an applicable suite executed it.
- Registered Docker images and run/ executables are never deleted or modified by the harness.
- Suite levain reports incomplete coverage.
- Levain is a synthetic corpus; counts are not real-world prevalence.
- The Levain negative-corpus control was not detected, so precision, false-positive counts and F1 are UNSCORED; positive-corpus recall remains observable.
- Legacy Leaky Repo score preserves the upstream line-count methodology.
- RNC rich score uses the line-level truth manifest and does not claim precision or F1 without a negative oracle.
- Upstream risk/informative aggregate categories conflict with source-line review for 6 rows; categories were not reassigned to force the upstream totals.
- Leaky Repo Git-history execution completed but could not be scored: target build failed.
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.
- Performance section status is BLOCKED; see its reason and limitations.
- Performance measurements used the DEV environment profile; the host was contended/uncontrolled and these timings are not release evidence.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
