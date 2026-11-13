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
| Run ID | `20261112T233543Z-db80aaa0` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-12T23:37:05Z |

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
| `docker-linux-amd64` | docker | PASS | v8.0.0-rnc.5f6ec56cfa6f | `sha256:33fc2eabcedd903fa843798d1d1dcbb1cc6a8f31cd6df41998c4d31bfe2104fe` |

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `gitleaks` | **COMPLETED_AND_SCORED** | PASS | False | scenarios passed=23; scenarios=23; assertions passed=147; assertions=147 |

### Product-level results

#### gitleaks

- functional-fixtures / `docker-linux-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `docker-linux-amd64`: **PASS**
- Limitation: One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- Limitation: The legacy fixture lane retains hashed reports rather than raw scanner report bytes.

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=None/None |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=None, FP=None, precision=None, recall=None, F1=None |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** None/None (None%), rich line-truth matched=None/None |
| Leaky Repo history | **UNSCORED** — truth=None, execution=None, occurrences=None/None, unique=None/None, recall=None%, pending=None, unverified=None |
| RNC Lab v3 filesystem | TP=None/None, unique=None/None, recall=None%, duplicates=None, FP alerts=None, pending=None, precision=NOT CERTIFIED |
| RNC Lab v3 Git | NOT_APPLICABLE; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Not available: the selected suites do not define a performance workload (the scanner-specific fixture lane is functional-only)

## Cleanup

- Status: **PASS**
- Retained by request: False
- No run-owned containers found.
- Removed 1 run-owned image(s).
- Removed image tag rnc-gitleaks-20261112t233543z-db80aaa0-5f6ec56cfa6f-docker-linux-amd64.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- One Linux-only symlink scenario is NOT_APPLICABLE on Windows native execution.
- The legacy fixture lane retains hashed reports rather than raw scanner report bytes.
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
