# Scanner Experiment Report

> **Outcome: COMPLETE_WITH_LIMITATIONS**

## Identity

| Field | Value |
| --- | --- |
| Scanner | RNC Scanner (`rnc`) |
| Registered build | `rnc-cp4a-local` |
| Scanner version | 0.1.0 |
| Artifact manifest | `run/manifest.toml` |
| Artifact manifest SHA-256 | `e56066972ecc5e81eb6a1809e71ab874694e687bc97fd94c82192e3a5ee8b53c` |
| Source commit (manifest metadata) | `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` |
| Source commit verification | NOT VERIFIED — operator-supplied metadata; no source checkout or build |
| Registered executable | `rnc-cp4a.exe` |
| Registered executable SHA-256 | `321fbdb388081a28d44f7f817a35be84bc3271dc8ed05f983f781c9fb3d9644c` |
| Registered Docker image | `rnc-cp5-test:93b4dda` |
| Registered Docker image ID | `sha256:f05f1b34d061d523090b0edc81c037edd7c7bde15da63a9e2d426378b9a9476d` |
| Rules/configuration file | `rules/rnc-providers-v1.json` |
| Rules/configuration SHA-256 | `87d7f9051ae41df34df29a0d5447ee8c9d71854ada46b789c9b7a00e4320a73a` |
| Adapter | `rnc` / RNC Scanner |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261113T171840Z-0b8eefbe` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-13T17:18:44Z |

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
| `docker-linux-amd64` | docker | PASS | `rnc-cp4a-local` | 0.1.0 | `sha256:f05f1b34d061d523090b0edc81c037edd7c7bde15da63a9e2d426378b9a9476d` | True |

Toolchain: Docker `29.9.3`, Git `git version 2.45.2.windows.1`, Python `Python 3.13.5`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `synthetic-filesystem` | **COMPLETED_AND_SCORED** | PASS | False | precision %=100.0; F1 %=100.0; expected=4; value-verified=4; line-only=0 |

### Product-level results

#### synthetic-filesystem

- controlled-filesystem / `docker-linux-amd64`: **COMPLETED_AND_SCORED** (PASS)
- target `docker-linux-amd64`: **PASS**

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=4/4 |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=None, FP=None, precision=None, recall=None, F1=None |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** None/None (None%), rich line-truth matched=None/None |
| Leaky Repo history | **UNSCORED** — truth=None, execution=None, occurrences=None/None, unique=None/None, recall=None%, pending=None, unverified=None |
| RNC Lab v3 filesystem | TP=None/None, unique=None/None, recall=None%, duplicates=None, FP alerts=None, pending=None, precision=NOT CERTIFIED |
| RNC Lab v3 Git | NOT_APPLICABLE; lane details in JSON |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history is scored only against the owner-approved source oracle; its reviewed negatives are not exhaustive, so precision/F1 are not certified. Unmatched and unverified findings remain in the investigation ledger.

## Performance (separate from detection)

Not available: the selected suites do not define a performance workload (the scanner-specific fixture lane is functional-only)

## Scanner invocations

Every row records the actual executed argument vector (not a reconstructed command), in execution order. Credential-bearing argument values are redacted only when a sensitive flag such as `--password` or `--token` is present; the original argv digest is retained in the JSON report.

| # | Type | Suite | Workload | Platform | Build | Artifact identity | Exit | Duration (s) | Timeout/error | Command |
| ---: | --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |
| 1 | verification | `—` | `ruleset-validation` | `docker-linux-amd64` | `rnc-cp4a-local` | `sha256:f05f1b34d061d523090b0edc81c037edd7c7bde15da63a9e2d426378b9a9476d` | 0 | 1.812 | none | `docker run --rm --pull=never --platform linux/amd64 --network none --mount type=bind,source=C:\Dev\rnc-benchmark-harness\run\rules\rnc-providers-v1.json,target=/rules.json,readonly --entrypoint rnc --label rnc-scan-harness.run=20261113T171840Z-0b8eefbe --label rnc-scan-harness.adapter=rnc --name rnc-20261113T171840Z-0b8eefbe-rules-a4192183 rnc-cp5-test:93b4dda rules validate --rules /rules.json --strategy auto` |
| 2 | detection | `synthetic-filesystem` | `synthetic-filesystem` | `docker-linux-amd64` | `rnc-cp4a-local` | `sha256:f05f1b34d061d523090b0edc81c037edd7c7bde15da63a9e2d426378b9a9476d` | 10 | 1.108 | none | `docker run --rm --pull=never --platform linux/amd64 --network none --read-only --tmpfs /tmp:rw,noexec,nosuid --env HOME=/tmp --mount type=bind,source=C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171840Z-0b8eefbe\evidence\synthetic-filesystem\target,target=/scan,readonly --mount type=bind,source=C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171840Z-0b8eefbe\evidence\synthetic-filesystem\lanes\docker-linux-amd64,target=/out --mount type=bind,source=C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171840Z-0b8eefbe\evidence\synthetic-filesystem\scanner-config.json,target=/rules.json,readonly --mount type=bind,source=C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261113T171840Z-0b8eefbe\evidence\synthetic-filesystem\lanes\docker-linux-amd64\rnc-isolation.toml,target=/config.toml,readonly --workdir /out --entrypoint rnc --label rnc-scan-harness.run=20261113T171840Z-0b8eefbe --label rnc-scan-harness.adapter=rnc --name rnc-20261113T171840Z-0b8eefbe-docker-1aafbdc5 rnc-cp5-test:93b4dda scan --root /scan --rules /rules.json --config /config.toml --output /out/report.json --format private --run-id 20261113T171840Z-0b8eefbe` |

Invocation types: `detection`, `warmup`, `measured`, and `verification` for artifact/ruleset validation. Detection and performance commands use the same registered executable or image.

## Cleanup

- Status: **PASS**
- Retained by request: False
- No run-created containers found.
- Removed run-owned benchmark workspace, generated datasets, and evidence.

## Limitations

- Source commit is operator-supplied manifest metadata; the harness did not clone, check out, or compile scanner source.
- The registered executable SHA-256 and Docker image ID are the executed artifact identities; they are verified before every run.
- A verified artifact is not counted as tested unless an applicable suite executed it.
- Registered Docker images and run/ executables are never deleted or modified by the harness.
- The rule bundle is the operator-provided rules_file registered in run/manifest.toml and hashed before execution.
- The empty repository configuration suppresses target auto-discovery; it does not alter the provider rule bundle.
- Git-history capability is declared by the operator in the manifest; an undeclared capability is reported as NOT_APPLICABLE rather than assumed.

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
