# Scanner Experiment Report

> **Outcome: FAIL**

## Identity

| Field | Value |
| --- | --- |
| Scanner | Gitleaks (`gitleaks`) |
| Scanner build version | unavailable |
| Source repository | https://github.com/RNC-Solutions-Group/gitleaks |
| Requested source commit | `0000000000000000000000000000000000000000` |
| Checkout HEAD | `—` |
| Checkout HEAD verified | False |
| Adapter | `gitleaks` / Gitleaks |
| Configuration profile | **default** |
| Configuration source | scanner bundled default rules |
| Configuration SHA-256 | `—` |
| Run ID | `20261111T182415Z-f1db8f61` |
| Harness version | 0.5.0 |
| Generated (UTC) | 2026-11-11T18:24:18Z |

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

Toolchain: Go `go version go1.27.3 windows/amd64`, Docker `29.9.3`, Git `git version 2.45.2.windows.1`.

## Benchmark outcomes

| Suite | Outcome | Status | Baseline? | Metrics |
| --- | --- | --- | --- | --- |
| `synthetic-filesystem` | **BLOCKED** | BLOCKED | False | — |

### Product-level results

#### synthetic-filesystem

- Reason: experiment failed: HarnessError: git -C C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261111T182415Z-f1db8f61\source failed (exit 128): fatal: remote error: upload-pack: not our ref 0000000000000000000000000000000000000000

## Detection summary

| Benchmark | Result |
| --- | --- |
| Synthetic filesystem | matched=None/None |
| Synthetic history | unique=None/None, occurrences=None/None |
| Levain | TP=None, FP=None, precision=None, recall=None, F1=None |
| Leaky Repo filesystem | **LEGACY COUNT COVERAGE** None/None (None%), rich line-truth matched=None/None |
| Leaky Repo history | **UNSCORED** — truth=None, execution=None, findings=None, unique fingerprints=None |

Legacy Leaky count coverage is not verified recall or precision. Leaky rich line-truth reports detection only; precision/F1 remain unavailable without a negative oracle. Leaky history has no defensible denominator and is never scored against the 175 filesystem items.

## Performance (separate from detection)

Not available: not reached

## Cleanup

- Status: **PASS**
- Retained by request: False
- No run-owned containers found.
- No run-owned images found.
- Removed run-owned checkout, build outputs, and evidence workspace.

## Diagnostics

```
Traceback (most recent call last):
  File "C:\Dev\gitleaks\gitleaks-harness\harness\experiment.py", line 339, in run
    source = acquire(
        requested_repository,
    ...<2 lines>...
        timeout=float(timeout or config.timeout),
    )
  File "C:\Dev\gitleaks\gitleaks-harness\harness\source.py", line 167, in acquire
    fetch_result, fetch_duration = _git_ok(fetch, timeout=timeout)
                                   ~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^
  File "C:\Dev\gitleaks\gitleaks-harness\harness\source.py", line 98, in _git_ok
    raise HarnessError(
    ...<2 lines>...
    )
harness.errors.HarnessError: git -C C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261111T182415Z-f1db8f61\source failed (exit 128): fatal: remote error: upload-pack: not our ref 0000000000000000000000000000000000000000

```

## Limitations

- Source commit is the primary experiment identity; artifact hashes and image IDs are supporting provenance.
- A successfully built artifact is not counted as tested unless an applicable suite executed it.
- DEFAULT isolation is enforced by omitting --config, clearing known scanner-config environment variables, and executing from an empty run-owned working directory.
- The scanner does not expose a machine-readable digest of its embedded default rule set; the harness therefore verifies invocation isolation rather than the rule-file bytes.
- Experiment failed before completion: HarnessError: git -C C:\Users\david\AppData\Local\Temp\rnc-scan-harness\20261111T182415Z-f1db8f61\source failed (exit 128): fatal: remote error: upload-pack: not our ref 0000000000000000000000000000000000000000

Statuses: PASS, FAIL, BLOCKED, NOT_RUN, NOT_APPLICABLE.
Outcomes: COMPLETED_AND_SCORED, COMPLETED_UNSCORED, NOT_APPLICABLE, FAILED, BLOCKED.
