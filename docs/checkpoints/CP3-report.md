# CP3 report â€” source-driven simplification and reproducible experiments

**Checkpoint:** CP3
**Branch:** `test/scan-harness`
**Starting HEAD:** `81a2434b41137d1812a88559a5414ad2c15cee83`
**Scope:** simplify the harness into an independent, one-scanner source-commit
evaluation application; remove cross-scanner execution/comparison; require exact
source builds; separate DEFAULT/CUSTOM configuration; retain unscored history
observations; integrate performance; and clean up run-owned resources. No PR,
merge, repository migration, or application-source change was performed.

## Executive summary

CP3 replaced scanner-release orchestration with a single canonical workflow:

```text
repository + exact commit
  -> disposable checkout (HEAD verified)
  -> adapter-owned native and Docker source builds
  -> automatic benchmark capabilities
  -> normalized findings -> independent scoring
  -> one experiment report
  -> scoped cleanup
```

Both supported scanners were built from source and executed on representative
Windows-native and Linux-Docker products. The source commit, not a release or image
tag, is the primary experiment identity. Betterleaks v1.8.1 remains a historical
CP2 identity only; it is no longer a runtime dependency.

The retired cross-scanner comparison path is gone. Running two scanners now means
two independent harness invocations and two reports, which external tools may
compare afterward. Multiple execution products of one source commit remain allowed
inside one report.

Leaky Repo Git history still executes. It reports **41 findings / 29 unique
fingerprints** for Betterleaks and **26 / 16** for Gitleaks, both as
`COMPLETED_UNSCORED` with historical truth `BLOCKED`. No historical recall,
precision, or filesystem denominator is invented.

All five active suites completed for Gitleaks; all four applicable suites completed
for Betterleaks, with the Gitleaks-specific functional fixture suite correctly
`NOT_APPLICABLE`. The full automated suite passed **201 tests**.

## Architectural simplifications

### One workflow, one report

`harness/experiment.py` is the sole experiment orchestrator. It acquires one
source checkout, builds selected products, runs requested suites, attaches
performance, writes one Markdown + JSON report, and cleans up. The report type is
`rnc-scan-harness/experiment`, schema version 2.

### Disposable exact-commit source identity

`harness/source.py`:

- requires a full 40-character commit;
- clones into a run-owned system-temporary directory;
- fetches the exact commit if it is not already present;
- checks out detached and verifies `HEAD == requested commit`;
- requires a clean working tree;
- records clone/fetch provenance, and fails without trying another revision.

`harness/workspace.py` owns unique run directories and cleanup. The old cached-target
acquisition (`harness/targets.py`) was removed.

### Adapter consolidation

`harness/adapters/base.py` now has one build/invoke/parse contract. The adapter
owns scanner identity, default repository, source build strategy, native/Docker
details, invocation, configuration behavior, parser, capabilities, and optional
fixture hooks. Source acquisition, platform selection, suites, scoring,
performance, reporting, and cleanup are harness-owned. The scoring engine imports
no adapter.

Removed from the generic adapter contract: source acquisition, Go-test execution,
internal evidence mapping, and a separate version-discovery step. Generic
orchestration/reporting contain no scanner names; an architecture test enforces it.

### Cross-scanner responsibility removed

Deleted:

- `harness/comparative.py` â€” multi-scanner execution and cross-scanner differences;
- `harness/product_comparison.py` â€” cross-run comparison contract;
- `harness/benchmark_runner.py` â€” separate performance orchestration;
- `harness/matrix.py` â€” old matrix CLI/orchestrator;
- `harness/targets.py`, `harness/consolidate.py`, `harness/internal_go.py`,
  `harness/docker_adapter.py`, `harness/suites/go_tests.py` â€” retired cached-target,
  consolidation, Go-contract, and obsolete orchestration paths.

The scalar `run` CLI, `matrix`, `benchmark`, and `comparative` commands were
removed. `experiment` is the primary command. Historical CP1Aâ€“CP2 evidence remains
unchanged.

### Strict output validation

A valid empty report (`[]`, or Betterleaks `null`) is zero findings. Missing,
empty-byte, malformed, truncated, schema-incompatible, or entry-invalid reports are
`REPORT_MISSING`/`REPORT_INVALID` execution failures. Parser failure can never
become a zero-finding result. Tests cover empty, truncated, and surrounding-text
reports.

## DEFAULT and CUSTOM configuration

DEFAULT uses the scanner's bundled rules. The harness passes no config argument,
removes known scanner-config environment variables, and invokes from an empty
run-owned working directory. Since neither scanner exposes a machine-readable
digest of its embedded rule set, the harness verifies invocation isolation rather
than the embedded bytes. That limitation is recorded in the report.

CUSTOM requires an explicit file and records its source path, SHA-256, applied
settings, scanner commit, and results. CUSTOM results are excluded from DEFAULT
baseline metrics. Synthetic integration controls use a separately labeled
`CONTROLLED_FIXTURE` rule and are also excluded from baseline metrics.

Real isolation check (`reports/cp3/default-profile-isolation.json`): a target
containing `.gitleaks.toml`/`.betterleaks.toml`-style hostile external configuration
and a marker value produced:

| Scanner | DEFAULT findings | CUSTOM findings | CUSTOM rule |
| --- | ---: | ---: | --- |
| Gitleaks | 0 | 1 | `hostile-config-rule` |
| Betterleaks | 0 | 1 | `hostile-config-rule` |

Thus DEFAULT did not load the external config, while CUSTOM applied it explicitly.
No raw marker value is stored in the evidence.

## Source-build validation

| Scanner | Product | Source commit | Build | Artifact / image |
| --- | --- | --- | --- | --- |
| Gitleaks | Windows AMD64 native | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | PASS | executable SHA-256 `c68865ea9cd5â€¦` |
| Gitleaks | Docker Linux AMD64 | same | PASS | image `sha256:f694e59cac97…` |
| Gitleaks | Docker Linux ARM64 (emulated) | same | PASS | image `sha256:b767f5d50c9b…` |
| Betterleaks | Windows AMD64 native | `5eab48332cc48565864514e3bc6de89df091a7c4` | PASS | executable SHA-256 `18d1fb705b85…` |
| Betterleaks | Docker Linux AMD64 | same | PASS | image `sha256:cb65a5ea0d70…` |

Checkout HEAD verification was `true` in every completed report. No release binary
or published scanner image was used. Higher-level provenance, image IDs, build
commands, toolchain, and per-product metadata are in each report.

The emulated ARM64 product was source-built (491 s cold build), passed the
controlled filesystem control (`4/4`), passed controlled history (`3/3` unique,
`5/5` occurrences), and cleaned up correctly. Its one measured performance run
(1.958 s) is recorded as a functional observation, not used for ranking.

The Betterleaks v1.8.1 upstream Dockerfile pins Go 1.24 while its `go.mod` requires
Go 1.25, so that Dockerfile cannot build the requested commit. The adapter writes a
matching-toolchain source Dockerfile and builds from the **same checkout**. This is
reported with strategy `adapter-source-dockerfile`, Dockerfile SHA-256, and
`upstream_dockerfile_compatible: false`. It is not a published-image substitution.

## Benchmark results

All numbers below come from the committed experiment reports. They are independent
per-scanner observations, not harness-produced cross-scanner rankings.

### Gitleaks

| Metric | Windows native | Docker AMD64 |
| --- | ---: | ---: |
| Suites | 5 PASS | 5 PASS |
| Leaky legacy count coverage | 22/175 (12.57%), 13/44 files | 22/175, 13/44 files |
| Leaky rich matched / missed | 22 / 153 | 22 / 153 |
| Leaky unexpected / duplicates | 0 / 0 | 0 / 0 |
| Leaky value-verified / line-only | 20 / 2 | 20 / 2 |
| Levain TP / FP / partial / duplicates | 47 / 3 / 1 / 2 | 47 / 3 / 1 / 2 |
| Levain precision / recall / F1 | 94.00 / 55.29 / 69.63 | same |
| Controlled filesystem | 4/4, 100% P/R/F1 | 4/4 |
| Controlled history | 3/3 unique, 5/5 occurrences | 3/3, 5/5 |
| Gitleaks fixtures | 22/23 scenarios, 141/141 assertions | 23/23, 147/147 |
| Leaky history observations | 26 findings / 16 fingerprints | 26 / 16 |
| Leaky history truth | BLOCKED / UNSCORED | BLOCKED / UNSCORED |

The native fixture lane's one `NOT_APPLICABLE` scenario is the Linux-only symlink
case. The Docker lane executes it and passes all 23 scenarios / 147 assertions.

### Betterleaks

| Metric | Windows native | Docker AMD64 |
| --- | ---: | ---: |
| Suites | 4 PASS + Gitleaks fixtures N/A | 4 PASS |
| Leaky legacy count coverage | 37/175 (21.14%), 22/44 files | 37/175, 22/44 |
| Leaky rich matched / missed | 37 / 138 | 37 / 138 |
| Leaky unexpected / duplicates | 0 / 0 | 0 / 0 |
| Leaky value-verified / line-only | 35 / 2 | 35 / 2 |
| Levain TP / FP / partial / duplicates | 48 / 5 / 3 / 2 | same |
| Levain precision / recall / F1 | 90.57 / 56.47 / 69.57 | same |
| Controlled filesystem | 4/4, 100% P/R/F1 | 4/4 |
| Controlled history | 3/3 unique, 5/5 occurrences | 3/3, 5/5 |
| Leaky history observations | 41 findings / 29 fingerprints | 41 / 29 |
| Leaky history truth | BLOCKED / UNSCORED | BLOCKED / UNSCORED |

Leaky Repo has no negative oracle, so precision and F1 remain `null`. The 175-item
figure is always labeled **LEGACY COUNT COVERAGE**, not verified recall. The six
upstream category conflicts remain explicit (31 count items flagged); no category
was reassigned to change totals.

### Unscored history proof

The Leaky Repo history lanes contain the **complete normalized finding list** â€”
path, commit, line, rule, safe secret/match hashes, fingerprint, and metadata â€” not
just counts. Example counts: Gitleaks 26/26 retained; Betterleaks 41/41 retained.
`truth_status` is `BLOCKED`, `scored` is false, outcome is `COMPLETED_UNSCORED`, and
`denominator` is `none`. The filesystem 175-item denominator is not applied.

### Test outcomes

All requested suites ended in one of the required outcomes:

- Gitleaks: all five `COMPLETED_AND_SCORED`; native symlink case is a scenario-level
  `NOT_APPLICABLE` inside an otherwise passed fixture suite.
- Betterleaks: four `COMPLETED_AND_SCORED`; Gitleaks-specific fixture suite
  `NOT_APPLICABLE` with reason.
- Leaky history: `COMPLETED_UNSCORED` despite truth being blocked.
- Incorrect commit: experiment `FAIL`, suite `BLOCKED`, cleanup `PASS`, report
  written.

## Performance

Workload: 610 files / 5,888,020 bytes (pinned Leaky tree Ã—10). Native runs used
5 warm-ups + 7 measured runs; Gitleaks Docker used 5 + 7; Betterleaks Docker used
5 + 7. Build time is separate from execution.

| Scanner | Product | Median s | Min/max s | CV | CPU median s | Peak MiB | Stability |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Gitleaks | Windows native | 0.699 | 0.482/0.912 | 0.215 | 2.328 | 67.9 | STABLE |
| Gitleaks | Docker AMD64 | 2.448 | 2.044/2.851 | 0.106 | N/A | N/A | STABLE |
| Betterleaks | Windows native | 0.666 | 0.516/0.819 | 0.160 | 1.531 | 119.4 | STABLE |
| Betterleaks | Docker AMD64 | 2.196 | 1.829/2.904 | 0.151 | N/A | N/A | STABLE |

All four representative sets are stable after the environment correction. Native
and container execution are not directly comparable. Docker CPU-seconds and peak
memory were unavailable and are `null`, not zero. No weighted
detection/performance score exists.

## Cleanup and safety

Successful native and Docker experiments reported cleanup `PASS`, removed the
run-owned checkout/build/evidence workspace, and removed the run-owned Docker image
by exact label/tag (for example Gitleaks image `f694…`, Betterleaks image `cb65…`).
No broad Docker prune, volume removal, or unrelated file traversal occurred. A
failed commit experiment also cleaned up and wrote a failure report.

`--retain-work` was executed and verified: the workspace remained, the report said
`retained: true`, and no Docker cleanup was attempted. That retained workspace was
then removed manually. Automated tests cover successful cleanup, failed cleanup,
cancellation cleanup, label-scoped container/image removal, and debug retention.

Historical commits execute build-time code. The CP3 evidence was produced on a
dedicated Windows developer host with Docker Desktop; no production VPS, production
credentials, website volumes, or deployment secrets were accessed.

## Automated tests

**201 tests, OK** (82.7 s), including:

- exact source commit, different-commit identity, short/branch identity rejection,
  wrong-commit failure, checkout HEAD verification, and local tag fallback;
- run-owned workspace uniqueness, successful/failed/cancelled cleanup, debug
  retention, and scoped Docker labels with no prune;
- DEFAULT/CUSTOM profile separation and provenance;
- strict empty/truncated/invalid report behavior;
- one-scanner experiment reports, no-overwrite naming, source failure, and cleanup;
- all suite outcomes, automatic Leaky history, unscored history evidence, Levain
  precision/F1, synthetic controls, and capability `NOT_APPLICABLE`;
- architecture boundaries: no scanner names in generic orchestration/reporting, no
  scoring adapter imports, and removed comparison modules absent;
- historical scoring, dataset, reporting, and fixture tests retained.

The full run was executed after the final code changes. No unexecuted test is
reported as passing.

## Remaining limitations and deferrals

- Leaky Repo historical truth remains **BLOCKED**; no historical recall/precision.
- Leaky Repo has no negative oracle; precision/F1 remain `null`.
- Six upstream category conflicts / 31 count items remain explicit.
- Docker Desktop timing showed environmental variance; the final regenerated
  performance sets are stable, but no cross-product ranking is claimed.
- Betterleaks v1.8.1's upstream Dockerfile is incompatible with its own Go version
  requirement; the adapter's source-build Dockerfile is documented.
- ARM64 Docker was built/executed only as an emulated product; no native ARM64
  evidence.
- macOS and native Linux executables remain outside the active product catalog.
- Gitleaks functional fixtures are scanner-specific and not reused for Betterleaks.
- Docker source builds depend on registry/toolchain network access; scan execution
  itself remains offline.
- No live targets, real credentials, credential validation, or production audit
  were used.
- No cross-scanner comparison is produced by design; external orchestration must
  compare separate reports.
- Repository migration remains a documented future action, not a CP3 change.

## Evidence

Representative reports:

- [`gitleaks-5f6ec56-native`](../../reports/cp3/gitleaks-5f6ec56-native-5f6ec56cfa6f-default.md)
- [`gitleaks-5f6ec56-docker-amd64`](../../reports/cp3/gitleaks-5f6ec56-docker-amd64-5f6ec56cfa6f-default.md)
- [`betterleaks-5eab483-native`](../../reports/cp3/betterleaks-5eab483-native-5eab48332cc4-default.md)
- [`betterleaks-5eab483-docker-amd64`](../../reports/cp3/betterleaks-5eab483-docker-amd64-5eab48332cc4-default.md)
- [`gitleaks-5f6ec56-docker-arm64`](../../reports/cp3/gitleaks-5f6ec56-docker-arm64-5f6ec56cfa6f-default.md)
- [`default-profile-isolation.json`](../../reports/cp3/default-profile-isolation.json)
- [`incorrect-commit` failure report](../../reports/cp3/incorrect-commit-000000000000-default.md)

The JSON reports are the machine-readable evidence; Markdown reports are readable
summaries. Report names include scanner, commit prefix, profile, and product, and
never overwrite an existing experiment.

## Validation environment

| Item | Value |
| --- | --- |
| Host | Windows 11 AMD64 developer host |
| Python | 3.13.5 |
| Go | 1.27.3 windows/amd64 |
| Docker | 29.9.3 (Docker Desktop/WSL2) |
| Git | 2.45.2.windows.1 |
| Gitleaks commit | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Betterleaks commit | `5eab48332cc48565864514e3bc6de89df091a7c4` |

Cold source builds observed approximately 99 s (Gitleaks native), 83 s
(Betterleaks native), 187 s (Gitleaks Docker AMD64), and 217 s (Betterleaks Docker
AMD64) without warm Go/BuildKit caches. Final report build durations were lower
because the caches were warm; build duration is never counted as scanner runtime.

## Evidence hashes

| Artifact | SHA-256 |
| --- | --- |
| `gitleaks-5f6ec56-native-…-default.json` | `e681f869262c8074eee1a59b07e2a62c9b19017a22cbf85ad78d252c2214a4d6` |
| `gitleaks-5f6ec56-docker-amd64-…-default.json` | `ce1e8713fa1af662e156069c89c821357173f2e44d658a163794d42f4ef45707` |
| `gitleaks-5f6ec56-docker-arm64-…-default.json` | `37e53a0c3c3587d023a250d0025900d60c698729855789ebccdf5ff03d07cc72` |
| `betterleaks-5eab483-native-…-default.json` | `7f41b0d79e5272187d034a4a9f87d0950e4b5e2ae8326ecacde72630123c4d71` |
| `betterleaks-5eab483-docker-amd64-…-default.json` | `0eaaa58d328bad558748abd7c2180b5b5329ad43bd7512fa6cc2ff7716332ab8` |
| `default-profile-isolation.json` | `5bc424bb24755a7cefaf8fd08b2fea060c454a87b52d4df4e409eb5f22146605` |
| `incorrect-commit-…-default.json` | `a15f860e287eb566a10c4bc176a4e456dbe398a3f82d1cc637c9e93865ce46c9` |

Hashes identify the committed evidence bytes. Reruns change timestamps, run IDs,
image IDs, and hashes.

## Recommendation

CP3 meets the acceptance criterion for the validated products: an operator can
supply one supported scanner repository and exact commit, execute available
benchmarks, receive one trustworthy report, and finish with no run-owned build
artifacts. **Awaiting owner review. Do not begin CP4 or migrate the repository.**

**Stop after CP3.**
