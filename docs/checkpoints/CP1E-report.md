# CP1E report — scoring finalization, Git history, and performance

**Checkpoint:** CP1E
**Branch:** `test/scan-harness`
**Starting HEAD:** `86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f`
**Scope:** finalize the CP1D scoring contract, validate individual finding
identity, remove active Go-contract obligations, add Git-history truth/execution,
implement an independent performance benchmark, and document readiness for CP2.
No second production scanner was integrated. CP2 was not started.

## Outcome

| Requirement | Status |
| --- | --- |
| CP1D rich-readiness propagation | Complete |
| Finding-level synthetic validation | **31/31, 100.0%** |
| Value-level rich identity | 20 value-verified / 2 explicit line-only Leaky matches |
| Per-file truth reconciliation | Complete; six category conflicts preserved |
| Active Go-contract obligations | Removed from active suite/reporting/CLI |
| Filesystem dual scoring | PASS on all three products |
| Git-history benchmark | Implemented; controlled corpus COMPLETE, Leaky history BLOCKED |
| Three-product history execution | PASS on Windows, Docker AMD64, Docker ARM64 |
| Independent performance module | Real repeated measurements, separate from detection |
| Compact reporting | 440 KB matrix evidence, full artifacts outside Git |
| Migration cleanup specification | Documented, not executed |

Overall matrix status: **`COMPLETE_WITH_LIMITATIONS`**. All products built and all
four suites passed. The limitation is Leaky Repo's known 12.57% filesystem count
coverage and the explicit **BLOCKED** Leaky history truth status; neither is
converted into a false pass.

## 1. CP1D correction register

See [`docs/cp1d-corrections.md`](../cp1d-corrections.md) for the full register.

Key corrections:

- Rich `NOT_READY` now fails the lane target, suite, and matrix scoring status;
  legacy success cannot mask it. Parity includes a rich-availability difference.
- Synthetic validation now checks individual expected/observed identity,
  classification, file/line, and identity confidence, including adversarial
  value mismatch, swapped identity, duplicate collision, wrong rule, redacted
  output, and correct counts with wrong identities.
- Truth items can carry safe value fingerprints. Matches are labeled `value` or
  `line`; PEM/private-key lines remain line-only; redacted output cannot satisfy
  a required value fingerprint.
- Parity maps include secret fingerprint/commit/index to avoid same-file/line
  collisions.
- Leaky truth validation checks every file's expected total and category counts;
  the six upstream conflicts remain annotated, not silently rewritten.
- Go-contract imports, methods, warnings, and the legacy `consolidate` CLI command
  were removed from the active harness. Historical mapping code remains archived.

## 2. Synthetic scoring validation

[`reports/cp1e/synthetic-scoring-validation.json`](../reports/cp1e/synthetic-scoring-validation.json)

| Field | Result |
| --- | ---: |
| Cases | 31 |
| Correct | **31** |
| Incorrect | **0** |
| Accuracy | **100.0%** |
| Unexpected classifications | **0** |
| Unresolved discrepancies | **0** |

The expected answers are static in the validator, independent of the engine. The
suite includes all 25 CP1D aggregate cases plus six identity/adversarial cases
with exact expected evaluation records.

## 3. Filesystem detection results

Final matrix: [`reports/cp1e/cp1e-baseline.json`](../reports/cp1e/cp1e-baseline.json)
(compact; full evidence in ignored `work/`).

| Suite | Result |
| --- | --- |
| Gitleaks fixtures | 69 scenarios (23/product), 68 applicable passes, 1 symlink N/A, **435/435 assertions** |
| Levain | **47/85 TP**, 1 partial, 2 duplicates, 3 negative FPs on every product |
| Leaky legacy | **22/175** count coverage, **13/44** files, 0 excess/unlisted |
| Leaky rich | **22 matched / 153 missed**, 0 duplicate, 0 unexpected, 12.57% recall |
| Rich identity | **20 value-verified**, **2 line-only** |
| Category conflicts | 31 items in 6 files; 8 aggregate category units; explicit CONFLICT |

No precision/F1 or verified false-positive claim is made for Leaky Repo; it has no
negative oracle.

## 4. Git-history benchmark

### Leaky Repo discovery

The pinned repository has **25 commits**, 61 current files, 65 changed paths,
4 historical-only paths, 62 additions, 52 modifications, 1 deletion, 3 renames,
and 207 Git objects. Discovery is pinned in
[`datasets/leaky-repo.history-scope.json`](../datasets/leaky-repo.history-scope.json).

Historical truth is **BLOCKED**: upstream publishes working-tree counts, not a
per-commit secret manifest. Gitleaks history execution observed **26 findings /
16 unique secret fingerprints across 25 commits**. These are unverified
observations, not recall or precision. The 175 filesystem denominator is not
applied.

### Controlled synthetic history

A deterministic five-commit corpus has alpha, repeated alpha, beta replacement and
repeat, gamma addition, and gamma removal. Truth distinguishes **3 unique secrets**
from **5 occurrences**.

| Result | Value |
| --- | ---: |
| History status | **COMPLETE** |
| Unique expected / matched | 3 / 3 |
| Occurrence expected / matched | 5 / 5 |
| Missed / unexpected / duplicates | 0 / 0 / 0 |
| Value-verified occurrences | 5 |
| Cross-product parity | PASS for all three pairs |

See [`reports/cp1e/history-accountability.json`](../reports/cp1e/history-accountability.json)
and [`docs/history-accountability.md`](../history-accountability.md).

## 5. Execution matrix

| Product | Build | Gitleaks | Levain | Leaky filesystem | Leaky history | Synthetic history |
| --- | --- | --- | --- | --- | --- | --- |
| Windows AMD64 native | PASS | PASS | PASS | PASS | PASS/observation | PASS |
| Docker Linux AMD64 | PASS | PASS | PASS | PASS | PASS/observation | PASS |
| Docker Linux ARM64 (emulated) | PASS | PASS | PASS | PASS | PASS/observation | PASS |

All pairwise detection/history comparisons PASS. Docker image architectures were
verified; ARM64 is explicitly emulated. Product identities are recorded in the
compact matrix; performance uses its own build identities.

## 6. Performance benchmark

Methodology: [`docs/performance-methodology.md`](../performance-methodology.md).
Evidence: [`reports/cp1e/performance.json`](../reports/cp1e/performance.json).

Workload: 610 files / 5,888,020 bytes (pinned Leaky tree replicated 10×), 1 warm-up
+ 5 measured runs, sequential. Actual measurements:

| Product | Median s | Min/max s | CV | CPU median s | Peak MiB | Throughput B/s | Stability |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Windows AMD64 native | 0.675 | 0.617/0.823 | 0.109 | 2.094 | 72.8 | 8,722,993 | STABLE |
| Docker Linux AMD64 | 2.129 | 1.878/2.401 | 0.082 | N/A | N/A | 2,765,627 | STABLE |
| Docker Linux ARM64 (emulated) | 5.377 | 4.985/7.286 | 0.150 | N/A | N/A | 1,095,038 | STABLE |

Native CPU utilization (320.9%) is process CPU across cores, not 320% of one core.
Docker CPU utilization was sampled (100.2% AMD64, 457.1% ARM64); Docker CPU-seconds
and peak memory were unavailable because the short containers finished before a
usable `docker stats` sample. They are `null`, not zero.

All performance comparisons are **`NOT_DIRECTLY_COMPARABLE`**: native vs container,
and AMD64 vs emulated ARM64. Detection similarities are recorded separately; no
weighted accuracy/performance score is produced.

## 7. Reporting and configuration

- Compact matrix evidence is 440 KB; full per-finding JSON remains in ignored
  `work/`.
- Console output is concise and exception-first; history and dual scores appear
  as separate lines.
- Markdown now separates filesystem dual scores, synthetic history, Leaky history
  observation, exceptions, parity, baseline, and limitations.
- `[leaky_repo] modes` supports filesystem/history/both (default both).
- `[performance] warmups` and `measured_runs` are configurable; CLI
  `--leaky-modes` and `benchmark --warmups/--runs/--copies/--detection-report`.
- `git-history` is a selectable suite and part of `all`.
- Raw artifacts remain export-or-discard; committed reports are sanitized.
- Full migration split: [`docs/repository-migration.md`](../repository-migration.md).

## 8. Evidence hashes

| Artifact | SHA-256 |
| --- | --- |
| `cp1e-baseline.json` | `9039734455c995481d3fe47d202db046a22542891bc9e92a0d356011d66416ec` |
| `cp1e-baseline.md` | `e37dcb32b71d296b3295c775887dd67ab93d98351432ad6da369bef8aec1a614` |
| `synthetic-scoring-validation.json` | `1a0c594c9bc7fc67b9ea6bc57534579f4a6d99bc1c6519fa10b22452da4416e2` |
| `synthetic-scoring-validation.md` | `a3f9fff7d1bfaf10918140033b1e635ae9c2a48aa2fd27e6493bd4a8d259e074` |
| `history-accountability.json` | `ec61b4d7043bc0ca859f0a17617c902e8b7c0149ca8b91f8298370ac8b49a542` |
| `history-accountability.md` | `99cb9aadd9297af25e8f58a5596b0a239fbeefeda4f09dc76a18ca327acf72bf` |
| `performance.json` | `ca72ddbc6138fce0d95deac98ed66e33290d41540584b98cbac460e49152cf6c` |
| `performance.md` | `5c964f51d90b4702884027e1a335e7f616b89fee2d49b22ed14fa76decabe0e2` |
| `datasets/leaky-repo.rnc-truth.json` | `621d3ad39929b7143e0c799883da03123d8ca6da2f174ef330aec3590365c8a9` |
| `datasets/leaky-repo.history-scope.json` | `c2161522927ba6770e8c1232367c4affb71cfb2f8062047fc1ef39daa2d5195a` |

Hashes refer to generated evidence at commit time; reruns change timestamps.

## 9. Readiness for CP2

**Full Python suite:** 198 tests, OK (about 69 s).

The architecture is ready for a second production scanner:

- adapters own build/invocation/parsing/capabilities;
- the normalized contract carries commit/value identity without scanner-specific
  rule requirements;
- scoring, history, performance, and reporting have separate boundaries;
- unsupported capabilities and unavailable metrics are explicit;
- controlled history proves occurrence/unique methodology even where upstream
  truth is unavailable.

CP2 must not treat the controlled synthetic history score as Leaky Repo history
completeness, and must not compare emulated ARM64 performance numerically with
native AMD64.

## Limitations

- Leaky Repo history truth is **BLOCKED**; 26 observations are not scored.
- Leaky Repo filesystem category reconciliation remains **CONFLICT** for six rows.
- No Leaky negative oracle: no precision/F1 or verified false positives.
- Docker CPU-seconds/peak memory unavailable on this short-run Docker Desktop host.
- ARM64 Docker is emulated, not native ARM64 hardware.
- Gitleaks Docker coverage is complete for the executed scenarios/assertions but
  remains bounded by the pinned fixture corpus.
- Legacy `consolidate` module is archived; migration cleanup is specified, not
  executed.

**Stop after CP1E. Awaiting owner review.**
