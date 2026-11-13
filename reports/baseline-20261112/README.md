# CP10 authoritative scanner baseline — 2026-11-12

**Status: PARTIAL / NOT A COMPLETE FOUR-SCANNER BASELINE.** The completed
Gitleaks native+Docker and RNC native cells are authoritative CP10 measurements.
Betterleaks and both RNC Docker cells are explicitly blocked by missing local
source/dependencies; no network substitution was made.

## Environment and identity

| Item | Value |
| --- | --- |
| Harness branch / starting HEAD | `test/scan-harness` / `034feff1ac5444221e2d32ff5b959d5dcb1ed75f` |
| Execution date | 2026-11-12 |
| Host | Windows 11, Intel i7-11375H, 4C/8T, 31.7 GiB RAM |
| Measurement profile | **DEV** — contended developer host; timings preliminary, not release evidence |
| Gitleaks source | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Betterleaks source | `5eab48332cc48565864514e3bc6de89df091a7c4` (local source **missing**) |
| RNC CP3 source | `5391d8457ea091c45733920078a7f714ec61f678` |
| RNC CP4A source | `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` |

### Truth identity

| Dataset | Identity |
| --- | --- |
| Leaky Repo history oracle | SHA-256 `bb6d24bfecd53c7208c2915c105a5b501cbb3af3390fac7a4e5fcf92e50a078c`, version `2026-11-12.3`; 184 total / 65 positive occurrences / 53 groups / 89 negatives / 30 informative |
| RNC Synthetic Secrets Lab | `rnc-synthetic-secrets-lab/1.2.0`, build `v3`; manifest `691548588679f4a1e5e41ecd5d253d7137693337c1ddef2c6e8943bbb7cd7d0b`; oracle `83dea16b343ff7a9340ff463513f4bdb454cea6faaf3234696a78fe8e6b85214`; corpus `161cb863f22b817982d26113b3981bec24b30bc37dd881fc10e9e8cc48ac91f3` |
| Lab denominators | filesystem 1,282 (640 positive); Git 320 (160 positive); 496 unique positive identities |

The lab manifest, oracle, corpus, and 51-commit local Git lineage were verified
before and after scanning. No frozen lab artifact was modified.

## Matrix status

| Benchmark | Gitleaks native | Gitleaks Docker | Betterleaks | RNC CP3 native | RNC CP3 Docker | RNC CP4A native | RNC CP4A Docker |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Gitleaks fixtures | PASS (22/23 native) | PASS (23/23) | N/A | N/A | N/A | N/A | N/A |
| Levain | PASS | PASS | BLOCKED | PASS | BLOCKED | PASS | BLOCKED |
| Leaky Repo filesystem | PASS | PASS | BLOCKED | PASS | BLOCKED | PASS | BLOCKED |
| Leaky Repo Git | PASS | PASS | BLOCKED | **NOT_APPLICABLE** | BLOCKED | PASS | BLOCKED |
| RNC Lab filesystem | PASS | PASS | BLOCKED | PASS | BLOCKED | PASS | BLOCKED |
| RNC Lab Git | PASS | PASS | BLOCKED | **NOT_APPLICABLE** | BLOCKED | PASS | BLOCKED |
| RNC Lab performance | PASS | PASS | BLOCKED | PASS | BLOCKED | PASS | BLOCKED |
| RNC Lab ×5 | PASS | PASS | BLOCKED | PASS | BLOCKED | PASS | BLOCKED |
| RNC Lab ×10 | PASS | PASS | BLOCKED | PASS | BLOCKED | PASS | BLOCKED |

`--suites all` remained **Levain + Leaky Repo only**. `rnclab` was run only via
`--suites rnclab`. The Gitleaks fixture lane ran without a performance workload.

## Detection results

### Levain (85 published positive credentials; negative corpus)

| Scanner/product | TP | FP | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Gitleaks native | 47 | 3 | 94.00% | 55.29% | 69.63% |
| Gitleaks Docker AMD64 | 47 | 3 | 94.00% | 55.29% | 69.63% |
| RNC CP3 native | 32 | 0 | 100.00% | 37.65% | 54.70% |
| RNC CP4A native | 43 | 2 | 95.56% | 50.59% | 66.16% |

### Leaky Repo filesystem (legacy 175 count units; never treated as verified recall)

| Scanner/product | Legacy coverage | Rich line-truth matched | Value-verified | Line-only |
| --- | ---: | ---: | ---: | ---: |
| Gitleaks native / Docker | 22/175 (12.57%) | 22/175 (12.57%) | 20 | 2 |
| RNC CP3 native | 33/175 (18.86%) | 32/175 (18.29%) | 30 | 2 |
| RNC CP4A native | 27/175 (15.43%) | 25/175 (14.29%) | 23 | 2 |

### Leaky Repo Git history (owner-approved 65 occurrences / 53 groups)

| Scanner | TP occurrences | Unique TP | Duplicates | Informative | FP alerts | Unique exposures | Pending | Unverified |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks native | 21 | 15 | 3 | 2 | 0 | 0 | 0 | 0 |
| Gitleaks Docker AMD64 | 21 | 15 | 3 | 2 | 0 | 0 | 0 | 0 |
| RNC CP3 | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| RNC CP4A native | 21 | 19 | 21 | 7 | 12 | 4 | 0 | 0 |

History precision/F1 remain `null` and
`BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`. The CP10 oracle migration is applied; the
retained-evidence regression rescore in `leaky-regression-rescore.json` confirms
the expected 21 TP / 21 duplicates / 7 informative / 12 FP alerts / 4 unique
exposures / 0 pending / 61 accounted.

### RNC Synthetic Secrets Lab v3 — filesystem (640 positive occurrences / 366 unique groups)

| Scanner/product | TP | FN | Occurrence recall | Unique TP | Unique recall | Duplicates | Informative | FP alerts | Pending | Unverified |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks native | 357 | 283 | 55.78% | 220 | 60.11% | 80 | 5 | 4 | 34 | 0 |
| Gitleaks Docker AMD64 | 357 | 283 | 55.78% | 220 | 60.11% | 80 | 5 | 4 | 34 | 0 |
| RNC CP3 native | 260 | 380 | 40.62% | 171 | 46.72% | 0 | 1 | 23 | 56 | 0 |
| RNC CP4A native | 297 | 343 | 46.41% | 194 | 53.01% | 0 | 0 | 23 | 66 | 3 |

RNC filesystem coverage is explicitly **PARTIAL** for the 11 lab symlink aliases
(`SYMLINK_NOT_FOLLOWED`); the 360 regular source files were inspected. No
occurrence is fabricated for a symlink alias.

### RNC Synthetic Secrets Lab v3 — Git (160 positive occurrences / 130 unique groups)

| Scanner/product | TP | FN | Occurrence recall | Unique TP | Unique recall | Duplicates | Informative | FP alerts | Pending | Unverified |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks native | 120 | 40 | 75.00% | 102 | 78.46% | 0 | 0 | 7 | 11 | 0 |
| Gitleaks Docker AMD64 | 120 | 40 | 75.00% | 102 | 78.46% | 0 | 0 | 7 | 11 | 0 |
| RNC CP3 | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| RNC CP4A native | 105 | 55 | 65.63% | 78 | 60.00% | 0 | 0 | 3 | 12 | 0 |

The RNC CP3 source revision was independently capability-assessed: its CLI does
not expose `--history/--ref`; it is `NOT_APPLICABLE`, not a zero score. CP3 was
not patched or substituted with CP4A.

## Performance results (DEV; median seconds)

Native timings are not comparable to Docker timings. Load profiles are
performance-only and were never scored against the canonical oracle.

| Scanner/product | Levain | Leaky FS (×10) | Leaky Git | Lab FS | Lab Git | Lab ×5 | Lab ×10 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks native | 0.102 | 0.337 | 0.155 | 0.230 | 0.212 | 1.484 | 2.711 |
| Gitleaks Docker AMD64 | 0.564 | 2.606 | 0.643 | 1.631 | 4.452 | 7.453 | 13.281 |
| RNC CP3 native | 0.134 | 0.415 | N/A | 0.313 | N/A | 2.077 | 3.210 |
| RNC CP4A native | 0.284 | 1.038 | 7.127 | 0.523 | 6.975 | 11.675 | 12.938 |

Canonical runs used 1 warm-up / 5 measured runs; load runs used 1 warm-up / 3
measured runs. Full per-iteration times, CPU, peak RSS, throughput, and
coefficients of variation are in the individual JSON reports. Docker Leaky
filesystem/Git and Docker Lab Git were `UNSTABLE` at the DEV stability threshold;
all other measured workloads were `STABLE`.

RNC CP4A load scans declared one `TOTAL_BYTE_LIMIT` exclusion per run in the
generated 8 MiB payload set. This is recorded as an explicit coverage caveat and
the inspected-file counts are reduced accordingly; the load was not treated as
canonical accuracy.

## Build provenance

| Product | Source | Artifact / image | Build strategy |
| --- | --- | --- | --- |
| Gitleaks native | `5f6ec56…` | `c68865ea9cd5645e21c6bef2cfdc16a49b4d693b24028b5e4badfda593a913d1` | Go source build, Windows AMD64 |
| Gitleaks Docker AMD64 | `5f6ec56…` | image IDs per report, e.g. `sha256:c2b722d86da811e20990b4de2e39a89cc065a40e539e4c877dc81a4e16757c8d` | adapter source Dockerfile, local `golang:1.27.4`, offline vendor tree, `--network none --pull=false` |
| RNC CP3 native | `5391d845…` | `e206a855af306982329e13e7c19c822ec11e33a0d60f6ee1e835628c5270b580` (all run) | Cargo release, Windows AMD64 |
| RNC CP4A native | `93b4dda9…` | `5c2642e226bac1d63aef19ece2a100e3cbc7325b0e857a3858fbef5a220214dc` (all run) | Cargo release, Windows AMD64 |
| Betterleaks | `5eab483…` | none | **BLOCKED — MISSING_LOCAL_SOURCE** |
| RNC Docker AMD64 | both RNC commits | none | **BLOCKED — MISSING_LOCAL_DEPENDENCY** (`bitflags 2.13.2` absent; `debian:bookworm-slim` absent) |

Fresh builds for separate experiments are independently attributable to the
source commit even where their artifact hashes differ (RNC Cargo rebuilds). No
downloaded release executable, published scanner image, or network dependency
was used.

## Blocked cells and limitations

- **Betterleaks:** no local source checkout/archive for the pinned commit. The
  local Go module cache contains only `v1.8.1.info`; no source zip or extracted
  module was available. Network acquisition was prohibited. See
  `betterleaks-5eab483-blocked.json`.
- **RNC Docker AMD64 (both commits):** offline Cargo vendoring fails on
  `bitflags v2.13.2`; the required `debian:bookworm-slim` base is not local.
  Native builds and benchmarks completed. See the two `rnc-*-docker-amd64-blocked.json`
  records.
- **RNC filesystem lab coverage:** 11 symlink aliases are explicitly
  unsupported; all 360 regular files were inspected. Symlink aliases carry no
  separate oracle occurrences.
- **RNC Lab load:** one scanner-declared `TOTAL_BYTE_LIMIT` exclusion per load run
  is visible in the performance caveat; load results are not accuracy scores.
- **DEV performance:** timings are preliminary and not release evidence. Docker
  performance is not directly comparable with native performance.
- **Precision/F1:** uncertified for Leaky history because reviewed negatives are
  not exhaustive. Lab precision/F1 are also reported `null`; unmatched and
  unverified findings remain in the investigation ledger.

## Reports

- [Machine-readable index](index.json)
- [Leaky retained-evidence regression rescore](leaky-regression-rescore.json)
- [Gitleaks native all](gitleaks-5f6ec56-native-all-5f6ec56cfa6f-default.json)
- [Gitleaks Docker all](gitleaks-5f6ec56-docker-amd64-all-5f6ec56cfa6f-default.json)
- [Gitleaks native RNC Lab](gitleaks-5f6ec56-native-rnclab-5f6ec56cfa6f-default.json)
- [Gitleaks Docker RNC Lab](gitleaks-5f6ec56-docker-amd64-rnclab-5f6ec56cfa6f-default.json)
- [RNC CP3 native all](rnc-5391d84-native-all-5391d8457ea0-default.json)
- [RNC CP3 native RNC Lab](rnc-5391d84-native-rnclab-5391d8457ea0-default.json)
- [RNC CP4A native all](rnc-93b4dda-native-all-93b4dda909cb-default.json)
- [RNC CP4A native RNC Lab](rnc-93b4dda-native-rnclab-93b4dda909cb-default.json)
- [Superseded development attempts](superseded/)

## Acceptance recommendation

**NO-GO for accepting a complete four-scanner, two-product CP10 baseline:**
Betterleaks has no local source, and both RNC Docker products have unresolved
local dependency gaps. The corresponding matrix cells remain `BLOCKED`, not
fabricated or zero-scored.

**GO for the completed cells:** Gitleaks native+Docker and RNC native results are
fresh, source-built, sequentially executed, independently scored, and supported
by the CP10 oracle and certified lab hashes. These cells may be cited as CP10
authoritative results only with the partial-baseline qualification above.
