# CP2 report — multi-scanner integration and comparative validation

**Checkpoint:** CP2
**Branch:** `test/scan-harness`
**Starting HEAD:** `8e9c2f40eb580d3cf69422adc67d3c766d782dc3`
**Scope:** integrate a second production secret scanner, make benchmark capability
selection automatic, validate end-to-end scanner/adapter/scorer controls, compare
detection and performance without conflation, and preserve compact evidence.
No PR or merge was performed. CP2 does not migrate the harness repository.

## Executive summary

Betterleaks **v1.8.1** was selected and integrated as the second production
scanner. It is MIT-licensed, maintained by the original Gitleaks author, and its
v1 CLI/JSON shape is compatible with the existing normalized adapter boundary.
It was validated on the same pinned benchmarks as Gitleaks on three execution
products: Windows AMD64 native, Docker Linux AMD64, and Docker Linux ARM64
(emulated).

Both scanners passed all applicable suites. Betterleaks detected more Leaky Repo
filesystem truth (**37/175** vs **22/175**) and had higher Levain recall
(**48/85** vs **47/85**), but lower Levain precision (**90.57%** vs **94.0%**)
because it produced more negative-corpus false positives (**5** vs **3**).
F1 was effectively tied (**69.57** vs **69.63**). Both scored **4/4** on the
controlled filesystem corpus and **5/5 occurrences / 3/3 unique secrets** on the
controlled Git-history corpus.

No unsupported precision/F1 or historical recall claims are made. Leaky Repo
Git-history truth remains **BLOCKED**. All same-platform cross-scanner
performance comparisons are stable and directly comparable in this environment;
native/container and AMD64/emulated ARM64 comparisons are explicitly not.

## Architecture corrections

The pipeline remains:

**benchmark target → adapter → normalized findings → scoring engine → comparison/reporting**

- The scoring engine remains scanner-agnostic and does not import either adapter.
- The adapter registry now has `gitleaks` and `betterleaks`.
- `synthetic-filesystem` was added as an end-to-end controlled fixture suite.
- Leaky Repo no longer has operator filesystem/history mode selection. It always
  evaluates filesystem and, when the adapter supports Git mode, history.
- `all` now resolves the complete registered suite catalog; unsupported suites
  are materialized as `NOT_APPLICABLE` rather than silently omitted.
- Gitleaks fixture scenarios remain Gitleaks-specific; Betterleaks reports the
  suite as `NOT_APPLICABLE` with a reason.
- Multi-scanner comparison is a reporting layer; it does not alter either
  scanner's normalized output or truth.
- `consolidate` remains archived/not exposed; no Go-contract obligations were
  reintroduced.

## Second-scanner selection

| Criterion | Finding |
| --- | --- |
| Identity | [Betterleaks](https://github.com/betterleaks/betterleaks), maintained by the original Gitleaks author |
| License | MIT; notice appended to `datasets/THIRD_PARTY_NOTICES.md` |
| Pinned release | `v1.8.1` (published 2026-08-18), source commit `5eab48332cc48565864514e3bc6de89df091a7c4` |
| Why v1 | Stable CLI/JSON v1 is compatible with the normalized adapter and is the current stable release; v2 is a release-candidate development line |
| Capabilities | Filesystem and Git history; JSON reports; Windows/Linux binaries; OCI multi-architecture image |
| Products | Windows AMD64 native; Docker Linux AMD64; Docker Linux ARM64 (emulated) |
| Windows binary SHA-256 | `727820f1a9f9264319cc50458b99f01acbb93e93df7a39b8eaa2715a7b1aaed5` |
| Windows archive SHA-256 | `94310d028285a1bcce7f160bc19eb62f87de6460c95bfd4319151ef5b501ed3f` |
| Docker AMD64 | `ghcr.io/betterleaks/betterleaks:v1.8.1` (image `sha256:8b9d12…`) |
| Docker ARM64 | `ghcr.io/betterleaks/betterleaks@sha256:12175773…` |

Betterleaks default configuration is richer than the Gitleaks pinned rule set.
No attempt was made to tune either scanner's rules to the other; both were run
with their production defaults for Leaky Repo and Levain, and with an identical
controlled RNC-token config for synthetic end-to-end fixtures.

## Capability coverage

| Suite | Gitleaks | Betterleaks | Meaning |
| --- | --- | --- | --- |
| Gitleaks fixtures | PASS | **NOT_APPLICABLE** | Gitleaks-specific functional scenarios |
| Synthetic filesystem | PASS | PASS | End-to-end adapter/scorer controls |
| Synthetic Git history | PASS | PASS | Unique-credential and occurrence controls |
| Levain | PASS | PASS | Negative/positive corpus |
| Leaky Repo filesystem + history | PASS | PASS | Legacy/rich filesystem and history observation |

Leaky Repo history capability is exercised automatically when supported. If an
adapter lacked Git mode, the suite would report `NOT_APPLICABLE`, not zero recall.

## Synthetic controls

### Layer 1 — scoring engine

The independent static validation remains **31/31, 100.0%**, zero unexpected
classifications. See [`reports/cp1e/synthetic-scoring-validation.md`](../reports/cp1e/synthetic-scoring-validation.md).
It validates identity, value mismatch, swapped identities, duplicates, wrong
rules, redacted output, partial/blocked/failure states, and baseline changes.

### Layer 2 — actual scanner integration

| Fixture | Gitleaks | Betterleaks |
| --- | ---: | ---: |
| Filesystem expected / matched | 4 / 4 | 4 / 4 |
| Filesystem precision / recall / F1 | 100 / 100 / 100 | 100 / 100 / 100 |
| History unique secrets | 3 / 3 | 3 / 3 |
| History occurrences | 5 / 5 | 5 / 5 |
| History missed / unexpected / duplicates | 0 / 0 / 0 | 0 / 0 / 0 |
| Value-verified occurrences | 5 | 5 |

These controls prove scanner execution, adapter normalization, and independent
scoring agree. They do not imply real-world detection accuracy, and the two
scanners happened to tie on this small controlled corpus.

## Actual detection results

### Leaky Repo filesystem

| Metric | Gitleaks | Betterleaks |
| --- | ---: | ---: |
| Legacy count coverage | 22/175 (12.57%) | **37/175 (21.14%)** |
| Files covered | 13/44 | **22/44** |
| Excess / unlisted | 0 / 0 | 0 / 0 |
| Rich matched | 22 | **37** |
| Rich missed | 153 | **138** |
| Duplicates / unexpected | 0 / 0 | 0 / 0 |
| Value-verified matches | 20 | 35 |
| Line-only matches | 2 | 2 |
| Precision / F1 | not claimed | not claimed |

The 175-item denominator and the six category conflicts are unchanged. Every
Gitleaks Leaky detection was also found by Betterleaks; Betterleaks found
15 additional truth items:

`.bash_profile:20`, `.bashrc:105`, `.remote-sync.json:17`,
`.vscode/sftp.json:6`, `db/mongoid.yml:4`, `db/robomongo.json:14`,
`db/robomongo.json:27`, `deployment-config.json:5`, `sftp-config.json:15`,
`ventrilo_srv.ini:7`, `ventrilo_srv.ini:8`, `web/var/www/.env:14`,
`web/var/www/.env:23`, `web/var/www/.env:33`,
`web/var/www/public_html/config.php:11`.

No Gitleaks-only Leaky truth item was observed. Gitleaks' CP1E filesystem counts
(22/175 Leaky, 47/85 Levain, 69 fixture scenarios/435 assertions) are unchanged;
the CP1E historical baseline remains valid for regression comparison.

### Levain

| Metric | Gitleaks | Betterleaks |
| --- | ---: | ---: |
| True positives / 85 | 47 | **48** |
| False positives (negative corpus) | **3** | 5 |
| Partial matches | 1 | 3 |
| Duplicates | 2 | 2 |
| Precision | **94.00%** | 90.57% |
| Recall | 55.29% | **56.47%** |
| F1 | **69.63** | 69.57 |

Levain has a valid negative oracle, so precision/F1 are reported. The two
scanners have materially different precision/recall tradeoffs; the F1 tie does
not mean equivalence.

### Gitleaks functional fixtures

Only Gitleaks executes this suite: 69 scenarios, 68 applicable passes (one
Windows symlink `NOT_APPLICABLE`), **435/435 assertions**. Betterleaks is
`NOT_APPLICABLE`.

## Git-history accountability

- Leaky Repo scope: 25 commits, 61 current files, 65 changed paths, 4
  historical-only paths, 62 additions, 52 modifications, 1 deletion, 3 renames,
  no duplicate current-blob groups, 207 Git objects.
- Leaky history truth remains **BLOCKED**. No authoritative per-commit secret
  manifest exists; constructing one would require unsupported assumptions.
- Betterleaks observed **41 findings / 29 unique fingerprints**; Gitleaks
  observed **26 / 16** across 25 commits. These are unscored observations.
- The controlled five-commit history corpus is **COMPLETE**: 3 unique secrets,
  5 occurrences, both scanners perfect on detection and value identity.

The filesystem 175-item denominator is never applied to history.

## Performance

Methodology and environmental caveats:
[`docs/performance-methodology.md`](../performance-methodology.md).

Workload: 610 files / 5,888,020 bytes (pinned Leaky tree replicated 10×), one
warm-up + five measured runs, sequential. All measurement sets were stable.

| Scanner | Product | Median | Min/max | CV | CPU median | Peak MiB | Throughput |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks | Windows AMD64 native | 0.786 s | 0.553/1.032 | 0.197 | 2.125 s | 71.4 | 7.49 MB/s |
| Betterleaks | Windows AMD64 native | **0.683 s** | 0.536/0.835 | 0.174 | **1.469 s** | 113.4 | 8.62 MB/s |
| Gitleaks | Docker Linux AMD64 | 3.578 s | 2.476/4.606 | 0.222 | N/A | N/A | 1.65 MB/s |
| Betterleaks | Docker Linux AMD64 | **2.870 s** | 2.572/2.977 | 0.061 | N/A | N/A | 2.05 MB/s |
| Gitleaks | Docker Linux ARM64 (emulated) | **6.929 s** | 5.726/7.445 | 0.086 | N/A | N/A | 0.85 MB/s |
| Betterleaks | Docker Linux ARM64 (emulated) | 9.249 s | 8.890/12.853 | 0.148 | N/A | N/A | 0.64 MB/s |

Same-platform cross-scanner comparisons:

- Windows native: Betterleaks **13.1% faster** in wall time, lower CPU time, but
  higher peak memory (113.4 MiB vs 71.4 MiB).
- Docker AMD64: Betterleaks **19.8% faster**.
- Docker ARM64 emulated: Gitleaks **33.5% faster**; emulated results are not
  native ARM64 evidence.
- Native vs container and AMD64 vs emulated ARM64 are **not directly
  comparable**.
- Docker CPU-seconds and peak memory were unavailable on short runs and are
  `null`, not zero.

Performance and detection are separate; no weighted combined score exists.

## Test evidence

**206 tests, OK** (about 90 s), including:

- scanner-independent scoring and 31 static synthetic cases;
- second-adapter registry, parser, and capability tests;
- automatic Leaky history execution without operator mode selection;
- unsupported suite → `NOT_APPLICABLE` and omitted-suite prevention;
- cross-scanner identity differences and capability matrix;
- Levain precision/F1 only with a negative oracle;
- performance telemetry, aggregation, failure handling, version comparison;
- Git-history corpus and discovery;
- compact reporting and raw-artifact cleanup;
- historical CP1A–CP1E evidence untouched.

Real execution additionally covered all applicable suites on all three products
for both scanners; all product parity comparisons PASS.

## Remaining defects and deferrals

- Leaky Repo history truth is BLOCKED; no historical recall claim.
- Leaky Repo has no negative oracle; precision/F1 intentionally `null`.
- Six category conflicts remain explicit; no forced reconciliation.
- Docker CPU-seconds/peak memory unavailable for short runs; ARM64 is emulated.
- Betterleaks v2 release-candidate line is not integrated; v1.8.1 was selected
  for stable CLI/JSON compatibility.
- Gitleaks fixture scenarios are scanner-specific and not reused for Betterleaks.
- macOS and native Linux products are not available in this environment.
- No live targets, credential validation, or real credentials were used.
- Repository migration cleanup remains documented but not executed.

## Migration readiness

The comparative layer is compact and scanner-independent. Adapter-specific
binaries/images are cached outside Git. Complete tracked evidence is limited to
summary JSON/Markdown, manifests, notices, and checkpoint docs. The future
tracked/ignored split in
[`docs/repository-migration.md`](../repository-migration.md) remains valid.

## Recommendation for next checkpoint

Before CP3, review the Levain precision/recall tradeoff and the Leaky coverage
difference. If Betterleaks is to become a permanent comparison scanner, pin the
release and image digests in CI artifact policy, and decide whether a negative
oracle can be established for Leaky Repo. Do not construct historical Leaky truth
from scanner output.

## Evidence hashes

| Artifact | SHA-256 |
| --- | --- |
| `reports/cp2/comparative.json` | `da727d0400d38ac5af877e9a4af1415b59f135ac0cab1b4b93f94629e5c11fe7` |
| `reports/cp2/comparative.md` | `0ae06760d852133167473f62f9625bfa824213e09d74562c9851e051e97eefb2` |
| `reports/cp2/performance.json` | `36ffeb6a05069a1169edad8a76cdf8a38b5c99ad3b383c929a04c85b1611de3c` |
| `reports/cp2/performance.md` | `ed55b30fb3fd3e29922bdb9c849704d8ce4b047dce247643696c326a3530bbdf` |

Hashes refer to generated evidence at commit time; reruns change timestamps.

**Stop after CP2. Awaiting owner review.**
