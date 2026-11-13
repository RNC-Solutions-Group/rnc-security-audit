# CP1D report — scoring-engine stabilization and dataset accountability

**Checkpoint:** CP1D, implemented and verified under the work package authorization.

**Branch:** `test/scan-harness` (orphan).

**Starting HEAD:** `cf8f9153a304fc9ab8d69f8b2b16bdbc1d00d2df`.

**Scope:** stabilize the scoring architecture before adding another production
scanner, establish Leaky Repo finding accountability, remove redundant active
matrix entries, execute every genuinely available product, and prove scoring
correctness with an independent synthetic adapter. CP2 was not started.

## Outcome

| Requirement | Status |
| --- | --- |
| Scanner-independent scoring engine | Complete |
| Normalized finding/truth/result contract | Complete |
| Complete Leaky Repo line-level accountability | 175/175 count units line-located; category conflict documented |
| Dual Leaky Repo scoring | Legacy + RNC rich, same normalized findings |
| Per-finding and per-file cross-target parity | Complete; all 3 product pairs PASS |
| Exception-first reporting | Complete; 586 normalized exceptions across the three suites, concise console |
| Baseline comparison | Complete; CP1C metric-only and CP1D normalized comparison |
| Active products actually executed | Windows AMD64, Docker Linux AMD64, Docker Linux ARM64 (emulated) |
| Removed build-only macOS/native Linux products | Complete |
| Removed active Go-test suite | Complete; mapping archived |
| Synthetic scoring validation | **25/25 cases, 100.0% accuracy** |

Overall: **`COMPLETE_WITH_LIMITATIONS`**. All active products executed all
applicable suites. Gitleaks coverage remains incomplete for the four unmapped
`INTERNAL_GO` contracts, and Leaky Repo retains an explicit upstream-category
conflict; neither was relabeled to produce a pass.

## Architecture corrections

See [scoring contract](scoring-contract.md) and
[architecture](architecture.md).

- `harness/scoring_engine.py` consumes only `NormalizedFinding`, truth manifests,
  and scoring policies. It imports no adapter, parser, executable, or
  Gitleaks-specific field.
- `harness/contracts.py` defines the portable normalized finding, truth item,
  evaluation, classification, and scoring result.
- `harness/suites/levain.py` now parses through the adapter and calls
  `scoring.assess_findings`; the former
  `suite → scoring → execution → gitleaks_parse` chain is broken.
- Boundary tests fail if shared scoring imports a scanner parser/adapter, if
  suites import scanner parsers, or if the synthetic validator imports Gitleaks
  or execution code.

## Leaky Repo accountability

The upstream `.leaky-meta/secrets.csv` is line/count based: 44 files, 96 risk +
79 informative = 175 count units. It does not publish individual locations. The
RNC truth manifest locates every count unit at a specific source line using the
file content and explicit source comments.

| Account | Value |
| --- | ---: |
| Upstream files | 44 |
| Upstream risk units | 96 |
| Upstream informative units | 79 |
| Upstream total | 175 |
| RNC line items | 175 |
| RNC files | 44 |
| RNC risk-designated lines | 88 |
| RNC informative-designated lines | 87 |
| RNC line fingerprints verified | 175/175 |
| Unaccounted count units | **0** |

### Category conflict

Six upstream rows have aggregate risk/informative totals that disagree with the
source-line review:

| File | Upstream risk/info | RNC risk/info |
| --- | ---: | ---: |
| `.esmtprc` | 2/1 | 1/2 |
| `.ftpconfig` | 3/2 | 2/3 |
| `deployment-config.json` | 3/1 | 1/3 |
| `filezilla/filezilla.xml` | 2/1 | 1/2 |
| `filezilla/recentservers.xml` | 3/3 | 2/4 |
| `web/var/www/.env` | 6/4 | 4/6 |

The upstream aggregate differs by **8 category units**. No line categories were
reassigned to force the upstream totals. Thirty-one truth items in these six
files carry `category_conflict: true`. Detection-level accountability is complete;
category-level reconciliation is explicitly **CONFLICT**, not silently resolved.

Reconciliation evidence:
[`reports/cp1d/leaky-truth-reconciliation.json`](../reports/cp1d/leaky-truth-reconciliation.json).

## Dual Leaky Repo scoring

Both scores are computed from the same normalized findings in one scanner
execution.

| Methodology | Version | Result |
| --- | --- | --- |
| Legacy upstream count | upstream CSV | 22/175 covered (12.57%), 13/44 files, 0 excess, 0 unlisted |
| RNC line-level rich | `rnc-leaky-truth-v1` | 22 matched, 153 missed, 0 duplicate, 0 unexpected, 12.57% detection recall |

The rich score reports detection recall only. It does **not** claim precision,
F1, or verified false positives because Leaky Repo has no negative oracle.
Category coverage is reported under both the upstream and RNC views. No rich
precision/F1 value is manufactured.

Both scores appear in console summaries, JSON, and Markdown. A `NOT_READY` rich
status is used if truth validation fails.

## Active product execution

| Product | Build | Execution | Gitleaks fixtures | Levain | Leaky Repo |
| --- | --- | --- | --- | --- | --- |
| Windows AMD64 native | PASS | Native | PASS | PASS | PASS |
| Docker Linux AMD64 | PASS | Docker | PASS | PASS | PASS |
| Docker Linux ARM64 | PASS | Docker, emulated on AMD64 host | PASS | PASS | PASS |

Image architecture was inspected and verified for both Docker images. ARM64 is
labeled **emulated**, not native ARM64 validation.

Gitleaks executions: 69 scenarios (23 per product), 68 applicable passes, 1
Linux-only symlink `NOT_APPLICABLE` on Windows, **435/435 assertions**.

Levain: **47/85 true positives**, 1 partial, 2 duplicates, 3 negative false
positives on every product.

Leaky Repo: legacy **22/175**, rich **22 matched / 153 missed**, all products.
All pairwise product comparisons PASS at finding/per-file identity level.

## Removed entries

- macOS AMD64/ARM64 executables: removed from the active matrix; they were
  build-only and never executed.
- Native Linux AMD64/ARM64 executables: removed from the active matrix; they
  could not be executed on the supported host.
- `go` scanner-harness suite: removed from the active suite registry, default
  configuration, and interactive CLI. The CP1C mapping code and historical
  evidence remain archived. Go unit testing remains the scanner development
  repository's responsibility.

CP1C historical seven-build evidence and reports are preserved unchanged.

## Configuration and reporting

- Corrected timeout schema: canonical `[execution] timeout`; loader also accepts
  the legacy root key. A non-default value is tested (`42` takes effect).
- Nested report configuration:
  `[reports.sanitized]`, `[reports.unsanitized]`, `[reports.summary]`,
  `[reports.exceptions]`; legacy flat keys remain accepted.
- Sanitized and unsanitized destinations are independently configurable;
  unsanitized destinations must be Git-ignored or outside tracked source.
- Raw scanner artifacts are exported only when enabled. Temporary scanner
  report/stdout/stderr files are removed from work before the run returns.
  `raw_policy` records `exported` or `discarded`.
- Exception reporting is exception-first and configurable: coverage gaps,
  skipped items, not-applicable items, and baseline deltas can be included or
  suppressed independently.
- Baseline CLI: `--baseline PATH`, with per-suite statuses `PASS`, `FAIL`,
  `METRIC_ONLY`, `NOT_COMPARABLE`, or `INCOMPATIBLE`.
- Exit codes: harness/config error `2`; execution or scoring-system failure `1`;
  detection-quality limitations `3`; complete `0`. A rich score that is
  `NOT_READY` is a scoring-system failure, not silent detection performance.
- Baseline comparison identifies existing gaps, new misses, recovered detections,
  new/resolved unexpected findings, and classification changes.

## Backlog disposition

| ID | Finding | Disposition |
| --- | --- | --- |
| P1.1 | Adapter independence | **Resolved**; normalized contract + architecture tests |
| P1.2 | Leaky finding reconciliation | **Resolved for line identities**; category conflict documented |
| P1.3 | Cross-target parity | **Resolved**; pairwise per-finding/per-file comparisons |
| P1.4 | Exception-first reporting | **Resolved**; normalized exceptions, config, reports |
| P1.5 | Synthetic validation | **Resolved**; 25/25, 100% |
| P2.1 | Timeout config | **Resolved**; `[execution] timeout`, test |
| P2.2 | Raw-report semantics | **Resolved**; export/discard policy, cleanup, test |
| P2.3 | Baseline comparisons | **Resolved**; CP1C metric-only + CP1D normalized |
| P2.4 | Versioned evidence | **Resolved**; hashes, versions, policy/platform metadata |
| P2.5 | Report configuration | **Resolved**; nested sanitized/unsanitized/summary/exceptions |
| CP4 | macOS/native Linux/Go removal | **Resolved**; active matrix limited to executable products |
| CP7 | Synthetic scoring proof | **Resolved**; 100% accuracy |

## Baseline results

Final three-product run:
[`reports/cp1d/cp1d-baseline.json`](../reports/cp1d/cp1d-baseline.json).

- All 3 products built and executed all 3 suites.
- Gitleaks: 69 scenarios, 68 passed, 1 `NOT_APPLICABLE`, 435/435 assertions.
- Levain: 47/85 TP, 1 partial, 2 duplicates, 3 negative FPs per product.
- Leaky: legacy 22/175, 13/44 files; rich 22 matched, 153 missed, 0 unexpected.
- Cross-target: all pairwise comparisons PASS.

Compared with CP1C:
[`reports/cp1d/cp1d-comparison.json`](../reports/cp1d/cp1d-comparison.json)
compares the normalized CP1D run against the CP1D baseline and reports **PASS**
with no new misses or unexpected findings. The CP1C report comparison is
**METRIC_ONLY** because CP1C contains no normalized scoring evaluations; the
apparent Gitleaks count increase 46→69 scenarios and 288→435 assertions is
explained by adding the second Docker architecture, not scanner improvement.

## Synthetic validation

[`reports/cp1d/synthetic-scoring-validation.json`](../reports/cp1d/synthetic-scoring-validation.json)

| Field | Result |
| --- | ---: |
| Synthetic test cases | 25 |
| Expected outcomes independently specified | 25 |
| Actual outcomes | 25 |
| Correct outcomes | **25** |
| Incorrect outcomes | **0** |
| Scoring accuracy | **100.0%** |
| Unexpected classifications | **0** |
| Unresolved discrepancies | **0** |

The synthetic adapter imports no Gitleaks parser, rule, executable, or result
model. Expected answers are static values in the validator, not values computed
by the scoring engine. Cases cover expected detection, zero detection, partial,
missing, unexpected, verified false positive, duplicates, multiple-same-file,
wrong file, wrong classification, overlapping ranges, identical counts with
different identities, skipped, unavailable, blocked, execution error, empty
dataset/output, malformed finding, ambiguous truth, invalid truth integrity,
baseline regression/improvement, and sanitized/unsanitized reporting.

## Verification

```sh
python -m unittest discover -s tests -t .
```

**Test suite:** **184 tests, OK** (about 57 s). The run includes architecture,
scoring-engine, truth-manifest, synthetic, baseline, configuration, reporting,
adapter, matrix, Docker legacy, and CP1B regression tests. No test result is used
as a substitute for the independently specified synthetic answers.

## Evidence hashes

| Artifact | SHA-256 |
| --- | --- |
| `cp1d-baseline.json` | `8d4244b1ecc1afc6a52346e8eec87eeec6894d6777fda0f258f3804bff76af28` |
| `cp1d-baseline.md` | `9367eca1c47e922b520f1effebd8ec26542f10eea65d1110abc0bb3e5bc13dde` |
| `cp1d-comparison.json` | `30a6938357f463d86699a17d7a55d83fd036099b09b7509351e0f257743c47be` |
| `cp1d-comparison.md` | `e889ca6c80eadb9ef98eb15dd9b7789a188a6f5f0dd19cbb11035ddbaa4185c5` |
| `leaky-truth-reconciliation.json` | `3881e3eb93d780292d642aa47756f81d1aabb55376c51522ce57ca3c2afb1f93` |
| `synthetic-scoring-validation.json` | `bee8aca96415ba5893fddcc2b08d3dea3dbd70815e885cb91550781b32b49f87` |
| `synthetic-scoring-validation.md` | `d815dde2829357efa80defd560560614526522357ecf167aca753345972134cc` |

These hashes refer to the generated report files at commit time. Regenerating a
run changes its `generated_at` and therefore its hash.

## Limitations

- Six upstream Leaky Repo rows / 8 category units conflict with source-line
  review; category reconciliation is CONFLICT. Line-level accountability is
  complete and 31 items are explicitly flagged.
- Leaky Repo has no negative oracle; no precision/F1 or verified false-positive
  claim is made.
- Four `INTERNAL_GO` contracts remain unmapped and 16 mapped contracts are
  skipped on Windows; Gitleaks Docker coverage remains `INCOMPLETE`.
- Docker ARM64 is emulated on the AMD64 host, not native ARM64 validation.
- Docker execution uses Windows 11 + Docker Desktop/WSL2.
- Go-test mapping and CP1C seven-platform build evidence are archived, not active.
- No second production scanner was integrated. CP2 has not started.

## Readiness assessment

The adapter/scorer/reporter boundary is ready for a second production scanner:
a new adapter needs only to resolve/build/invoke its product, validate its
configuration, and emit the normalized finding contract. It should not require
changes to shared scoring, truth manifests, baseline comparison, or report
rendering.

The Leaky Repo finding-level baseline is usable for detection scoring. Category
aggregates carry an explicit upstream conflict and are not certified as fully
reconciled; a future dataset revision should resolve those six rows at the source.
Gitleaks Docker coverage also remains incomplete for the four unmapped
`INTERNAL_GO` contracts. Neither limitation is hidden by the current pass.

**Stop after CP1D. Awaiting owner review.**
