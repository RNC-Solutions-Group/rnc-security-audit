# CP0 audit — contracts, synthetic truth, Go/Rust evidence and CP1 handoff

> **Status:** CP0 audit package prepared for operator acceptance. No production RNC detector, policy engine, reporter or CI adapter is implemented. The original PR #3 was already merged before this audit; the recovery path is recorded in [cp0-audit-recovery.md](cp0-audit-recovery.md).

## 1. Executive result

The original CP0 branch established useful foundations: architecture specifications, six draft schemas, a nine-target authored corpus, a deterministic 1,000-target generator, twelve outcome cases and primitive Go/Rust probes. It did **not** satisfy CP0 on its own. The audit found material contract contradictions, missing coverage cases, no independent scoring mechanism, no representative language comparison, no language decision and no concrete external-harness handoff.

This audit corrected the contracts to schema **v0.2.0**, expanded the authored and generated corpus, added an independent harness/calibration path, executed the pinned external harness scoring engine against the handoff, built equivalent representative Go/Rust scanners, selected **Rust** in [ADR-007](../architecture/adr-007-detector-language.md), and produced an implementation-ready [CP1 handoff](cp1-detection-engine.md).

**Readiness:** pending the final CI run and operator review. The CP0 gates and limitations are listed in §12–§13. No external corpus was executed and no scanner recall/precision claim is made.

## 2. Baseline claim verification

| Original claim | Verified? | Evidence |
| --- | --- | --- |
| Nine authored synthetic targets | Yes | `synthetic-v0`: 9 targets, 8 inspected / 1 blocked |
| Fourteen authored known markers | Yes | 14 unique markers; 13 expected detections because one is behind a verified block |
| 1,000 generated targets | Yes | Generator reproduced twice; per-target SHA-256 verified |
| 2,000 generated known markers | Yes | 2,000 expected findings; 35 generated targets verified-blocked |
| Twelve result-classification cases | Yes | 12 v0 cases preserved; 16 additional v0.2 cases added (28 total) |
| Perfect / missed / false-positive stub modes | Partial | Existing stub emitted only findings; corrected to emit execution/policy/result/CI and calibrated by an independent harness |

The claim “11 local tests” was accurate for the original tree. The audited suite now contains **69 tests** and covers the added contracts, corpus, harness, external handoff and benchmark infrastructure.

## 3. Deliverable inventory and disposition

| CP0 deliverable | Baseline state | Disposition | Audit outcome |
| --- | --- | --- | --- |
| Architecture specs and operating contract | Present | **COMPLETE** | Preserved and aligned to v0.2; Rust decision and handoff added |
| Six JSON schemas | Draft v0.1 | **DEFECTIVE** | Replaced with v0.2 record schemas plus unified config schema; compatibility documented |
| Cross-record invariants | Reference reconciler only | **DEFECTIVE** | Rebuilt as schema + identity + coverage + policy + digest + publication validation |
| Unified config and legacy migration | Design prose | **PARTIAL** | `config.schema.json`, `.rncscanner.toml`, explicit `security.config` subset migration and fixtures |
| Authored synthetic corpus | 9 targets / 14 markers | **PARTIAL** | v0 preserved; v1 adds 21 targets, 26 markers, 25 expected findings and required edge cases |
| Generated 1,000-target corpus | Generator present | **COMPLETE** as a breadth lane | Reproducibility and hashes verified; independent scorer now accounts for it |
| Large/oversize edge corpus | Missing | **MISSING** | Deterministic 2 MiB / 9 MiB edge generator and truth manifest |
| Result-classification table | 12 cases | **COMPLETE** baseline | Preserved; expanded to 28 cases with required/optional and invalid-policy collisions |
| Synthetic stub | Findings only | **PARTIAL** | Full v0.2 bundle modes: perfect, miss, FP, duplicate, wrong location, blocked leak, missing target, invalid contract, error/interruption |
| Independent harness/scorer | Missing | **MISSING** | Implemented; 18/18 controlled scenarios exact (100%) |
| Primitive Go/Rust probes | Nine profiles | **COMPLETE** as a preliminary baseline | Preserved; not used as the selection basis |
| Representative Go/Rust benchmark | Missing | **MISSING** | 64-rule equivalent scanners, whole/stream, large/small/FP/Unicode/PEM/worst-case, 18 profiles |
| Language-selection ADR | Missing | **MISSING** | Rust selected with Go tradeoffs recorded |
| External harness compatibility | Inventory only | **PARTIAL** | Pinned revision re-inspected; actual truth loader + scoring engine executed on handoffs |
| CP0 CI workflow | One job | **PARTIAL** | Required contract/corpus/harness, benchmark and external-contract lanes; 90-day artifacts |
| Security/redaction boundary | Principles | **PARTIAL** | Publication check rejects secret-shaped values, locators and absolute paths; handoff uses digests only |
| CP1 handoff | Short brief | **PARTIAL** | Implementation-ready Rust module, rule, interface, coverage and acceptance brief |
| PR acceptance checklist | Missing/merged | **MISSING** | New audit PR carries the complete checklist; PR #3 is cross-referenced, not rewritten |

## 4. Defects found and corrected

### D1 — Schema-valid impossible results (critical)

v0.1 allowed a result with `result_code: 1` / `CLEAN` while counts said `actionable > 0`, `detected > 0`, `verified_blocked > 0` or zero required inspection. JSON Schema alone could not compare the count fields. v0.2 adds conditionals for the obvious contradictions and recomputes every count and the final code from the records. A zero-required-scope scan is `INCOMPLETE`, never `CLEAN`.

### D2 — Optional coverage was misclassified

`required_scope` existed on source units but was ignored. A missing optional unit could force `INCOMPLETE`, and a missing required unit could be lost in the same total. v0.2 separates total and required counts and classifies on `required_uninspected`. Optional gaps remain visible and do not force a required failure.

### D3 — Broken coverage accounting

`required_scanners_missing` was added to the classifier's `uninspected` local value but not to result counts, so `discovered = inspected + blocked + uninspected` could fail. The field was removed from the CP0 record. Scanner selection belongs to orchestration, not source-unit coverage.

### D4 — Unstable identity and impossible locations

Unit and finding IDs were arbitrary strings. Findings could exceed inspected bytes or claim a line unrelated to the byte range. v0.2 defines SHA-256 identity formulas, requires content hashes and line counts, and validates byte range, line, line-end and evidence digest against bytes when content is available.

### D5 — Unverified blocks and silent policy requests

A block could be claimed with a boolean but without a linked request or unit. Requested-but-unapplied policy existed only in an outcome test. v0.2 requires one-to-one blocked-unit/applied-block/request reconciliation, `verified_non_access: true`, enforcement method, policy/origin/reason equality, and a request register with `APPLIED`/`NOT_MATCHED`/`UNSUPPORTED`/`INVALID`.

### D6 — CI could drift from the result

A CI object could claim acceptance inconsistent with the result or exit code. v0.2 CI records reference the exact result digest, use only `0/10/20/30`, check the accepted set and never accept `4`/`5`.

### D7 — No unified config schema or executable migration

The decision required one versioned configuration model, but only prose existed. CP0 now defines `config.schema.json`, canonical `.rncscanner.toml`, a reviewed legacy subset, dual-source failure and global-only mandatory policy validation.

### D8 — Truth validation ignored rule association

The old corpus check compared a flattened sorted marker list. It could not distinguish a marker declared under the wrong rule, nor prove per-target accounting. The new loader materializes declared marker occurrences, verifies occurrence counts, hashes, scopes and overlapping-rule expectations, and rejects unaccounted markers.

### D9 — No independent grading

The stub emitted findings only. There was no execution/policy/result record, no scorer and no expected metrics. The new harness scores contract validity, execution accounting, detection, policy and classification/CI separately, and proves 18/18 controlled cases exactly.

### D10 — Required corpus edge cases were missing

The baseline lacked CR-only, binary/malformed input, empty/oversize, overlapping rules, stable IDs, cancellation and policy collisions. The v1 and edge lanes add these. Symlink/traversal enforcement remains a CP1 adapter test, not a CP0 production claim.

### D11 — Benchmark was not representative

The original probes measured only file read plus a literal byte search. The audit adds shared compiled rules, capture groups, validation, whole-file/streaming, high/low density, 2,000 small files, 64 rules, FP-heavy, Unicode, multiline, worst-case/ bounded execution and thread variants.

### D12 — No language decision

The preliminary result did not justify choosing Rust. ADR-007 selects Rust on representative regex/adversarial evidence while recording Go's faster many-small-files, build and static-distribution advantages.

### D13 — Harness compatibility was asserted, not tested

The inventory named the external harness but had no concrete export. CP0 now exports its schema-v1 line-addressed truth/finding contract and executes the pinned harness's own loader and scoring engine. The audit also found and removed a real same-line collision in `binary.bin` that made two findings ambiguous under line scoring.

### D14 — CI evidence was narrow and short-lived

The single job did not run an independent scorer, representative benchmark or external-contract check; artifacts lasted 14 days. The new workflow separates required lanes, fails on missing toolchains, preserves machine-readable evidence for 90 days, and tests deterministic generation twice.

### D15 — No publication-safety check

The old tests did not reject secret-shaped values or private paths in public records. CP0 adds a fail-closed publication check and a redacted handoff.

## 5. Contract revision v0.2

Seven schemas validated at `0.2.0`:

1. `source-unit.schema.json`
2. `finding.schema.json`
3. `execution.schema.json`
4. `policy.schema.json`
5. `result.schema.json`
6. `ci-decision.schema.json`
7. `config.schema.json`

Key invariants are documented in [contracts/README.md](../contracts/README.md), and the v0.1 → v0.2 compatibility consequences in [compatibility.md](../contracts/compatibility.md). v0.1 records are rejected, not silently promoted.

Validation evidence:

```text
python -m tools.cp0.validate
status: CP0_CONTRACTS_VALIDATED
schemas: 7
v0 corpus: 9 targets / 14 markers / 13 expected findings
v1 corpus: 21 targets / 26 markers / 25 expected findings
outcome cases: 28 (12 baseline + 16 expanded) × 3 acceptance sets
config fixtures: unified + explicit legacy migration + dual-source rejection
```

## 6. Synthetic corpus and scoring

### Authored lanes

| Lane | Targets | Unique markers | Expected findings | Notable coverage |
| --- | ---: | ---: | ---: | --- |
| `synthetic-v0` (preserved) | 9 | 14 | 13 | Baseline clean/TP/blocked/duplicate/decoy/Unicode |
| `synthetic-v1` (expanded) | 21 | 26 | 25 | CRLF, CR-only, BOM, binary/invalid UTF-8, empty, no trailing newline, nested path, overlapping rules, multiline PEM, exempted/actionable mixed, optional uninspected |
| `synthetic-edge-v1` (generated) | 2 | 4 | 3 | 2 MiB file, 9 MiB oversize required uninspected unit |
| Generated breadth | 1,000 | — | 2,000 | Deterministic hashes, locations, dispositions, 35 verified-blocked targets |

The v1 difference between 26 unique markers and 25 expected findings is deliberate: one blocked and one optional-uninspected marker are not detection expectations, while the overlapping-rules target contributes two expected rule findings for one marker occurrence. Every inspected expected finding is accountable by target, rule, byte range and evidence digest; blocked/uninspected scope is separately accounted.

### Independent harness

`tools/cp0/harness.py` consumes a v0.2 bundle and the independent truth manifest. It reports:

- contract valid/invalid and error codes;
- target accounting, missing required/optional units, scope mismatches, unexpected units;
- expected/matched/missed/unexpected/false-positive/duplicate/scope-violation counts;
- recall and precision, with precision as a separate field;
- policy correctness, disposition mismatches, applied/requested counts;
- result and CI correctness separately.

`python -m tools.cp0.harness --self-check` produces **18/18 correct cases, 100%**, including deliberately missed findings and false positives. It also proves default CI rejects `ACTIONABLE`, explicit acceptance works, and all-exempt policy yields `POLICY_APPLIED` with an unchanged raw detection count.

The scoring is calibrated against a manifest-reading stub. This is **not** scanner accuracy evidence.

## 7. Representative Go/Rust comparison

Both disposable scanners share:

- the same 64-rule table (8 active + 56 scale rules) and pinned regex semantics;
- capture groups, candidate validation, deduplication, canonical checksum;
- whole-file and 256 KiB streaming with 8 KiB overlap;
- identical output contract and failure behavior.

Profiles: 32 MiB low/high density, 2,000 small files (1/4 threads), 8 MiB FP-heavy, 8 MiB Unicode, 8 MiB expanded ruleset, 8 MiB worst-case, 8 MiB multiline. Every run is checked against an independently generated expected count and FNV-1a checksum. Alternating run order, warmups and five repetitions prevent ordering bias; peak RSS/CPU are captured through GNU time where available. Build times, binary sizes, toolchains and dependency trees are recorded.

Local audit run (Windows, Go 1.27.3, Rust 1.85.0, 3 runs) showed both implementations correct on all 18 profiles. Rust had lower median latency on 13/18 profiles, including the security-relevant FP-heavy, worst-case and large-rule-set loads; Go was faster on the many-small-files profiles. The pinned CI run is the authoritative evidence and uses Go 1.23.4 / Rust 1.85.0 on one Ubuntu runner with five runs. Raw host-dependent results are retained as CI artifacts rather than copied as a release benchmark.

**Language decision:** Rust, [ADR-007](../architecture/adr-007-detector-language.md). Go remains a comparator; it is not a second production engine.

## 8. External harness compatibility

Pinned harness: `RNC-Solutions-Group/gitleaks@test/scan-harness`, revision `86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f`, scoring schema version 1.

CP0 exports line-addressed normalized findings, truth items, scope items (`BLOCKED`/`SKIPPED`), byte metadata and a policy/result sidecar. The pinned external truth loader and scoring engine were executed on four synthetic handoffs:

| Case | Expected | Matched | Missed | FP | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| synthetic-v1 perfect | 25 | 25 | 0 | 0 | COMPLETED |
| synthetic-v1 miss-one | 25 | 24 | 1 | 0 | COMPLETED |
| synthetic-v1 false-positive | 25 | 25 | 0 | 1 | COMPLETED |
| synthetic-v0 perfect | 13 | 13 | 0 | 0 | COMPLETED |

No external corpus was downloaded or scanned. Native corpus scores and RNC normalized scores remain separate. The known line-granularity collision and outstanding integration tasks are recorded in [harness-handoff.md](../contracts/harness-handoff.md).

## 9. Configuration

- Canonical repository file: `.rncscanner.toml`.
- Legacy `security.config` is read only through an explicit reviewed subset; if both files exist, `CONFIG_DUAL_SOURCE` fails the run.
- Mandatory policies can originate only globally.
- CI acceptance defaults to `{1, 2}`; `3` requires explicit opt-in; `4`/`5` cannot be accepted.
- Limits are positive; symlink following is disabled; unsanitized legacy reporting fails.
- The reference loader and migration are tested; the production policy engine remains CP2.

## 10. Security and redaction

- All committed fixtures use harmless `RNC_SYNTH_KEY_*` values, never real credentials.
- Findings carry evidence digests and offsets, not matched bytes.
- Public handoff/result checks reject secret-shaped strings, absolute paths, `..`, and forbidden private keys.
- Execution/policy/finding records are private; only result and CI decision are publication-safe.
- External corpus material, raw findings and private evidence remain outside this repository.
- No network probing, credential validation or external service was used.

## 11. CI and reproducibility

The workflow `.github/workflows/cp0-contracts.yml` has three required lanes:

1. **contracts, corpus and synthetic harness** — validation, 69 tests, deterministic 1,000-target generation twice, edge corpus, stub modes, harness self-check, handoff export;
2. **equivalent Go/Rust benchmarks** — pinned Go 1.23.4 and Rust 1.85.0, literal baseline, representative 18-profile benchmark, machine-readable artifacts;
3. **pinned independent-harness scoring contract** — fetches the exact external revision by SHA and executes its truth loader/scoring engine on CP0 handoffs.

Missing toolchains fail the job; they are not skipped and reported as success. Artifacts are retained for 90 days. No secrets or raw matched values are uploaded.

<!-- CI_EVIDENCE -->

## 12. Known limitations and deferred work

1. **No production detector.** CP1 is not started. The synthetic stub is not product code.
2. **No external corpus execution.** Levain, Leaky Repo and Prowlbench were not run. External accuracy claims are prohibited until the harness adapter and corpus gates pass.
3. **Line-granularity compatibility.** The external harness cannot distinguish two same-rule findings on one line. The CP0 corpus avoids this collision; CP1 must define a composite policy or extend the harness.
4. **Config implementation is a reference.** The production loader/policy engine belongs to CP2. The legacy subset is intentionally narrow; unknown fields fail closed.
5. **No real input adapter.** Symlink/TOCTOU/oversize behavior is specified and partly exercised by unit truth, but bytes are not acquired by a production adapter in CP0.
6. **Memory measurement depends on GNU time.** CI supplies it; local Windows runs report memory/CPU unavailable rather than estimating.
7. **Schema is pre-1.0.** v0.2 is a CP0 revision, not a released compatibility guarantee. Any production record change requires the documented migration/version policy.
8. **Rust distribution work remains.** Static musl/Linux, Windows and macOS cross-builds must be validated in CP1/CP4; the ADR records the risk.
9. **No operator acceptance yet.** Passing checks do not authorize CP1 implementation or a PR merge.

## 13. CP0 acceptance checklist

- [x] All seven schemas validate under JSON Schema 2020-12.
- [x] Cross-record identities, counts, precedence, policy provenance and digests are enforced.
- [x] Optional versus required coverage is unambiguous and tested.
- [x] Synthetic truth is independent of scanner output and every expected fixture has ground truth.
- [x] Controlled stub scenarios grade at 100% (18/18).
- [x] Baseline claims (9/14/1,000/2,000/12) are independently verified.
- [x] Representative Go/Rust workloads are equivalent and correctness-checked.
- [x] Rust selection is recorded with alternatives and tradeoffs.
- [x] `.rncscanner.toml` and explicit legacy migration are specified and reference-tested.
- [x] Default CI acceptance and `4`/`5` rejection are enforced independently of result codes.
- [x] Public/redaction checks fail closed for secret-shaped values and locators.
- [x] Pinned external harness scoring engine accepts the synthetic handoff.
- [x] CP1 module boundaries, interfaces, rule lifecycle, coverage and acceptance tests are documented.
- [ ] Final CI run green and evidence recorded.
- [ ] Operator accepts the CP0 package; no merge or CP1 implementation by the agent.

## 14. Readiness classification

**Pending final CI evidence.** If the required workflow is green, the CP0 package is **READY** for operator acceptance, with the limitations in §12 disclosed. It is not **accepted**, and CP1 remains blocked until the operator decides.
