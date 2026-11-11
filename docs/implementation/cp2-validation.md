# CP2 integrated scanner — validation report

> **Status:** CP2 implementation and required CP2 CI complete; awaiting operator review. PR [#6](https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/6) targets `main`; no merge has occurred. CP0/CP1 foundation commits are present in `feat/cp2`.

## Repository state

| Item | Value |
| --- | --- |
| Branch | `feat/cp2` |
| Starting commit | `e20ac29` (operator merge of CP1 into `feat/cp2`) |
| Final implementation commit | `5a97de5` (plus this documentation commit) |
| PR | https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/6 |
| Target | `main` |
| Merge status | Open / unmerged |

## Implementation

| Area | Delivery |
| --- | --- |
| Backends | `crates/rnc-core/src/backend.rs`: reference regex, RegexSet, Aho-Corasick prefilter, capability/provenance |
| Candidate contract | `MatchCandidate { rule_index, start, end }`; capture semantics applied before validation |
| Planner | `auto` → reference regex; explicit strategies; deterministic fallback with recorded reason |
| Streaming | Bounded windows, max-match carry, deferred edge candidates, final-carry rescan |
| Configuration | `crates/rnc-core/src/config.rs`: TOML, global/repository/CLI, mandatory caps, provenance, legacy migration |
| Scope policy | `crates/rnc-core/src/policy.rs` + `input.rs`: glob selectors, inherited directory blocks, verified non-access |
| Exemptions | Post-detection dispositions; raw findings immutable; expiry/shadowing deterministic |
| Ledgers | Execution, findings and policy records reconciled before finalization |
| Classification | Five results with `FAILED > INCOMPLETE > ACTIONABLE > POLICY_APPLIED > CLEAN` |
| CI | Default `{1,2}`, explicit `3`, never `4/5`; exits 0/10/20/30 and 64 for invalid invocation |
| Reporting | Sanitized allowlist JSON; private evidence outside root; `0600` on Unix; publication failure is nonzero |
| CLI | `scan`, `rules validate`, strategy/config/acceptance/policy options |

### Strategies

| Requested | Effective | Mechanism |
| --- | --- | --- |
| `regex` | reference regex | Every rule's exact regex; authoritative |
| `regexset` | RegexSet | Set selects patterns, exact regex extracts spans |
| `prefilter` | Aho-Corasick | Proven required literals filter rules; exact regex remains authoritative |
| `auto` | reference regex | Conservative; no unjustified promotion |

Required-literal extraction is sound-by-construction and conservative: alternation requires a common prefix across every branch; variable/optional constructs stop extraction; no-literal rules always run exact regex.

## Correctness

### Test inventory

- **52 Rust tests**: path/config/policy/result/backend units, engine integration, CLI integration.
- **5 CP1 Python rule tests** and **74 CP0 regression tests**.
- **20 CP2 integration cases**: v0/v1/edge × whole/stream × regex/regexset/prefilter/auto.
- **22 CP2 policy/configuration/classification scenarios** in Linux CI.
- **4 external scoring handoffs**, one per strategy.

### Independent truth

Every strategy produced:

| Corpus | Modes | Expected | Actual | Result |
| --- | --- | ---: | ---: | --- |
| synthetic-v1 | whole, stream | 25 | 25 | ACTIONABLE (3) |
| synthetic-v0 | whole, stream | 13 | 13 | ACTIONABLE (3) |
| synthetic-edge | stream | 3 | 3 | INCOMPLETE (4) |

All 20 cases validated v0.2 schemas and cross-record invariants. Canonical findings, units, result and CI exit were identical across strategies. Edge cases include LF/CRLF/CR-only, BOM/Unicode, binary/invalid UTF-8, multiline, overlapping rules, repeated markers, boundary crossing, empty files, oversize and optional coverage.

### External harness

Pinned revision `86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f` scored the actual CP2 handoff for **each** strategy:

| Strategy | Expected | Matched | Missed | Unexpected | False positive | Duplicate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| regex | 25 | 25 | 0 | 0 | 0 | 0 |
| regexset | 25 | 25 | 0 | 0 | 0 | 0 |
| prefilter | 25 | 25 | 0 | 0 | 0 | 0 |
| auto | 25 | 25 | 0 | 0 | 0 | 0 |

Scoring status `COMPLETED`, execution `PASS`. This is synthetic scoring-engine integration only: **no external corpus was executed and no production accuracy claim is made.**

### Policy/classification scenarios

CI passed 22 scenarios:

clean; verified pre-scan block; mixed exemption; fully exempted; incomplete required coverage; failed execution; optional uninspected; zero required scope; requested-but-unmatched block/exemption; mandatory global block; global acceptance cap; dual repository sources; reviewed legacy migration; limit precedence; invalid selector; sanitized output; explicit actionable acceptance; rejected `POLICY_APPLIED`; incomplete-with-findings; overlapping-block collision; Unix unreadable-file no-access proof.

The incomplete-with-findings case proves lower-priority actionable evidence remains present while the final result is `INCOMPLETE`.

## Performance

CI run [42947298472](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/42947298472), Linux x86_64, 4 vCPU, 3 repetitions per profile, release build:

- Build: 21.473 s; binary: 3,021,360 bytes; binary digest `sha256:ea678524…`.
- Host: `Linux-7.0.0-1017-azure-x86_64-with-glibc2.39`.
- CP1 reference build from the previous checkpoint: 18.46 s, 2.39 MB binary. Runner load varies; compare correctness and relative strategy behavior, not absolute milliseconds across runs.

Representative medians:

| Workload | Mode | Regex ms / MiB/s | RegexSet ms / MiB/s | Prefilter ms / MiB/s | Auto |
| --- | --- | --- | --- | --- | --- |
| large-low 32 MiB | whole | 64.6 / 495.7 | 60.1 / 532.0 | 58.6 / 546.1 | regex 63.2 / 506.7 |
| large-high 32 MiB | whole | 92.8 / 344.8 | 91.1 / 351.1 | 94.8 / 337.6 | regex 94.7 / 337.9 |
| large-low 32 MiB | stream | 64.7 / 494.3 | 60.1 / 532.7 | 57.6 / 555.4 | regex 63.3 / 505.7 |
| large-high 32 MiB | stream | 201.9 / 158.5 | 197.1 / 162.4 | 196.1 / 163.2 | regex 196.1 / 163.2 |
| 2,000 × 4 KiB | whole | 55.4 / 141.0 | 53.2 / 146.8 | 52.6 / 148.5 | regex 54.4 / 143.7 |
| FP-heavy 8 MiB | whole | 42.4 / 188.7 | 46.7 / 171.2 | 64.9 / 123.3 | regex 42.9 / 186.6 |
| Unicode 8 MiB | whole | 19.0 / 420.2 | 17.9 / 447.0 | 16.8 / 476.4 | regex 18.3 / 436.1 |

Peak RSS was approximately 42–46 MB for whole large-file scans and 4.8–25 MB for streaming; CPU was approximately 52–96% of one core. Full samples, p95, files/s and per-profile CPU/RSS are in the artifact. Because this run was materially faster than the preceding CP2 run on the same runner class, absolute values are reported as observed rather than as a stable production prediction.

### Interpretation

- No portable strategy has a uniform advantage. Prefilter helps low-density/large and Unicode workloads but is materially slower on the false-positive-heavy workload because many rules have matching literals.
- RegexSet is close to regex and slightly better on large/Unicode profiles, but not uniformly.
- Auto therefore remains the reference backend. Explicit acceleration remains available for controlled use.
- CP2 is slower than CP1 on some profiles because it materializes candidates, validates all ledgers, computes record digests and builds configuration/policy. This is integrated-work overhead, not a like-for-like primitive comparison. No regression is hidden; the reference strategy remains the default.
- CP2 remains single-threaded.

## Security and adversarial validation

- Strict canonical locators; traversal/backslash/drive/UNC/control/bidi/device-name rejection.
- Symlink entries uninspected; `O_NOFOLLOW`/Windows reparse-point open closes discovery-to-read substitution.
- Pre-scan block proof on Unix by blocking a mode-`000` file: it remains `VERIFIED_BLOCKED`, which is only possible because it was not opened.
- Directory-wide blocks are inherited during enumeration; file contents are not opened.
- Duplicate/overlapping block requests resolve one deterministic winner; shadowed requests remain `UNSUPPORTED`.
- Exemptions cannot rewrite findings; expired/shadowed/unmatched requests do not apply.
- Unknown TOML fields, dual sources, mandatory-policy escalation, unsafe reporting and symlink following fail closed.
- Private output outside root with `0600` on Unix; sanitized output contains no locators, finding IDs, evidence digests or raw bytes.
- `FILE_CHANGED`, size/total/finding limits, timeout, partial reads and output publication failure are explicit failures or coverage gaps.
- No real credentials were used.

## Known issues

### P0

None identified.

### P1

1. **No OS-signal cancellation.** Cooperative deadline interruption exists; Ctrl-C/termination handling is deferred.
2. **Prefilter regression on FP-heavy content.** Explicit prefilter is slower; auto does not select it. Investigate rule-literal density and candidate reuse before any promotion.

### P2

1. Single-threaded execution; parallel characteristics are recorded as not implemented.
2. Same-rule/same-line external-harness ambiguity remains; findings are byte-addressed but the pinned harness is line-addressed.
3. External corpora (Levain/Leaky Repo/Prowlbench) remain deferred.
4. Installer/signing and non-x86_64 packaging deferred; x86_64 musl build passes.
5. Committed rules are synthetic test rules, not a production signature set.
6. The private envelope is schema-checked by the independent Python validator in CI, not by a Rust JSON-Schema runtime.

## CI

CP2 workflow [42947298472](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/42947298472) at `5a97de5` passed all required jobs; CP0 and CP1 regression workflows also passed:

- quality, integration, policy and classification;
- multi-strategy benchmark;
- external harness scoring for all strategies;
- Ubuntu, Windows, macOS;
- static Linux musl;
- dependency advisory audit.

Artifacts:

- `cp2-integration-policy-evidence` — ID `13822479059`, digest `sha256:d1642e7a8fccd82cef9a2057154a6d158c638906ced04130db5375c1239ab9a9`.
- `cp2-benchmark-evidence` — ID `13822714653`, digest `sha256:25a4fcb911da8967fa5925cef4cb5ca0711b0caf90c19178ac58f4257eb8a1e6`.
- `cp2-external-harness-score` — ID `13823177341`, digest `sha256:371feebf9ad7d0b599e926565101e8dc798075d1781124f5af3e8d7f6422e1c9`.

Sanitized CI artifacts contain no private findings, locators or evidence digests. Private handoffs are generated in runner temp and scored without upload.

## Acceptance

- [x] Functional multi-strategy architecture with reference regex preserved.
- [x] RegexSet and Aho-Corasick strategies functional and differential-equivalent.
- [x] Deterministic planner and explicit fallback provenance.
- [x] Production unified configuration with mandatory caps and legacy migration.
- [x] Verified pre-scan blocks and post-scan exemptions.
- [x] Three ledgers, five-state classifier and CI exit semantics.
- [x] Sanitized/private reporting with redaction and path controls.
- [x] Independent synthetic scoring for every strategy.
- [x] Security/adversarial coverage and cross-platform/static-musl builds.
- [x] Documentation and ADRs.
- [ ] Operator review and merge.

**Readiness: READY for operator review.** All required CP2 CI gates pass; no unresolved correctness mismatch or security-critical defect is known. The P1/P2 items above are disclosed, not concealed; the default path avoids the measured prefilter regression.
