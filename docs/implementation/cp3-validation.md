# CP3 validation - detection intelligence and accuracy

> **Historical CP3 evidence.** CP3 was merged into the authorized CP4 baseline.
> CP4 now provides a read-only Git-history adapter and a 37-rule catalog; those
> later capabilities do not change this CP3 evidence. CP4A retired the internal
> benchmark job from routine CI; this report and its measured results remain as
> historical evidence, while the independent harness owns future benchmarking.
> See [CP4 validation](cp4-validation.md) and
> [CP4A hardening](cp4a-hardening.md).

> **Status:** CP3 corrective review complete; **READY FOR OPERATOR MERGE**.
> Provider format recognition is not proof of an active, authorized, complete or
> non-revoked credential.

## Repository state

| Field | Value |
| --- | --- |
| Branch | `feat/cp3` |
| Reviewed starting head | `13b1d6b40cc56b7389bbd2eeef7d70794c15a68c` |
| Final implementation head | `8c004945fc64ac11d3947c73acc65b100c803d90` |
| Documentation evidence | branch head at report time; see PR [#10](https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/10) |
| Pull request | [#10](https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/10) |
| Target | `feat/cp4` (operator redirected PR #10 from `main`) |
| Merge | Operator-owned; no merge performed |
| Base | `feat/cp4` at `e54d5bc`; `main` remains at `e54d5bc` |

The CP2 implementation, CP0-CP2 contracts and all synthetic v0/v1 truth are
preserved. CP3 still uses a separate provider catalog; it does not change the
synthetic bundles' schema or established digests.

### Operator CI workflow correction

The operator added commit `8c00494` ("Change push branch from feat/cp3 to main")
to `.github/workflows/cp3-provider.yml`. It changes only the `push.branches`
filter from `feat/cp3` to `main`; the `pull_request` trigger remains
branch-independent, so PR #10 still executes after the target was redirected to
`feat/cp4`. This is an operator-owned CI correction; the corrective CP3 code did
not alter the workflow semantics. The green CP3 run below was created by the
`pull_request` event at `8c00494`, not by a push to `feat/cp3`.

## Corrective findings and dispositions

| Finding | Root cause | Correction | Tests | Disposition |
| --- | --- | --- | --- | --- |
| AWS resource identifiers classified as access keys | One rule/validator accepted all 12 IAM unique-ID prefixes and called them access-key IDs | `aws-access-key-id` limited to `AKIA`/`ASIA`; `ABIA` and `ACCA` moved to distinct identifier rules; eight resource prefixes no longer emitted | AWS taxonomy 20 cases x 2 modes x 4 strategies; Rust validator tests | Corrected |
| Gitleaks observation reuse | Matcher used path plus substring and did not enforce one-to-one assignment; positions and duplicates were insufficiently verified | Deterministic maximum-cardinality one-to-one byte reconciliation with family, position, duplicate, ambiguity and unscored handling | 18 comparator negative controls; Tier 2/Tier 3 re-run | Corrected |
| Modern GitHub installation tokens missed | `ghs_` was folded into the OAuth rule with an alphanumeric, fixed-ish body assumption | Dedicated `github-app-installation-token` rule/validator for legacy opaque and stateless `ghs_APPID_JWT`; OAuth rule no longer claims `ghs_` | Legacy, modern, variable length, malformed, punctuation, same-line, boundary, oversize, all strategies | Corrected |
| Tier 2/3 independence overstated | Both corpora use the same fixture generator, templates and seed conventions | Shared dependency documented; hand-authored Tier 4 challenge added with its own templates/seeds, explicit oracle and separate reporting | Challenge manifest reproducibility, 14/14 exact findings, 24-case integration | Improved, with stated limits |

## Delivered

- Provider schema `0.2.0`, ruleset `2026.11.2`, **19 rules across 12 families**.
- Dedicated AWS access-key and sensitive-identifier taxonomy.
- Legacy and stateless GitHub App installation-token coverage.
- Tier 2 controlled corpus: 24 files, 27 expected occurrences, four negative
  files.
- Tier 3 separately specified held-out corpus: 10 files, 15 expected occurrences.
- Tier 4 hand-authored challenge: 9 files, 14 expected occurrences, one negative
  file. It does not reuse the Tier 2/3 generator.
- Independent byte-addressed truth, scorer, one-to-one comparator, negative
  controls and coverage gate.
- External harness adapter with explicit line-addressing limitation.
- Scoped Levain, Leaky Repo and corrected Gitleaks evidence.
- Corrected provider benchmark with a long installation-token workload.
- CP3 CI with quality, accuracy, external-harness, benchmark, cross-platform,
  musl and dependency-audit lanes.

Catalog: [`rules/rnc-providers-v1.json`](../../rules/rnc-providers-v1.json),
digest `sha256:3ddd1e0aee36ecadb67ee8a2032fbe3a6047803bb56c0d45d65f85851c9b2142`.
See [cp3-detection-catalog.md](cp3-detection-catalog.md).

## Verification suites

| Suite | Result |
| --- | --- |
| Rust workspace, `--all-targets` | **106 tests** pass on Linux CI: 61 core + 10 CLI integration + 9 CLI unit + 18 engine + 4 provider + 2 AWS taxonomy + 2 GitHub installation. Local Windows runs **95** because platform-gated tests are excluded. |
| CP0 contract/corpus/harness | **74 tests** pass |
| CP1 synthetic rules | **5 tests** pass |
| CP3 Python schema/scorer/adapter/security | **55 tests** pass |
| CP2 differential integration | **20 cases**, `all_correct`, `all_equivalent` |
| CP2 policy/classification | **23 cases**, `all_passed` |
| CP1 synthetic integration | v1/v0/edge pass |
| Provider catalog validation | 19 rules valid under all four strategies |
| Provider integration | **24 cases** (Tier 2, Tier 3, challenge x 2 modes x 4 strategies), all correct and equivalent |
| Gitleaks comparator negative controls | **18** deterministic controls pass |

## Controlled accuracy

All results use exact byte ranges and exact expected rule identity.

| Dataset | Expected | TP | FP | FN | Precision | Recall | Duplicates | Ambiguous | Coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Tier 2 provider fixture | 27 | 27 | 0 | 0 | 100% | 100% | 0 | 0 | 100% |
| Tier 3 held-out | 15 | 15 | 0 | 0 | 100% | 100% | 0 | 0 | 100% |
| Tier 4 hand-authored challenge | 14 | 14 | 0 | 0 | 100% | 100% | 0 | 0 | 100% |

The result is identical for `whole` and `stream` under `regex`, `regexset`,
`prefilter` and `auto`. Tier 3 was not used to tune individual rules. Tier 4 is
not an externally sourced corpus; its provenance is explicit in the manifest.

The 24-case integration run also validates CP0 records, exact offsets, finding
identities, validation status, coverage, private-report non-disclosure and CI
acceptance for every case. All 24 cases produce the same canonical findings across
modes and strategies.

## AWS classification evidence

The taxonomy has 20 cases, including all 12 AWS prefixes, invalid prefix/length/
characters, the AWS docs placeholder, multiple identifiers on one line, an IAM
JSON policy containing only resource identifiers, a policy containing a real
`AKIA`, and punctuation boundaries.

Result under both modes and all strategies:

- `AKIA`/`ASIA` only -> `aws-access-key-id`;
- `ABIA` only -> `aws-sts-service-bearer-token-id`;
- `ACCA` only -> `aws-context-specific-credential-id`;
- `AIDA`/`AGPA`/`AIPA`/`ANPA`/`ANVA`/`APKA`/`AROA`/`ASCA` -> no credential finding;
- 10 expected findings total in the generated taxonomy fixture; no resource
  identifier was reported.

`ABIA`/`ACCA` findings are `PLAUSIBLE_UNVERIFIED` with identifier-only notes and
medium confidence. A bare identifier is not proof of a complete usable
credential.

## GitHub installation-token evidence

The dedicated suite covers:

- legacy 40-character opaque `ghs_` tokens;
- stateless `ghs_APPID_JWT` tokens at variable segment lengths;
- modern tokens adjacent to punctuation and multiple tokens on one line;
- incomplete tokens, missing app separator, one-dot/two-dot malformed variants,
  placeholders and oversize values;
- whole/stream boundary crossings and all four strategies;
- parser/candidate bounds: oversized modern segments are not emitted and the scan
  still completes.

Legacy tokens are `FORMAT_VALID`; modern stateless tokens are
`PLAUSIBLE_UNVERIFIED`. No signature, issuer, claim or online validity is
trusted.

## External evidence

### Pinned independent harness (line-addressed)

At revision `86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f`:

- matched: **25/27**
- ambiguous: **2** (two distinct same-line GitHub occurrences)
- false positives: **0**
- missed: **2** (the same-line items the line model cannot disambiguate)

The byte scorer classifies both same-line items correctly. This remains
compatibility evidence, not the authoritative accuracy score.

### Levain (MIT)

| Metric | Value |
| --- | ---: |
| Mapped expected positives | 31 |
| TP | 30 |
| FP | 0 |
| FN | 1 |
| Precision | 100% |
| Recall | 96.77% |
| F1 | 98.36% |
| Negative-corpus findings | 0 |
| Out-of-scope unsupported-family observations | 5 |

The one miss is a deliberately malformed PEM whose base64 body is not decodable.
RNC rejects it structurally. Unsupported Levain kinds are excluded from the
denominator, not counted as RNC failures. Re-running after the AWS correction did
not change this scoped score.

### Leaky Repo (MIT)

Count-based inventory, not credential-level truth:

- observed findings: **33**
- covered count: **33/175** (18.86%)
- files covered: **18/44**
- excess findings: **0**
- unlisted findings: **0**

No TP/FP/precision/recall is claimed.

### Gitleaks

Pinned build `sha256:c8bf14bc271caf34692dc76ea008f7932b4916fcf27254440e178775177ffc98`,
native default configuration, same filesystem fixtures.

Original (pre-correction) measurement:

| Dataset | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Tier 2 | 22/27 | 2 | 5 | 91.67% | 81.48% | 86.28% |
| Tier 3 | 11/15 | 0 | 4 | 100% | 73.33% | 84.61% |

Corrected one-to-one measurement:

| Dataset | TP | FP | FN | Duplicates | Ambiguous | Unscored | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Tier 2 | 22/27 | 0 | 5 | 2 | 0 | 0 | 100% | 81.48% | 89.80% |
| Tier 3 | 11/15 | 0 | 4 | 0 | 0 | 0 | 100% | 73.33% | 84.61% |

The two original Tier 2 false positives were duplicate decoded private-key
observations at the same source span. The corrected reconciler counts them as
duplicates, not TP or FP. Tier 3 was unaffected. The original result is preserved
above and in the prior CI artifact; it has not been silently rewritten.

This is a controlled-corpus coverage comparison, not a general product ranking.
Gitleaks supports families outside the RNC catalog and has Git-history capability
that RNC does not implement. Betterleaks was not executed because no pinned
binary or image was available.

## Backend correctness

| Requirement | Result |
| --- | --- |
| Equivalent rules/family | Yes |
| Equivalent byte offsets | Yes |
| Equivalent captures | Yes |
| Equivalent validators/status | Yes |
| Equivalent evidence digest | Yes |
| Equivalent finding identity | Yes |
| Equivalent coverage/result | Yes |
| Fallback behavior | Explicit; no silent rule skip |
| Unresolved mismatch | None on the controlled corpora (24 cases) |

`regex` remains the reference. `auto` selects reference regex. `prefilter` uses
Aho-Corasick required literals with exact-regex fallback for rules without a
proven literal; `regexset` uses the required-literal filter plus exact regex.
17 of 19 rules have proven literals; two use explicit exact-regex fallback. No
pathological full-pattern RegexSet implementation was reintroduced.

## Security

- Candidate materialization is capped at 100,000 per window; exceeding the cap
  makes the unit uninspected and the execution interrupted/failed, not clean.
- Rule count, pattern size, match length and candidate length are bounded.
- Validators reject oversize/malformed JWT segments, invalid base64/DER, PEM
  label mismatches and placeholder bodies. Validation errors carry static
  reasons, never candidate bytes.
- Public artifacts contain no raw fixture values, private locators or absolute
  host paths; `tools/cp3/privacy_check.py` passes and now also checks the Tier 4
  challenge values.
- No network validation, credential redemption, provider authentication or
  external build-script execution occurred.
- Existing CP2 source containment, report publication, policy authority and CI
  safeguards are unchanged. Issues #7-#9 remain open platform residuals; this
  correction did not absorb or silently close them.
- Raw provider-shaped fixture bytes remain outside Git where necessary; the
  provider bundle is hex-encoded and materialized only in temporary roots. The
  independently authored challenge is generated at test time.

## Performance

See [cp3-benchmark-methodology.md](cp3-benchmark-methodology.md). The corrected
benchmark has **88 profiles** (11 workloads x 2 modes x 4 strategies).

Local Windows reference build: **38.150 s**, binary
**2,650,624 bytes**, SHA-256 `183323e7...`. Rule compilation median
**80.661 ms**, p95 **80.713 ms** (three runs). Local CPU/RSS fields are `null`
because GNU `time` is unavailable; the isolated Linux CI benchmark supplies
CPU/RSS.

### Local whole-file medians

| Workload | Regex ms | RegexSet ms | Prefilter ms | Auto ms |
| --- | ---: | ---: | ---: | ---: |
| `large-low` | 170.5 | 163.4 | 132.6 | 226.3 |
| `large-high` | 226.8 | 181.2 | 233.5 | 233.8 |
| `github-installation-long` | 142.3 | 123.1 | 133.3 | 144.9 |
| `small-many` | 411.3 | 324.7 | 300.8 | 400.4 |
| `fp-heavy` | 260.5 | 235.9 | 298.9 | 253.8 |

Final CI Linux benchmark (`cp3-benchmark-evidence`, run `43101673071`):

- Build: **33.304 s**
- Binary: **3,172,912 bytes**, SHA-256
  `10a1f757e0eb9d892dc54f74f247420af5e7ffa9ed51ef888f96c579bc959516`
- Rule compilation: median **45.171 ms**, p95 **48.256 ms**
- **88 profiles** (11 workloads x 2 modes x 4 strategies), all expected finding
  counts correct

| Workload | Regex ms | RegexSet ms | Prefilter ms | Auto ms | Regex peak RSS KiB | Regex CPU % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `large-low` | 147.7 | 115.4 | 125.3 | 147.0 | 31,216 | 94.72 |
| `large-high` | 189.9 | 156.8 | 164.3 | 189.6 | 39,936 | 94.78 |
| `github-installation-long` | 107.4 | 99.9 | 104.1 | 107.3 | 27,088 | 93.08 |
| `small-many` | 66.7 | 65.1 | 64.9 | 66.3 | 23,720 | 89.22 |
| `fp-heavy` | 212.8 | 223.8 | 220.5 | 212.2 | 27,776 | 93.99 |

On the controlled CI host, the new installation-token workload is
**107.4 ms** under reference regex and **99.9 ms** under RegexSet. Large-high is
**189.9 ms** regex and **156.8 ms** RegexSet. The RegexSet implementation
remains the required-literal filter, not the pathological full-pattern set.
The prior CI run for the 16-rule catalog measured build 35.158 s, binary
3,168,816 bytes and compile median 39.1 ms; the corrected catalog adds a rule,
a workload and the modern token path. That is a workload-plus-engine change,
not a pure speedup or regression claim.

The provider catalog is materially slower than the synthetic 10-rule CP2
baseline, as expected from 19 rules, multiline PEM/JWT structure and validation.
No validator was removed to recover throughput. Local and CI numbers are from
different hosts and are not a controlled cross-host comparison.

## Required CI

Final implementation/workflow head `8c004945fc64ac11d3947c73acc65b100c803d90`
passed the complete corrective matrix. The operator CI correction in `8c00494`
changes only the push branch filter; the `pull_request` event is branch-independent
and ran the PR-targeted workflows.

### CP3 required run

[Run 43101673071](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43101673071)
completed **success**. All seven required jobs passed:

- quality, provider rules, byte accuracy and external adapter;
- provider catalog benchmark;
- Ubuntu 24.04 build/tests;
- Windows build/tests;
- macOS build/tests;
- static Linux musl build;
- dependency advisory audit.

The quality job ran 106 Rust tests (Linux; platform-gated tests make local
Windows 95), 74 CP0 tests, 5 CP1 tests and 55 CP3 Python tests. It validated all
19 provider rules under all four strategies and ran the 24-case provider
integration: `all_correct=true`, `backend_equivalent=true`, three dataset groups,
Tier 2 27/27, Tier 3 15/15 and Tier 4 14/14. The external line harness reported
25 matched, 2 ambiguous, 0 false positives. Privacy check returned **PASS**.

The benchmark job produced **88 profiles**, all correct. Build **33.304 s**,
binary **3,172,912 bytes**, SHA-256
`10a1f757e0eb9d892dc54f74f247420af5e7ffa9ed51ef888f96c579bc959516`;
rule compilation median **45.171 ms** (p95 **48.256 ms**).

Sanitized artifacts:

- `cp3-integration-accuracy-evidence` — artifact ID `13890589771`,
  digest `sha256:ea90d5a2182ed060205e0da8c0ec71b201261d3d1d2b6c382179114bffc5e050`;
  24/24 correct and equivalent; external 25 matched + 2 ambiguous; privacy PASS.
- `cp3-benchmark-evidence` — artifact ID `13891343299`,
  digest `sha256:642765a0e6f01cb86ed643a28c69f1059ed97f942f51bd9cb21c06ae0b863e53`;
  88 profiles.

### Other required checkpoints at the same head

- CP0: [run 43101672932](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43101672932) — success.
- CP1: [run 43101672867](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43101672867) — success.
- CP2: [run 43101673069](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43101673069) — success.

The historical pre-correction CP3 runs `43087012245` at `c8779e9` and
`43087717965` at `13b1d6b` remain preserved but are not evidence for the
corrected rules.

## Historical pre-correction evidence

The reviewed `13b1d6b` state had:

- 16 provider rules across 12 families, digest `sha256:e2900d90...`;
- Tier 2 27/27 and Tier 3 15/15, 16 integration cases;
- Gitleaks Tier 2 22 TP / 2 FP / 5 FN (precision 91.67%, recall 81.48%,
  F1 86.28%) and Tier 3 11 TP / 0 FP / 4 FN;
- the first CI artifact set `cp3-integration-accuracy-evidence` ID
  `13886408382` and `cp3-benchmark-evidence` ID `13887865802`.

Those values are retained so the correction can be audited. They are not the
corrected implementation's score.

## Limitations and disposition

### Known limitations

**P0 - none identified.** No source-containment, report-publication, evidence
integrity or CI-authority defect was found or introduced by the corrective work.

**P1 - documented residuals (not CP3 acceptance blockers):**

- RNC Scanner has no Git-history input adapter. All external comparisons are
  filesystem-to-filesystem; Git-history capability is `NOT_APPLICABLE`.
- Windows path-based directory enumeration (#7), inherited private-evidence ACLs
  (#8) and OS-signal cancellation (#9) remain open CP2 platform residuals.
- Betterleaks was not executed because no pinned binary or image was available.
- The Levain result is scoped to declared families (**30/31**); the miss is a
  deliberately malformed PEM. It is not a universal real-world recall claim.
- Leaky Repo provides count coverage, not credential-level truth.
- The external harness is line-addressed; its **2 ambiguous** same-line results
  are preserved as a limitation.
- `ABIA`/`ACCA` identify sensitive credentials but are not complete credential
  proofs. Modern `ghs_APPID_JWT` tokens are opaque and structurally validated
  only. Provider-format recognition is not active-credential verification.
- Tier 4 is hand-authored by the same project, not externally sourced. It
  reduces shared-generator dependence but does not prove broad generalization.

**P2 - future work:**

- Add checksum/structural checks where providers publish them without
  introducing false negatives.
- Expand provider families and rule lifecycle evidence.
- Add Git-history and additional source adapters.
- Evaluate Betterleaks and additional pinned comparators when binaries and
  licenses are available.
- Add phase-level acquisition/matching/report timing.

### Disposition

**READY FOR OPERATOR MERGE.** The AWS misclassification, one-to-one comparator
defect and modern GitHub installation-token gap are corrected and tested.
Controlled accuracy is **27/27**, **15/15** and **14/14** with strategy
equivalence. The final implementation/workflow head passed all four required
checkpoint workflows and all seven CP3 jobs, including Ubuntu, Windows, macOS,
musl and dependency audit. The documented residuals - absent Git-history adapter,
unavailable Betterleaks, Windows #7-#9 platform hardening, scoped external
corpora, identifier-only AWS semantics and the first-party Tier 4 corpus - remain
visible but do not invalidate the corrective acceptance evidence. No condition
is hidden as a passing accuracy claim. No merge was performed; the operator owns
the merge decision.
