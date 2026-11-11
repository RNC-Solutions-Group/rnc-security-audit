# CP3 validation - detection intelligence and accuracy

> **Status:** CP3 corrective review complete; operator review pending. Provider
> format recognition is not proof of an active, authorized, complete or
> non-revoked credential.

## Repository state

| Field | Value |
| --- | --- |
| Branch | `feat/cp3` |
| Reviewed starting head | `13b1d6b40cc56b7389bbd2eeef7d70794c15a68c` |
| Final head | `PENDING-FINAL-HEAD` |
| Pull request | [#10](https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/10) |
| Target | `main` |
| Merge | Operator-owned; no merge performed |
| Base | `main` at `e54d5bc`; CP2 was merged into `feat/cp3`, not `main` |

The CP2 implementation, CP0-CP2 contracts and all synthetic v0/v1 truth are
preserved. CP3 still uses a separate provider catalog; it does not change the
synthetic bundles' schema or established digests.

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
| Rust workspace, `--all-targets` | **95 tests** pass: 59 core + 8 CLI integration + 5 CLI unit + 15 engine + 4 provider + 2 AWS taxonomy + 2 GitHub installation |
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

Local Windows reference build: **39.133 s**, binary
**2,650,624 bytes**, SHA-256 `f0bdf6b3...`. Rule compilation median
**76.993 ms**, p95 **81.144 ms** (three runs). Local CPU/RSS fields are `null`
because GNU `time` is unavailable; the isolated Linux CI benchmark supplies
CPU/RSS.

### Local whole-file medians

| Workload | Regex ms | RegexSet ms | Prefilter ms | Auto ms |
| --- | ---: | ---: | ---: | ---: |
| `large-low` | 232.1 | 147.4 | 161.2 | 221.1 |
| `large-high` | 250.9 | 174.4 | 172.1 | 195.0 |
| `github-installation-long` | 139.7 | 181.3 | 155.8 | 135.6 |
| `small-many` | 389.4 | 402.6 | 415.9 | 383.4 |
| `fp-heavy` | 244.0 | 261.4 | 306.5 | 284.0 |

The new long installation-token workload completes at 136-181 ms across
strategies. RegexSet remains faster than reference regex on large-high and
large-low; auto deliberately stays on reference regex. The provider catalog is
materially slower than the synthetic 10-rule CP2 baseline, as expected from 19
rules, multiline PEM/JWT structure and validation. No validator was removed to
recover throughput. Cross-version numbers are workload-plus-engine changes, not
pure speedups.

Final CI Linux benchmark values and artifact IDs are recorded in the final
evidence section after the final-head CI run.

## Required CI

Final-head CI evidence: `PENDING-FINAL-CI`.

Historical pre-correction CP3 CI run `43087012245` at `c8779e9` passed all seven
jobs; docs-head run `43087717965` at `13b1d6b` also passed all seven. Those runs
are preserved as historical evidence and are not presented as validation of the
corrected rules.

Final sanitized artifacts: `PENDING-FINAL-ARTIFACTS`.

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

**P1 - explicit conditions:**

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

**CONDITIONAL GO for operator review.** The AWS misclassification, one-to-one
comparator defect and modern GitHub installation-token gap are corrected and
tested. Controlled accuracy is 27/27, 15/15 and 14/14 with strategy equivalence.
The conditions are the documented platform residuals, scoped external evidence,
unavailable Betterleaks/Git-history comparisons, identifier-only AWS semantics
and the hand-authored (not externally sourced) Tier 4 corpus. No condition is
hidden as a passing accuracy claim. No merge was performed.
