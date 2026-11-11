# CP3 validation — detection intelligence and accuracy

> **Status:** Implementation, controlled/external evidence and required CI
> complete; operator review pending. Provider-format recognition is not proof of
> an active, authorized or complete credential.

## Repository state

| Field | Value |
| --- | --- |
| Branch | `feat/cp3` |
| Starting head | `0090ddd` (CP2 merge + CP3 seed README) |
| Final implementation head | `c8779e9` |
| Pull request | [#10](https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/10) |
| Target | `main` |
| Merge | Operator-owned; no merge performed |
| Base | `main` at `e54d5bc`; CP2 was merged into `feat/cp3`, not `main` |

The CP2 implementation and its hardened contracts are preserved. CP3 adds a
separate catalog and does not change the synthetic bundles' schema or established
digests.

## Delivered

- Provider schema `0.2.0` with 16 rules across 12 families.
- Reusable offline validators for prefixes, lengths, charsets, base64/base64url,
  hex, placeholders, entropy downgrade, PEM labels/decoding/DER shape, JWT
  structure, database userinfo and generic assignments.
- Tier 2 controlled corpus: 24 files, 27 expected occurrences, four dedicated
  negative files.
- Tier 3 separately authored held-out corpus: 10 files, 15 expected occurrences.
  Fixture bytes are committed as a review-safe hex bundle and materialized into a
  temporary scan root by tests; raw provider-shaped text is not committed.
- Independent byte-addressed truth, scorer, negative controls and coverage gate.
- External harness adapter with explicit line-addressing limitation.
- Scoped Levain, Leaky Repo and Gitleaks evidence.
- Provider-catalog benchmark harness and methodology.
- CP3 CI workflow with quality, accuracy, external-harness, benchmark,
  cross-platform, musl and dependency-audit lanes.

## Detection catalog

See [cp3-detection-catalog.md](cp3-detection-catalog.md) for the complete table.
Implemented families:

1. AWS access key IDs and assignment/Terraform-context secret keys.
2. Google Cloud API keys.
3. GitHub classic, fine-grained and OAuth/app tokens.
4. GitLab personal/project/group access tokens.
5. Stripe secret/restricted keys.
6. Slack bot/user/app tokens.
7. SendGrid API keys.
8. npm auth tokens.
9. PEM/OpenSSH private-key containers.
10. Bearer JWTs.
11. Database URI userinfo credentials.
12. Low-confidence generic assignments.

Public keys, certificates, provider-specific families not listed, bare JWTs and
Git-history input remain out of scope.

## Verification suites

| Suite | Result |
| --- | --- |
| Rust workspace, Linux CI `--all-targets` | **99 tests** pass: 58 core + 18 engine + 4 provider + 9 CLI unit + 10 CLI integration |
| Rust workspace, local Windows | **89 tests** pass; platform-gated Unix tests excluded |
| CP0 contract/corpus/harness | **74 tests** pass |
| CP1 synthetic rules | **5 tests** pass |
| CP3 schema/scorer/adapter/security | **31 tests** pass |
| CP2 differential integration | **20 cases**, `all_correct`, `all_equivalent` |
| CP2 policy/classification | **23 cases**, `all_passed` |
| CP1 synthetic integration | v1/v0/edge pass |
| Provider catalog validation | 16 rules valid under all four strategies |

## Controlled accuracy

All results use exact byte ranges and exact expected rule identity. The table
aggregates the 16 integration cases (two datasets × two modes × four strategies):

| Dataset | Expected | TP | FP | FN | Precision | Recall | Duplicates | Ambiguous |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Tier 2 provider fixture | 27 | 27 | 0 | 0 | 100% | 100% | 0 | 0 |
| Tier 3 held-out | 15 | 15 | 0 | 0 | 100% | 100% | 0 | 0 |

The result is identical for `whole` and `stream` under `regex`, `regexset`,
`prefilter` and `auto`. The Tier 3 set was not used to tune individual rules.

## External evidence

### Pinned independent harness (line-addressed)

Actual RNC output was normalized and scored at revision
`86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f`. The harness is line-addressed:

- matched: **25/27**
- ambiguous: **2** (two distinct same-line GitHub occurrences)
- false positives: **0**
- missed: **2** (the same-line items the line model cannot disambiguate)

The local byte scorer correctly classifies both same-line items. This is
compatibility evidence, not the authoritative accuracy score. The external
repository was not modified.

### Levain (MIT)

Scoped to families declared by the RNC catalog:

| Metric | Value |
| --- | ---: |
| Mapped expected positives | 31 |
| TP | 30 |
| FP | 0 |
| FN | 1 |
| Precision | 100% |
| Recall | 96.77% |
| Negative-corpus findings | 0 |
| Out-of-scope unsupported-family observations | 5 |

The one miss is a deliberately malformed PEM whose base64 body is not
decodable. RNC rejects it by structural validation rather than emitting a
malformed private key. Unsupported Levain kinds are excluded from the
denominator, not counted as RNC failures.

### Leaky Repo (MIT)

Count-based inventory, not credential-level truth:

- observed findings: **33**
- covered count: **33/175** (18.86%)
- files covered: **18/44**
- excess findings: **0**
- unlisted findings: **0**

No TP/FP/precision/recall is claimed. Count coverage is not a quality score.

### Gitleaks

A pinned local Gitleaks build (`sha256:c8bf14bc…`) was run with its native
default configuration on the same filesystem fixtures. Findings were matched by
source path and exact fixture bytes, not rule-name identity.

| Dataset | Gitleaks TP | FP | FN | Precision | Recall | RNC |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Tier 2 | 22/27 | 2 | 5 | 91.67% | 81.48% | 27/27 |
| Tier 3 | 11/15 | 0 | 4 | 100% | 73.33% | 15/15 |

This is a controlled-corpus comparison, not a general product ranking. Gitleaks
supports families outside the RNC catalog and has Git-history capability that
RNC does not implement. Betterleaks was not executed because no pinned binary or
image was available; no Betterleaks result is claimed.

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
| Unresolved mismatch | None on the controlled corpus |

`regex` remains the reference. `auto` selects reference regex. `prefilter` uses
Aho-Corasick required literals with exact-regex fallback for rules without a
proven literal; `regexset` is used when the set compiles. Any fallback is
reported in plan provenance.

## Security

- Candidate materialization is capped at 100,000 per window; exceeding the cap
  makes the unit uninspected and the execution interrupted/failed, not clean.
- Rule count, pattern size, match length and candidate length are bounded.
- Validators reject oversize/malformed JWT segments, invalid base64/DER, PEM
  label mismatches and placeholder bodies. Validation errors carry static
  reasons, never candidate bytes.
- Public artifacts contain no raw fixture values, private locators or absolute
  host paths; `tools/cp3/privacy_check.py` passes on generated evidence.
- No network validation, credential redemption, provider authentication or
  external build-script execution occurred.
- Existing CP2 source containment, report publication, policy authority and CI
  safeguards are unchanged. Issues #7–#9 remain open platform residuals; CP3
  did not absorb or silently close them.

## Performance

See [cp3-benchmark-methodology.md](cp3-benchmark-methodology.md) and the
machine-readable `artifacts/cp3/bench.json` generated on the final local run.
Local Windows runs do not have GNU `time`, so CPU/peak RSS are `null`; the
isolated Linux CI benchmark provides those fields. Wall times are not compared
across different runners as a controlled speedup.

Release build: **52.65 s**, binary **2,647,040 bytes**, SHA-256
`1def3f63…`. Rule compilation: median **149.5 ms**, p95 **181.8 ms**. Three
runs per profile.

### Whole-file reference (`regex`)

| Workload | Median ms | p95 ms | Throughput MiB/s | RegexSet ms | Prefilter ms | Auto ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `large-low` | 291.9 | 376.1 | 27.4 | 257.3 | 269.6 | 380.0 |
| `large-high` | 448.2 | 535.8 | 17.9 | 401.8 | 393.7 | 455.7 |
| `small-many` | 780.0 | 4108.1 | 0.2 | 861.6 | 781.0 | 2652.9 |
| `credential-configs` | 265.3 | 369.7 | 15.1 | 233.3 | 239.8 | 244.0 |
| `fp-heavy` | 406.2 | 423.4 | 9.8 | 453.1 | 374.9 | 420.2 |
| `high-entropy` | 204.8 | 297.0 | 19.5 | 159.9 | 179.6 | 178.3 |
| `multi-family` | 85.8 | 100.6 | 1.4 | 129.3 | 117.6 | 168.3 |
| `long-pem` | 122.6 | 374.7 | 0.3 | 127.3 | 150.6 | 192.6 |
| `structured` | 257.0 | 257.8 | 0.1 | 202.4 | 128.5 | 133.5 |
| `same-line` | 106.6 | 121.7 | 0.2 | 139.8 | 116.7 | 121.6 |

### Streaming reference (`regex`)

| Workload | Median ms | p95 ms | Throughput MiB/s | RegexSet ms | Prefilter ms | Auto ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `large-low` | 425.0 | 521.9 | 18.8 | 338.8 | 335.5 | 458.5 |
| `large-high` | 1145.4 | 1162.7 | 7.0 | 994.8 | 797.8 | 1156.0 |
| `small-many` | 793.3 | 2174.4 | 0.2 | 746.3 | 620.1 | 667.4 |
| `credential-configs` | 575.8 | 712.8 | 7.0 | 560.6 | 525.1 | 500.2 |
| `fp-heavy` | 559.0 | 713.5 | 7.2 | 630.5 | 566.9 | 552.0 |
| `high-entropy` | 172.5 | 204.0 | 23.2 | 143.4 | 164.0 | 164.7 |
| `multi-family` | 268.4 | 302.4 | 0.4 | 248.4 | 261.1 | 331.1 |
| `long-pem` | 146.9 | 178.9 | 0.2 | 119.5 | 131.2 | 122.5 |
| `structured` | 188.4 | 220.1 | 0.2 | 157.7 | 123.0 | 114.8 |
| `same-line` | 129.7 | 176.4 | 0.2 | 153.1 | 140.9 | 164.5 |

`small-many` p95 is dominated by a single host outlier; its median is stable.
The initial RegexSet implementation over full provider patterns was correct but
pathologically slow (6.5 s for the 8 MiB low-density whole-file profile). CP3
replaced it with a **required-literal RegexSet filter** plus exact regex for
eligible rules; the same profile is now 257 ms with identical canonical
findings. This is a performance fix, not a correctness strategy change.

### CI Linux reference

The isolated Linux CI benchmark (`cp3-benchmark-evidence`, artifact ID
`13887865802`, SHA-256 `ca9f5259…`) had GNU `time` available. Release build
**35.158 s**, binary **3,168,816 bytes**, SHA-256 `898f3af9…`; rule compilation
median **39.1 ms**.

| Workload | Whole regex ms | Whole MiB/s | Whole CPU % | Whole RSS KiB | Stream regex ms | Stream MiB/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `large-low` | 135.5 | 59.0 | 95.9 | 29,832 | 176.7 | 45.3 |
| `large-high` | 178.3 | 44.9 | 90.3 | 38,312 | 643.2 | 12.4 |
| `small-many` | 60.2 | 2.6 | 81.7 | 22,220 | 64.8 | 2.5 |
| `credential-configs` | 98.7 | 40.5 | 91.2 | 26,600 | 273.3 | 14.6 |
| `fp-heavy` | 198.8 | 20.1 | 95.5 | 27,328 | 285.9 | 14.0 |
| `high-entropy` | 78.0 | 51.3 | 88.5 | 25,624 | 94.2 | 42.4 |
| `multi-family` | 56.5 | 2.0 | 88.5 | 27,804 | 128.3 | 0.9 |
| `long-pem` | 42.2 | 0.8 | 71.0 | 21,532 | 42.3 | 0.8 |
| `structured` | 44.2 | 0.7 | 67.9 | 22,640 | 51.1 | 0.6 |
| `same-line` | 44.2 | 0.5 | 67.9 | 21,968 | 53.2 | 0.4 |

On the CI host, whole-file large-high medians were regex **178.3 ms**,
regexset **149.3 ms**, prefilter **164.0 ms** and auto **181.0 ms**. The local
Windows table and the CI table are from different hosts and are not presented as
a controlled cross-host speedup.

The provider catalog is materially slower than the synthetic 10-rule CP2
baseline, as expected from 16 rules, multiline PEM/JWT structure and validation.
No validator was removed to recover throughput. Acquisition, matching and
reporting are not separately instrumented; that limitation is explicit.

## Required CI

CP3 workflow run [43087012245](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43087012245)
at implementation head `c8779e9` passed all seven required jobs:

- quality, provider rules, byte accuracy and external adapter;
- provider catalog benchmark;
- Ubuntu, Windows and macOS builds/tests;
- static Linux musl build;
- dependency advisory audit.

Final sanitized artifacts:

- `cp3-integration-accuracy-evidence` — ID `13886408382`,
  SHA-256 `ceed50b3…`; 16/16 integration cases `all_correct`, all equivalent;
  external line score 25 matched + 2 ambiguous; privacy check `PASS`.
- `cp3-benchmark-evidence` — ID `13887865802`, SHA-256 `ca9f5259…`;
  80 profiles, all correct.

The CP3 PR is [#10](https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/10),
targeting `main`. No merge was performed.

## Limitations and disposition

### Known limitations

**P0 — none identified.** No source-containment, report-publication, evidence
integrity or CI-authority defect was found or introduced by CP3.

**P1 — explicit conditions:**

- RNC Scanner has no Git-history input adapter. All external comparisons are
  filesystem-to-filesystem; Git-history capability is `NOT_APPLICABLE`.
- Windows path-based directory enumeration (#7), inherited private-evidence ACLs
  (#8) and OS-signal cancellation (#9) remain open CP2 platform residuals. CP3
  did not weaken or close them.
- Betterleaks was not executed because no pinned binary or image was available.
  The Gitleaks comparison is the only executed external-scanner comparison.
- The Levain result is scoped to declared families (**30/31**, one deliberately
  malformed PEM rejected by structural validation). It is not a universal
  real-world recall claim.
- Leaky Repo provides count coverage, not credential-level truth. Its 33/175
  count coverage is not a precision or recall measurement.
- The external harness is line-addressed; its **2 ambiguous** same-line results
  are preserved as a limitation and are not hidden inside a headline score.
- Provider-format recognition is not active-credential verification. JWT,
  OAuth/app-token, database-URI and generic-assignment families are experimental
  or lower confidence.

**P2 — future work:**

- Add checksum/structural checks where providers publish them, without
  introducing false negatives.
- Expand provider families and rule lifecycle evidence.
- Add separate acquisition/detection/report phase instrumentation and a clean
  controlled benchmark lane.
- Evaluate Git-history and additional source adapters.
- Evaluate Betterleaks and additional pinned comparators when binaries and
  licenses are available.

### Disposition

**CONDITIONAL GO for operator review.** The code, controlled accuracy,
strategy-equivalence gate, independent scorer, external adapter, security
checks, benchmark and documentation are implemented. The conditions are the
documented platform residuals, the scoped external-corpus results, the absent
Betterleaks/Git-history adapters, and the deliberate malformed-PEM rejection.
No condition is hidden as a passing accuracy claim. Final CI evidence at the
delivered head is recorded in the pull request.
