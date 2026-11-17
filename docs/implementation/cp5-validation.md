# CP5 validation — detection recovery and performance optimization

> **Status:** Implementation complete; local validation complete. Independent
> harness re-scoring and the production 50-configuration matrix are **not**
> performed here. This document does not claim independently certified accuracy.

## Revision and environment

| Field | Value |
| --- | --- |
| CP4C reference | `805e3bb79276b94de636e27024f38773da303b44` |
| CP5 branch | `feat/cp5` |
| CP5 implementation commit | `e885b1431820e877991f10977e818ef192eaddef` |
| Ruleset | `rnc-providers-v1` version `2026.11.6` |
| Ruleset digest | `sha256:b893978c4a720c41951a20c0771d67f29bbb54ad1057a6bd5bf0feef68c5de2a` |
| Rules / families | 38 / 23 |
| Host | Native Windows 11 AMD64, Intel Core i7-11375H (4C/8T), 34 GB RAM |
| Toolchain | Rust 1.85.0, locked dependencies |
| Environment | DEV contended workstation; timings are preliminary |

All timings below compare two locally built executables on the same host and
workloads:

- **CP4C** — the preserved CP4C binary and ruleset `2026.11.5`;
- **CP5** — the CP5 release binary and ruleset `2026.11.6`.

Each measurement uses warmups plus the stated repetitions. Peak memory is the
scanner process working set sampled every 15 ms; CPU is scanner-process CPU
time. Production baseline values from the 15 November cross-scanner run are not
directly comparable to this host and are not substituted for these measurements.

## Technical assessment

### Candidate matching

CP4C `--strategy auto` resolved to the reference regex backend. Profiling of the
legacy ×10 filesystem load showed exact-regex candidate extraction as the
dominant phase. Every rule's regex ran over every window.

The existing `prefilter` and `regexset` backends were already exact, but their
required-literal extraction was weak: case-insensitive patterns produced no
literal or a single common byte, and alternations only contributed a common
prefix. On the legacy load, 37 regexes were evaluated for most windows.

CP5 reuses the existing prefilter backend and improves its input rather than
adding a new matcher:

- required literals are extracted as a set (one member must occur);
- small factored classes and alternation branches contribute alternatives;
- case-insensitivity flags are removed only for literal extraction, then the
  filter is matched ASCII-case-insensitively;
- all current 38 rules have a proven literal;
- the exact regex still produces every candidate and capture span.

`auto` now selects `prefilter`. The aggregate candidate budget is enforced in
the reference regex backend, and capture-group cloning was removed.

### Filesystem open path

Per-file canonicalization of the root and the final handle path dominated open
time on many-small-file workloads. CP5 computes the canonical root once per scan
and keeps every containment and reparse-point check. This reduced the measured
`scan.open` phase on the legacy ×10 load from about 1.98 s to 1.16 s in the
diagnostic profile. The remaining cost is the per-component Windows metadata
inspection and handle-path validation.

### Git discovery and acquisition

CP4C launched one `git diff-tree` process per commit and, by default, one
`git cat-file blob` process per object. On Windows process creation dominated
both phases. CP5:

- sends non-merge commits to one persistent `git diff-tree --stdin` process in
  batches of 256;
- keeps the exact two-tree invocation for merge commits;
- falls back to individual `diff-tree` calls if a batch exceeds the output
  bound;
- makes persistent `git cat-file --batch` the default acquisition strategy,
  with a process fallback if the batch reader cannot start.

Whole-history and diff-history semantics, first-parent merge behavior,
deletion-only handling, binary-diff handling and unit identity are unchanged.

### Memory

The CP4C step from one to two workers was dominated by per-regex search caches,
not thread stacks or result buffering. Reducing the configured cache bound from
2 MiB to 1 MiB or 512 KiB **increased** observed private memory and did not
improve time, so the library default was retained. The prefilter reduces how
many regexes and caches are populated, which lowered peak working set on
parallel workloads. The default worker count remains `1`.

## Performance comparison

Medians of repeated runs. Ratios are CP4C ÷ CP5; values above 1 are
improvements. Memory is peak working set.

| Workload | Config | CP4C wall | CP5 wall | Wall ratio | CP4C CPU | CP5 CPU | Memory CP4C → CP5 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| RNC Lab legacy ×10 filesystem | 1 worker | 13.785 s | 2.989 s | **4.61×** | 13.578 s | 2.969 s | 120.9 → 113.8 MiB |
| RNC Lab legacy ×10 filesystem | 8 workers | 5.031 s | 1.781 s | **2.82×** | 24.219 s | 3.859 s | 371.6 → 316.5 MiB |
| RNC Lab filesystem | 1 worker | 0.576 s | 0.486 s | **1.19×** | 0.531 s | 0.469 s | 84.9 → 81.3 MiB |
| RNC Lab filesystem | 8 workers | 0.446 s | 0.440 s | 1.01× | 0.766 s | 0.625 s | 330.0 → 169.1 MiB |
| RNC Lab Git whole | 1 worker | 7.672 s | 0.821 s | **9.34×** | 1.031 s | 0.312 s | 83.0 → 66.1 MiB |
| RNC Lab Git whole | 8 workers | 4.549 s | 0.950 s | **4.79×** | 1.188 s | 0.422 s | 313.9 → 124.0 MiB |
| Leaky Repo filesystem | 1 worker | 0.404 s | 0.380 s | 1.06× | 0.375 s | 0.297 s | 83.7 → 66.9 MiB |
| Leaky Repo Git whole | 1 worker | 9.209 s | 1.040 s | **8.85×** | 1.062 s | 0.375 s | 85.0 → 66.5 MiB |
| Leaky Repo Git whole | 8 workers | 3.852 s | 1.071 s | **3.60×** | 1.438 s | 0.422 s | 319.8 → 101.5 MiB |
| Levain filesystem | 1 worker | 0.386 s | 0.344 s | 1.12× | 0.344 s | 0.328 s | 84.0 → 77.9 MiB |

Run counts: legacy 3; RNC Lab filesystem 5; RNC Lab/Leaky Git 3; Leaky
filesystem and Levain 3. Warmups were performed outside the recorded runs. The
Git comparison uses the CP4C default process strategy for CP4C and the CP5
default batch strategy for CP5; an explicit process-to-process comparison is
also recorded in the Git acquisition section below.

### Isolated matching improvement

On the legacy ×10 load, with the same CP5 scan path and only the strategy
changed, diagnostic profiles measured:

| Phase | CP4C regex | CP5 prefilter |
| --- | ---: | ---: |
| `matching.regex` | 11.0–15.8 s | 0.30–0.34 s |
| `matching.literal_filter` | — | 0.23–0.26 s |
| `scan` wall | 13.0–18.9 s | 3.0–3.2 s |

The ranges reflect host-load variation across diagnostic runs; the medians
above are the authoritative comparison.

### Git acquisition detail

On the RNC Lab Git workload:

| Strategy | Wall | `git.deltas` | Acquisition |
| --- | ---: | ---: | ---: |
| CP4C process + per-commit diff-tree | 7.672 s | 2.9 s | 6.2 s |
| CP5 process + batched diff-tree | ~3.5 s | 0.2 s | 6.2 s |
| CP5 batch + batched diff-tree | 0.821 s | 0.2 s | 0.08 s |

The isolated values are diagnostic measurements, not additional median rows.

## Detection comparison

Target-level checking used the retained RNC Lab oracle and the published
target inventory. It maps scanner findings by path, commit, line and exact
source-span or identity digest. This is a **local diagnostic**, not the
independent harness score.

### RNC Lab filesystem

| Family | CP4C value-verified | CP5 value-verified | Total oracle targets |
| --- | ---: | ---: | ---: |
| WordPress authentication material | 0 | **126** | 126 |
| Application HMAC key | 39 | **51** | 60 |
| JWT signing key | 10 | **20** | 20 |

The nine remaining HMAC targets are the SQLite/container and unresolved
`SECRET_KEY` cases documented in the CP4C root-cause report. All 126 WordPress
targets are exact source-span matches: 112 WordPress `.env`/`php_define` values
and 14 Kubernetes base64 spans.

### RNC Lab Git

| Family | CP4C value-verified | CP5 value-verified | Total oracle targets |
| --- | ---: | ---: | ---: |
| Application signing key | 0 | **31** | 31 |

Units, commits and history scope are unchanged at 116 units.

### Leaky Repo

- Filesystem findings increased from 33 to 41: eight new WordPress
  authentication findings, all eight authored `wp-config.php` keys/salts, with
  no CP4C finding lost.
- Git-history findings increased from 64 to 88, including 24 WordPress
  revision occurrences. No CP4C finding was lost.

### Levain

Findings and units are unchanged (3 findings, 40 units). The signing-identifier
change does not affect this corpus.

### Equivalence and non-regression

- Across RNC Lab filesystem, RNC Lab Git, Leaky filesystem, Leaky Git and the
  legacy load, every CP4C finding is retained with the same unit, rule family,
  byte span and evidence digest, except rule-version migration for the four
  generic rules.
- The RNC Lab filesystem increase is exactly the expected 126 WordPress plus 22
  signing/HMAC findings; no unrelated rule gained a finding.
- The Leaky filesystem increase is exactly the eight WordPress findings.
- Negative fixtures reject placeholders, variables, short values, algorithm
  names, `…_ID`/`…_HINT` aliases and non-credential `KEY`/`SALT` occurrences.
- Exact-value tests assert captured source bytes, not only rule IDs or counts.

## Regression coverage

New tests:

- `crates/rnc-core/tests/cp5_detection.rs` — five tests covering PHP
  `define()`, `.env`, Kubernetes base64, JSON camelCase, signing/HMAC aliases,
  negative aliases, placeholder rejection and backend equivalence;
- `backend::tests::extracts_required_literals_conservatively` — literal sets,
  classes, alternations and case-insensitive flags;
- `backend::tests::case_insensitive_flag_rewrite_preserves_other_flags`;
- `backend::tests::regex_backend_enforces_the_aggregate_candidate_budget`;
- `backend::tests::plan_resolves_auto_and_explicit` — asserts `auto` resolves to
  `prefilter`;
- `git::tests::diff_tree_batch_parser_associates_records_with_commit_ids`;
- `git::tests::diff_tree_batch_parser_rejects_malformed_framing`;
- CLI history defaults test — `--history` defaults to batch acquisition while
  workers remain `1`.

Full local suite: **173 Rust tests** across unit and integration binaries, all
passing, plus the Python regression suites: CP0 74/74, CP1 5/5 and CP3 55/55.
`cargo fmt --check` and warnings-denied Clippy pass. The locked release build
succeeds.

## Remaining limitations

- The 50-configuration production matrix and independent harness scoring were
  not run. Performance and accuracy conclusions are local and conditional.
- The local target check is not the scoring authority; the harness must re-score
  the new executable and ruleset.
- Nine RNC Lab application-HMAC targets remain outside the recovered
  identifier representation (SQLite/container or unresolved value shape).
- The WordPress rule requires 32–512 byte values and accepts printable
  punctuation; deliberately short or encoded non-Kubernetes representations are
  not covered. The Kubernetes finding captures the exact base64 source span, not
  the decoded salt bytes.
- Batched Git discovery is fail-closed on timeout: an in-flight batch can be
  recorded uninspected rather than partially applied.
- The batch object reader is serialized and remains a ceiling for very large
  histories with many large blobs.
- Discovery and containment checks still dominate many-small-file filesystem
  workloads; the largest gains are on large files and Git history.
- Worker count remains `1` by default. `--workers auto` improves wall time on
  large loads but increases CPU and memory.

## Readiness

**CONDITIONAL — ready for operator review and independent re-evaluation.**

Mandatory local engineering gates pass, the CP4C reference path remains exact,
and the measured performance improvements are material and reproducible on this
host. The unresolved acceptance conditions are independent harness re-scoring,
the controlled production matrix, and the remaining detection gaps listed above.
