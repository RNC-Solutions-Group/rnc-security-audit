# CP2 integrated scanner — validation and security-hardening report

> **Status:** CP2 hardening implementation complete; required CP2, CP1 and CP0 CI is green at `560bce7`. Awaiting operator review. PR [#6](https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/6) targets `main`; no merge has occurred. This report applies to the hardened CP2 branch, not the superseded pre-hardening head.

## Repository state

| Item | Value |
| --- | --- |
| Branch | `feat/cp2` |
| Starting commit (prior CP2) | `4875fe2` |
| Hardening commits | `41517ae`, `ca521b1`, `aa72abe`, `560bce7` |
| Final implementation commit | `560bce7` (plus this documentation commit) |
| PR | https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/6 |
| Target | `main` |
| Merge status | Open / unmerged / mergeable |
| `main` | Unchanged at `e54d5bc` |

## Findings and corrections

### P0 — report output path and filesystem safety

**Original issue:** unresolved relative parents fell back to their original representation; symlink checking and file opening were separate path operations; a destination could be redirected or partially written.

**Correction:** `crates/rnc-cli/src/report.rs`

- Relative paths resolve against the process working directory; resolution failure is fatal.
- The parent is canonicalized and must exist; the parent and final path must be outside the canonical scan root.
- Final symlinks/reparse points, directories and non-regular files are rejected.
- Unix creates a unique temporary file with `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` in the already-open parent directory, writes/flushes/fsyncs, sets `0600` for private evidence, rechecks the final object, and publishes with `renameat`. Parent substitution cannot redirect the operation.
- Windows opens/verifies a parent directory handle, creates a temporary file, verifies the temp handle resolves within that parent, then publishes with `NtSetInformationFile(FileRenameInformation)` relative to the verified parent handle.
- Interrupted/failed writes leave the old destination untouched; temp files are removed where possible. Publication failure exits `30`.

**Regression tests:** bare relative output inside root; `../` relative; absolute inside/outside; existing regular replacement; final symlink; symlinked parent into root; deterministic parent substitution; deterministic final-component substitution; invalid parent; Unix mode `0600`; read-only parent I/O failure; symlink report rejection; atomic replacement. Unix tests passed in a Linux container and in CI.

**Residual:** Windows private evidence relies on inherited directory ACLs rather than Unix mode bits; this is documented in [source-acquisition.md](../architecture/source-acquisition.md) and not claimed as equivalent.

### P0 — authorized source root containment

**Original issue:** `symlink_metadata` plus final-component `O_NOFOLLOW` did not prevent ancestor-directory substitution between discovery and open.

**Correction:** `crates/rnc-core/src/input.rs`, `stream.rs`

- Unix opens the root and every intermediate directory with `openat` + `O_NOFOLLOW`; the final file is opened with `O_NOFOLLOW`. Reads and size/mtime checks use the descriptor.
- Windows rejects reparse-point ancestors/final targets, opens with `FILE_FLAG_OPEN_REPARSE_POINT`, and verifies the opened handle with `GetFinalPathNameByHandleW` against the canonical root before reading.
- Discovery canonicalizes every directory and verifies it remains under the root; symlink/reparse directories are rejected or recorded as uninspected. Directory-wide blocks are inherited before file content access.
- Discovery has finite entry, depth, time and policy-work budgets. Exhaustion produces `DISCOVERY_TIMEOUT`, `DISCOVERY_ENTRY_LIMIT`, `DISCOVERY_DEPTH_LIMIT`, `POLICY_BUDGET_EXCEEDED`, `DIRECTORY_ESCAPE`/`DIRECTORY_SYMLINK_ESCAPE` fatal errors, never a completed clean scan.

**Regression tests:** final-component symlink substitution; ancestor-directory substitution; directory symlink escape; removed file; changed file; symlink loop/entry; malformed paths; discovery entry/depth/timeout; policy budget; Unix mode-`000` blocked file proving non-access; all strategy differentials after acquisition changes.

**Residual:** Windows directory enumeration remains path-based; an ancestor substitution during enumeration is a documented race. Content reads and report publication use handle-verified paths. Unix report/source file operations are `openat`-relative.

### P1 — CI acceptance authority

**Original issue:** repository configuration could add `ACTIONABLE (3)` when no higher-level list existed.

**Correction:** `config.rs`, `run_scan`

- Default `{1,2}`.
- Global configuration may broaden to include `3`; its list is the mandatory cap.
- Explicit trusted CLI `--accept-result 3` may broaden when no global cap exists.
- Repository configuration may only narrow to a subset of the default/global cap; repository-only authorization of `3` fails closed with exit `64`.
- CLI cannot exceed a global cap. `4`/`5` are never accepted.
- Per-code provenance records `default`, `global`, `repository` or `cli`.

**Regression tests:** repository-only actionable denial; CLI actionable acceptance; global actionable acceptance; mandatory global override of repository/CLI; repository narrowing; incomplete/failed always rejected; immutable result; exit codes.

### P1 — resource-bounded policy matching and discovery

**Original issue:** recursive `**` matching enumerated segment assignments; discovery ran outside the main deadline.

**Correction:** `policy.rs`, `input.rs`, `engine.rs`, CLI

- Glob matching uses bounded dynamic programming over pattern/path positions.
- Limits: 4096 selector scalars, 64 selector segments, 256 matched path segments, 256 selectors.
- Discovery: 1,000,000 entries, depth 128, overall scan deadline (discovery and detection share the CLI deadline), 50,000,000 estimated policy-work units.
- Policy work is charged before matching; exhaustion aborts discovery with a fatal code.

**Regression tests:** 32 consecutive `**` segments against 200 path segments; 65-segment rejection; selector-count limit; entry/depth/timeout/policy budgets; deterministic repeated runs; deep/Unicode/long path discovery.

### P2 — policy digest and provenance integrity

**Original issue:** individual policy digests derived only from policy ID/version.

**Correction:** `policy.rs`

`EffectivePolicy.digest` now binds a canonical declaration containing policy ID, version, origin, mandatory status, and all block/exemption selectors, reasons and expirations. Declaration order is canonicalized. Effective-policy digest, policy record digest and final result digest remain linked. Duplicate policy IDs with conflicting version/origin/mandatory declarations fail.

**Regression tests:** equivalent inputs/order give identical digests; selector change changes digest; expiry change changes digest; conflicting declarations fail; policy/result digests validate against the CP0 reference reconciler.

## Security behavior by platform

| Property | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Source content root containment | `openat` + `O_NOFOLLOW` chain | same | reparse checks + final handle path verification |
| Ancestor substitution during read | rejected | rejected | rejected by handle path verification |
| Directory enumeration containment | canonical check + symlink rejection | same | canonical check + reparse rejection; path-based residual race |
| Pre-scan block before content open | yes | yes | yes |
| Report atomic publication | `openat`/`renameat`, temp + fsync | same | parent handle + `NtSetInformationFile`, temp + fsync |
| Private evidence mode | `0600` | `0600` | inherited ACL, documented |
| Final/parent symlink report rejection | yes | yes | reparse checks + handle verification |

## Validation

- **78 Rust tests on Unix** (42 core + 17 engine + 9 CLI unit/report + 10 CLI integration); **67 on Windows** (platform-gated tests account for the difference). `cargo fmt --check`, clippy `-D warnings`, release builds pass.
- **74 CP0 regression tests**; **5 CP1 Python rule tests**.
- **20 CP2 integration cases**: v0/v1/edge × whole/stream × regex/regexset/prefilter/auto; all v0.2 records valid; all expected findings found; all strategies canonical-equivalent.
- **24 policy/configuration/classification scenarios** on Linux CI (clean, blocked, exemptions, mixed, incomplete, failed, optional/zero scope, unmatched requests, mandatory global, repository/global/CLI acceptance, dual config, legacy migration, limits, invalid selector, sanitized output, incomplete-with-findings, block collision, no-access).
- Pinned external harness revision `86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f`: **25/25 expected, 25 matched, 0 missed, 0 unexpected, 0 false positive, 0 duplicate** for each of regex, regexset, prefilter and auto. No external corpus was executed; no production accuracy claim.
- CP1 compatibility integration remains green. CP0 regression workflow remains green.

### Security negative controls

The deterministic `write_with_hook` tests fail against the pre-correction path-based report logic (parent/final substitution). The ancestor-substitution and Unix mode-`000` block tests fail against a final-component-only check. Repository-only `accepted_result_codes = [1,2,3]` fails against the old intersection-only model. The 32-`**`/200-segment test exercises the old combinatorial matcher shape. Policy digest tests fail when only ID/version is hashed.

## Performance

Final CI run [42955912642](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/42955912642), Linux x86_64, 4 vCPU, release build, 3 repetitions:

- Build: **31.184 s**; binary **3,095,088 bytes**.
- Prior CP2 reference run: 21.473 s, 3,021,360 bytes.

| Workload | Auto whole median | Throughput | CPU | Peak RSS |
| --- | ---: | ---: | ---: | ---: |
| large-low 32 MiB | 112.6 ms | 284.2 MiB/s | 88.8% | 41,692 KiB |
| large-high 32 MiB | 152.1 ms | 210.4 MiB/s | 92.1% | 45,748 KiB |
| 2,000 × 4 KiB | 95.7 ms | 81.6 MiB/s | 93.1% | 17,200 KiB |
| FP-heavy 8 MiB | 71.6 ms | 111.7 MiB/s | 83.8% | 17,400 KiB |
| Unicode 8 MiB | 30.7 ms | 260.8 MiB/s | 65.2% | 14,552 KiB |

Same-host controlled comparison (prior `4875fe2` binary vs hardened):

| Workload | Prior | Hardened | Delta |
| --- | ---: | ---: | ---: |
| large-low whole | 102 ms | 125 ms | ~+23% |
| 2,000 small files whole | 367 ms | 501 ms | ~+36% |

The final CI run was slower across all profiles than the preceding CI run, including unaffected CPU-bound work; that is consistent with host/environment variance. The controlled comparison shows a real acquisition cost from canonical checks, per-component reparse metadata and `openat` traversal, which is the intended security tradeoff. No security control was removed to recover performance.

No separate phase timing for discovery/matching/reporting is instrumented; total wall-clock includes discovery, and separate phase figures are not claimed. This is a measurement limitation, not a claim of zero overhead.

Strategy behavior is unchanged: no portable alternative has a uniform advantage; `auto` remains reference regex. Prefilter remains slower on FP-heavy content.

## Known issues

### P0

None identified after the corrections above.

### P1

1. **No OS-signal cancellation.** Cooperative deadlines/timeout accounting exist; SIGINT handling remains deferred.
2. **Windows directory-enumeration race.** File reads and report publication use handle-verified paths; path-based `read_dir` remains a documented residual race on Windows.
3. **Windows private ACLs.** Private evidence relies on inherited destination ACLs; Unix `0600` equivalence is not claimed.

### P2

1. Single-threaded execution; parallelism not implemented.
2. External corpora (Levain/Leaky Repo/Prowlbench) not executed.
3. Same-rule/same-line external-harness ambiguity remains; RNC findings stay byte-addressed.
4. Installer/signing and non-x86_64 packaging deferred; x86_64 musl passes.
5. Rules remain synthetic test rules.
6. Phase-level discovery/matching/reporting timings are not separately instrumented.

## CI

| Workflow | Result |
| --- | --- |
| CP2 [42955912642](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/42955912642) | All 8 required jobs pass: quality/integration/policy, benchmark, all-strategy external scoring, Ubuntu/Windows/macOS, musl, audit |
| CP1 [42955912636](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/42955912636) | All 7 required jobs pass |
| CP0 [42955912646](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/42955912646) | All 3 required jobs pass |

Final artifacts:

- `cp2-integration-policy-evidence` — ID `13827550520`, digest `sha256:0618536ddbd780d8b218db065b966f7c2b8faebaa56f546e02ac74e08be51422`.
- `cp2-benchmark-evidence` — ID `13827250922`, digest `sha256:fa58b0f3acd2a7b51976712241f7fdadd4d62a57bd1edd88a2f9e9cd2eecdd46`.
- `cp2-external-harness-score` — ID `13826414825`, digest `sha256:b7ab8c02eae2e68a2043d452492b5b833bc92d7a70db2b77164c31ffbe417029`.

## Acceptance

- [x] Output destinations cannot escape the reporting boundary (Unix fd-relative; Windows handle-relative).
- [x] Private evidence publication is atomic, restrictive on Unix, and fails closed.
- [x] Authorized source content is root-contained (Unix openat chain; Windows handle verification).
- [x] Documentation distinguishes documented platform guarantees; Windows enumeration/ACL residuals are explicit.
- [x] Repository configuration cannot authorize `ACTIONABLE`; global/CLI authority and provenance are enforced.
- [x] Policy matching is dynamically bounded; discovery and policy work are finite.
- [x] Policy declaration digests bind content.
- [x] All three strategies remain canonically equivalent; external scoring remains valid.
- [x] CP0/CP1/CP2 regressions and cross-platform CI pass.
- [x] Documentation, ADRs and operator guide updated.
- [ ] Operator review and merge.

**Final disposition: CONDITIONAL GO for operator review.** All required CI is green and no known P0 defect remains. The conditions are explicit: accept the documented Windows directory-enumeration/ACL residual and deferred OS-signal cancellation, or authorize a follow-up for full Windows handle-relative discovery and cancellation. This is not a claim of identical platform guarantees.
