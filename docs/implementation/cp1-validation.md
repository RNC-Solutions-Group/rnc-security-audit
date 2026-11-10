# CP1 — Rust detection engine validation

> **Status:** CP1 implementation complete; awaiting operator acceptance. CP0 corrections are on `feat/cp0-audit-hardening`; CP1 is on `feat/cp1-rust-detection-engine` and targets the CP0 branch as a stacked PR. No merge has occurred.

## Implementation

| Component | Artifact |
| --- | --- |
| Library core | `crates/rnc-core` — path, input, rules, validators, findings, streaming, coverage, engine |
| CLI | `crates/rnc-cli` — `rnc scan`, `rnc rules validate` |
| Rule bundles | `rules/rnc-synthetic-v0.json`, `rules/rnc-synthetic-v1.json` |
| Rule schema | `docs/contracts/rules/rule-bundle.schema.json` |
| Independent integration | `tools/cp1/integration_check.py` |
| Production benchmark | `tools/cp1/bench.py` |
| External scoring | `tools/cp1/external_harness_score.py` |
| CI | `.github/workflows/cp1-rust.yml` |

Rust 1.85.0 is pinned by `rust-toolchain.toml`; dependencies are pinned by version and `Cargo.lock`.

## Correctness evidence

### Independent synthetic truth

`tools/cp1/integration_check.py` stages only source files (never the truth manifest), invokes the real CLI, validates all records against CP0 v0.2 schemas, builds synthetic policy evidence, and compares findings to the independently expanded truth.

| Corpus | Mode | Expected | Actual | Targets | Blocked | Uninspected | Result |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| synthetic-v1 | whole | 25 | 25 | 21 | 1 | 1 (optional) | ACTIONABLE (3) |
| synthetic-v1 | stream | 25 | 25 | 21 | 1 | 1 (optional) | ACTIONABLE (3) |
| synthetic-v0 | whole | 13 | 13 | 9 | 1 | 0 | ACTIONABLE (3) |
| synthetic-v0 | stream | 13 | 13 | 9 | 1 | 0 | ACTIONABLE (3) |
| synthetic-edge | stream | 3 | 3 | 2 | 0 | 1 (oversize required) | INCOMPLETE (4) |

Verified independently for every finding:

- target path and rule association;
- exact start/end byte offsets and line;
- SHA-256 evidence digest over the exact matched bytes;
- canonical finding ID;
- inspected unit content hash, byte length and line count;
- blocked/uninspected units have no content evidence;
- required versus optional scope;
- result/CI integration through the CP0 reference reconciler;
- repeated execution with the same run ID is byte-identical for findings and units;
- whole-file and streaming modes produce the same canonical findings;
- ruleset digest matches the independent Python canonical digest.

The scanner **never reads the truth manifest** during a scan.

### External harness

The actual CP1 v1 handoff was scored by the pinned independent `harness.truth.from_dict` + `harness.scoring_engine.score_findings` at revision `86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f`:

- expected **25**, matched **25**, missed **0**, false positive **0**, duplicate **0**;
- blocked **1**, skipped **1**;
- scoring status `COMPLETED`, execution status `PASS`.

This is a scoring-engine integration check on synthetic output. **No external corpus was executed and no production scanner accuracy is claimed.**

### Rust tests

`cargo test --workspace --locked` covers:

- locator grammar positive/negative cases and cross-language unit ID;
- line mapping for LF, CRLF and CR-only;
- finding identity and digest;
- rule schema, finite bound enforcement, duplicate IDs, unsupported unbounded patterns, digest ordering;
- candidate validation, including near-miss decoys;
- deterministic discovery, no symlink follow (Unix), pre-scan block without content evidence;
- optional/required coverage, oversize handling, timeout interruption;
- duplicate occurrences, multipart multiline rule, whole versus stream boundary matching;
- CLI JSON privacy, summary redaction, usage failure and rule validation.

CP1 Python tests validate the rule schema, digests and synthetic-only provenance. The complete suite is reported in the CI artifact.

## Performance evidence

Local Windows development run (5 repetitions per profile, release build, 1.92 MB binary, single-threaded):

| Workload | Whole MiB/s | Stream MiB/s | Whole median ms | Stream median ms |
| --- | ---: | ---: | ---: | ---: |
| large-low 32 MiB / 64 markers | 281 | 287 | 114 | 112 |
| large-high 32 MiB / 4,096 markers | 282 | 128 | 113 | 251 |
| small-many 2,000 x 4 KiB | 21 | 24 | 367 | 331 |
| fp-heavy 8 MiB / 16 markers | 100 | 116 | 80 | 69 |
| unicode 8 MiB / 256 markers | 211 | 170 | 38 | 47 |

Local rule compilation (`rnc rules validate`) measured ~8.8 ms median. Build time and RSS/CPU are environment-dependent; CI records pinned Linux measurements and retains the machine-readable artifact. The many-small-file lane is dominated by per-file acquisition; one local p95 sample reached 10.5 s from host I/O/antivirus interference while the median remained 367 ms. The outlier is retained in the sample rather than deleted.

These values are **production-engine measurements**, not the CP0 disposable-probe numbers. The CP0 Rust probe was faster because it performed no line index, rule validation, hashing or v0.2 record generation.

## Security and adversarial evidence

- All fixtures are harmless synthetic `RNC_SYNTH_KEY_*` values.
- JSON findings contain no raw matched bytes.
- Default summary contains no marker bytes, `evidence_digest` or `finding_id`.
- JSON output requires an explicit path; on Unix it is created with mode `0600`.
- Symlink files are never followed; symlink entries are recorded as uninspected.
- Path traversal, backslashes, absolute/drive/UNC paths, `./`, repeated separators, dot segments, control/bidi characters and Windows device names are rejected.
- The CLI never implements policy exemptions, result classification or CI acceptance.
- Timeout and max-findings stops retain prior findings but mark the current/remaining units uninspected; a partial unit does not claim inspection.
- File metadata is checked after reading; size/mtime changes produce `FILE_CHANGED` rather than silent acceptance.

## Known limitations

1. **Single-threaded.** CP1 does not implement parallel file scanning. Parallelism is a CP4/CP5 measurement target.
2. **Timeout, not signal cancellation.** Cooperative deadline interruption is implemented; OS signal handling is not.
3. **No external corpus execution.** Levain/Leaky Repo/Prowlbench remain deferred; no external accuracy claim.
4. **Same-line external collision.** The external harness is line-addressed; the CP1 handoff retains byte offsets but two same-rule findings on one line still need a composite policy or harness extension.
5. **No full CP2 policy/config integration.** CP1 accepts explicit `--exclude`/`--skip`/`--optional` scope controls; it does not load `.rncscanner.toml` or apply exemptions.
6. **Platform distribution.** Release builds are validated in CI on Linux/Windows/macOS where available; static musl packaging and installer work are deferred.
7. **No real credential validation or network verification.** This is intentional.
8. **Synthetic rules only.** The committed bundles are test/synthetic rules, not a production signature set.

## Acceptance gates

- [x] Workspace builds with pinned toolchain.
- [x] `cargo fmt --check` and `cargo clippy -D warnings`.
- [x] Rust unit/integration tests and CP1 Python tests.
- [x] CP0 v0.2 schema and cross-record compatibility.
- [x] 100% match against independent v1/v0/edge truth.
- [x] Whole and streaming equivalence on tested fixtures.
- [x] Stable repeated output.
- [x] Actual CP1 handoff scored by pinned external engine.
- [x] No raw credentials in logs/public artifacts.
- [x] Performance and build evidence produced.
- [ ] Required CI runs green and evidence recorded.
- [ ] Operator accepts CP0 and CP1.

## Readiness

**Pending final CI.** Once required CP1 CI and the stacked PR checks pass, CP1 is **READY for operator review**. It is not accepted, deployed or merged by this work.
