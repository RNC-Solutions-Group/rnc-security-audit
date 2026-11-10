# ADR-007 — Production detector language: Rust

**Status:** Accepted for CP0 handoff; operator acceptance of the CP0 package is still required before CP1 implementation.
**Date:** 10 November 2026
**Supersedes:** the open language decision in ADR-001. The Go/Rust benchmark requirement remains binding.

## Context

CP0 was required to benchmark Go and Rust with equivalent credential-detection workloads before selecting the production engine language. The preliminary CP0 probes measured only whole-file reads plus a literal byte search. They were preserved as a baseline but were explicitly insufficient for a production decision.

The audit added a representative disposable scanner in both languages:

- the same 64-rule table (8 active rules; 64-rule set for scale), compiled safe regexes, capture groups, candidate validation and deterministic output;
- whole-file and 256 KiB streaming modes with 8 KiB overlap;
- 32 MiB large files at low and high match density;
- 2,000 small files, with one and four worker threads;
- false-positive-heavy, Unicode, PEM-like multiline and large-rule-set inputs;
- an 8 MiB worst-case near-prefix workload with no valid matches;
- the same corpus bytes, expected finding count and FNV-1a checksum for both implementations.

Measured results are retained as a machine-readable CI artifact. The local CP0 audit run (Windows, Go 1.27.3, Rust 1.85.0, three alternating repetitions) showed every workload correct and identical between implementations. Rust had the lower median latency on 13 of 18 profiles. The largest differences were on security-relevant adversarial/false-positive-heavy inputs (roughly 7–10×), large rulesets (3–5×), and large files (2–3×). Go was faster on the many-small-files profiles (roughly 2×) and tied on Unicode input.

The pinned CI run uses Go 1.23.4 and Rust 1.85.0 on the same Ubuntu runner with five alternating repetitions; its artifact is the authoritative performance record. The local results are directionally consistent.

## Options considered

| Option | Assessment |
| --- | --- |
| **Rust** | Selected. Best measured regex, adversarial and large-file throughput; memory-safe; small stripped binary; regex crate is linear-time and rejects backreferences/lookaround. Costs: slower cold builds, five pinned crates, target-specific cross-builds. |
| **Go** | Rejected for the production engine, retained as a comparator. Fast builds, one static binary, trivial cross-compilation, standard library only. It was slower on representative regex-heavy workloads and especially on false-positive-heavy/worst-case inputs, though faster on many-small-files. |
| **Python** | Rejected for the detector core. The historical audit controller may remain Python, but byte-precise, high-throughput rule execution and portable distribution favor a compiled engine. |
| **Defer selection** | Rejected. CP1 cannot begin without a stable language and module boundary; the evidence is sufficient for a reversible CP0 decision. |

## Decision criteria

| Criterion | Rust evidence | Go evidence | Weight |
| --- | --- | --- | --- |
| Correctness | Exact counts/checksums on all profiles | Exact counts/checksums on all profiles | Mandatory gate; tie |
| Representative performance | Lower median latency on most profiles, including worst-case and FP-heavy | Better on many small files; acceptable on large files | High |
| Build and CI cost | ~20 s cold build; one third-party ecosystem dependency tree | ~1 s build; standard library only | Medium |
| Binary/distribution | 1.55 MB stripped; glibc dynamic by default | 2.16 MB stripped; static by default | Medium |
| Security | Memory-safe; `regex` rejects unsafe constructs and is linear-time | Memory-safe; RE2-style `regexp` is linear-time | Mandatory gate; tie |
| Portability | Requires target toolchains/linkers; musl static builds mitigate glibc | `GOOS/GOARCH` cross-compiles directly | Medium |
| Maintainability | Strong types, no GC, smaller runtime; dependency pinning required | Simpler build, fewer dependencies; GC and slower regex | Medium |
| Integration | Standalone binary with JSON records, same as Go | Standalone binary with JSON records | Low/medium |

The decision does **not** treat the preliminary literal-byte result as sufficient. Rust is selected on the representative regex/validation/streaming evidence, with the Go tradeoffs recorded rather than erased.

## Consequences

1. CP1 implements the detector core in Rust with a pinned `regex` crate version and a committed `Cargo.lock`.
2. Rules are compiled once, validated at load time, and restricted to bounded/linear constructs. Backreferences, lookaround and unbounded ambiguous repetition are rejected by rule validation.
3. Candidate validation, deduplication and output ordering are deterministic and byte-addressed. No policy, reporting or CI logic enters the engine crate.
4. Distribution uses a CI cross-build matrix for Windows, Linux (musl static) and macOS. The initial CP1 slice may build only the host target, but the release shape must not assume a single platform.
5. The Go implementation remains in `tools/cp0/bench` as a disposable comparator. It is not a second production detector and must not be shipped as RNC Scanner.
6. Dependency additions require a documented purpose, license and maintenance review. `cargo audit`/`cargo deny` become CP1 CI candidates; they are not claimed as implemented in CP0.
7. Performance is re-measured after CP1 rule-bundle and validator implementation. A regression against the CP0 comparator is investigated; CP0 numbers are not production scanner accuracy or throughput claims.

## Validation evidence

- `python -m tools.cp0.bench_runner --runs 5 --output artifacts/cp0/representative-benchmarks.json`
- Literal baseline preserved: `python -m tools.cp0.benchmark --runs 5 --output artifacts/cp0/literal-benchmarks.json`
- Machine-readable artifacts are retained by the CP0 workflow; host-dependent raw output is not committed.
- The CP0 report records the CI run, toolchain versions, runner, profile medians and limitations.

## Revisit triggers

Revisit this ADR if CP1 demonstrates that file-open overhead dominates real repository scans, if cross-platform Rust distribution proves impractical, or if a security review rejects the dependency/toolchain posture. A reversal requires a new ADR and benchmark evidence, not a silent engine swap.
