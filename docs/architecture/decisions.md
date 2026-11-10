# CP0 architecture decisions — ADR register

Status: **Approved directions, implementation details pending benchmark evidence** (10 November 2026).

| ID | Decision | Consequence / next check |
| --- | --- | --- |
| ADR-001 | **Benchmark Go and Rust before selecting the detector language** | Same synthetic workloads and algorithm; pin compilers, capture correctness, latency, memory where available. CP1 language remains undecided until review |
| ADR-002 | **Unified configuration schema with migration** | One normalized effective policy and provenance model; legacy `security.config` read only through a documented, non-silent migration layer |
| ADR-003 | **Default CI acceptance: `CLEAN` and `POLICY_APPLIED`** | OS exit `0` for finalized codes `1` or `2`; actionable `3` fails by default; codes `4`/`5` never pass |
| ADR-004 | **Full synthetic corpus and benchmark work in CP0** | Commit deterministic corpus source/manifest generator and hand-authored truth anchors; execute Go/Rust comparison in CI and attach artifacts before language decision |
| ADR-005 | **Production detector never evaluates its own accuracy** | An independent harness scores normalized findings, with the manufactured synthetic stub as a controlled test adapter |

## Decision review checkpoints

1. Confirm CP0 schema shape and cross-record identity/count/finalization rules.
2. Read actual CI-run Go/Rust benchmark artifacts; verify compiler/runtime versions, input digests, correctness, repetitions and hardware parity. These probes test only a small common primitive; **they cannot alone settle production language choice**.
3. Record the selected language plus regex/streaming/validation prototype evidence in a follow-up ADR before CP1.
4. Agree the unified config filename/namespace and compatibility warning/deprecation windows before adding parsers.

The former README recommended Python for the audit **controller**. This is independent of the detector language decision. Rejected/default choices are not silently removed from the record.
