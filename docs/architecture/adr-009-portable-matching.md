# ADR-009 — Portable multi-strategy matching architecture

- **Status:** Accepted for CP2
- **Date:** 11 November 2026
- **Checkpoint:** CP2

## Context

CP1 coupled rule compilation, regex iteration, validation and finding creation inside `stream.rs`. That was sufficient for one backend but would duplicate finding/validation/coverage logic for every future strategy. CP2 must support native Rust regex, RegexSet and Aho-Corasick acceleration without creating separate scanner products or native dependencies.

## Decision

Introduce a narrow backend boundary:

1. `LoadedBundle` owns rule definitions, exact regexes and a conservatively derived required literal.
2. `MatchPlan` owns a selected backend and emits `MatchCandidate { rule_index, start, end }` spans with capture semantics already applied.
3. `stream.rs` owns acquisition windows, candidate validation, deduplication, line mapping and finding construction. Every backend uses this one path.
4. `BackendRequest` is `regex`, `regexset`, `prefilter` or `auto`. The reference regex backend is always available and remains the default for `auto`.
5. `PlanProvenance` records requested/effective strategy, implementation version, literal coverage, fallback use and fallback reason.

The backend never sees policy, exemptions, report formatting, CI decisions or source locator policy.

## Consequences

- A new backend must produce exact capture-group spans and pass differential equivalence; reporting and policy need no changes.
- RegexSet first identifies applicable patterns, then runs each matched rule's exact regex. Presence alone is not a finding.
- The Aho-Corasick strategy is a prefilter: if a rule has a proven required literal, the exact regex runs only when that literal occurs in the window. Rules without a proven literal always run exact regex.
- No dynamic plugins, trait-object registry or native accelerator is introduced. The enum boundary is deliberately small.
- Backend selection is explicit except for the conservative `auto` default.

## Validation

`tools/cp2/integration_check.py` compares canonical findings, units, result and CI exit across all four strategies for v0/v1/edge corpora and whole/stream modes. Any mismatch fails CI.
