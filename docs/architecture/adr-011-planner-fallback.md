# ADR-011 — Execution planning and conservative fallback

- **Status:** Accepted for CP2
- **Date:** 11 November 2026

## Context

CP2 supports three portable strategies. Automatic selection must not become an opaque performance heuristic that changes findings. The current rule bundle has ten rules, and measured Aho-Corasick/RegexSet results are workload-dependent; neither showed a consistent advantage on every CP2 profile.

## Decision

- `auto` resolves to the reference regex backend for the current production bundles.
- Explicit `regexset` and `prefilter` are supported and tested.
- The planner records requested/effective strategy, rule count, rules with/without required literals, implementation version, fallback use and reason.
- A failed RegexSet or Aho-Corasick compile falls back to reference regex with an explicit reason. A rule without a proven required literal is evaluated by exact regex even when the selected strategy is prefilter.
- A rule is never skipped merely because a convenient keyword is absent; literal extraction is conservative and `None` means full exact evaluation.

## Consequences

- The default path prioritizes correctness and predictability.
- Optimized strategies remain available for controlled evaluation and future rule sets.
- Promotion of `auto` to a non-reference strategy requires benchmark and differential evidence; it is not a configuration-only change.
- No per-file performance prediction or machine-learning routing is introduced.

## Validation

CP2 benchmark (`tools/cp2/bench.py`) records all strategies; the CP2 differential gate enforces equivalence. See [adaptive-matching.md](adaptive-matching.md).
