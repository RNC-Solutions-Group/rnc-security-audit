# ADR-018 — CP5 execution and detection changes

- **Status:** Accepted for CP5 operator review
- **Date:** 16 November 2026
- **Supersedes in part:** [ADR-011](adr-011-planner-fallback.md) (`auto`
  backend decision); [ADR-009](adr-009-portable-matching.md) backend default
- **Related:** [CP5 optimization architecture](cp5-optimization-architecture.md)

## Context

CP4C established parallel workers, configurable matching backends, process and
batch Git acquisition, whole/diff history and a versioned profile. Independent
evidence then showed three material costs:

1. The reference regex strategy ran every rule's exact regex over every window.
   The alternative backends were exact but `auto` still selected regex, so the
   default path paid the full cost.
2. Git discovery launched one `diff-tree` process per commit, and the default
   object path launched one `cat-file blob` process per blob. On Windows, process
   creation dominated Git-history wall time.
3. The filesystem open path recomputed canonical paths and probed the final
   handle path on every file.

Independent detection-gap analysis also identified WordPress authentication
material and HMAC/signing identifiers as high-confidence identifier-lexicon
misses.

## Decision

1. **`auto` selects `prefilter`.** Required literals are extracted as a set, with
   case-insensitive flag normalization, and matched ASCII-case-insensitively by
   one Aho-Corasick automaton. Every eligible rule still runs its exact regex.
   Explicit `regex` remains the reference oracle.
2. **Aggregate candidate budget in the regex backend.** Candidate materialization
   is bounded across rules, not only per rule.
3. **Cache the canonical scan root once.** The Windows containment checks remain
   per open; only repeated canonicalization and the length-probe syscall are
   removed.
4. **Batch Git delta enumeration.** Non-merge commits use one
   `diff-tree --stdin` process per bounded batch; merge commits retain the exact
   two-tree invocation. Output-limit failures fall back to the single-commit
   path.
5. **Default Git object acquisition changes to `batch`.** A failed batch start
   falls back to the exact process path. Explicit `--git-io process` preserves
   the CP4C reference.
6. **Add a bounded WordPress authentication rule** for the eight core
   `wp-config.php` names plus `WP_SALT_n`, in PHP `define()`, assignment,
   Kubernetes data and quoted representations, with a dedicated structural
   validator.
7. **Add `SIGNING_KEY` and `HMAC_KEY`/`HMAC_SECRET` to the generic assignment
   identifier family.** `JWT_SIGNING_KEY`, `PAYMENTS_SIGNING_KEY` and
   camelCase/hyphenated forms are covered by the same identifier suffix; no bare
   `KEY` rule is introduced.
8. **Keep the worker default at `1`.** The prefilter reduces memory and CPU, but
   `auto` still trades CPU and memory for wall time. The operator can select it
   explicitly.

## Alternatives

See [CP5 optimization architecture § Rejected alternatives](cp5-optimization-architecture.md#rejected-alternatives).
The principal rejected choices were RegexSet for `auto`, lowering regex cache
capacity, dropping ancestor reparse checks, parallel `diff-tree` processes and a
persistent worker pool.

## Consequences

- Default filesystem and Git-history scans are materially faster and use less
  memory than CP4C on the measured Windows workloads.
- The default Git path now depends on `git cat-file --batch`; a conservative
  process fallback preserves compatibility.
- `auto` and default Git acquisition are behavioral changes. The exact CP4C
  reference remains reachable with explicit flags.
- All current rules have a proven required literal. Future rule authoring should
  preserve that property where practical, but a missing proof only costs
  performance and never changes findings.
- Rule versions for the four generic rules and the new WordPress rule are
  `2026.11.6`; the ruleset is `2026.11.6`.

## Validation

CP5 records local equivalence, performance and detection evidence in
[CP5 validation](../implementation/cp5-validation.md). Independent harness
scoring remains authoritative and is not claimed here.
