# ADR-010 — Reference regex backend and equivalence standard

- **Status:** Accepted for CP2
- **Date:** 11 November 2026

## Context

RegexSet reports which patterns matched but does not expose all capture groups. Aho-Corasick finds literals, not credential spans. Either optimization could silently lose a finding if treated as a complete detector.

## Decision

The original `regex::bytes::Regex` backend is authoritative for CP2. A candidate is accepted only when:

- the exact rule regex matches;
- the declared capture group is present and non-empty;
- candidate validation succeeds;
- the canonical byte span produces the same finding ID and evidence digest as the reference backend.

Optimized strategies must match the reference exactly for:

- source unit and locator;
- rule ID and version;
- start/end byte offsets;
- line and line-end;
- validation names;
- duplicate suppression;
- finding ID and evidence digest;
- execution/disposition coverage.

The differential gate runs all four strategies over synthetic-v0, synthetic-v1, edge, whole-file and streaming inputs. A strategy that fails is not promoted.

## Consequences

- Performance optimization cannot justify a missed finding.
- Same-line/same-rule collisions remain a harness integration concern; RNC findings stay byte-addressed.
- Backend implementation changes require re-running the differential suite.
- The reference backend remains selectable even when acceleration is available.

## Validation

`tools/cp2/integration_check.py`; `crates/rnc-core/src/backend.rs` tests; pinned external harness scoring of each strategy's handoff.
