# Adaptive matching architecture

> **Implemented in CP2, extended in CP3.** One scanner, three portable strategies, one immutable evidence contract.

## Boundaries

```text
authorized source
  -> LocalSource discovery + policy scope gate (no open for blocked units)
  -> MatchPlan (regex | regexset | prefilter)
       -> MatchCandidate { rule_index, value span, full-match span, optional identifier span }
  -> candidate context + validation
  -> deterministic finding records
  -> post-scan exemption dispositions
  -> result + CI decision
```

`backend.rs` owns strategy compilation and candidate extraction. `stream.rs` owns source-window acquisition, boundary handling, validation, dedupe, line mapping and finding construction. `policy.rs` owns blocks, exemptions and the policy ledger. `result.rs` owns classification and CI exit. `config.rs` owns the immutable effective configuration. None of these modules silently performs another's responsibility.

## Strategies

| Strategy | Mechanism | Correctness guarantee |
| --- | --- | --- |
| `regex` | Each rule's exact `regex::bytes::Regex` | Reference; always available |
| `regexset` | A `RegexSet` of proven required literals selects eligible rules; exact regex extracts candidates | Exact extraction; presence is not a finding; no-literal rules always use exact regex |
| `prefilter` | Sound required-literal Aho-Corasick filter; exact regex for eligible rules | No-literal rules always use exact regex; literals are proven |
| `auto` | Conservative planning | Currently reference regex |

The CP3 regexset change was necessary because a full-pattern `RegexSet` over large bounded provider patterns was correct but pathologically slow. The literal-filter set preserves the same candidate contract and is differential-tested against reference regex.

## Required-literal extraction

The planner accepts a literal only when every match must contain it. Extraction recursively handles literals, concatenation, captures, bounded repetition with `min >= 1`, single-byte classes and alternation common prefixes. A required literal may occur anywhere in the match, not only at the prefix; concatenation requires every part, so a literal proven by any mandatory part is safe. If any branch lacks a common literal, or a construct is not provably literal, the result is `None` and the rule remains on exact regex.

This is intentionally conservative. Missing a candidate is a hard correctness failure; evaluating an extra regex is only a performance cost.

## Streaming

A match plan is applied to bounded windows. The carry overlap is the bundle's proven maximum match length. A candidate ending exactly at a non-final window edge is deferred to the next window so a truncated match is never emitted. The final carry is rescanned. Absolute offsets, evidence digests and finding IDs are computed by the common path.

## Candidate context

`MatchCandidate` now retains the exact full-match span and an optional
assignment-identifier span in addition to the value span. `context.rs` derives
a bounded delimiter/quote/`define(...)` view without allocating or changing the
candidate coordinates. Only rules that declare `identifier_capture_group` use
the generic syntax gate; all other rules keep their previous validation path.
The context is never serialized; finding offsets and evidence digests continue
to describe the captured value only.

## Provenance

`PlanProvenance` records:

- requested and effective strategies;
- implementation/version;
- rule count and literal coverage;
- whether a fallback occurred and why.

The private evidence bundle includes `execution_plan` and `configuration`; sanitized reports omit both.

## Differential gate

`tools/cp2/integration_check.py` runs every strategy over v0/v1/edge corpora in whole and stream modes. It validates all v0.2 records and requires identical canonical findings, units, result and CI exit. Any divergence fails CI.

## Deferred

Hyperscan/VectorScan, per-file dynamic routing and parallel strategy execution are deliberately out of scope. See [ADR-012](adr-012-deferred-accelerators.md).
