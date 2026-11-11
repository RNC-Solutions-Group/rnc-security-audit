# CP0 architecture decisions — ADR register

Status: **CP0–CP3 decisions recorded; operator review pending.** The production detector language is selected as **Rust** in [ADR-007](adr-007-detector-language.md); CP2 implements portable strategies and policy/reporting boundaries. CP3 adds a separately versioned provider catalog in [ADR-015](adr-015-provider-credential-catalog.md).

| ID | Decision | Consequence / next check |
| --- | --- | --- |
| ADR-001 | **Benchmark Go and Rust before selecting the detector language** | Satisfied by the shared-rule representative benchmark. Go remains a comparator; Rust selected in ADR-007 |
| ADR-002 | **Unified configuration schema with migration** | `.rncscanner.toml` is canonical; explicit `security.config` subset migration; no dual-loading. Reference loader tested |
| ADR-003 | **Default CI acceptance: `CLEAN` and `POLICY_APPLIED`** | OS exit `0` for finalized codes `1` or `2`; actionable `3` fails by default; codes `4`/`5` never pass |
| ADR-004 | **Full synthetic corpus and benchmark work in CP0** | Authored baseline + expanded corpus + generated 1,000-target corpus + edge corpus; representative Go/Rust comparison executed in CI |
| ADR-005 | **Production detector never evaluates its own accuracy** | Independent harness scores normalized findings; synthetic stub is a controlled test adapter only |
| ADR-006 | **Adopt contract revision v0.2** | Required-scope counts, canonical identities, record digests, policy requests, evidence validation and publication checks. v0.1 drafts are not silently accepted |
| ADR-007 | **Select Rust for the production detector** | Representative evidence favors Rust; build/distribution mitigations are mandatory. See [ADR-007](adr-007-detector-language.md) |
| ADR-008 | **External harness compatibility is line-addressed with byte metadata sidecar** | Pinned external scoring engine executed on CP0 handoffs; full external corpus integration remains deferred |
| ADR-009 | **Portable multi-strategy matching behind one candidate contract** | Regex is the reference backend; RegexSet and Aho-Corasick are interchangeable strategies. See [ADR-009](adr-009-portable-matching.md) |
| ADR-010 | **Exact reference equivalence is a hard gate** | Optimized strategies must reproduce canonical findings, offsets, identity and coverage. See [ADR-010](adr-010-reference-regex-equivalence.md) |
| ADR-011 | **Conservative planner and explicit fallback** | `auto` stays on reference regex for current bundles; no silent rule skipping. See [ADR-011](adr-011-planner-fallback.md) |
| ADR-012 | **Hyperscan/VectorScan deferred** | Portable Rust-only CP2; future native backends require a separate ADR and equivalence evidence. See [ADR-012](adr-012-deferred-accelerators.md) |
| ADR-013 | **CI acceptance has a trusted authority** | Repository config may narrow only; global or explicit CLI may authorize `ACTIONABLE`. See [ADR-013](adr-013-ci-acceptance-authority.md) |
| ADR-014 | **Root-contained acquisition and atomic reports** | Unix openat/no-follow chains; Windows reparse checks with documented residual race; atomic publication. See [ADR-014](adr-014-root-contained-acquisition.md) |
| ADR-015 | **Separate provider credential catalog** | Schema `0.2.0` adds provider/family/credential metadata, bounded candidate captures and offline validators. Synthetic `0.1.0` digests are unchanged. See [ADR-015](adr-015-provider-credential-catalog.md) |

## Decision review checkpoints

1. Confirm CP0 schema v0.2 and cross-record identity/count/finalization rules.
2. Review the representative Go/Rust benchmark artifact, including median/tail latency, memory where available, build characteristics and binary size. The preliminary literal probe is retained as a baseline, not the decision basis.
3. Review [ADR-007](adr-007-detector-language.md) and its acceptance risks: Rust build cost, dependency pinning, and cross-platform distribution.
4. Approve `.rncscanner.toml` as the repository filename and the legacy migration subset before parsing untrusted config.
5. Accept the CP0 package before any CP1 production engine work. No PR merge is implied by this register.

The former README recommended Python for the audit **controller**. That is independent of the detector language decision. Rejected/default choices are not silently removed from the record.
