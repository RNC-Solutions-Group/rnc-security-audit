# Roadmap — RNC Scanner into RNC Security Audit

> **Working roadmap, 12 November 2026.** Capability proofs, not release dates. No checkpoint is claimed complete merely because its design is documented. Independent detection accuracy, comparative and performance grading is owned by the external RNC Scanner Harness; the scanner repository retains correctness and security regressions only.

## Delivery strategy

**Build the center first:** (1) our own detection/identification engine, then (2) evidence accounting, policy-aware reporting and result/CI contracts. Only then widen input types, credential categories, output formats and the wider audit orchestrator. Every stage must be testable with synthetic fixtures independently of Gitleaks.

| Priority | Checkpoint | Deliverable | Exit gate |
| --- | --- | --- | --- |
| **Now** | **CP0 — operating contracts** | v0.2 schemas, validated cross-record invariants, expanded synthetic corpus, independent harness, representative Go/Rust benchmark, Rust ADR, CP1 handoff | Operator accepts the CP0 audit package; no unresolved foundational interface decision before CP1 |
| **P1** | **CP1 — RNC detection core** | One authorized local-source adapter, versioned rules, matching/validation, stable finding events, traceable coverage | Every known in-scope synthetic credential is identified with accurate locations; clean/invalid/partial inputs accounted for; deterministic repeat runs |
| **P2** | **CP2 — adaptive engine + policy/reporting backbone** | Portable matching, verified pre-scan blocks, post-scan exemptions, config provenance, independent records, five-state classifier, sanitized/private JSON, CI acceptance | Differential equivalence, counts reconcile, precedence tests pass, no private leakage, CI acceptance never rewrites results |
| **P3** | **CP3 — independent accuracy harness** | Reuse/harden adapter-agnostic harness; synthetic stub first, complete target-by-target truth manifest, canonical normalized findings and metrics | Stub produces **100% correct expected scoring** on constructed cases; engine scored independently for recall, precision, false positives and misses |
| **P4** | **CP4 — detection expansion and history acquisition** | Generic credential extraction, private-key representations, additional documented provider families, read-only Git-history source adapter | All CP0-CP3 regressions pass; new detection/negative suites pass; all strategies and modes remain equivalent; history acquisition is read-only, bounded and explicit about incomplete coverage |
| **P1 corrective** | **CP4A — hardening and release preparation** | Structured password-component evidence, Windows private-report ACLs, CI benchmark retirement, documentation and a development evaluation package | Primary finding identities unchanged; component offsets/digests verified; private/sanitized isolation and Windows ACL tests pass; package smoke passes from a clean extraction |
| **PARKED** | **CP5 — audit orchestration integration** | Third-party adapter/orchestration work | Explicitly parked by the operator; no work until the standalone scanner is accepted and independently validated |
| **Later** | **CP6 — portability and interfaces** | Additional source/backends, richer report exports (e.g. SARIF), noninteractive CI packages, optional TUI/GUI and portable RNC Security Toolkit distribution | No duplicated detection or policy logic across interfaces/platforms |

CP0 and CP1 may define interfaces for downstream modules without implementing them. CP2 is the **second major system** after detection, not a detour into dashboard work. CP3's synthetic stub scoring contract is also a prerequisite for trusting any published accuracy comparison, even if the scanner is prototyped earlier.

## Work packages

### CP0 — lock the operating contract

- [x] Establish documentation-only architecture, historical foundation, and proposed five result classes.
- [x] Correct and validate canonical schemas and finalization rules for unit IDs, findings, policy events, reporting and CI decisions (v0.2; see [compatibility](contracts/compatibility.md)).
- [x] Define target manifest, required versus optional coverage, no-read enforcement and error taxonomy.
- [x] Prepare authored and generated synthetic fixtures with **known truth by target** and independently defined expected report outputs (9-target baseline, 21-target expansion, 1,000-target generated lane, large/oversize edge lane).
- [x] Agree Go/Rust benchmark requirement, CI default codes `1,2`, full synthetic corpus scope and unified config migration direction in the [ADR register](architecture/decisions.md).
- [x] Implement and test explicit [config migration](architecture/config-migration.md) for `.rncscanner.toml` and the reviewed `security.config` subset; draft [threat model](architecture/threat-model.md).
- [x] Create [machine-readable schemas](contracts/README.md), cross-record validator and independent synthetic harness.
- [x] Preserve and observe the compiled Go/Rust **primitive** benchmark baseline.
- [x] Evaluate representative compiled rule/regex/validation/streaming/memory workloads and select Rust in [ADR-007](architecture/adr-007-detector-language.md).
- [x] Execute the pinned external harness scoring engine against the CP0 handoff; external corpus execution remains deferred.
- [x] Required CI lanes passed on run 42905889622: contracts/tests/harness, representative Go/Rust benchmarks, external scoring contract.
- [ ] Operator accepts schema v0.2, Rust selection, `.rncscanner.toml`, required-scope details, rule-set licensing and CP1 entry gate.

### CP1 — prove the detector independently

- [x] Implement Rust source adapter + pre-scan input boundary with exact byte/line mapping, read-only access, symlink/traversal rejection and TOCTOU accounting.
- [x] Implement versioned rule bundle and candidate validation; no CI/report/exemption imports into the engine.
- [x] Emit normalized v0.2 finding events and explicit operational/coverage errors.
- [x] Test zero findings, known positives, duplicates, overlapping rules, invalid content, symlinks, encoding, limits, cancellation/timeouts and interruption.
- [x] Record pinned build/ruleset and measured throughput/memory before optimization; compare against the CP0 comparator.
- [x] Pass independent synthetic truth for v1/v0/edge; pinned external harness scores actual CP1 output.
- [ ] Required CP1 CI green and operator acceptance.

### CP2 — prove accountability and enforcement

- [x] Implement portable reference/RegexSet/Aho-Corasick matching with a conservative planner and differential equivalence.
- [x] Implement policy composition with origin, mandatory controls, requested/applied state and narrow exemptions.
- [x] Implement complete execution, detection and policy ledgers with deterministic reconciliation.
- [x] Implement final result classifier and **all precedence collisions**.
- [x] Emit safe canonical JSON; prove fail-closed sanitization and private evidence isolation.
- [x] Implement result-to-OS-exit policy with both accepted and rejected `POLICY_APPLIED` outcomes.
- [x] Final security hardening: atomic report publication, root-contained source acquisition, trusted CI acceptance authority, bounded policy/discovery work and content policy digests.
- [ ] Operator review of CP2 and merge decision.

### CP3 — grade, do not self-grade

- [x] Separate first-party provider catalog (`0.2.0`, ruleset `2026.11.2`) preserving synthetic `0.1.0` regression truth.
- [x] Bounded patterns, candidate caps and reusable offline validators for cloud, developer-platform, service, cryptographic, structured and generic credential families.
- [x] Controlled provider-format positives, negatives, malformed and same-line/multiline/binary fixtures, plus a hand-authored Tier 4 challenge that does not reuse the Tier 2/3 generator.
- [x] Independent byte-addressed truth, conservative scorer and one-to-one Gitleaks reconciler, including negative controls for empty, over-reporting, duplicate, shifted, wrong-source, wrong-family, wrong-position, unknown-rule and incomplete scanners.
- [x] All four matching strategies and whole/stream modes produce identical Tier 2/3/challenge findings (27/27, 15/15, 14/14).
- [x] Pinned external-harness handoff with explicit line-addressing limitation.
- [x] Scoped Levain FP/TP evidence, count-based Leaky Repo scan and pinned Gitleaks comparison.
- [x] Provider-catalog benchmark methodology and measured evidence.
- [x] Required pre-correction CP3 CI preserved (run 43087012245, seven required jobs); corrected final-head CI is recorded in the CP3 validation report.
- [ ] PR review and operator acceptance.

### CP4 — expand detection and add history acquisition

- [x] Expand generic assignments across `.env`, shell, JSON, YAML, TOML, INI, XML, PHP, SQL, quoted/escaped/multiline values and authorization contexts.
- [x] Add escaped, base64-wrapped, log-embedded and PGP private-key representations with bounded structural validators.
- [x] Add documented provider families: Azure Storage, Tailscale, Groq, xAI, Perplexity, Doppler, Slack webhooks and OpenAI-labelled keys; mark weak formats experimental.
- [x] Add a read-only Git-history source adapter with explicit `--history`, selected refs, occurrence-level commit/path identity, bounded traversal and fail-closed coverage.
- [x] Add generic, private-key, provider and history regression suites across whole/stream modes and all matching strategies.
- [x] Preserve CP0-CP3 truth, synthetic bundles and rule identities; update documentation and README.
- [x] Final CP4 CI on the pushed branch is green across the required matrix.
- [ ] Operator review and merge decision.

### CP4A — corrective hardening and release preparation

- [x] Derive private password-component evidence from validated database URI findings without changing the primary finding span, digest, ID or rule identity.
- [x] Add bounded ANSI SGR normalization with original source offsets, source and normalized hashes, and explicit unsupported-escape behavior.
- [x] Add explicit Windows private-report DACL creation and handle verification before payload writes; test permissive-parent replacement and unrelated-principal denial.
- [x] Retire the internal provider benchmark job from routine CI while preserving historical benchmark evidence and correctness regressions.
- [x] Add a reproducible Windows/Linux development evaluation package and clean-extraction smoke test.
- [x] Update CP4A documentation, roadmap and repository status without deleting historical evidence.
- [ ] Operator review, PR #11 update and explicit merge decision. No merge to `main` by the developer.

### CP5 — parked

CP5 orchestration work is **explicitly parked** by operator direction. It is not authorized by CP4A and does not begin until the standalone scanner, package and private-evidence security posture are accepted and independently validated.

### CP6 — later

- Add report formats and CI integrations as consumers of the same records; later choose portable packaging and operator UI from evidence.
- Expand source adapters and backend experiments only through versioned interfaces.
- No duplicated detection or policy logic across interfaces/platforms.

Independent detection accuracy, comparative and performance evaluation is owned by the external RNC Scanner Harness. The scanner repository retains synthetic truth, exact-byte correctness gates and security regressions; it does not operate an authoritative internal benchmark suite.

## Original material to reuse

The [preserved foundation](foundation/README.md) contains the first audit-orchestration roadmap, Python CLI sketches, per-scanner preflight, target confirmation, private versus sanitized exclusion reports, and the original Docker/Gitleaks Proof 1. They are **not discarded**:

| Earlier design | Where it adds value now |
| --- | --- |
| Gitleaks/Docker end-to-end proof | Third-party scanner adapter and audit-orchestration integration in CP5; can separately serve as a comparison baseline earlier |
| Independent readiness (`READY/UNAVAILABLE/DISABLED/NOT_APPLICABLE`) | Coverage/accountability taxonomy for optional versus required external checks |
| Verified input bypass report | CP2 no-read policy provenance and raw-versus-sanitized reporting |
| Target confirmation and authorized active modes | Later container/image/web adapters and red-team operator safeguards |
| Python CLI, backend, cleanup and evidence sketches | Future audit controller; no requirement that RNC's detection engine itself be Python |

The independent Gitleaks scan harness is **external validation infrastructure** and should keep its own adapter-agnostic scoring code and manifest. No harness self-test should be counted as scanner accuracy evidence.

## Non-goals and control gates

- No real credentials in committed fixtures or reports, and no public raw evidence.
- No automatically active/production network scanning, exploitation, or arbitrary third-party executable commands.
- No self-declared scan accuracy from the production detector.
- No date-driven rush to GUI, AI summaries, marketplace, installer, database or cloud dashboard.
- Every checkpoint lands through an inspected feature branch and PR. No automatic merge to `main`.

## Open engineering decisions

Resolved in CP0: detector language **Rust** ([ADR-007](architecture/adr-007-detector-language.md)); repository config entry point **`.rncscanner.toml`** with explicit legacy migration; schema revision **v0.2**; CI default acceptance **`1,2`**.

Still requiring operator/CP1 evidence: exact rule-bundle file format and licensing; private evidence retention; public safe-location policy; default required-scope rules; cross-platform exit/signal behavior; whether the wider audit controller shares `.rncscanner.toml` or retains a compatible separate namespace. None changes the five-result conceptual contract.
