# Roadmap — RNC Scanner into RNC Security Audit

> **Working roadmap, 10 November 2026.** Capability proofs, not release dates. No checkpoint is claimed complete merely because its design is documented.

## Delivery strategy

**Build the center first:** (1) our own detection/identification engine, then (2) evidence accounting, policy-aware reporting and result/CI contracts. Only then widen input types, credential categories, output formats and the wider audit orchestrator. Every stage must be testable with synthetic fixtures independently of Gitleaks.

| Priority | Checkpoint | Deliverable | Exit gate |
| --- | --- | --- | --- |
| **Now** | **CP0 — operating contracts** | Four architecture specs, schema examples, precise scope/status semantics, synthetic fixture/answer-key design, baseline threat model | Review and sign off interfaces; expected results known before detector code |
| **P1** | **CP1 — RNC detection core** | One authorized local-source adapter, versioned rules, matching/validation, stable finding events, traceable coverage | Every known in-scope synthetic credential is identified with accurate locations; clean/invalid/partial inputs accounted for; deterministic repeat runs |
| **P2** | **CP2 — policy + reporting backbone** | Verified pre-scan blocks, post-scan exemptions, config provenance, independent execution/detection/policy records, five-state classifier, sanitized JSON, CI acceptance | Counts reconcile exactly, precedence tests pass, output leaks no test secrets, CI acceptance never rewrites results |
| **P3** | **CP3 — independent accuracy harness** | Reuse/harden adapter-agnostic harness; synthetic stub first, complete target-by-target truth manifest, canonical normalized findings and metrics | Stub produces **100% correct expected scoring** on constructed cases; engine scored independently for recall, precision, false positives and misses |
| **P4** | **CP4 — accuracy and speed hardening** | Rule/category expansion, validator tuning, file edge cases, adversarial fixture suite, controlled comparison with Gitleaks/Betterleaks, measured performance | Reproducible version-pinned benchmarks, no unexplained regressions, transparent coverage/corpus limits |
| **P5** | **CP5 — audit orchestration integration** | Bring forward Gitleaks, Trivy and other third-party adapter designs; preflight, runtime backends, required/optional check selection, raw/sanitized audit aggregation | Independent tool failures and findings stay distinct; second scanner adds without changing the five-result semantics |
| **Later** | **CP6 — portability and interfaces** | Additional source/backends, richer report exports (e.g. SARIF), noninteractive CI packages, optional TUI/GUI and portable RNC Security Toolkit distribution | No duplicated detection or policy logic across interfaces/platforms |

CP0 and CP1 may define interfaces for downstream modules without implementing them. CP2 is the **second major system** after detection, not a detour into dashboard work. CP3's synthetic stub scoring contract is also a prerequisite for trusting any published accuracy comparison, even if the scanner is prototyped earlier.

## Work packages

### CP0 — lock the operating contract

- [x] Establish documentation-only architecture, historical foundation, and proposed five result classes.
- [ ] Approve canonical schemas and finalization rules for unit IDs, findings, policy events, reporting and CI decisions.
- [ ] Define target manifest, required versus optional coverage, no-read enforcement and error taxonomy.
- [ ] Prepare synthetic fixtures with **known truth by target** and independently defined expected report outputs.
- [x] Agree Go/Rust benchmark requirement, CI default codes `1,2`, full synthetic corpus scope and unified config migration direction in the [ADR register](architecture/decisions.md).
- [x] Draft [config migration semantics](architecture/config-migration.md) and [threat model](architecture/threat-model.md).
- [x] Create initial [machine-readable schemas](contracts/README.md) and authored + generated synthetic corpus specification with CP0 validation tests.
- [ ] Observe Go/Rust benchmark CI artifact, confirm toolchain/platform fairness and document language selection criteria.
- [ ] Approve final schema version, rule-set licensing, required-scope details, config filename, and CP1 entry gate.

### CP1 — prove the detector independently

- [ ] Implement source adapter + pre-scan input boundary with exact byte/line mapping and read-only access.
- [ ] Implement versioned rule bundle and candidate validation; no CI/report/exemption imports into the engine.
- [ ] Emit normalized finding events and explicit operational/coverage errors.
- [ ] Test zero findings, known positives, duplicates, invalid content, symlinks, encoding, limits and interruption.
- [ ] Record pinned build/ruleset and measured throughput/memory before optimization.

### CP2 — prove accountability and enforcement

- [ ] Implement policy composition with origin, mandatory controls, requested/applied state and narrow exemptions.
- [ ] Implement complete execution, detection and policy ledgers with deterministic reconciliation.
- [ ] Implement final result classifier and **all precedence collisions**.
- [ ] Emit safe canonical JSON; prove fail-closed sanitization and private evidence isolation.
- [ ] Implement result-to-OS-exit policy with both accepted and rejected `POLICY_APPLIED` outcomes.

### CP3 — grade, do not self-grade

- [ ] Complete independent scanner-agnostic manifest and normalized-result adapters.
- [ ] Prove scoring with an intentionally manufactured synthetic scanner adapter; expected scoring must be exact for each known input.
- [ ] Record per-target accountable secrets, false positives, misses, ambiguous cases and completeness.
- [ ] Score RNC Scanner and external comparators using the **same** held-out fixtures and declared scope.

### CP4–CP6 — broaden without changing the engine contract

- Expand credential categories, validation, input adapters and safe non-read methods incrementally; benchmark every ruleset and engine change.
- Integrate third-party scanners and different runtime backends through the original orchestration seams, not inside RNC detection.
- Add report formats and CI integrations as consumers of the same records; later choose portable packaging and operator UI from evidence.

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

These require evidence at kickoff rather than premature commitments: detector language/runtime; exact rule format and deterministic matching limits; private evidence retention; public safe-location policy; default required-scope rules; cross-platform exit/signal behavior; whether the wider audit controller shares `.rncscanner.toml` or retains a separate compatible `security.config` namespace. None changes the five-result conceptual contract.
