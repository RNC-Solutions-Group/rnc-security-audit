# Implementation checkpoints

This folder holds capability-proof briefs, test commands and verified outcomes. Current intent and acceptance are defined in the [roadmap](../roadmap.md); architecture interfaces are in [the specs](../architecture/README.md).

| Checkpoint | Current state | First acceptance evidence |
| --- | --- | --- |
| CP0 — contracts | **Corrected audit package: v0.2 contracts, expanded corpus, independent harness, representative Go/Rust benchmark, Rust ADR, strict paths and CI propagation. Operator acceptance pending** | [CP0 audit report](cp0-contract-validation.md), schema/corpus/harness tests, benchmark artifact, external handoff check |
| CP1 — RNC detector | **Implementation complete; awaiting operator acceptance** | Rust detector finds all in-scope synthetic markers, accounts for every unit, deterministic repeat runs |
| CP2 — adaptive engine/policy/reporting | **Implementation, security hardening and CI complete; awaiting operator review** | Portable strategies equivalent; verified blocks/exemptions; reconciled ledgers; five results; sanitized/private reports; CI exits |
| CP3 — provider intelligence and accuracy | **READY FOR OPERATOR MERGE; corrective review, controlled/external evidence and CI complete** | Provider catalog, AWS identifier taxonomy, GitHub installation tokens, byte-addressed independent truth, Tier 4 challenge, strategy equivalence, scoped external corpora and corrected one-to-one comparative Gitleaks evidence |
| CP4 — detection expansion and Git history | **READY FOR OPERATOR REVIEW; CI complete** | Generic extraction, PEM/PGP representations, 37-rule catalog, read-only history adapter, occurrence and cross-platform tests |
| CP4A — hardening and release preparation | **IMPLEMENTED; operator review pending** | Private password-component evidence, Windows private-report DACL, benchmark CI retirement, documentation and clean-extraction package smoke |
| CP4B — contextual candidate validation | **IMPLEMENTED; CI complete; operator review pending** | Candidate context, assignment-syntax gate, `BASE` qualifiers, context-aware hex classification and exact-byte regression |
| CP5 — orchestrator | **PARKED by operator direction** | No CP5 work authorized during CP4B |
| CP6 — distribution | Deferred | Portable CLI without duplicated policy/detection logic |

The original [Gitleaks Proof 1](../foundation/orchestration-v0/proof-1.md) was scoped to a **third-party audit-orchestration vertical slice**. It is preserved for future integration, **not** silently renamed as the new RNC detection CP1.

CP1 implementation evidence is in [cp1-validation.md](cp1-validation.md); the CP2 system, evidence and limitations are in [cp2-validation.md](cp2-validation.md), with operating instructions in [cp2-operator-guide.md](cp2-operator-guide.md). Adaptive matching is described in [../architecture/adaptive-matching.md](../architecture/adaptive-matching.md). CP3 detection capability is in [cp3-detection-catalog.md](cp3-detection-catalog.md), scoring in [cp3-accuracy-methodology.md](cp3-accuracy-methodology.md), benchmark design in [cp3-benchmark-methodology.md](cp3-benchmark-methodology.md), and final evidence in [cp3-validation.md](cp3-validation.md). CP4 adds [detection catalog](cp4-detection-catalog.md), [generic credentials](cp4-generic-credentials.md), [private keys](cp4-private-keys.md), [Git history](cp4-git-history.md) and [validation](cp4-validation.md). CP4A adds [structured evidence, Windows private-report security, CI retirement and package proof](cp4a-hardening.md). CP4B adds [contextual candidate validation, assignment-syntax checks and hex/name classification](cp4b-contextual-validation.md). The CP0 recovery record for the already-merged PR #3 is [cp0-audit-recovery.md](cp0-audit-recovery.md).

CP0 also tracks the independently pinned [external corpus compatibility inventory](corpus-compatibility.md), retaining organic Leaky Repo and richer normalized score semantics side by side.

Proof briefs should include exact objective, input corpus/truth, executable steps, negative tests, measured outcomes, limitations, branch/commit and PR reference. Do not claim green CI or a successful implementation from a proposed acceptance matrix.
