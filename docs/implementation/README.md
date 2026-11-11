# Implementation checkpoints

This folder holds capability-proof briefs, test commands and verified outcomes. Current intent and acceptance are defined in the [roadmap](../roadmap.md); architecture interfaces are in [the specs](../architecture/README.md).

| Checkpoint | Current state | First acceptance evidence |
| --- | --- | --- |
| CP0 — contracts | **Corrected audit package: v0.2 contracts, expanded corpus, independent harness, representative Go/Rust benchmark, Rust ADR, strict paths and CI propagation. Operator acceptance pending** | [CP0 audit report](cp0-contract-validation.md), schema/corpus/harness tests, benchmark artifact, external handoff check |
| CP1 — RNC detector | **Implementation complete; awaiting operator acceptance** | Rust detector finds all in-scope synthetic markers, accounts for every unit, deterministic repeat runs |
| CP2 — adaptive engine/policy/reporting | **Implementation, security hardening and CI complete; awaiting operator review** | Portable strategies equivalent; verified blocks/exemptions; reconciled ledgers; five results; sanitized/private reports; CI exits |
| CP2 — policy/reporting | Not started | Exact reconciliation, redaction, five outcomes and CI acceptance |
| CP3 — harness | External harness exists; CP0 scoring-engine handoff executed, external corpora not run | Independent adapter and per-target external corpus results |
| CP4 — hardening | Not started | Pinned comparative benchmark and adversarial corpus |
| CP5 — orchestrator | Historical design retained; not implemented here | Second independent scanner/backend integration and partial-coverage truthfulness |
| CP6 — distribution | Deferred | Portable CLI without duplicated policy/detection logic |

The original [Gitleaks Proof 1](../foundation/orchestration-v0/proof-1.md) was scoped to a **third-party audit-orchestration vertical slice**. It is preserved for future integration, **not** silently renamed as the new RNC detection CP1.

CP1 implementation evidence is in [cp1-validation.md](cp1-validation.md); the CP2 system, evidence and limitations are in [cp2-validation.md](cp2-validation.md), with operating instructions in [cp2-operator-guide.md](cp2-operator-guide.md). Adaptive matching is described in [../architecture/adaptive-matching.md](../architecture/adaptive-matching.md). The CP0 recovery record for the already-merged PR #3 is [cp0-audit-recovery.md](cp0-audit-recovery.md).

CP0 also tracks the independently pinned [external corpus compatibility inventory](corpus-compatibility.md), retaining organic Leaky Repo and richer normalized score semantics side by side.

Proof briefs should include exact objective, input corpus/truth, executable steps, negative tests, measured outcomes, limitations, branch/commit and PR reference. Do not claim green CI or a successful implementation from a proposed acceptance matrix.
