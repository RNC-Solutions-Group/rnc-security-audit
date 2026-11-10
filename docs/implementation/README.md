# Implementation checkpoints

This folder will hold short capability-proof briefs, test commands and verified outcomes **as each checkpoint begins**. Current intent and acceptance are defined in the [roadmap](../roadmap.md); architecture interfaces are in [the specs](../architecture/README.md).

| Checkpoint | Current state | First acceptance evidence |
| --- | --- | --- |
| CP0 — contracts | **Documentation drafted; review pending** | Reviewed schemas, precedence matrix, manifest and fixture truth |
| CP1 — RNC detector | Not started | Deterministic synthetic detections and complete unit ledger |
| CP2 — policy/reporting | Not started | Exact reconciliation, redaction, five outcomes and CI acceptance |
| CP3 — harness | External work exists; integration not validated here | Synthetic stub grades exactly as predicted; independent scanner adapter |
| CP4 — hardening | Not started | Pinned comparative benchmark and adversarial corpus |
| CP5 — orchestrator | Historical design retained; not implemented here | Second independent scanner/backend integration and partial-coverage truthfulness |
| CP6 — distribution | Deferred | Portable CLI without duplicated policy/detection logic |

The original [Gitleaks Proof 1](../foundation/orchestration-v0/proof-1.md) was scoped to a **third-party audit-orchestration vertical slice**. It is preserved for future integration, **not** silently renamed as the new RNC detection CP1.

Proof briefs should include exact objective, input corpus/truth, executable steps, negative tests, measured outcomes, limitations, branch/commit and PR reference. Do not claim green CI or a successful implementation from a proposed acceptance matrix.
