# Documentation guide

| Area | Status | Contents |
| --- | --- | --- |
| [Architecture](architecture/README.md) | **Current design contract** | Detector, policy, reporting, scan result and CI boundaries |
| [Contracts](contracts/README.md) | **Validated v0.2 contract** | Seven schemas, identities, cross-record invariants |
| [Contract compatibility](contracts/compatibility.md) | **Current revision record** | v0.1 → v0.2 changes and migration policy |
| [Harness handoff](contracts/harness-handoff.md) | **Tested handoff** | Pinned external scoring contract and outstanding integration |
| [Roadmap](roadmap.md) | **Current plan** | Ordered proofs, acceptance gates, future orchestration |
| [Implementation](implementation/README.md) | **CP0 audit + CP1 handoff** | Deliverable dispositions, evidence, acceptance and checkpoint briefs |
| [Foundation](foundation/README.md) | **Historical, preserved** | Initial audit orchestrator sketches and original Proof 1 brief |

Specifications describe **intended behavior**, not shipped software. A proof becomes complete only with the implementation commit, commands, fixtures, and verified test outcomes. Historical files should inform new designs but do not override the current operating contract.

Conventions: lowercase kebab-case `.md` files, Markdown tables for exact contracts, Mermaid for meaningful flows, no production secrets or raw secret evidence, and operator-controlled PR merges. Synthetic markers are explicitly harmless and nonfunctional. Host-dependent benchmark output is retained as a CI artifact; documentation summarizes methods and decision consequences rather than publishing a single universal score.
