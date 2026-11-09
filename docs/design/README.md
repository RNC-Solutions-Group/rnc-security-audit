# Design sketches

This directory contains **illustrative day-zero designs** for RNC Security Audit. These are not executable commands, actual scan reports, or evidence that a capability is implemented.

| Sketch | Purpose |
| --- | --- |
| [CLI workflow](cli-workflow.md) | The overall interactive operation flow and partial-coverage summary |
| [Scanner preflight](scanner-preflight.md) | Per-scanner readiness, reasons for unavailability, and continuing ready scans |
| [Target confirmation](target-confirmation.md) | Optional target IDs and explicit image/application confirmation |
| [Raw bypass report](bypass-report-raw.md) | Proposed private path-level exclusion evidence and enforcement claims |
| [Sanitized bypass report](bypass-report-sanitized.md) | Proposed counts-only exclusion summary |
| [Application structure](application-structure.md) | Python packages and responsibility boundaries |

These sketches evolve as the proofs validate or change the theory. The [project README](../../README.md) explains the product promise and overall roadmap; [implementation briefs](../implementation/README.md) define testable proof objectives.

**Conventions:** lowercase kebab-case Markdown filenames, GitHub-friendly headings/tables, and fenced `text` or `mermaid` blocks for content whose whitespace must remain intact.
