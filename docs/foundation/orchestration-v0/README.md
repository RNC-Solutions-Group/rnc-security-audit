# Original RNC Security Audit design snapshots

The files linked here are **preserved byte-for-byte** from the initial design branch when the application was conceived as an orchestrator of Gitleaks and other tools rather than a first-party detector. They are not live implementation guidance. Historical internal links may refer to former paths.

| Preserved file | Value to the current project |
| --- | --- |
| [Original README](project-readme.md) | Complete day-zero product concept and original phased roadmap |
| [Original design index](design-readme.md) | The original design inventory |
| [Application structure](application-structure.md) | Python orchestration package boundaries and backend separation |
| [CLI workflow](cli-workflow.md) | Operator flow and partial-coverage reporting |
| [Scanner preflight](scanner-preflight.md) | Required/optional readiness model |
| [Target confirmation](target-confirmation.md) | Image/application authorization and safe scopes |
| [Raw bypass report](bypass-report-raw.md) | Verified non-access exclusions and private evidence |
| [Sanitized bypass report](bypass-report-sanitized.md) | Safe aggregate exclusion reporting |
| [Original implementation index](implementation-readme.md) | Original proof sequencing |
| [Original Proof 1](proof-1.md) | Gitleaks/Docker audit controller proof, suitable for future CP5 adaptation |

Nothing in this archive is proof that a scanner or toolkit executable shipped. Refer instead to the current [design contracts](../../architecture/README.md) and [roadmap](../../roadmap.md).
