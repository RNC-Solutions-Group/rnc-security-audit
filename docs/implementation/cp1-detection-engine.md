# CP1 — First-party RNC detection engine handoff (planned)

> **Not authorized to implement until CP0 contract review.** This is the downstream acceptance brief, not a claim that detection exists.

## Scope

- One local working-tree input adapter with approved scope and stable source/byte offsets.
- Versioned rule bundle and deterministic matching/validation interface in the CP0-selected language.
- Normalized finding events conforming to the [finding schema](../contracts/schemas/finding.schema.json); no policy/CI/report formatting logic in the engine.
- Explicit unit coverage, failures, timeouts and resource caps; no silent skipped targets.
- Read-only source access and no unauthorized network verification, credential uploads, or secret printing.

## Non-goals

No full audit orchestrator, remote targets, GUI, cloud service, active testing, standalone installer, arbitrary command plug-ins, or self-scoring. Policy/reporting implementation follows in CP2; the CP1 detector emits records that those modules will consume.

## Acceptance

1. Consume a pinned approved synthetic corpus and rule bundle with reproducible findings and accurate byte/line mappings, including Unicode and CRLF.
2. Produce expected immutable finding IDs and per-unit inspection/error records; all detector output validates against CP0 schemas.
3. Confirm blocked units cannot enter detection; post-scan exemption does not modify raw detection events.
4. Demonstrate bounds and explicit errors for invalid input, symlink/TOCTOU cases, oversize files and cancellation.
5. Record measured throughput/memory and actual correctness separately by corpus; never publish a recall/precision score until the independent harness is validated.
6. No leaked synthetic matched values in any public report or CI log.

Implement through a feature branch and PR. Final engine language is not pre-selected; it is an explicit CP0 dependency.
