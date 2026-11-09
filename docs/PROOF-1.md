# Proof 1 — Gitleaks end-to-end audit

> **Planning contract — no implementation yet.** This is the first engineering checkpoint for [RNC Security Audit](../README.md), not a promise of a shipped release.

## Objective

Prove the complete audit lifecycle with **one scanner, one mode, one source type, and one execution backend**:

`validated repo path → resolved config → scanner preflight → operator confirmation → execute → validate evidence → preserve private raw output → sanitize and summarize → reconcile coverage → clean up only run-owned resources`

Proof 1 succeeds when a real repository-directory scan demonstrates each of those steps, including failures and omissions. Launching the Gitleaks process by itself is **not** sufficient.

## Recommended initial slice

| Item | Initial choice | Reason |
| --- | --- | --- |
| Language | Python 3.11+ | `tomllib` is built in; filesystem/process/report handling can start without a web stack |
| Interface | One CLI command, `pr-checks`; interactive initially | Smallest coherent user-facing pathway; `passive-audit` and `red-team-ops` remain future entry points |
| Scanner | Gitleaks | Focused source secret-detection test of redaction and findings-versus-failure behavior |
| Source | One explicitly selected **local working-tree directory** | No application ID, remote service, or image target needed |
| Execution | **Existing Docker** as first-backend candidate | Reproducible pinned scanner runtime on Dave's current machines; confirm this choice at kickoff |
| Image policy | Approved, version-pinned Gitleaks image; digest preferred | No implicit `latest` or unverified scanner download |
| Source permissions | Read-only source mount; no network needed for a local-source scan | Narrow input surface; outputs go to separate private run-owned location |
| Raw evidence | Outside repository, at configured private location | Findings may contain sensitive content |
| Sanitized evidence | Individual Gitleaks result + aggregate run/coverage summary | One scanner still exercises the future multi-scanner report contract |

The source-only command supported by current Gitleaks is `gitleaks dir`. Exact CLI flags, image location, and findings/exit-code handling must be checked against the **pinned version**, not guessed. References: [Gitleaks official project](https://github.com/gitleaks/gitleaks) and [Python `tomllib`](https://docs.python.org/3.11/library/tomllib.html).

For the first slice, use an explicitly consented fixture repository with a **dummy secret**, plus a clean fixture. Never publish real credentials or raw results. Do **not** scan a production application, image, Git history, or network endpoint in Proof 1.

## Minimal design contracts

### Configuration

Only implement settings that are actually consumed in Proof 1. The target interface is:

- Toolkit `config/settings.toml`: enabled scanner catalog/profile, runtime image and digest/version expectations, timeout, report/redaction policy.
- Target repository `security.config` (TOML): scan mode and scanner enablement, project reporting preferences; **no target ID needed** for Gitleaks directory mode.
- Optional private untracked config: locations for private raw evidence and machine-specific runtime values; no plaintext secrets.

Load and validate configuration once in the core; pass an immutable/validated per-scanner plan to the adapter. Scanner adapters do not each reinterpret TOML, and repo config cannot inject arbitrary commands.

### Scanner and backend separation

- **Gitleaks adapter:** approved command arguments (as an array, never shell concatenation), selected source scope, expected report type/path, scanner-specific exit-code interpretation.
- **Docker backend:** available-runtime check, source mount and writable private report mount, subprocess launch, timeout/cancellation, exit capture, run-owned resource cleanup.
- **Runner:** invokes preflighted work and returns structured outcomes without fabricating findings.
- **Reporter:** verifies expected raw report and logs, preserves private evidence, emits sanitized Gitleaks + aggregate status, including omitted checks.

Use one backend now; keep the seam explicit so Proof 3 can add another without rewriting the adapter or reporter.

### Readiness and outcomes

A scanner is `READY`, `UNAVAILABLE`, `DISABLED`, or `NOT APPLICABLE` at preflight. Enabled-but-`UNAVAILABLE` scanners **do not abort ready independent scanners**, but they must be marked `SKIPPED` with each reason in the report. Globally unreadable policy/unauthorized scope is a **hard stop**.

Execution outcome is different: `COMPLETED (NO FINDINGS)`, `COMPLETED (FINDINGS)`, `FAILED`, `INCOMPLETE`, `SKIPPED`, or `CANCELLED`. A finding is not a tool failure. Report **execution** and **coverage** separately, including `PARTIAL` coverage when enabled scans were omitted.

In CI later, non-interactive `pr-checks` must not wait for prompts. Strict/permissive policy will decide whether missing *required* scans fail the job; no automatic promotion of an incomplete audit to an all-clear.

### Evidence schema (minimal candidate)

One run record should provide:

- Run ID, time window, mode and selected source directory.
- Git revision/dirty state if available; explicit directory-scan scope, with a warning that **Git history was not scanned**.
- Config/profile fingerprints or references, backend identity, scanner name and pinned version/digest.
- Readiness outcome and all reasons, requested vs executed scanner set.
- Exit-code classification, duration, **validated** findings count, evidence validation result.
- Separate private raw reference and sanitized report reference (never expose a private absolute path in a public report).
- Aggregate execution status, coverage status, omissions, and report validation outcome.

Raw output retains provenance and diagnostic details. Sanitized output never includes matched secrets, hidden target IDs, private file paths, or raw log fragments. If sanitization fails, **do not publish** the report; keep the private evidence and record an incomplete reporting result.

## Acceptance matrix

| Test | Required observable result |
| --- | --- |
| Clean fixture | Scanner ran; evidence validated; zero findings; run completed with complete coverage |
| Fixture with a harmless synthetic leak | Scanner ran; findings recorded without being treated as a process crash; raw private, sanitized non-secret |
| Docker/runtime unavailable | Scanner `UNAVAILABLE`; no scan execution; accurate skipped reason and zero coverage; CLI exits gracefully |
| Invalid Gitleaks-specific config | Scanner `UNAVAILABLE`; explicit reasons; no fabricated clean result |
| Global config cannot be parsed / scope unauthorized | Explicit hard stop before invoking scanner |
| Scanner process returns operational error | `FAILED`, with logs and no claim of successful clean scan |
| Expected report missing or unreadable | `INCOMPLETE`; no sanitized success publication |
| Sanitization cannot be verified | Private raw retained, public output withheld; reported failure |
| Operator cancels | `CANCELLED`; previously captured evidence retained; only run-owned resources cleaned |
| Repo path missing, invalid, or unexpectedly escapes allowed scope | Rejected before scanner execution |

Prove the separation between *no findings*, *no scan*, *scan failure*, and *missing evidence*. Tests should never rely on real leaked secrets.

## Execution sequence for the first implementation PR

1. **Choose and pin:** select one Docker-supported Gitleaks release/image, precise source-only command and expected exit/report behavior, test fixtures, and reporting destinations.
2. **Skeleton:** establish `pyproject.toml`, package entry point, config loader, CLI arguments, typed result/readiness structures, and tests for config/path validation.
3. **Vertical slice:** implement the Docker backend, Gitleaks adapter, and one end-to-end `pr-checks` directory scan.
4. **Evidence first:** validate tool output and exit semantics, retain private raw report, produce redacted scanner report and aggregate run/coverage record.
5. **Adversarial QA:** run the acceptance matrix and cross-check that failures cannot silently produce `PASS` or leak secret fields.
6. **Review:** open a feature PR with tests, sample sanitized artifacts, exact local commands, limitations, and a back brief. **No automatic merge to `main`.**

## Intentionally deferred

- Second scanner (Trivy) and true scanner independence / partial-coverage multi-scanner execution — **Proof 2**.
- Confirmations for application IDs and image targets; active network or red-team scans.
- Future file/directory **non-access** bypass engine and verified exclusion reporting. A scanner allowlist that merely suppresses findings is insufficient.
- Native/Podman/WSL Containers backend support — Proof 3 or later.
- TUI (Proof 4), packaged executable and on-demand binaries (Proof 5), GUI, AI, installers, scheduling, hosted service, and database.

## Decisions to make at kickoff

- Which machine will host the reproducible Proof 1: the Windows development VM with existing Docker, or native Linux?
- Should the raw-report directory be explicitly selected on every invocation or have a machine-local default (still outside repos)?
- Should the Proof 1 interface use Python standard-library `argparse` first or adopt Typer immediately? Both fit the single-engine architecture; decide on measured complexity.
- Do we require a human `[Y/N]` confirmation for every local run, while reserving `--non-interactive` for explicit authorized CI mode later?

**Exit criterion:** One real, repeatable Gitleaks source scan and the full acceptance matrix pass on the selected initial backend. At that point, Proof 2 can add a second scanner without changing the meaning of `READY`, `UNAVAILABLE`, `COMPLETED`, `FAILED`, or `PARTIAL`.
