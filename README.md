# RNC Security Audit

> **Working concept — day zero.** This repository currently describes a proposed open-source application. No scanner engine, executable, installer, or release has been implemented. The design is intentionally open to refinement.

**Working product name:** RNC Security Audit  
**Possible future distribution name:** RNC Security Toolkit

## The promise

> **RNC Security Audit provides a consistent, configurable interface for running established security tools, while preserving scan integrity, evidence, and operator control.**

The goal is to make repeatable security checks approachable without hiding what was tested, what was skipped, what failed, or where the evidence went.

RNC Security Audit would **coordinate existing scanners, not build another detection engine**. It would bring source repositories, dependencies, container images, and authorized local applications into a common workflow: select a target, load configuration, verify scope, run applicable tools, capture evidence, and return an honest result.

It should work for someone comfortable editing TOML and using a CLI, while leaving room for an interactive terminal interface and, eventually, a graphical application. A database, hosted dashboard, persistent agent, or mandatory cloud service is not part of the core concept.

## Purpose and use cases

The initial audience is developers, maintainers, small teams, and operators who want a consistent way to audit projects using tools they already trust.

Potential use cases include:

- **Before a pull request:** run approved source, secret, dependency, and configuration checks without starting an active penetration test.
- **Before staging or release:** examine a repository and, where applicable, its built image or local container; retain an evidence-backed pre-production report.
- **While developing locally:** assess a deliberately selected local website or service, using its approved address, ports, and scan modes.
- **During an authorized security exercise:** choose active tests explicitly, confirm the exact target and scope, and maintain separate reporting from passive checks.
- **Across different projects:** reuse the same application while each repository declares which checks apply to its stack.

For example, a WordPress project might enable PHP/source checks, secret detection, image/dependency scanning, and limited passive local-web checks. A TypeScript application might select a different scanner set. Neither needs custom orchestration scripts or a new reporting system.

**Scope boundary:** this application would report what its tools observed; it would not certify that a project is secure, automatically exploit findings, or replace manual security review.

## How an audit would feel

The operator starts a mode, provides a repository path when needed, and reviews a preflight assembled from configuration—not a series of ad hoc scanner questions. **Scanner availability is evaluated independently:** one missing or misconfigured scanner does not prevent ready scanners from running.

1. **Identify the target.** Validate the supplied path, repository identity, configured local application targets, and applicable environment references.
2. **Resolve the plan.** Load toolkit and repository settings, evaluate each enabled scanner, and detect supported execution backends.
3. **Display the preflight.** Separate **READY**, **UNAVAILABLE**, and **DISABLED** scanners. Show the applied safe settings and reasons for unavailability, selected target scope, execution method, and private/sanitized report destinations.
4. **Verify targets when applicable.** Repository-only checks need no application target ID. For image or application/system scans, ask the operator to type and confirm the configured target **for each scanner that requires one**. Hide sensitive target IDs in displayed output.
5. **Confirm the plan and begin.** Confirm the configuration and then the actual execution as separate decisions. An unavailable scanner is skipped with reasons; the operator may continue with ready scanners. Active operations require additional scope/authorization checks.
6. **Run and report.** Execute ready, eligible scanners independently; validate evidence; preserve raw outputs; produce sanitized individual reports and an aggregate report that discloses unavailable/omitted checks.
7. **Clean up safely.** Remove only disposable resources created and owned by that run; leave shared runtimes, existing images, other projects, and evidence untouched.

This is the intended operator experience, not an implemented command flow.

## Operating modes

The original three-script idea remains useful as **three commands or thin entry points over one shared engine**:

| Working command | Intended role | Interaction policy |
| --- | --- | --- |
| `pr-checks` | Focused source, secret, dependency, and configuration checks | Restricted, repeatable, suitable for CI after validation |
| `passive-audit` | Broader repository, image, container, and explicitly scoped passive application checks | Operator-triggered preflight; no active attack tests |
| `red-team-ops` | Authorized active testing against a defined local or otherwise explicitly approved target | Interactive target verification, test selection, warnings, and authorization |

These are **different operating policies**, not separate applications. Unattended checks must never silently promote themselves into active testing. A scanner's presence in the tool catalog does not mean it is eligible for every mode.

## Proposed application architecture

The core design separates five responsibilities:

1. **Interface:** a Python CLI first; a TUI later; a GUI only if useful. Every interface would operate the same audit engine.
2. **Configuration and policy:** parse TOML once, validate supported inputs and authorized scope, and construct a deterministic per-scanner execution plan. Each adapter receives validated settings rather than parsing config files independently.
3. **Scanner adapters:** define each tool's supported targets, arguments, expected evidence, exit-code semantics, and safe scan profiles.
4. **Execution backends:** run an approved scanner as a native executable or through an available container runtime without changing how findings are interpreted.
5. **Evidence and reporting:** preserve the scanner's original output, validate completeness, generate sanitized reports, and reconcile the run status.

Python is the proposed core language because the workload is mainly configuration, process orchestration, file handling, validation, and reporting. Typer/Rich are candidates for the CLI, Textual for the later TUI, and PyInstaller or equivalent packaging for OS-specific standalone builds. None is a dependency decision yet.

### Interchangeable execution methods

The application should not care whether a properly supported scanner is launched through native binaries, Docker, Podman, or another backend. The scanner adapter defines the **what**; the execution backend handles the **how**.

Possible backend directions:

| Environment | Candidate methods |
| --- | --- |
| Linux | Native scanner binary; existing Docker or rootless Podman |
| Windows | Native scanner binary; existing Docker/Podman; WSL Containers (`wslc`) where supported |
| macOS | Native scanner binary; available Docker/Podman or other supported container host |

The first proof may support only **one** backend. The separation exists from the beginning so a second backend can be added without rewriting scanning and reporting. A future Windows package could use the WSL Containers CLI or API to manage disposable Linux containers without requiring Docker Desktop, while still depending on compatible WSL runtime components. Container availability is not a guarantee of hardened isolation from untrusted workloads.

### Two configuration layers, with private overrides

- **Toolkit `config/settings.toml`:** approved scanners, scanner runtime image references or native release sources, supported modes, version/digest expectations, default profiles, timeouts, resource limits, and non-negotiable safety controls.
- **Project `security.config` (TOML syntax):** project identity, applicable checks (simple enable/disable choices), authorized local targets and ports **only where a selected scanner requires them**, optional environment-file *references*, and reporting preferences. Projects with no application/system scanning may omit or comment out target IDs.
- **Optional untracked private override:** machine-specific absolute paths and sensitive operational locations, such as private raw-report storage. Public repository configuration should remain publishable without disclosing local directory layouts or credentials.

The application repository stores **no scan data, secrets, target-specific local paths, or private reports**. Repository settings can select supported features, but cannot insert arbitrary shell commands, widen network authorization, or override mandatory safety rules. An `.env` reference is a path hint, not blanket authorization to read or mount credentials.

Each scanner definition should be data-driven where practical: changing an approved **scanner runtime** image tag/digest or scanner profile should not require editing Python execution code. A scanner's runtime image is distinct from the **target image being scanned**. Download-on-demand tool installation is a future option, subject to source verification, platform compatibility, and license review.

### Per-scanner preflight and partial coverage

Readiness is **not** an audit-wide pass/fail gate:

| Readiness | Intended behavior |
| --- | --- |
| **READY** | Enabled and applicable; backend, settings, target (if required), and evidence destination validated; eligible to execute |
| **UNAVAILABLE** | Enabled and applicable, but scanner-specific preflight failed (for example missing backend, invalid scanner settings, or missing required target); skip that scanner and record *all* reasons |
| **DISABLED** | Explicitly disabled in project config; do not execute, with status recorded |
| **NOT APPLICABLE** | Scanner is irrelevant to the selected mode/target; do not execute, with reason recorded |

The CLI must display applied **non-sensitive** settings for ready scanners and concrete reasons for unavailable ones. A scanner-specific invalid setting **does not block other ready scanners**. A global failure that prevents parsing the plan or enforcing authorization remains a hard stop; continuing without a trustworthy scope is different from skipping one tool. A run with zero ready scanners must not be represented as a successful security check.

Interactive runs ask before proceeding with ready scanners when coverage is partial. Non-interactive CI never waits for a prompt: an eventual policy controls whether skipped **required** scanners produce a nonzero job result; ready checks should still run and report. A permissive job may finish with partial coverage but can never claim comprehensive coverage.

Target verification applies only to scanners requiring an image/application/system target, and only after an explicit scanner has been enabled for the chosen mode. A configured target ID may be checked against exact operator input without echoing it. Active network targets remain subject to stronger authorization rules.

## Execution integrity and reporting

**A vulnerability finding is not a scanner failure. A scanner failure is not a clean security result.** This distinction should be enforced by the engine rather than inferred from an attractive summary.

An audit run should distinguish at least:

| Outcome | Meaning |
| --- | --- |
| Completed — no findings | Expected scan and evidence finished; no findings in that tool's scope |
| Completed — findings | Expected scan and evidence finished; findings require assessment |
| Failed | Tool, runtime, or execution error |
| Incomplete | Missing, malformed, or unvalidated required evidence; overall audit cannot be called complete |
| Skipped (unavailable) | Enabled scanner did not execute because one or more preflight requirements were unmet; reasons preserved |
| Disabled / not applicable | Explicitly disabled or outside selected mode/target; distinct from unavailable |
| Cancelled | Explicit operator interruption, with partial evidence retained |

Important reporting principles:

- Record target identity, repository revision/working-tree state, scan plan, versions or image digests, timestamps, tool outcomes, and report references.
- Preserve raw scanner output and execution logs **outside the public application repository** in a private, user-controlled location. Raw results can themselves contain secrets.
- Write only validated, sanitized per-scanner reports and a consolidated summary to a project-configured destination such as `docs/pre-production/`.
- Do not publish a sanitized report if redaction or evidence validation fails. Write a specific failure record instead.
- Continue independent ready scanners when one is unavailable or fails, unless an audit-wide authorization/integrity condition prevents safe continuation. Preserve already-collected evidence and record missing coverage; never fabricate results or substitute another scanner's output to fill a gap.
- Report **run execution** separately from **coverage**: an audit can finish executing while coverage is **partial** because one enabled scanner was unavailable, skipped, or failed. Only individually completed scans may be described as clear of findings within their stated scope.
- Apply read-only source access and least-privilege execution where possible. Treat active network scans as separately authorized operations.
- Only remove run-owned temporary files, containers, volumes, and ephemeral images. Never prune a user's shared container environment as part of routine cleanup.
- Make optional AI-generated summaries subordinate to validated evidence; AI may explain results but must not decide whether the scan actually ran.

The engine must distinguish a tool's **findings exit code** from its **execution failure code**. Reliable interpretation belongs in the scanner adapter, backed by test cases for empty findings, real findings, tool errors, missing reports, unavailable backends, and cancellation.

### Future input bypasses and known false positives

File/directory exclusions are a **later capability, not a Proof 1 prerequisite**. The intended policy is that excluded paths are **not accessed by the scanner**, not merely that findings about them are hidden afterward. Toolkit-wide and repository-specific exclusions may be combined with an explicit opt-in and per-scanner enforcement, while retaining which configuration supplied each path.

Scanner-provided ignore/allowlist flags are **not automatically proof of non-access**. Some rules suppress findings after reading files; Git history, container images, and archives are different target surfaces. Where non-access cannot be verified, label enforcement as unsupported/unavailable or use a tested filtered snapshot that does not expose excluded inputs. Never claim that a suppression rule prevented scanning.

Private **raw** reporting should disclose the actual file and directory exclusions by config origin, affected scanner, effective count, validation result, and **verified enforcement method**. **Sanitized** reporting should disclose affected scanners and only aggregate file/directory counts per origin, without paths or sensitive target IDs. Both must distinguish requested exclusions from those **actually applied**. See the conceptual [raw](RAW-REPORT-BYPASSED.txt) and [sanitized](SANITIZED-REPORT-BYPASSED.txt) examples.

## Product roadmap — proofs before features

These are **capability checkpoints**, not dated releases or commitments to a feature list. Each proof should leave an independently testable result before the next expands scope.

| Checkpoint | Proposed deliverable | Question it answers |
| --- | --- | --- |
| **Day zero — design contracts** | Agree on the scope, configuration schema, scanner/backend interface, safety rules, and evidence/report contract | Do we know what a trustworthy audit means? |
| **Proof 1 — one complete scan** | Gitleaks against a selected local repository, using one approved backend, with raw evidence, sanitized report, cleanup, and honest failures | Can the smallest workflow run end-to-end? |
| **Proof 2 — second scanner** | Add Trivy or another materially different scanner without rewriting the core; prove per-scanner readiness, partial coverage, and target-specific confirmation | Are scanner adapters and their failures truly independent? |
| **Proof 3 — second backend** | Execute an approved scan through a second supported environment (for example, native binary versus container) | Is the audit engine independent of its runtime? |
| **Proof 4 — TUI** | Offer interactive scanner selection and preflight using the same engine as the CLI | Can the interface improve without duplicating behavior? |
| **Proof 5 — portable distribution** | Package OS-specific lightweight application builds and evaluate verified on-demand scanner downloads | Can users operate it without managing a Python development environment? |
| **Future exploration** | Optional WSL Containers integration, installer assistance, GUI, additional scanners, structured export formats, and AI commentary | Which additions make the application meaningfully easier or more useful? |

**First candidate: Gitleaks.** It is focused, does not need a live target, and makes the reporting/redaction contract especially important. The first proof is not simply "run Gitleaks"; it is **validate target → execute approved scan → capture and validate evidence → sanitize → report status → clean up run-owned resources**.

Candidate scanners for later evaluation include Trivy, Semgrep, Syft, Grype, OWASP ZAP, WPScan, and Nuclei. Eligibility will depend on target type, safe mode, distribution constraints, maintenance, and licensing. Supporting many scanners is not itself a success metric.

### Day-zero design examples and execution plan

The files currently in this draft PR are **illustrative**, not executable or validated output:

- [CLI-CONCEPT.md](CLI-CONCEPT.md) — initial interactive flow and scanner preflight.
- [CLI-2.txt](CLI-2.txt) — an enabled-but-unavailable scanner while others are ready.
- [CLI-Target.txt](CLI-Target.txt) — explicit image/application target confirmation.
- [RAW-REPORT-BYPASSED.txt](RAW-REPORT-BYPASSED.txt) and [SANITIZED-REPORT-BYPASSED.txt](SANITIZED-REPORT-BYPASSED.txt) — future input-bypass evidence presentation.
- [STRUCTURE.md](STRUCTURE.md) — proposed package/module ownership, not created directories.
- [docs/PROOF-1.md](docs/PROOF-1.md) — first Gitleaks proof scope, acceptance checks, and implementation sequence.

## Explicitly out of scope for the first proof

- A hosted service, dashboard, user-account system, database, or scheduler.
- Installer development, native GUI, or distributing bundled third-party scanners.
- Mandatory AI, automated remediation, or autonomous exploitation.
- Automatically attacking public or production targets.
- A scanner marketplace or arbitrary user-supplied executable command definitions.
- Building a new vulnerability detection engine or claiming a clean scan guarantees security.

**RNC Security Toolkit** remains a potential name for a later packaged edition of this same application, not a second implementation. Source-first, CLI-first development should remain useful on its own even if the portable edition never materializes.

## What remains open

The design contracts, tool eligibility and licensing, CI policy defaults, report schema, cross-platform backend compatibility, private configuration conventions, and portability choices all need practical validation. Open decisions are tracked as **proof acceptance questions** in [docs/PROOF-1.md](docs/PROOF-1.md), rather than prematurely presenting them as implemented capabilities.

This README is the working theory for the project. **No implementation, scan result, security assurance, release date, or supported-platform claim is implied.**
