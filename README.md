# RNC Security Audit

> Working concept — not yet implemented. This README records an idea to explore, challenge, and refine.

## The idea

RNC Security Audit would be a small, local-first command-line utility that coordinates established security scanners across source repositories, container images, and locally running applications.

It would **orchestrate tools, not replace their detection engines**. The goal is repeatable security assessments without requiring a database, dashboard, always-running service, or elaborate security platform.

An operator points the runner at a repository. It loads the runner configuration and the project's configuration, validates the environment, displays the exact scope and reporting destinations, requests confirmation where appropriate, runs applicable checks, and returns an evidence-backed result.

## Possible execution modes

| Entry point (working name) | Purpose | Operation |
| --- | --- | --- |
| `pr-checks.py` | Fast source, secrets, dependencies, and configuration checks | Suitable for unattended CI |
| `passive-audit.py` | Broader local checks, image assessment, and tightly scoped passive web testing | On demand, with a preflight |
| `red-team-ops.py` | Targeted active testing and security exercises | Explicitly interactive and operator-controlled |

These would be thin entry points sharing one Python execution, Docker integration, and reporting core.

## Two configuration layers

**Global `audit.toml`** (in this repository) would describe supported scanner adapters, local container image names/tags/digests, possible native executables, default modes, timeouts, resource limits, evidence requirements, and mandatory safety rules.

**Project `security.config`** (TOML syntax, in the repository under test) would identify the project, enable or disable applicable checks, identify approved local containers/ports/URLs, and declare private raw-evidence and sanitized-report destinations. It could reference external environment-file locations, but never store credential values.

The project config can choose supported checks; it must not weaken mandatory safeguards or supply arbitrary shell commands or privileged Docker flags.

## Intended operator experience

1. Enter a repository root path.
2. Validate the repository identity, selected targets, available tools, configuration, and output locations.
3. Display the enabled/disabled checks, the target scope, environment references, and report destinations.
4. Confirm the resolved configuration: **yes/no**.
5. Confirm execution: **yes/no**.

Unattended PR checks would use a restricted non-interactive profile. Active operations would have separate target verification, test selection, and authorization.

## Execution and reporting principles

- Prefer disposable, one-shot scanner containers with read-only source snapshots or mounts.
- Never silently follow a redirect outside the authorized target scope.
- Record source revision, tool versions/image digests, resolved settings, timestamps, execution status, and evidence references.
- Keep raw reports and logs outside this public repository in a user-controlled private directory.
- Write sanitized per-tool reports and a consolidated summary to a project-configured location.
- Distinguish **security findings** from **tool failures**. Finding a vulnerability is a completed scan; crashing or failing to capture evidence is not.
- Stop when a required tool fails and label the overall operation **INCOMPLETE** while preserving the evidence already collected.
- Clean up only temporary containers, volumes, and images demonstrably created by the current run.
- Treat optional AI summaries as commentary on sanitized evidence, never as the source of execution truth.

Possible tools to evaluate include Gitleaks, Semgrep, Trivy, Syft, Grype, OWASP ZAP, WPScan, and Nuclei. Tool choice, safe defaults, licensing, and redistribution requirements remain open questions. Not every scanner belongs in unattended execution.

## Future portability

The first backend could use an existing Docker-compatible runtime. A future native backend could invoke platform-specific scanner executables without requiring Docker, enabling a portable folder or packaged application. Some functionality, such as building and running containers, would still require a suitable local or remote runtime.

**RNC Security Toolkit** could be the name of an eventual packaged distribution. It would not need its own codebase unless that product materially diverges.

## Open questions

- What is the smallest useful scanner set for a first prototype?
- Which existing open-source orchestrators should inform the design?
- How should we validate target scope, active-test safety, build isolation, and cleanup?
- What common report format preserves each tool's original evidence?
- Which tools can run natively on Windows, macOS, and Linux?
- What third-party licenses constrain bundled releases?

This repository currently documents a proposed approach. It does not claim to perform scans or provide a finished security product.
