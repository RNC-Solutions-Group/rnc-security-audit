# CP1 assignment — Levain corpus bootstrap and initial scoring

**Status:** CP1 completed with a controlled stub. CP1A later built and ran a real pinned Gitleaks baseline; see [`CP1A-report.md`](CP1A-report.md). Do not begin CP2 without separate authorization.

**Branch:** `test/scan-harness` only.

**Prerequisites:** Read root `AGENTS.md`, root `README.md`, `docs/assessment-roadmap.md`, and `datasets/manifest.toml`.

## Objective

Establish one fully repeatable, offline-capable synthetic secrets benchmark using Levain's **MIT-licensed positive and negative corpora**. Build only the minimal reusable interface needed to support additional datasets later. No Gitleaks application source changes.

## Scope

1. Verify the identity, license, checksum, and pinned full commit SHA of `https://github.com/levainbot/fp-corpus`; preserve the license and a human-readable source citation. If any provenance check fails, stop importing and report it.
2. Verify the published positive and negative fixture manifests and scoring units. Record actual pinned-version case counts; never infer TN directly from line count in an unsplit file.
3. Implement an explicit `prepare` operation that downloads into ignored cache, validates SHA/hash, detects cache corruption, and can work offline afterward. No hidden network calls during benchmark execution.
4. Implement a deterministic `run` operation accepting a **user-provided, resolved Gitleaks binary path** and explicit configuration/target settings. Capture command, exit status, elapsed time, error, report artifacts, and binary SHA.
5. Implement scoring against the frozen answer key. Distinguish findings from expected leaks, unexpected positives, misses, duplicates, and `NOT_RUN` failures. Use a positive control to detect a scanner that silently scans nothing.
6. Produce Markdown and JSON reports with raw secret values redacted or omitted. Include source commit, dataset revision/hash, config hash, OS, runtime, and scenario version.
7. Add focused tests for parsing and scoring, including a deliberately failing scanner invocation and a scanner that returns no findings.
8. Run the harness against the specified Gitleaks binary if available. If unavailable, validate the harness with a controlled stub and mark live scanner execution `BLOCKED`.

## Required questions

- Are the case IDs and expected labels unambiguous and independently published?
- Does the upstream scoring helper already solve this problem reliably, or would an adapter improve compatibility with Gitleaks?
- Are all expected positives in scope for the selected Gitleaks configuration? Report out-of-scope cases separately.
- Can the same pinned data be reused without network access or mutation?
- Does the runner distinguish actual zero findings from failed execution?
- What remains untested after this checkpoint?

## Hard stops

- Do not alter the Gitleaks source branch, fork files, or external repositories.
- Do not commit downloaded corpora or unredacted findings.
- Do not enable ProwlBench or import Leaky Repo.
- Do not validate candidate secrets through remote services.
- Do not implement CP2's broad command/flag sweep in this checkpoint.
- Do not automatically advance after reporting CP1.

## Definition of done

- Source and license verification recorded.
- Dataset revision and checksums pinned in the manifest; `enabled` only after successful verification.
- Prepare/cache/verify works on a clean environment and detects altered inputs.
- Runner and scorer have automated assertions, including error-path coverage.
- At least one actual scanner run documented **or** clearly marked `BLOCKED`.
- Report lists observed TP/FP/FN/TN under a precise counting definition, plus `NOT_RUN` where appropriate.
- All changes stay on `test/scan-harness`; final summary includes commit SHA(s), tests, limitations, and pending decisions.
