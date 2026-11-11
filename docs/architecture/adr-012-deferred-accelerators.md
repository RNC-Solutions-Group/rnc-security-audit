# ADR-012 — Deferred Hyperscan/VectorScan experimentation

- **Status:** Accepted for CP2
- **Date:** 11 November 2026

## Context

Hyperscan and similar native engines can provide high multi-pattern throughput, but introduce platform-specific builds, C/C++ toolchains, licensing/distribution constraints and a second matching semantic. CP2 must remain portable, including static musl, Windows and macOS builds.

## Decision

- Do not add Hyperscan, VectorScan or another native accelerated dependency in CP2.
- Keep the `MatchPlan`/`MatchCandidate` boundary as the future extension point.
- A future native backend must implement the same candidate contract, be explicitly selectable, pass the differential gate and never become the sole backend.
- No speculative native backend code is committed.

## Consequences

- CP2 builds with Rust-only dependencies and portable static Linux output.
- Multi-pattern performance remains bounded by the portable strategies.
- Any future accelerator requires a separate ADR, dependency/licensing review, cross-platform plan and independent correctness evidence.

## Validation

CP2 CI includes Linux, Windows, macOS, static musl and dependency audit lanes. See [adaptive-matching.md](adaptive-matching.md).
