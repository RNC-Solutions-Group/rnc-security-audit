# Detection engine specification

> **Design contract v0.1 — not implemented.** Initial domain: credentials and secrets in explicitly authorized local source content. The engine is RNC-owned; Gitleaks/Betterleaks remain external comparators and possible audit-tool adapters.

## Responsibility

The detector receives a stream of **normalized, authorized content units** and a versioned rule bundle. It identifies and validates candidate matches, emits stable finding events with evidence references, and records processing/errors. It **must not** consult user exemptions, select output formats, accept CI results, or grade its own recall.

```
source acquisition -> input adapter -> approved content units -> rule engine -> detection events
                                      ^                                  |
                                      |                                  v
                              verified scope plan               immutable evidence log
```

The input adapter is responsible for source type, safe enumeration, stable IDs, encodings and offsets; the scope layer filters content **before** ingestion. Adapter acquisition errors go into the execution record, not synthetic findings. The detector may use configurable limits, but must disclose anything truncated or uninspected so the classifier can mark required coverage incomplete.

## Logical input contract

| Field | Purpose |
| --- | --- |
| `run_id`, `unit_id`, `source_id` | Unambiguous traceability across adapter, engine and reporting |
| `source_kind` | Initially `working_tree_file`; Git history, archives and URLs are future, separate adapters |
| `canonical_locator` | Private evidence reference; redacted/hashed as needed for public output |
| `content` / `content_handle` | Bytes or bounded stream from the adapter, never arbitrary shell commands |
| `encoding`, `offset_map` | Stable byte/line mapping and accurate locations after normalization |
| `scope_plan_id`, `adapter_version` | Tie an inspected unit to the validated policy plan |
| `ruleset_id`, `ruleset_digest` | Exact rules used for the run; reject unknown or malformed bundles |

Inputs are **read-only** from the engine's perspective. A symlink, oversized item, unreadable file, malformed archive, binary/encoding ambiguity or timeout is handled explicitly, not silently treated as clean. Resource caps and safe file traversal are required.

## Rule and identification pipeline

1. **Candidate matching:** compile approved patterns/heuristics once per rule bundle; bound runtime and memory.
2. **Validation:** apply rule-specific deterministic checks (for example syntax, length, checksums or known token structure) and confidence signals. Network verification is **not** implicit.
3. **Normalization:** emit a stable `finding_id`, rule/category, source unit, offsets, validation reasons and evidence digest/reference; deduplicate only with a documented deterministic key.
4. **Accounting:** emit inspected units, matched candidates, validated findings, limits, warnings and errors. Failed or partially processed units remain visible in execution coverage.

Changes to patterns, validators, categories, entropy thresholds or candidate verification can change detections; **version the rule set and its configuration separately from engine binaries**. Adding AWS, provider-specific keys, HTTP(S)-related credential contexts or other categories is an input/rule expansion, not a reason to rewrite reporting or CI policy.

## Logical detection event (illustrative)

```json
{
  "schema_version": "0.1.0",
  "run_id": "synthetic-run-001",
  "finding_id": "f-0007",
  "source_id": "file-003",
  "rule_id": "example-token",
  "category": "credential",
  "byte_range": [120, 148],
  "line": 8,
  "confidence": "high",
  "validation": ["format-matched", "checksum-valid"],
  "evidence_digest": "sha256:<illustrative-digest>"
}
```

This example intentionally omits raw secret values. Private evidence may retain authorized raw content securely; **public reports must not emit matched bytes**. The finding's `actionable/exempted` status is **not an engine field**—it belongs to the post-scan policy record.

## Determinism and acceptance

- Same exact content, adapter normalization, engine build, rule-set digest and settings must produce equivalent ordered findings (ignoring run IDs/timestamps).
- Known synthetic credentials are reported with correct rule, byte/line location, stable identity, validation detail and no policy-induced changes.
- Intentionally blocked content is never provided to the engine; an exemption does not prevent detection.
- Empty content, encoding failures, oversized files, inaccessible units, timeouts and cancellation produce explicit coverage/error records.
- Benchmarks record throughput, memory, and false-positive tradeoffs; **no performance claim** before measurements.
- Initial engine language and matching implementation remain an engineering decision informed by benchmarks. The earlier Python/Docker proposal applies to audit orchestration and is not a mandate for the detector core.

## External test boundary

An **independent, scanner-agnostic harness** owns the secret manifest and scores recall, precision, false positives, missed fixtures and execution correctness. It must accept an intentionally synthetic adapter stub and calculate **100% correct expected metrics on known inputs** before being trusted to grade the RNC engine or Gitleaks. The production detector must never receive the answer key or calculate its own grade.
