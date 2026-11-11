# Detection engine specification

> **Design contract v0.2 — CP1 implemented in Rust.** Initial domain: credentials and secrets in explicitly authorized local source content. See [CP1 validation](../implementation/cp1-validation.md). The engine is RNC-owned; Gitleaks/Betterleaks remain external comparators and possible audit-tool adapters.

## Responsibility

The detector receives a stream of **normalized, authorized content units** and a versioned rule bundle. It identifies and validates candidate matches, emits stable finding events with evidence references, and records processing/errors. It **must not** consult user exemptions, select output formats, accept CI results, or grade its own recall.

```text
source acquisition -> input adapter -> approved content units -> rule engine -> detection events
                                      ^                                  |
                                      |                                  v
                              verified scope plan               immutable evidence log
```

The input adapter owns source type, safe enumeration, stable IDs, encodings and byte/line offsets. The scope layer filters content **before** ingestion. Acquisition errors go into the execution record, not synthetic findings. The detector may use configurable limits, but must disclose anything truncated or uninspected so the classifier can mark required coverage incomplete.

## Logical input contract

| Field | Purpose |
| --- | --- |
| `schema_version`, `run_id`, `unit_id`, `source_id` | Unambiguous, versioned traceability across adapter, engine and report |
| `source_kind` | Initially `working_tree_file`; Git history, archives and URLs are future, separate adapters |
| `locator` | Private canonical relative locator; strict NFC, `/`-only, case-sensitive grammar; never published as-is |
| `required_scope` | Whether the unit is required for trustworthy coverage |
| `content` / `content_handle` | Bytes or bounded stream from the adapter, never arbitrary shell commands |
| `encoding`, line-ending handling, `offset_map` | Stable byte/line mapping; bytes remain the authority |
| `scope_plan_id`, `adapter_version` | Tie an inspected unit to the validated policy plan |
| `ruleset_id`, `ruleset_version`, `ruleset_digest` | Exact rules used; reject unknown or malformed bundles |

The adapter converts native platform separators to `/`, requires NFC, and checks case-collision behavior before calling the contract. `canonical_locator` rejects rather than repairs backslashes, `./`, repeated separators, absolute/drive/UNC paths, `.`/`..`, control characters, platform-ambiguous characters and Windows device names. Case is preserved and never folded. See [contracts/README.md](../contracts/README.md) for the complete grammar.

Inputs are **read-only** from the engine's perspective. Symlink escape, oversized items, unreadable files, malformed archives, binary/encoding ambiguity, timeouts and cancellation are explicit execution outcomes, not silently clean files. The initial adapter must not follow symlinks outside approved scope and must resolve TOCTOU ambiguity by recording what was actually read.

## Rule and identification pipeline

1. **Candidate matching.** Compile approved patterns once per rule bundle. Prefer bounded/linear regex constructs; disallow patterns with unbounded backtracking or document a hard execution budget. Rule `id` and `version` are part of every finding identity.
2. **Validation.** Apply rule-specific deterministic checks (syntax, length, known structure/checksum, context constraints) and confidence signals. Network verification is **not** implicit.
3. **Normalization.** Emit the canonical `finding_id`, rule/version, category, unit, byte offsets, line/line-end, validation reasons and evidence digest. Deduplicate only by the documented deterministic key. Overlapping rules are separate findings when both rules legitimately match.
4. **Accounting.** Emit inspected units, matched candidates, validated findings, limits, warnings, coverage errors and failures. Failed or partially processed units remain visible.

Changes to patterns, validators, categories, entropy thresholds or candidate verification can change detections; **version the rule set and its configuration separately from engine binaries**. Adding provider categories is a rule-bundle expansion, not a reason to rewrite reporting or CI policy.

## Logical detection event

```json
{
  "schema_version": "0.2.0",
  "run_id": "synthetic-run-001",
  "finding_id": "f-<sha256-derived-identity>",
  "unit_id": "u-<sha256-derived-identity>",
  "rule_id": "example-token",
  "rule_version": "2026.11.1",
  "category": "credential",
  "start_byte": 120,
  "end_byte": 148,
  "line": 8,
  "line_end": 8,
  "confidence": "high",
  "validation": ["FORMAT_MATCH", "CHECKSUM_VALID"],
  "evidence_digest": "sha256:<digest-of-matched-bytes>"
}
```

The event intentionally omits raw secret values. Private evidence may retain authorized raw content securely; **public reports must not emit matched bytes**. The finding's actionable/exempted status is **not an engine field** — it belongs to the post-scan policy record.

The `evidence_digest` is an unkeyed SHA-256 of matched bytes. It is a private matching/integrity value, not a public redaction: low-entropy credentials can be guessed offline from an unkeyed digest. `finding_id` inherits that property and is also private. Public reports use aggregate counts and, if needed, CSPRNG run-scoped opaque IDs. See [evidence-privacy.md](evidence-privacy.md) for the digest classes and keyed-HMAC evaluation.

## Determinism and resource controls

- Same content, adapter normalization, engine build, ruleset digest and settings must produce equivalent ordered findings, ignoring run IDs and timestamps. Run-independent finding IDs make cross-run comparison possible.
- Known synthetic credentials are reported with correct rule, byte/line location, stable identity and no policy-induced changes.
- Intentionally blocked content is never provided to the engine; an exemption does not prevent detection.
- Empty content, encoding failures, oversized files, inaccessible units, timeouts, cancellation and partial execution produce explicit coverage/error records.
- Bounded streaming is preferred over whole-file allocation for large inputs. Chunk overlap must cover the longest possible match; duplicate matches across overlap are suppressed by absolute `(rule_id, start_byte, end_byte)`.
- Record actual limits: max file bytes, max total bytes, timeout, max findings and per-rule execution budget. Truncation is never reported as clean.
- Benchmarks record throughput, tail latency, memory and false-positive tradeoffs; **no performance claim** before measurements. The CP0 Go/Rust benchmarks are described in the [CP1 handoff](../implementation/cp1-detection-engine.md).

## External test boundary

An **independent, scanner-agnostic harness** owns the secret manifest and scores recall, precision, false positives, missed fixtures and execution correctness. It must accept an intentionally synthetic adapter stub and calculate **100% correct expected metrics on known inputs** before being trusted to grade the RNC engine or Gitleaks. The production detector must never receive the answer key or calculate its own grade.

CP0 exports a tested line-addressed handoff to the pinned external harness at `RNC-Solutions-Group/gitleaks@86de44bf...`; see [harness-handoff.md](../contracts/harness-handoff.md). The external scoring engine was executed on synthetic handoffs. No external corpus was run, and no production accuracy claim follows.
