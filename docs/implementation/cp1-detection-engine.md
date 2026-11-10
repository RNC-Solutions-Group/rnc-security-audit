# CP1 — First-party RNC detection engine handoff

> **Not authorized to implement until CP0 operator acceptance.** This is the implementation-ready CP1 brief. Rust is selected in [ADR-007](../architecture/adr-007-detector-language.md); no production engine exists.

## CP1 objective

Implement one authorized local-working-tree adapter and the Rust detection core that consumes a versioned rule bundle, emits normalized v0.2 finding events, and accounts for every inspected, blocked, uninspected, failed or partially processed unit. Detection only: policy, reporting and CI enforcement remain outside this checkpoint.

## Module boundaries

Suggested workspace (names may change; responsibilities may not):

```text
crates/
  rnc-core/            # library; no CLI, policy, reporting or CI
    src/input.rs       # AuthorizedUnit, adapter boundary types
    src/rules.rs       # rule-bundle load, compile, validate, digest
    src/matcher.rs     # byte-oriented regex execution and overlap handling
    src/validate.rs    # deterministic candidate validators
    src/finding.rs     # canonical finding identity and event emission
    src/coverage.rs    # unit outcomes, errors, limits, cancellation
    src/stream.rs      # bounded streaming and whole-file path
  rnc-cli/             # thin adapter/runner for CP1; no detection logic
```

Hard boundaries:

- `rnc-core` must not read `.rncscanner.toml`, policy dispositions, exemptions, CI acceptance, report formats or the independent harness truth.
- The CLI may acquire authorized bytes and serialize records; it must not reinterpret findings.
- Policy/reporting modules in CP2 consume core records; they never rewrite them.
- The harness adapter lives outside the engine and receives no answer key.

## Input interface

The input adapter provides immutable, read-only units:

```rust
pub struct AuthorizedUnit {
    pub run_id: String,
    pub unit_id: String,          // u-<sha256(source_id, canonical_locator)>
    pub source_id: String,
    pub locator: String,          // private, relative, normalized
    pub required_scope: bool,
    pub adapter_version: String,
    pub bytes: UnitBytes,         // bounded whole buffer or streaming handle
}
```

Adapter requirements:

- Resolve scope before reading content. A blocked unit reaches the engine only as a scope outcome, never as bytes.
- Do not follow symlinks outside the authorized root. Detect circular links and record an explicit uninspected outcome.
- Record the content length, line count and content SHA-256 actually inspected. A file that changes during access is not silently accepted as the enumerated file; record a stability/TOCTOU error.
- Handle empty, binary, malformed UTF-8, CRLF, CR-only, BOM, nested paths and oversized files explicitly. Matching is byte-oriented; Unicode decoding is not a prerequisite for byte/line identity.
- Enforce configurable max file bytes, max total bytes, timeout and max findings. Truncation or omission is an `UNINSPECTED`/error outcome with a reason code.

## Output interface

Every finding must validate against `docs/contracts/schemas/finding.schema.json` v0.2 and use:

```text
finding_id = "f-" + sha256(unit_id + NUL + rule_id + NUL + rule_version + NUL
                           + start_byte + NUL + end_byte + NUL + evidence_digest)
```

Fields: `schema_version`, `run_id`, `finding_id`, `unit_id`, `rule_id`, `rule_version`, `category`, `start_byte`, `end_byte`, `line`, optional `line_end`, `confidence`, `validation`, `evidence_digest`. Never include raw matched bytes, a file path, a policy disposition or a CI decision.

Unit outcomes must validate against `source-unit.schema.json` and feed `execution.schema.json`:

- `INSPECTED` with `byte_length`, `line_count`, `content_sha256`;
- `VERIFIED_BLOCKED` with a reason code and no content fields;
- `UNINSPECTED` with a reason code and no content fields.

The engine emits no final `result_code`; CP2's reporter reconciles execution, findings and policy.

## Initial rule bundle

Use a versioned canonical JSON rule bundle (or an equivalently deterministic typed format) with at least:

```json
{
  "schema_version": "0.1.0",
  "ruleset_id": "rnc-synthetic-v1",
  "ruleset_version": "2026.11.1",
  "rules": [
    {
      "rule_id": "synthetic-aws",
      "rule_version": "2026.11.1",
      "category": "synthetic-credential",
      "pattern": "RNC_SYNTH_KEY_AWS_[A-Z0-9]{4,24}",
      "capture_group": 0,
      "validators": ["FORMAT_MATCH", "MARKER_PREFIX"],
      "confidence": "high",
      "max_match_bytes": 128
    }
  ]
}
```

Rules are data, not code. Reject unknown fields, invalid regexes, unsupported constructs, duplicate `rule_id`, missing versions and patterns whose bounded match length cannot be established. Compute `ruleset_digest` over canonical serialized content (sorted keys, explicit schema version). The digest is carried into every execution and result; a changed bundle changes the digest even when the engine binary is unchanged.

### Rule versioning and validation lifecycle

1. Author a rule with stable `rule_id`, immutable semantic `rule_version`, category, pattern, capture group, validators and confidence.
2. Load and schema-validate the bundle. Reject duplicate IDs, unknown validator names and unsupported regex features.
3. Compile patterns once with the pinned Rust `regex` crate. Reject backreferences, lookaround, unbounded ambiguous repetition and other non-linear constructs. Enforce a maximum compiled size and match budget.
4. Validate every candidate deterministically (format, length, allowed alphabet, checksum/context where defined). Validation failure is not a finding.
5. Emit findings with rule ID/version and validation reason codes.
6. Record the bundle digest in execution. Changing a pattern, validator, category, confidence threshold or capture group requires a rule-version change and re-benchmarking.
7. Deprecate rules explicitly; never silently reuse a `rule_id` for different semantics. Rollback means selecting a previous immutable bundle, not editing history.

No remote rule download, network validation or secret exfiltration is permitted in CP1.

## Streaming and resource controls

- Prefer byte-oriented streaming over whole-file allocation. Default chunk size and overlap are explicit constants/config; overlap must cover the longest possible match plus capture context and never silently truncate it.
- Deduplicate the same `(rule_id, start_byte, end_byte)` across overlap windows. Emit findings in canonical `(unit_id, start_byte, end_byte, rule_id, rule_version, finding_id)` order.
- Whole-file fallback is allowed only under a configured limit; record which path was used.
- Enforce max file bytes, max total bytes, timeout, max findings, max regex match length and cancellation. A timeout/cancellation produces an `INTERRUPTED`/`ERROR` execution outcome with partial evidence, not a clean result.
- No unbounded allocation from attacker-controlled file size or rule count. Rule compilation and matching budgets are tested adversarially.

## Stable locations and evidence

- Byte offsets are the authority. Line numbers are derived from bytes, treating LF, CRLF and CR as line boundaries consistently.
- `line_end` is required when a match spans lines; otherwise equal to `line`.
- `evidence_digest` is SHA-256 of exactly `bytes[start_byte..end_byte]`. Raw bytes stay in a private evidence store outside public artifacts.
- Finding IDs do not include `run_id`; the same unit/rule/version/location/evidence is stable across runs.
- No Unicode normalization, lowercasing or line-ending rewriting may change the finding's byte identity. Rule semantics may be case-sensitive unless the rule pattern explicitly says otherwise.

## Error and coverage propagation

- Every discovered unit has exactly one disposition. A required unit that cannot be read is `UNINSPECTED`, not a zero-finding inspected file.
- Pre-scan block events are emitted by policy/adapter code, not the engine. A block must prove non-access; an ignore flag that reads then suppresses does not qualify.
- Operational errors are explicit `fatal_errors`/`failure_codes`; findings already emitted remain valid partial evidence.
- Coverage caps that stop work must mark the remaining units uninspected with a reason code.
- The engine never computes `CLEAN` or any result code. It reports what was inspected, what was not, and what was found.

## Acceptance tests

CP1 is complete only when all of these are executable and pass:

1. **Corpus truth.** Run against `tests/fixtures/synthetic-v1` and the generated edge corpus. Every inspected expected marker is found with the correct rule, byte range, line and evidence digest; every blocked/uninspected target is accounted for and produces no finding.
2. **Determinism.** Two runs with identical bytes, ruleset and settings produce identical ordered finding IDs, offsets, digests and coverage records (ignoring run IDs/timestamps).
3. **Line endings and Unicode.** LF, CRLF, CR-only, UTF-8 BOM and multibyte prefixes preserve byte offsets and line numbers.
4. **Binary and malformed input.** NUL bytes and invalid UTF-8 are handled without panic or silent skip; matches are byte-oriented.
5. **Boundaries.** Empty files, no trailing newline, marker at offset 0, marker at EOF, nested paths and maximum-size files produce explicit outcomes.
6. **Duplicate and overlapping rules.** Repeated occurrences are distinct findings; overlapping rules produce distinct rule events; no double-counting from overlap windows.
7. **Blocked versus uninspected.** A blocked unit has verified no-access and no finding; an inaccessible required unit is uninspected and forces incomplete classification when combined with a reporter.
8. **Cancellation, timeout and partial execution.** A cancelled run retains partial findings and explicit coverage gaps; it never reports clean.
9. **Resource limits.** Oversized file, total-byte cap, max findings and rule compile limits fail closed with reason codes.
10. **Redaction.** Findings/logs contain no raw matched values; only digests, offsets, rule IDs and safe reason codes.
11. **Schema conformance.** All emitted records validate against v0.2 schemas and pass the reference cross-record validator when paired with synthetic policy/reporting fixtures.
12. **Performance.** Record throughput, median/tail latency, peak memory and build characteristics on the pinned runner; compare against the CP0 comparator and investigate regressions. Do not publish a recall/precision claim until the independent harness scores the engine.

## Independent harness integration path

CP1 exposes a neutral adapter surface (JSON records plus a line-addressed projection). The CP0 handoff in [`harness-handoff.md`](../contracts/harness-handoff.md) is the starting contract:

1. Emit normalized findings with `file`, `line`, `rule_id`, digest fields and byte metadata.
2. Export truth separately from the manifest; never let the engine read it.
3. Preserve native corpus scoring and RNC normalized scoring as separate lanes.
4. Run the pinned external scoring engine against a controlled stub before scoring RNC Scanner. Then run external corpora only with authorization, integrity checks and resource limits.
5. Resolve the external harness's line-granularity limitation: either define a documented composite line identity or extend the harness with byte-range matching. Byte offsets are retained in CP0 metadata for this purpose.

## Non-goals

No policy engine, exemptions, report formatting, CI pass/fail decision, self-scoring, external corpus execution, remote targets, GUI, installer or audit orchestration in CP1. No production release is implied by passing CP1.

## Entry gate

Do not begin CP1 until the operator accepts the CP0 package, including schema v0.2, the Rust selection, `.rncscanner.toml`, the CI acceptance semantics and the remaining limitations in the CP0 validation report.
