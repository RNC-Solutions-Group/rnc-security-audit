# CP0 machine-readable contracts — v0.2

**Status:** Reviewed CP0 contract revision, validated by executable schema and cross-record tests. No production scanner, policy engine, reporter or CI adapter is implemented.

The six **record** schemas are versioned at `0.2.0`. A seventh schema defines the unified effective configuration required by the approved CP0 decision. Contract revision `0.1.0` was a provisional CP0 draft and is not silently accepted by the v0.2 validators; see [compatibility](compatibility.md).

| Schema | Producer | Consumer | Public handling |
| --- | --- | --- | --- |
| `source-unit.schema.json` | Authorized input adapter / scope policy | Execution ledger and engine | Private record; `locator` never published |
| `finding.schema.json` | Detection engine | Post-scan finding policy and harness adapter | Private evidence metadata; no raw bytes |
| `execution.schema.json` | Runner / preflight | Reporter, classifier and harness | Private record with safe summary projection |
| `policy.schema.json` | Pre-scan and post-scan policy | Reporter / classifier | Private provenance; public counts only |
| `result.schema.json` | Classifier after reconciliation | Reporter, CI and operator | Publication-safe summary |
| `ci-decision.schema.json` | CI acceptance adapter | CI log and audit evidence | Publication-safe enforcement record |
| `config.schema.json` | Unified configuration loader | Scan/policy modules | Effective config; origin retained |

## Identity formulas

Identities are deterministic and independent of a particular run:

```text
unit_id    = "u-" + sha256(source_id + NUL + canonical_locator)
finding_id = "f-" + sha256(unit_id + NUL + rule_id + NUL + rule_version + NUL
                           + start_byte + NUL + end_byte + NUL + evidence_digest)
request_id = "r-" + sha256(policy_id + NUL + kind + NUL + selector)
```

`canonical_locator` is a **strict trust-boundary check, not a path cleaner**. It requires:

- a non-empty Unicode string in NFC form; non-NFC input is rejected rather than normalized;
- forward-slash separators only; backslashes are rejected;
- a path relative to the authorized source root; leading `/`, `//`, `~`, drive prefixes and UNC forms are rejected;
- no leading `./`, no repeated separators, no empty segments, no trailing separator;
- no `.`/`..` segments, NUL/control characters, or platform-ambiguous characters (`<>:"\\|?*`);
- no Windows device names (`CON`, `NUL`, `COM1`, etc.) and no segment with a trailing space or dot;
- case-sensitive identity with no normalization or folding;
- a maximum length of 4096 Unicode scalar values.

Adapters must perform platform acquisition normalization (native separators, NFC, case-collision detection) before calling the contract. Distinct filesystem objects must never collapse to one source identity. Policy selectors are a separate glob grammar and are not passed through `canonical_locator`. The external harness adapter uses the same canonical locator contract. Regression tests cover accepted paths and each rejected class.

`evidence_digest` is `sha256:` followed by the SHA-256 of the exact matched bytes. A finding carries only that digest, never the matched bytes. Raw bytes belong in a private evidence store outside public artifacts. Because a digest over a low-entropy credential can permit offline guessing, finding records and digests are **private evidence**, not public report fields; see the [evidence privacy boundary](../architecture/evidence-privacy.md).

## Cross-record invariants

JSON Schema validates shape and obvious relationships. The reference validator in `tools/cp0/contracts.py` additionally enforces:

1. **Run and version linkage.** All records share one `run_id`; embedded units and findings carry schema `0.2.0`.
2. **Unique source identity.** `unit_id` and `(source_id, locator)` are unique. `unit_id` matches its formula.
3. **Coverage is disjoint and complete.**
   `discovered = inspected + verified_blocked + uninspected`.
   Required-scope counts are a subset and satisfy the same equation. Optional uninspected units do not make required coverage incomplete.
4. **Inspection evidence exists only where content was inspected.** Inspected units carry `byte_length`, `line_count` and `content_sha256`. Blocked or uninspected units carry a reason code and carry no content fields.
5. **Verified blocks are proven.** Every `VERIFIED_BLOCKED` unit has exactly one applied block event with `verified_non_access: true`; the event links to an `APPLIED` block request with matching policy, origin, reason and unit.
6. **Findings are inside inspected bytes.** The unit is `INSPECTED`; `start_byte < end_byte <= byte_length`; the line is within `line_count`; the finding ID matches its formula; and when content is supplied, the line, line range and evidence digest match the exact bytes.
7. **One disposition per finding.** `detected = actionable + exempted`; every finding appears exactly once in policy; an `EXEMPTED` finding links to an `APPLIED` exemption request; an `ACTIONABLE` finding claims no applied policy.
8. **Requests cannot be silently promoted.** `NOT_MATCHED`, `UNSUPPORTED` and `INVALID` requests carry no matches and do not affect classification. Applied requests must have matches and must reconcile to the block/disposition evidence.
9. **Policy provenance is queryable.** Every policy ID resolves to an effective policy with origin, version, digest and mandatory flag. Mandatory policies must originate globally. `effective_policy_digest` covers the canonical effective policy array.
10. **Final classification is recomputed.**
    `FAILED > INCOMPLETE > ACTIONABLE > POLICY_APPLIED > CLEAN`.
    Zero required scope is never `CLEAN`. A completed clean result requires at least one required unit, all required coverage reconciled, valid evidence, and zero detections or applied policies. A completed actionable result retains any exemptions and blocks in its counts.
11. **A result commits to its evidence.** The result carries canonical digests of the execution record, ordered finding array and policy record. The CI event carries the exact result digest.
12. **CI is independent.** Acceptance is a separate event; it never mutates `result_code`. Codes `4`/`5` can never be accepted. Completed results use process exit `0` when accepted and `10` when rejected; `4` uses `20`; `5` uses `30`.
13. **Serialization is deterministic.** Units, findings, policies, requests, applied blocks, dispositions and reason codes are validated in canonical sorted order and serialized with sorted object keys.
14. **Public output is bounded.** A publication check rejects raw secret-shaped values, private locators, absolute paths and forbidden private keys. Execution, policy and finding records are private by default; only the result and CI decision are publication-safe.

## Five immutable results

| Code | Result |
| --- | --- |
| `1` | `CLEAN` |
| `2` | `POLICY_APPLIED` |
| `3` | `ACTIONABLE` |
| `4` | `INCOMPLETE` |
| `5` | `FAILED` |

The numeric result code is a report field, not the operating-system exit code. Default CI acceptance is `{1, 2}`; `3` requires explicit acceptance; `4` and `5` are never acceptable as successful scans under the CP0 contract.

## CP1 rule-bundle contract

The Rust detector consumes a separate data-only rule bundle at `docs/contracts/rules/rule-bundle.schema.json` (schema `0.1.0`). It is not one of the seven v0.2 record schemas; see [rule authoring](../implementation/cp1-rule-authoring.md).

## Validate

From the repository root, with Python 3.11+ and `jsonschema==4.26.0`:

```sh
python -m tools.cp0.validate
python -m unittest discover -s tests/cp0 -v
python -m tools.cp0.harness --self-check
python -m tools.cp0.synthetic_stub --mode perfect --output artifacts/cp0/stub-perfect.json
python -m tools.cp0.harness --bundle artifacts/cp0/stub-perfect.json
```

The validator proves contract and corpus consistency. It does **not** launch a production detector or calculate scanner recall. The harness calibrates against a synthetic stub that reads the answer key and is explicitly barred from release builds.
