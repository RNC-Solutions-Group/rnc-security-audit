# CP0 machine-readable contracts — v0.1

**Provisional, machine-validated schemas; no production scanner implementation.** These schemas are independently versioned at `0.1.0` and live in [schemas/](schemas/).

| Schema | Producer | Consumer |
| --- | --- | --- |
| `source-unit.schema.json` | Authorized input adapter / scope policy | Execution ledger and engine |
| `finding.schema.json` | Detection engine | Post-scan finding policy and reporter |
| `execution.schema.json` | Runner/preflight | Reporter/classifier |
| `policy.schema.json` | Policy modules | Reporter/classifier |
| `result.schema.json` | Classifier after reconciliation | Reporter and CI |
| `ci-decision.schema.json` | CI acceptance adapter | CI log and audit report |

## Invariants beyond JSON Schema

JSON Schema validates structure; the implementation must additionally enforce **cross-record** constraints:

1. Exactly one `run_id` across linked records; unique unit and finding IDs; all findings refer to actually inspected units.
2. `discovered = inspected + verified_blocked + uninspected`, counted on disjoint canonical units.
3. `detected = actionable + exempted`; each finding has exactly one effective disposition.
4. Every verified blocked unit has an applied block event proving non-access. A requested-but-unapplied block does not count.
5. Effective policy provenance remains queryable by policy ID, origin and reason. Mandatory global controls cannot be erased by repo/CLI values.
6. `FAILED > INCOMPLETE > ACTIONABLE > POLICY_APPLIED > CLEAN`; `CLEAN` cannot describe zero required inspection, partial evidence, or an applied block/exemption.
7. A result is frozen on finalization. CI acceptance is a separate record referencing its exact `result_code` and never revises it.
8. Public output must not contain credential bytes, private locators or raw diagnostic fragments.

All schemas currently cover **local working-tree files**. Source kinds for Git history, archives, images and URLs require reviewed extensions before use. `locator` is deliberately private evidence metadata and not publishable as-is.

These schema files specify **shape**, not a complete verified implementation. The CP0 validator and tests demonstrate local consistency of the defined examples; CP1 must enforce the cross-record conditions independently.

## Run validations

From repository root, with Python 3.11+ and `jsonschema==4.26.0` installed:

```sh
python -m tools.cp0.validate
python -m unittest discover -s tests/cp0 -v
```

The validator checks schemas, authored fixture truth and the independently declared twelve-result decision table. It does **not** launch a real detector or calculate scanner recall.
