# CP1 rule authoring and versioning

> CP1 production-oriented rule format. Rules are data, never executable code.

## Bundle format

Schema: [`docs/contracts/rules/rule-bundle.schema.json`](../../contracts/rules/rule-bundle.schema.json)

```json
{
  "schema_version": "0.1.0",
  "ruleset_id": "rnc-synthetic-v1",
  "ruleset_version": "2026.11.1",
  "rules": [
    {
      "rule_id": "synthetic-generic",
      "rule_version": "2026.11.1",
      "category": "synthetic-credential",
      "pattern": "RNC_SYNTH_KEY_GENERIC_[A-Z0-9_]{1,64}",
      "capture_group": 0,
      "validators": ["MARKER_FORMAT", "MARKER_SUFFIX", "ASCII_ONLY"],
      "confidence": "high",
      "max_match_bytes": 128
    }
  ]
}
```

## Hard requirements

- `rule_id` unique across the bundle; it is never reused for different semantics.
- `rule_version` changes whenever pattern, capture group, validators, category, confidence or bounds change.
- `pattern` compiles with Rust `regex` 1.11.1 and has a **finite maximum match length** established by `regex-syntax`. Unbounded repetition is rejected. `max_match_bytes` must be at least the computed maximum.
- `capture_group` must exist. Group `0` is the whole match; group `1` is used for multiline wrappers.
- `validators` must be known: `MARKER_FORMAT`, `MARKER_SUFFIX`, `ASCII_ONLY`.
- `max_match_bytes` is between 1 and 1 MiB.
- Unknown fields are rejected by both the JSON Schema and the Rust loader.
- No remote rule download, proprietary rule import, executable plugin or network validation occurs.

`MARKER_FORMAT` requires `RNC_SYNTH_KEY_`, ASCII uppercase/digits/underscore, and total length 16–128. `MARKER_SUFFIX` requires a final underscore-delimited segment of at least four characters and rejects `DECOY`/`FAKE`.

## Digest and lifecycle

`ruleset_digest = sha256(canonical-json(normalized bundle with rules sorted by rule_id))`. The CLI reports it; CP0 execution/result records carry it. JSON whitespace and rule-array order do not change the digest. Python and Rust tests assert the same known digests.

Lifecycle:

1. Author the rule in a branch.
2. Run `cargo test --workspace --locked` and `rnc rules validate --rules <bundle>`.
3. Add a synthetic positive and a near-miss negative fixture.
4. Update expected counts/digests and the rule version.
5. Benchmark the rule set before accepting a material change.
6. Review licensing and provenance for any non-RNC rule. CP1 ships only original synthetic rules.

## Commands

```sh
cargo build --release --workspace --locked
target/release/rnc rules validate --rules rules/rnc-synthetic-v1.json
target/release/rnc scan --root /approved/tree --rules rules/rnc-synthetic-v1.json \
  --format json --output /private/evidence.json --mode auto
```

`--format json` requires `--output`; the JSON contains private finding IDs and evidence digests. The default summary prints counts only.
