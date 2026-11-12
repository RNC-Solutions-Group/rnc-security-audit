# CP1 rule authoring and versioning

> CP1 production-oriented rule format. Rules are data, never executable code.
> CP3 adds the separate provider catalog in schema `0.2.0`; the original
> synthetic bundle contract remains `0.1.0` and its digests are unchanged.

## Bundle format

Schema: [`docs/contracts/rules/rule-bundle.schema.json`](../contracts/rules/rule-bundle.schema.json)

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
- Provider rules may declare optional `value_capture_groups` when a pattern has mutually exclusive value alternatives (for example double-quoted, single-quoted and unquoted values). The matcher uses the first non-empty group in that list. Every listed group must exist, be a 1–255 capture group and satisfy `max_candidate_bytes`; the base schema continues to default to `capture_group`.
- Assignment-context provider rules may declare optional `identifier_capture_group` for bounded validation context. It must reference a distinct existing group with a finite maximum length, must not overlap a value group, and is never included in the finding span. If declared, the group is mandatory for a match; a missing identifier is an integrity error.
- `validators` must be recognized by the Rust loader and the provider catalog schema. Synthetic rules use `MARKER_FORMAT`, `MARKER_SUFFIX` and `ASCII_ONLY`; provider rules add the offline AWS/GitHub/PEM/generic/provider validators documented in the catalog schema.
- `max_match_bytes` is between 1 and 1 MiB.
- Unknown fields are rejected by both the JSON Schema and the Rust loader.
- No remote rule download, proprietary rule import, executable plugin or network validation occurs.

`MARKER_FORMAT` requires `RNC_SYNTH_KEY_`, ASCII uppercase/digits/underscore, and total length 16–128. `MARKER_SUFFIX` requires a final underscore-delimited segment of at least four characters and rejects `DECOY`/`FAKE`.

## Provider catalog — schema 0.2.0

Production provider rules live in [`rules/rnc-providers-v1.json`](../../rules/rnc-providers-v1.json)
and validate against
[`provider-rule-bundle.schema.json`](../contracts/rules/provider-rule-bundle.schema.json).
They add:

- `provider`, `family`, `credential_type` identity;
- `context` (`standalone`, `assignment`, `bearer`, `container` or `uri`);
- optional `identifier_capture_group` for assignment context;
- `max_candidate_bytes`, checked against the capture group's finite maximum;
- `fixture_set` and digest-bound `provenance` references.

Provider patterns must compile in the Rust linear-time byte-regex engine. A
pattern that cannot have a finite maximum, or whose capture exceeds its declared
candidate bound, is rejected. RegexSet may fall back explicitly to the reference
regex; a rule is never silently skipped.

Provider validators return format-valid, plausible-unverified or rejected.
Rejected candidates are not emitted. Plausible candidates are retained with a
`PLAUSIBLE_UNVERIFIED` validation token and a downgraded confidence. A validator
reason is a static string and never contains the candidate.

### Provider lifecycle

1. Confirm the format from provider documentation; record the reference and
   review date in `provenance`.
2. Write a bounded pattern and declare the exact capture group and candidate
   maximum.
3. Select reusable offline validators; never call a provider API or redeem a
   token.
4. Add a harmless deterministic positive, a structural near-miss, a malformed
   value and a documentation-placeholder negative.
5. Add the rule to independent truth outside the scanner root and verify the
   byte spans by hashing source bytes.
6. Run all four strategies and both modes; reject any unexplained difference.
7. Measure the provider catalog benchmark before accepting a material cost.
8. Bump `rule_version`, update the ruleset digest and preserve the previous
   bundle when a release must remain reproducible.
9. Deprecate by rule version and documentation; never reuse a rule ID for a
   different semantic.
10. Keep synthetic regression rules separate from provider rules.

### Provider classification decisions

An identifier is not automatically a credential. AWS `AKIA`/`ASIA` are the only
prefixes accepted by `aws-access-key-id`; `AIDA`, `AGPA`, `AIPA`, `ANPA`,
`ANVA`, `APKA`, `AROA` and `ASCA` are ordinary IAM resource identifiers and do
not get credential findings. `ABIA` and `ACCA` are sensitive identifiers with
their own rules and `service-bearer-token-id` / `context-specific-credential-id`
classifications; they are not alternate access-key prefixes.

GitHub `ghs_` installation tokens are separate from `gho_`/`ghu_`/`ghr_` OAuth
tokens. Legacy opaque and stateless `ghs_APPID_JWT` forms share a dedicated
rule; the modern form is structurally validated only, never signature-verified
or sent to GitHub.

A rule count is not a coverage metric. Unsupported, experimental and
implemented families are distinguished in the [detection catalog](cp3-detection-catalog.md).

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
