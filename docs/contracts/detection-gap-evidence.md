# Detection-gap evidence, input pinning, and publication contract

This document defines the audit rules for the read-only `detection-gaps` command.
The command consumes retained harness reports and frozen oracles. It does not
execute a scanner, change a rule, rewrite an oracle, or alter a certified score.

## Deterministic input selection

The command no longer selects the newest JSON report by filesystem modification
time. The default is [`reports/detection-gaps/analysis-inputs.json`](../../reports/detection-gaps/analysis-inputs.json).

Each lock entry records:

- repository-relative report path;
- report SHA-256;
- registered build ID and scanner;
- source-commit metadata and executable/image identity where present;
- run ID, profile, report generation time;
- scanner-argument digest/classification where present.

The lock also records dataset/oracle SHA-256 values for the RNC Lab, Leaky Repo
and Levain inputs, the scoring epoch, harness version, and the harness source
revision used when the lock was written.

Selection is fail-closed:

- a missing lock, missing entry, changed report hash, changed build ID, or changed
  source-commit metadata is an actionable error;
- multiple matching reports are never resolved by timestamp;
- explicit `--cp4c-report`, `--v14-report`, and similar overrides are identity
  checked, recorded as `explicit-override`, and cannot be described as pinned.

### Reproducibility

The substantive report files are deterministic for a fixed input lock and
analysis code. The following are deliberately outside that set:

- `analysis-run.json` - generation timestamp, command, input selection;
- `publication.json` - publication timestamp and file manifest;
- absolute temporary paths in any intermediate diagnostic output.

Regenerating twice from the same lock must produce identical substantive CSV,
Markdown and summary JSON files. A test or release check should compare those
files while excluding the two volatile metadata files.

## Source inspection is not a detection result

Three concepts are independent:

1. **Source capability** - does a scanner/source declaration claim support for
   this container or source type?
2. **Inspection evidence** - does retained evidence prove this specific source
   unit/member/record was reached?
3. **Detection outcome** - was the expected credential credited?

Inspection states:

| State | Meaning | Can support CONFIRMED? |
| --- | --- | --- |
| `INSPECTED_VERIFIED` | Scanner-native coverage or a credited finding proves the unit was reached | Yes |
| `NOT_INSPECTED_VERIFIED` | Coverage record explicitly lists the unit as skipped/uninspected | Yes |
| `INSPECTION_UNVERIFIED` | No unit-level proof either way | No |
| `UNSUPPORTED_VERIFIED` | Validated scanner/source capability contract excludes the type | Yes |
| `NOT_APPLICABLE` | Lane/capability does not apply | No for a detection claim |

Capability values are `CLAIMED_SUPPORTED`, `DECLARED_UNSUPPORTED`, or
`NOT_DECLARED`. A container miss with no member/record evidence is classified as
`SOURCE_INSPECTION_UNVERIFIED` with `UNRESOLVED` confidence. It is **not**
`SOURCE_UNSUPPORTED/CONFIRMED` merely because no finding in that container class
was credited. An absence of findings is not evidence of failed inspection.

A signature, finding, or coverage record at one location does not prove every
constituent archive member, database row, or nested container was inspected. The
source-unit identity is preserved in the CSV inventories.

When inspection is unverified for an ordinary file, the detection hypothesis may
remain but `CONFIRMED` is downgraded to `PROBABLE` and the evidence string says
that source inspection is not independently verified.

## Root-cause taxonomy

The reports use these distinct causes:

`RULE_ABSENT`, `IDENTIFIER_MISMATCH`, `FORMAT_UNSUPPORTED`, `CAPTURE_MISMATCH`,
`CONTEXT_INSUFFICIENT`, `VALIDATOR_REJECTION`, `SOURCE_NOT_INSPECTED`,
`SOURCE_UNSUPPORTED`, `SOURCE_INSPECTION_UNVERIFIED`, `GIT_SCOPE_OR_ATTRIBUTION`,
`SCORING_MISMATCH`, `INFORMATIVE_REFERENCE`, `UNKNOWN`.

The first seven imply different development work and are not interchangeable.
`CAPTURE_MISMATCH` requires a retained same-location observation whose value
evidence failed. `SCORING_MISMATCH` requires a usable observation rejected by the
scorer. `SOURCE_NOT_INSPECTED` requires a coverage record.

## Report-set publication

`generate_reports` writes a complete candidate set to a staging directory,
validates JSON parseability and the core reconciliation checks, then publishes:

1. `publication.json` is written as `IN_PROGRESS` before any substantive file is
   replaced.
2. Each file is written atomically.
3. `publication.json` becomes `COMPLETE` only after every file and SHA-256 is
   recorded.

A crash or disk failure leaves `IN_PROGRESS`. Consumers must not treat a directory
as finalized unless the marker says `COMPLETE` and every listed hash matches.

An existing non-empty directory without a valid completion marker is not
overwritten unless `--replace` is supplied explicitly. This prevents a routine
run from replacing an unrelated historical report tree.

## Privacy and spreadsheet safety

- Report paths are repository-relative or reduced to `<external>/<name>`.
- Invocation/argument fields are credential-redacted before analysis.
- Source context is redacted by `redact_span`/`safe_identifier`.
- CSV output neutralises leading `=`, `+`, `-`, and `@` with a leading apostrophe
  unless the value is a genuine numeric value. Leading whitespace, tabs, newlines
  and control characters are considered before the formula prefix.
- Markdown table cells escape pipes and convert embedded newlines to `<br>`;
  code spans choose a backtick fence that does not collide with the value.

## Validation invariants

The generated `analysis-validation.json` must retain:

- expected target IDs and lane partitions;
- credited and missed target IDs;
- original benchmark scores and unique-group accounting;
- root-cause totals equal to miss totals;
- evidence for every missed target;
- the 26 non-plaintext targets separated from ordinary files;
- `oracle_or_scoring_changed: false`.

Inspection labels, root causes, confidence counts and development priorities may
change when the evidence model changes. Certified scores and target IDs may not.
