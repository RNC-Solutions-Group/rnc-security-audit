# Detection-gap analysis

Target-level false-negative and source-context investigation for the current-scoring Windows AMD64 baselines. These reports are generated from retained harness evidence and frozen oracles; no scanner, rule, oracle or scoring policy was modified.

Generated: `2026-11-16T03:08:16+00:00`

Analysis version: `1.0.0`

## Individual reports

### RNC Scanner CP4C

- [Detection gaps](cp4c/cp4c-detection-gaps.md)
- [Root causes](cp4c/cp4c-root-causes.md)
- [Development backlog](cp4c/cp4c-development-backlog.md)
- [Target inventory](cp4c/cp4c-target-inventory.csv)
- [Missed targets](cp4c/cp4c-missed-targets.csv)
- [Provider context](cp4c/cp4c-provider-context.csv)
- [Location analysis](cp4c/cp4c-location-analysis.csv)
- [Machine summary](cp4c/cp4c-summary.json)

Expected 1125, matched 570, missed 555 (468 risk-bearing).

### RNC-Mod V14

- [Detection gaps](rnc-mod-v14/v14-detection-gaps.md)
- [Root causes](rnc-mod-v14/v14-root-causes.md)
- [Development backlog](rnc-mod-v14/v14-development-backlog.md)
- [Target inventory](rnc-mod-v14/v14-target-inventory.csv)
- [Missed targets](rnc-mod-v14/v14-missed-targets.csv)
- [Provider context](rnc-mod-v14/v14-provider-context.csv)
- [Location analysis](rnc-mod-v14/v14-location-analysis.csv)
- [Machine summary](rnc-mod-v14/v14-summary.json)

Expected 1125, matched 591, missed 534 (448 risk-bearing).

### RNC-Mod V16

- [Detection gaps](rnc-mod-v16/v16-detection-gaps.md)
- [Root causes](rnc-mod-v16/v16-root-causes.md)
- [Development backlog](rnc-mod-v16/v16-development-backlog.md)
- [Target inventory](rnc-mod-v16/v16-target-inventory.csv)
- [Missed targets](rnc-mod-v16/v16-missed-targets.csv)
- [Provider context](rnc-mod-v16/v16-provider-context.csv)
- [Location analysis](rnc-mod-v16/v16-location-analysis.csv)
- [Machine summary](rnc-mod-v16/v16-summary.json)

Expected 1125, matched 592, missed 533 (447 risk-bearing).
Fresh current-scoring V16 baseline: native Windows AMD64, default settings, 1 warmup + 3 measured runs, no profiling.

## Shared comparison

- [CP4C/V14/V16 target overlap](cp4c-v14-target-overlap.md)
- [Target overlap CSV](cp4c-v14-target-overlap.csv)
- All-scanner common misses: **368**

## Validation

- [Machine validation](analysis-validation.json)
- Every scanner's reconstructed per-target matched count is checked against its retained report metric, by lane and in total.
- Root-cause totals equal the reconstructed miss totals for every scanner.
- The 1,125-target universe is partitioned into 85 Levain, 175 Leaky filesystem, 65 Leaky Git, 640 RNC Lab filesystem and 160 RNC Lab Git targets.
- Leaky Git preserves 65 occurrences and 53 unique groups; RNC Lab preserves 800 occurrences and 496 unique groups. They are never conflated.
- The 10 archive members, 12 database records and 4 binary key containers are classified as non-plaintext, not ordinary files.
- RNC Lab and Leaky Git precision/F1 are not claimed; their negative oracles are incomplete.

## Regeneration

```powershell
python -m harness detection-gaps --out-dir reports/detection-gaps
python -m unittest tests.test_detection_gaps -v
```

Raw evidence remains under Git-ignored `run/`. Tracked files contain target IDs, redacted structural context and nonsecret source locators only.
