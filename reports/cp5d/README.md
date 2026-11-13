# CP5D — lineage integrity and negative-reference evidence

Offline rescoring of retained evidence; no scanner was rerun. The authoritative
report is
[`docs/checkpoints/CP5D-lineage-integrity-report.md`](../../docs/checkpoints/CP5D-lineage-integrity-report.md).

## Files

| File | Purpose |
|---|---|
| [`cross-scanner-rescore.json`](cross-scanner-rescore.json) | CP5C→CP5D metrics, native/Docker parity, proposed-migration simulation |
| [`finding-accountability.json`](finding-accountability.json) | 19 CP5C observations + adjacent Salesforce line-6, current vs proposed |
| [`proposed-oracle-migration.json`](proposed-oracle-migration.json) | Three proposed negative records; **not applied** |
| `rnc-native-history.json`, `rnc-docker-amd64-history.json` | RNC rescores |
| `gitleaks-native-history.json`, `gitleaks-docker-amd64-history.json` | Gitleaks rescores |
| `betterleaks-native-history.json`, `betterleaks-docker-amd64-history.json` | Betterleaks rescores |

## Current result

| Metric | RNC |
|---|---:|
| Observed | 61 |
| TP occurrences | 21 |
| Unique TP groups | 19 |
| FN | 44 |
| FP alerts | 1 |
| Unique verified nonsecret exposures | 1 |
| Duplicates | 21 |
| Informative matches | 7 |
| Unmatched pending | 11 |
| Unverified | 0 |
| Accounted | 61/61 |

The 20-observation subset (19 original plus the adjacent Salesforce line-6
invalid informative) is currently **8 duplicates, 1 verified FP, 11 pending**.
If the proposed migration is approved, the simulation is **8 duplicates, 12 FP,
0 pending**, with **4 unique verified nonsecret exposures** and **12 FP alert
observations**.

## Proposed migration — not applied

| Record | Source | Exact value | Covered alerts |
|---|---|---|---:|
| `PNM-001` | `.leaky-meta/secrets.csv:46` at `9f1468c` | `sshPassphrase` | `168f39bc…` | 4 |
| `PNM-002` | `.leaky-meta/secrets.csv:67` at `9f1468c` | `passphrase` | `1e089e3c…` | 4 |
| `PNJ-001` | `web/js/salesforce.js:6` at `903a9ca` | `function(err` | `7a6d503c…` | 3 |

The two metadata records replace the four overlapping CP5C proposals because
`9f1468c` is an ancestor of `4ad3f90`, `226fcb4`, and `2e951359`. The exact-value
JavaScript negative is scoped to `function(err`, not the whole line containing the
approved informative `salesforcepassword`.

If approved: reviewed negatives **86 → 89**, total records **181 → 184**;
positive occurrences remain **65**, unique groups **53**, informative references
**30**. Precision/F1 remain `null` and `BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`.

Full regression suite: **269 tests passed**, 0 failures/errors, 153.103 s.

No scanner source, default rules, synthetic-lab registration, or owner-approved
oracle file was changed. Proposed records are marked `PROPOSED_NOT_APPLIED`.
