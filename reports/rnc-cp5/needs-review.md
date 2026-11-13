# RNC CP5 — 19 unmatched historical findings requiring review

Source experiment: `reports/rnc-cp5/rnc-93b4dda-official-93b4dda909cb-default.json`
Scanner: RNC `0.1.0` at `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde`

These are `UNMATCHED_PENDING_REVIEW` observations from the frozen historical scoring run. They are **not** false positives. No owner-approved truth was changed.

## Summary

- Total findings: **19**
- Unique source locations: **10**
- Benchmark metadata path: **8**
- Possible value-representation mismatch: **1**
- Source location not adjudicated: **10**
- Native/Docker parity: **true**

## Manifest

| ID | Location | Commit | Rule | Reason | Group observations | Priority |
| --- | --- | --- | --- | --- | ---: | --- |
| NR-01 | `.leaky-meta/secrets.csv:46` | `4ad3f90463c8` | `generic-secret-assignment` | `BENCHMARK_METADATA_PATH_NOT_ADJUDICATED` | 2 | LOW |
| NR-02 | `.leaky-meta/secrets.csv:46` | `9f1468c79df2` | `generic-secret-assignment` | `BENCHMARK_METADATA_PATH_NOT_ADJUDICATED` | 2 | LOW |
| NR-03 | `.leaky-meta/secrets.csv:48` | `226fcb481daf` | `generic-secret-assignment` | `BENCHMARK_METADATA_PATH_NOT_ADJUDICATED` | 2 | LOW |
| NR-04 | `.leaky-meta/secrets.csv:48` | `2e951359cac5` | `generic-secret-assignment` | `BENCHMARK_METADATA_PATH_NOT_ADJUDICATED` | 2 | LOW |
| NR-05 | `.leaky-meta/secrets.csv:67` | `4ad3f90463c8` | `generic-secret-assignment` | `BENCHMARK_METADATA_PATH_NOT_ADJUDICATED` | 2 | LOW |
| NR-06 | `.leaky-meta/secrets.csv:67` | `9f1468c79df2` | `generic-secret-assignment` | `BENCHMARK_METADATA_PATH_NOT_ADJUDICATED` | 2 | LOW |
| NR-07 | `.leaky-meta/secrets.csv:69` | `226fcb481daf` | `generic-secret-assignment` | `BENCHMARK_METADATA_PATH_NOT_ADJUDICATED` | 2 | LOW |
| NR-08 | `.leaky-meta/secrets.csv:69` | `2e951359cac5` | `generic-secret-assignment` | `BENCHMARK_METADATA_PATH_NOT_ADJUDICATED` | 2 | LOW |
| NR-09 | `hub:4` | `903a9caba59d` | `generic-secret-assignment` | `ORACLE_ITEM_VALUE_REPRESENTATION_MISMATCH` | 1 | MEDIUM |
| NR-10 | `web/django/settings.py:24` | `4ad3f90463c8` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |
| NR-11 | `web/django/settings.py:24` | `9f1468c79df2` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |
| NR-12 | `web/js/salesforce.js:7` | `4ad3f90463c8` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |
| NR-13 | `web/js/salesforce.js:7` | `9f1468c79df2` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |
| NR-14 | `web/var/www/.env:14` | `4ad3f90463c8` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |
| NR-15 | `web/var/www/.env:14` | `9f1468c79df2` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |
| NR-16 | `web/var/www/.env:33` | `4ad3f90463c8` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |
| NR-17 | `web/var/www/.env:33` | `9f1468c79df2` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |
| NR-18 | `web/var/www/public_html/config.php:11` | `4ad3f90463c8` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |
| NR-19 | `web/var/www/public_html/config.php:11` | `9f1468c79df2` | `generic-secret-assignment` | `SOURCE_LOCATION_NOT_ADJUDICATED` | 2 | MEDIUM |

## Review procedure

1. Open the listed commit/path/line in the pinned Leaky Repo source. RNC reports byte offsets and safe SHA-256 evidence only; no raw value is in this manifest.
2. Decide whether the source line is credential-bearing, benchmark metadata, an informative reference, or a non-secret.
3. For `.leaky-meta/secrets.csv`, verify whether the line is benchmark metadata rather than a production source occurrence. Do not count benchmark metadata as an oracle occurrence without an explicit owner decision.
4. For `hub:4`, compare RNC’s generic assignment span with owner item `LH-0179`. The owner-approved digest is different; determine whether RNC extracted a different representation before proposing any change.
5. For the remaining locations, record the source review result. Any new expected occurrence requires separate owner approval and an oracle revision; do not edit the oracle or scorer to improve a score.
6. Preserve `finding_id`, `unit_id`, commit, path, line, and safe digests in any review record. Never paste raw credentials into the manifest, console output, issue, or commit.

## Safety

- This manifest contains only scanner metadata, locations, and safe SHA-256 digests.
- `raw_values_included` is false for every item.
- RNC component source digests and component offsets are not included.
- `UNMATCHED_PENDING_REVIEW` is not a precision-denominator false positive.
- The owner-approved historical oracle remains unchanged.
