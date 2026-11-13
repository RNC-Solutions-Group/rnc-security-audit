# Leaky Repo Git-history oracle — final owner approval

**Authority:** Owner-approved source classifications as of November 11, 2026. **Harness integration status (November 12, 2026): source-validated runtime matching is implemented; reviewed negatives remain non-exhaustive, so precision/F1 are NOT CERTIFIED.**

- Canonical source oracle: [`datasets/leaky-repo.history-oracle.json`](../../datasets/leaky-repo.history-oracle.json)
- Updated owner-adjudicated inventory: [`leaky-history-candidates.csv`](leaky-history-candidates.csv). Original proposal retained in `proposed_classification`; authoritative decision is `owner_disposition`.
- Pinned head: `2e951359cac53addbee56437da3ffb546e3dfe24`, all 25 reachable commits, including side branches and historical-only paths.
- **65 POSITIVE source occurrences / 53 unique credential groups; 86 NEGATIVE; 30 INFORMATIVE; 0 LINEAGE_ONLY. 181 records, zero holds.**
- Repeated placements: SG-001 (4), SG-010 (4), SG-013 (4), SG-020 (3), SG-042 (2); extra placements beyond unique groups: 12.
- Owner's final correction retains LH-0124 as NEGATIVE (literal OAuth placeholder). LH-0170 is INFORMATIVE / RENAME_LINEAGE; its identical-blob `.docker/config` -> `config` rename introduces no new credential.
- Negative-audit corrections: LH-0001, LH-0079, LH-0081 are INFORMATIVE identifiers matching LH-0083. Original source's AWS formats are synthetic and `.s3cfg` source labels are inverted.
- Corrected 5 formerly unscored positives: LH-0032, LH-0091, LH-0092, LH-0103, LH-0160. All 65 approved positives now have YES occurrence credit.
- LH-0128 (L4) and LH-0129 (L11) are INFORMATIVE structural PPK metadata tied to positive LH-0127. LH-0139 is a symmetric Rails application encryption key.
- PEM LH-0126 normalized representation excludes the file's final newline; both examined scanners detected the full block. LH-0039 is reversibly obfuscated JetBrains FTP material; LH-0103's oracle hashes embedded MongoDB password whereas Betterleaks hashes the URI. Typed attribution is required for credit.
- Docker and FileZilla encoded credentials are scored by source occurrence, not only distinct decoded value.
- **Every unmatched scanner finding MUST be retained in an investigation queue.** Unmatched is not automatically a false positive, and must never be silently ignored. Preserve source commit, path, line, rule, safe evidence hashes, scanner profile and matching failure reason.
- Explicit reviewed NEGATIVE matches can become verified false positives only when the actual extracted evidence is validated against that source. These 85 reviewed negatives do not exhaustively cover every line in all history. INFORMATIVE matches remain separately visible, not primary TPs.
- Preserve per-category expected, found, missed, unmatched, duplicates, informative matches, and verified negatives. No multiple credit for one source occurrence; history persistence and renames add zero new source occurrences. Use ancestry-aware source validation.
- The **175-item filesystem truth** remains separate and has `negative_oracle=false`; it contains 88 risk and 87 informative EXPECTED_DETECTION entries, **not 175 negative samples**.

**Status gates:** CP-OR1 source truth approved and recorded; CP-OR2 ancestry-aware/typed matcher **implemented**; CP-OR3 full finding adjudication and rescoring **implemented for retained evidence, pending review**; CP-OR4 metric certification **remains blocked by the non-exhaustive negative oracle**. Do not claim certified historical precision/F1. Do not modify scanner implementations to favor the benchmark.
