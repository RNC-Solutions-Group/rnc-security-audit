# RNC Scanner CP5 source-commit evidence

Pinned scanner source: `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde`

This experiment was built from a disposable checkout of
`https://github.com/RNC-Solutions-Group/rnc-security-audit`; source HEAD was
verified. No scanner source, default rule, scoring implementation, or owner
oracle was changed.

## Default configuration

| Fact | Value |
| --- | --- |
| Rule bundle | `rules/rnc-providers-v1.json` |
| Ruleset | `rnc-providers-v1` `2026.11.4` |
| Rules / families | 37 / 22 |
| Component extractor | `database-uri-password` |
| Rule file SHA-256 | `87d7f9051ae41df34df29a0d5447ee8c9d71854ada46b789c9b7a00e4320a73a` |
| Canonical ruleset digest | `sha256:dc1ab16f64a5dfb91262b46f321a9f5b219a13ed3bfb49e0f79c067de40bbc0f` |
| Native executable SHA-256 | `e6ee7be57e156ca8272677d75e511d7bf9d536d2aaf779df41daa0d089b61ecc` |
| Docker image ID | `sha256:27aea2a7304230730c2859ba493cb3b99f60e886a9d25b22e86cbf2db47e4bf8` |

## Historical benchmark

The scanner was invoked with `--history --ref HEAD`, preserving the pinned
Leaky Repo HEAD's reachable history. The scanned unit model is **changed
commit/path revisions**, not full snapshots.

| Metric | Native Windows AMD64 | Docker Linux AMD64 |
| --- | ---: | ---: |
| Observed findings | 61 | 61 |
| Historical commits | 25 | 25 |
| Inspected revisions | 166 | 166 |
| Coverage | COMPLETE / verified | COMPLETE / verified |
| Matched occurrences | 21 / 65 | 21 / 65 |
| Matched unique groups | 19 / 53 | 19 / 53 |
| Occurrence recall | 32.31% | 32.31% |
| Unique-group recall | 35.85% | 35.85% |
| Duplicates | 13 | 13 |
| Informative matches | 8 | 8 |
| Verified false positives | 0 | 0 |
| Unmatched pending review | 19 | 19 |
| Unverified evidence | 0 | 0 |
| Accounted observations | 61 / 61 | 61 / 61 |

The native and Docker evaluation multisets are identical. Precision/F1 remain
`null` with `BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`; the reviewed negatives are not
exhaustive.

### Matched groups

`SG-002`, `SG-005`, `SG-007`, `SG-008`, `SG-013`, `SG-015`, `SG-020`, `SG-022`,
`SG-037`, `SG-038`, `SG-045`, `SG-048`, `SG-049`, `SG-050`, `SG-057`, `SG-058`,
`SG-071`, `SG-074`, `SG-075`.

### Investigation ledger

The 19 unmatched findings collapse to ten unique source locations:

- `.leaky-meta/secrets.csv` benchmark metadata at lines 46, 48, 67, 69 across
  several commits (8 findings);
- `hub:4` (OAuth token representation differs from the owner-approved digest);
- `web/django/settings.py:24`;
- `web/js/salesforce.js:7`;
- `web/var/www/.env` lines 14 and 33;
- `web/var/www/public_html/config.php:11`.

These are not counted as false positives. `.leaky-meta/secrets.csv` is benchmark
metadata, not an approved source occurrence. `hub:4` is a scanner representation
mismatch. No finding was suppressed.

Informative matches: `cloud/.s3cfg:1` (AWS access-key identifier, three snapshot
observations), `web/js/salesforce.js:6`, and four Firefox login metadata entries.

## Filesystem benchmark

The same experiment also ran the filesystem suite:

- 29 observed findings;
- 25/175 rich line-truth matches, 23 value-verified and 2 line-only;
- 2 unexpected findings (retained in the ledger);
- 27/175 legacy count coverage, 18/44 files (15.43% legacy coverage).

This is not a negative oracle and no filesystem precision/F1 is certified.

## Performance

DEV environment profile, one warm-up and three measured filesystem runs on a
61-file workload:

| Product | Median | Min / max | CV | Stability |
| --- | ---: | ---: | ---: | --- |
| Windows AMD64 native | 0.441 s | 0.403 / 0.467 s | 0.0601 | STABLE |
| Docker Linux AMD64 | 1.354 s | 1.265 / 1.373 s | 0.0354 | STABLE |

These are preliminary contended-DEV measurements, not release evidence.

## Needs-review manifest

The 19 unmatched findings are available as a machine-readable, sanitized
manifest: [`needs-review.json`](needs-review.json), with a reviewer table in
[`needs-review.md`](needs-review.md). It contains only locations, scanner/rule
metadata, and safe SHA-256 evidence; no raw credentials or private component
digests/offsets are included.

## Evidence files

- `rnc-93b4dda-official-93b4dda909cb-default.json`
- `rnc-93b4dda-official-93b4dda909cb-default.md`
