# Git-history accountability

## Leaky Repo discovery (pinned history)

- HEAD: `2e951359cac53addbee56437da3ffb546e3dfe24`
- Commits: 25
- Current files: 61
- Changed paths: 65
- Historical-only paths: 4
- Additions / modifications / deletions: 62 / 52 / 1
- Renames: 3
- Duplicate current-blob groups: 0
- Git objects: 207
- Historical truth status: **BLOCKED**

The pinned repository has no independently verified per-commit secret manifest. Git-history observations cannot be converted into recall or precision without inventing historical expectations.

Historical-only paths: `.docker/config`, `benchmarking/DETECT-SECRETS.md`, `benchmarking/TRUFFLEHOG.md`, `misc-keys/cert-example.pem`

Leaky Repo history execution observed **26** findings (**16** unique secret fingerprints) across **25** commits. Those observations are not scored against recall or precision.

## Controlled synthetic history

- Status: **COMPLETE**
- Unique expected secrets: 3
- Unique matched secrets: 3
- Expected occurrences: 5
- Matched occurrences: 5
- Missed / unexpected / duplicates: 0 / 0 / 0
- Value-verified occurrences: 5

All three scanner products passed the history parity comparison.
