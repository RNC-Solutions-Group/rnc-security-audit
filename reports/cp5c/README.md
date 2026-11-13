# CP5C — historical attribution and rescoring evidence

These files were produced offline from retained normalized findings. No scanner
was rebuilt or rerun. The authoritative CP5C report is
[`docs/checkpoints/CP5C-scoring-integrity-report.md`](../../docs/checkpoints/CP5C-scoring-integrity-report.md).

## Files

| File | Purpose |
|---|---|
| [`cross-scanner-rescore.json`](cross-scanner-rescore.json) | Before/after RNC, Gitleaks, and Betterleaks metrics; native/Docker parity |
| [`rnc-19-reconciliation.json`](rnc-19-reconciliation.json) | Before/after classification of all 19 original RNC unmatched observations |
| [`proposed-negative-additions.json`](proposed-negative-additions.json) | Four owner-review proposals; **not applied** to the oracle |
| [`rnc-native-history.json`](rnc-native-history.json) | RNC native rescore |
| [`rnc-docker-amd64-history.json`](rnc-docker-amd64-history.json) | RNC Docker AMD64 rescore |
| [`gitleaks-native-history.json`](gitleaks-native-history.json) | Gitleaks native rescore |
| [`gitleaks-docker-amd64-history.json`](gitleaks-docker-amd64-history.json) | Gitleaks Docker AMD64 rescore |
| [`betterleaks-native-history.json`](betterleaks-native-history.json) | Betterleaks native rescore |
| [`betterleaks-docker-amd64-history.json`](betterleaks-docker-amd64-history.json) | Betterleaks Docker AMD64 rescore |

## RNC before/after

| Metric | Before | After |
|---|---:|---:|
| Observed | 61 | 61 |
| TP occurrences | 21 | 21 |
| Unique TP groups | 19 | 19 |
| FN | 44 | 44 |
| FP | 0 | 1 |
| Duplicates | 13 | 21 |
| Informative matches | 8 | 7 |
| Unmatched pending | 19 | 11 |
| Unverified | 0 | 0 |

Of the original 19 unmatched observations: 8 are now `DUPLICATE`, 1 is
`FALSE_POSITIVE` (`LH-0124`), and 10 remain pending. One adjacent Salesforce
line-6 `function(err` finding was previously an invalid `INFORMATIVE_MATCH`; it
is now pending, making 11 total pending.

## Cross-scanner

| Scanner | Observed | TP | Unique TP | FN | FP | Duplicates | Informative | Unmatched | Unverified |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| RNC `93b4dda` | 61 | 21 | 19 | 44 | 1 | 21 | 7 | 11 | 0 |
| Gitleaks `5f6ec56` | 26 | 21 | 15 | 44 | 0 | 3 | 2 | 0 | 0 |
| Betterleaks `5eab483` | 41 | 36 | 28 | 29 | 0 | 3 | 2 | 0 | 0 |

Gitleaks and Betterleaks are unchanged before/after. RNC retains 21 TP and 19
unique groups. Native/Docker classification parity passes for all three.
Precision/F1 are `null` with `BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`; the one RNC
verified negative does not make the negative inventory exhaustive.

## Denominators

Unchanged: **65** positive occurrences, **53** unique groups, **86** reviewed
negatives, **30** informative references. RNC remains **21/65 = 32.31%**
occurrence recall and **19/53 = 35.85%** unique recall.

## Proposed negatives

`proposed-negative-additions.json` contains four metadata-comment proposals
(`PN-001`–`PN-004`) with `status: PROPOSED_NOT_APPLIED`. They did not affect these
scores. They overlap on the `2e951359` merge because both branch lineages reach
the same comment; owner approval must decide whether overlapping branch negatives
collapse. No negative is proposed for `web/js/salesforce.js` because that line
contains the approved informative `salesforcepassword`; the incorrect
`function(err` extractions remain pending.
