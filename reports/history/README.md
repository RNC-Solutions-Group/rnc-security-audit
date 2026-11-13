# Leaky Repo Git-history rescoring evidence

These files were produced offline from retained normalized findings. No scanner
was rebuilt or rerun. The input reports are the CP3 source-commit experiments
under `reports/cp3/`.

| Scanner | Product | Observed | Occurrences matched | Unique groups matched | Occurrence recall | Unique recall | Duplicates | Informative | Verified FP | Unmatched | Unverified |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks `5f6ec56` | Windows AMD64 native | 26 | 21 / 65 | 15 / 53 | 32.31% | 28.30% | 3 | 2 | 0 | 0 | 0 |
| Gitleaks `5f6ec56` | Docker Linux AMD64 | 26 | 21 / 65 | 15 / 53 | 32.31% | 28.30% | 3 | 2 | 0 | 0 | 0 |
| Betterleaks `5eab483` | Windows AMD64 native | 41 | 36 / 65 | 28 / 53 | 55.38% | 52.83% | 3 | 2 | 0 | 0 | 0 |
| Betterleaks `5eab483` | Docker Linux AMD64 | 41 | 36 / 65 | 28 / 53 | 55.38% | 52.83% | 3 | 2 | 0 | 0 | 0 |

The native and Docker evaluation multisets are identical for each scanner
(70 evaluations each, zero differences). The products are not directly
comparable as performance measurements; this parity statement is about
classification of the same retained history findings.

The 65 occurrence and 53 unique-group denominators come from the owner-approved
[`leaky-repo.history-oracle.json`](../../datasets/leaky-repo.history-oracle.json):

- 65 POSITIVE source occurrences;
- 53 unique positive groups;
- 86 NEGATIVE references;
- 30 INFORMATIVE references;
- 0 LINEAGE_ONLY;
- `reviewed_negatives_exhaustive = false`.

Precision and F1 are therefore `null` with
`precision_certification_status = BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`. Every
observed finding is present in the evaluation ledger; the metrics reconcile
26/26 and 41/41 respectively. Informative AWS access-key identifier findings are
reported separately and earn no primary recall.

The matcher credits full PEM blocks across terminal-newline variation, Docker and
FileZilla Base64 representations, and the MongoDB URI representation where the
source value is still evidenced. JetBrains material is credited only for the
validated encoded source attribute; no decoded equivalence is claimed.

Reproduce:

```sh
python -m harness rescore-history \
  --report reports/cp3/gitleaks-5f6ec56-native-5f6ec56cfa6f-default.json \
  --platform windows-amd64 \
  --out reports/history/gitleaks-5f6ec56-native-history.json
```
