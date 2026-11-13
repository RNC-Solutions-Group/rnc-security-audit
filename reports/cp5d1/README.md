# CP5D.1 — source-identity hardening evidence

Offline rescoring and proposal validation. No scanner was rerun.

Authoritative report:
[`docs/checkpoints/CP5D1-final-source-identity-report.md`](../../docs/checkpoints/CP5D1-final-source-identity-report.md).

## Files

| File | Purpose |
|---|---|
| [`proposal-validation.json`](proposal-validation.json) | Official proposed 184/89 oracle-validation result and RNC simulation |
| [`cross-scanner-rescore.json`](cross-scanner-rescore.json) | CP5D→CP5D.1 retained metrics and native/Docker parity |
| [`rnc-native-history.json`](rnc-native-history.json), [`rnc-docker-amd64-history.json`](rnc-docker-amd64-history.json) | RNC rescoring |
| [`gitleaks-native-history.json`](gitleaks-native-history.json), [`gitleaks-docker-amd64-history.json`](gitleaks-docker-amd64-history.json) | Gitleaks rescoring |
| [`betterleaks-native-history.json`](betterleaks-native-history.json), [`betterleaks-docker-amd64-history.json`](betterleaks-docker-amd64-history.json) | Betterleaks rescoring |

## Current retained result

| Scanner | TP | Unique TP | Duplicates | Informative | FP alerts | FP exposures | Unmatched |
|---|---:|---:|---:|---:|---:|---:|---:|
| RNC | 21 | 19 | 21 | 7 | 1 | 1 | 11 |
| Gitleaks | 21 | 15 | 3 | 2 | 0 | 0 | 0 |
| Betterleaks | 36 | 28 | 3 | 2 | 0 | 0 | 0 |

RNC remains **21/65 = 32.31%** occurrence recall and **19/53 = 35.85%** unique
recall. Precision/F1 are `null` and `BLOCKED_INCOMPLETE_NEGATIVE_ORACLE`.
Native/Docker parity is PASS for all three (RNC 105 evaluations, Gitleaks 70,
Betterleaks 70).

## Proposed migration — not applied

The official proposed-oracle profile reports **PASS**:

- total **184**
- reviewed negatives **89**
- positives **65**
- informative **30**
- unique groups **53**
- source validation **184/184**

Exact digests:

| ID | Value | SHA-256 |
|---|---|---|
| `PNM-001` | `sshPassphrase` | `168f39bc81005d2aae6aa2a5ed563bc29b9afb92be9bd33ae58e5676866afa73` |
| `PNM-002` | `passphrase` | `1e089e3c5323ad80a90767bdd5907297b4138163f027097fd3bdbeab528d2d68` |
| `PNJ-001` | `function(err` | `7a6d503ccb60241ad7a7f8381c4442792fb8143ea4625942bc9d7578750a1a0d` |

Simulated RNC accounting if approved: **21 TP, 21 duplicates, 7 informative,
12 FP alerts, 4 unique nonsecret exposures, 0 pending, 61/61 accounted**.

The approved 181/86 oracle file was not changed. Proposed records are marked
`PROPOSED_NOT_APPLIED`.

Full suite: **276 tests passed**, 0 failures/errors, 180.370 s.
