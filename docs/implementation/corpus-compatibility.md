# External corpus compatibility — CP0 inventory

The existing [RNC Gitleaks harness](https://github.com/RNC-Solutions-Group/gitleaks/tree/test/scan-harness) is independent grading infrastructure; its scoring semantics **must not** be copied into the production detector. Inspected harness revision: `cf8f9153a304fc9ab8d69f8b2b16bdbc1d00d2df` (10 November 2026). These are **observed manifest declarations**, not claims that CP0 executed the external datasets.

| Corpus | Pinned source revision (as declared by harness) | Native truth/counting unit | CP0 integration status |
| --- | --- | --- | --- |
| [Levain FP corpus](https://github.com/levainbot/fp-corpus) | `c130c321aa9046af17a6c876cb97e2ed71397110` (MIT) | 116 negative sections/0 secrets; 45 positive sections/85 planted secrets, including 3 hard sections/3 hard secrets; individual labeled cases | Pinned and verified in external harness; not executed here |
| [Leaky Repo](https://github.com/Plazmaz/leaky-repo) | `2e951359cac53addbee56437da3ffb546e3dfe24` (MIT) | Organic `.leaky-meta/secrets.csv`: **175** total = 96 risk + 79 informative, over 44 files | Pinned and verified in external harness; symlink/OOM handling must be honored before CP0 run |
| Gitleaks fixtures | Harness-owned `datasets/gitleaks-fixtures.toml` | Per-rule and file fixtures | Adapter integration pending |
| Prowlbench | Not approved | License status requires separate review | Explicitly excluded |

The manifest in the external branch contains content hashes, expected totals and provenance records. Do not duplicate the downloaded datasets or their potentially secret-shaped raw data into `rnc-security-audit` source. CP0's generated corpus is deliberately nonfunctional synthetic input.

## Reporting requirements

When the independent harness is integrated, every corpus run must display **both**:

1. **Corpus-native score:** especially Leaky Repo's organic 175-unit/risk/informative accounting, retaining its precise counting rules.
2. **RNC normalized score:** complete/normalized/partial/ambiguous finding reconciliation, precision, recall, false positives, misses and coverage where ground truth permits.

Keep both records side by side with their **counting units, versions, denominators and coverage limitations**. Do not collapse unlike denominators into one misleading percentage. Negative-only Levain corpus does not have a defensible per-line true-negative count.

The external harness already has modular `harness/scoring.py`, `harness/adapters/`, `harness/suites/`, and a controlled `tests/fixtures/stub_scanner.py`. Our CP0 `synthetic_stub.py` supplies a supplemental adapter shape for later crosswalk; it does not replace the harness's own proven scoring paths.

## Gate before accuracy claims

- [ ] Agree normalized adapter mapping between RNC finding IDs/byte offsets and the harness's supported evidence fields.
- [ ] Verify both native and normalized scores on a manufactured oracle/miss/false-positive run.
- [ ] Run the actual pinned external corpora safely, with the harness's integrity checks and corpus-specific counting semantics.
- [ ] Record results separately for RNC Scanner and any Gitleaks/Betterleaks comparator on matching target scopes.

Until then, **no scanner recall/precision claim** follows from CP0's contract tests or language probes.
