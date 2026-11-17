# External corpus compatibility — CP0 inventory

The existing [RNC Gitleaks harness](https://github.com/RNC-Solutions-Group/gitleaks/tree/test/scan-harness) is independent grading infrastructure. Its scoring semantics are **not** copied into the production detector.

- Inspected harness revision: `86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f` (10 November 2026).
- External scoring contract schema version: `1`.
- CP0 executed that harness's `harness.truth.from_dict` and `harness.scoring_engine.score_findings` against the CP0 synthetic handoff. This is **integration-path evidence**, not external corpus execution.
- No Levain, Leaky Repo or Prowlbench content was downloaded or scanned in this repository.

The prior CP0 inventory cited `cf8f9153...`; the audit re-inspected the newer revision. Counts and pins below are declared by the harness's own `datasets/manifest.toml` and inventory at that revision, not independently re-counted here.

| Corpus | Pinned source revision | Native truth/counting unit | CP0 integration status |
| --- | --- | --- | --- |
| [Levain FP corpus](https://github.com/levainbot/fp-corpus) | `c130c321aa9046af17a6c876cb97e2ed71397110` (MIT) | 116 negative sections/0 secrets; 45 positive sections/85 planted secrets, including 3 hard sections/3 hard secrets; individual labeled cases | Pinned/declared by external harness; **not executed here** |
| [Leaky Repo](https://github.com/Plazmaz/leaky-repo) | `2e951359cac53addbee56437da3ffb546e3dfe24` (MIT) | Organic `.leaky-meta/secrets.csv`: **175** total = 96 risk + 79 informative, over 44 files | Pinned/declared by external harness; symlink/OOM handling must be honored; **not executed here** |
| Gitleaks fixtures | Harness-owned `datasets/gitleaks-fixtures.toml` | Per-rule and file fixtures | Adapter integration pending; not executed here |
| Prowlbench | Not approved | License status requires separate review | Explicitly excluded; no download, execution or vendoring |

The external harness's manifest contains content hashes, expected totals and provenance records. Do not duplicate downloaded datasets or secret-shaped raw data into `rnc-security-audit` source. CP0's corpus is deliberately nonfunctional synthetic input.

## What CP0 actually proved

| Check | Result | What it does not prove |
| --- | --- | --- |
| Handoff shape | 27 truth items / 25 findings for synthetic-v1; line-addressed | External corpus compatibility |
| External truth loader | Accepted CP0 manifest at schema version 1 | External corpus truth semantics |
| External scoring engine | Perfect 25/25; miss-one 24/25; false-positive 1 FP; v0 13/13 | RNC Scanner accuracy |
| Scope accounting | Blocked/skipped truth items counted separately | Real inaccessible external files |
| Public safety | No raw marker bytes, absolute paths or private locators in handoff | External raw evidence handling |

See [harness-handoff.md](../contracts/harness-handoff.md) for the exact mapping and the test command.

## Reporting requirements

When the independent harness is integrated, every corpus run must display **both**:

1. **Corpus-native score:** Leaky Repo's 175-unit risk/informative accounting, Levain's section/credential accounting, and each corpus's exact counting rules.
2. **RNC normalized score:** complete/normalized/partial/ambiguous finding reconciliation, precision, recall, false positives, misses and coverage where ground truth permits.

Keep both records side by side with their counting units, versions, denominators and coverage limitations. Do not collapse unlike denominators into one percentage. A negative-only corpus has no defensible per-line true-negative count; precision/F1 require an authoritative negative oracle.

## Known compatibility limitation

The external harness scores by file and line. Two findings with the same rule on the same line are ambiguous. CP0's synthetic corpus avoids that collision by placing binary markers on separate lines; the handoff retains byte offsets for a future byte-range extension. CP1 must either define a documented line-composite identity or extend the harness before claiming accuracy on corpora with same-line collisions.

## Gate before external accuracy claims

- [ ] Add an RNC adapter inside the external harness (outside this repository) consuming the CP0 handoff.
- [ ] Decide byte-range versus line-composite matching for same-line collisions.
- [ ] Prepare and verify Levain and Leaky Repo caches with the harness's integrity checks and resource limits.
- [ ] Run both corpora, recording native and normalized scores separately, with per-target coverage and execution exceptions.
- [ ] Obtain a licensing disposition before Prowlbench work.
- [ ] Never publish raw matched values, private paths or unpublished corpus content.

Until then, **no scanner recall/precision claim** follows from CP0's contract tests, synthetic handoff or language benchmarks.
