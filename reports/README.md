# Reports

Only redacted, reproducible reports are committed here. Raw scanner output,
matched values, and temporary scan directories are never committed; they are
written only under ignored paths (`reports/raw/`, `reports/local/`) when a caller
explicitly opts in.

| Report | Scanner | Purpose |
| --- | --- | --- |
| [`baseline-20261112/`](baseline-20261112/README.md) | Gitleaks / RNC / Betterleaks (blocked) | **Authoritative CP10 baseline:** source-built native/Docker experiments, RNC Lab canonical and load testing, consolidated index, and explicit blocked cells |
| [`cp5d1/`](cp5d1/) | RNC / Gitleaks / Betterleaks | CP5D.1 rename-lineage hardening, exact negative identities, official 184/89 proposal validation, and retained rescoring |
| [`cp5d/`](cp5d/) | RNC / Gitleaks / Betterleaks | CP5D lineage-integrity fixes, exact-value negative design, false-positive accounting, and proposed oracle migration |
| [`cp5c/`](cp5c/) | RNC / Gitleaks / Betterleaks | CP5C historical attribution corrections, 19-finding reconciliation, and cross-scanner before/after rescoring |
| [`rnc-cp5/`](rnc-cp5/) | RNC Scanner `93b4dda` | Native + Docker filesystem/history experiment, ruleset provenance, and structured-evidence evidence |
| [`history/`](history/) | Gitleaks / Betterleaks | Offline rescoring of retained CP3 history findings against the owner-approved source oracle |
| [`cp3/`](cp3/) | Gitleaks / Betterleaks | Source-commit experiment reports, performance, and DEFAULT/CUSTOM isolation evidence |
| [`cp2/comparative.md`](cp2/comparative.md) | Gitleaks + Betterleaks | Historical CP2 multi-scanner comparison; comparison workflow retired in CP3 |
| [`cp2/performance.md`](cp2/performance.md) | Gitleaks + Betterleaks | Historical CP2 performance comparison |
| [`cp1e/cp1e-baseline.md`](cp1e/cp1e-baseline.md) | Gitleaks | Historical CP1E four-suite evidence |
| [`cp1e/synthetic-scoring-validation.md`](cp1e/synthetic-scoring-validation.md) | synthetic | 31-case finding-level scoring proof |
| [`cp1e/history-accountability.md`](cp1e/history-accountability.md) | Gitleaks + synthetic | Leaky history scope and controlled-history results |
| [`cp1e/performance.md`](cp1e/performance.md) | Windows + Docker AMD64/ARM64 | Real repeated performance measurements |
| [`cp1d/cp1d-baseline.md`](cp1d/cp1d-baseline.md) | Windows + Docker AMD64/ARM64 | Historical CP1D three-product report |
| [`cp1d/cp1d-comparison.md`](cp1d/cp1d-comparison.md) | Windows + Docker AMD64/ARM64 | Historical normalized baseline comparison |
| [`cp1d/leaky-truth-reconciliation.json`](cp1d/leaky-truth-reconciliation.json) | — | Historical Leaky Repo 175-unit reconciliation |
| [`cp1d/synthetic-scoring-validation.md`](cp1d/synthetic-scoring-validation.md) | synthetic | Historical 25-case CP1D proof |
| [`cp1c/cp1c-both.md`](cp1c/cp1c-both.md) | Gitleaks executable + Docker | Historical CP1C all-suite matrix |
| [`cp1c/cp1c-all-builds.md`](cp1c/cp1c-all-builds.md) | Gitleaks | Historical CP1C seven-platform build catalog evidence |
| [`consolidated/cp1b-both.md`](consolidated/cp1b-both.md) | executable + Docker | Historical CP1B matrix |
| [`consolidated/cp1b-executable.md`](consolidated/cp1b-executable.md) | executable | Historical CP1B executable-only matrix |
| [`consolidated/cp1b-docker.md`](consolidated/cp1b-docker.md) | Docker | Historical CP1B Docker-only matrix |
| [`consolidated/consolidated-5f6ec56.md`](consolidated/consolidated-5f6ec56.md) | executable + Docker | Initial consolidation report; historical |
| [`CP1A-gitleaks-baseline.md`](CP1A-gitleaks-baseline.md) | pinned Gitleaks `5f6ec56` | First genuine detection baseline; default config |
| [`CP1A-build-metadata.json`](CP1A-build-metadata.json) | — | Source, toolchain, build, binary, and CLI identity |
| [`CP1-stub-validation.md`](CP1-stub-validation.md) | stub (`all-lines`) | Historical CP1 helper-validation report |
| [`CP1-stub-negative-clean.md`](CP1-stub-negative-clean.md) | stub (`control-only`) | Historical CP1 witnessed-clean report |

**CP5D.1:** Rename identity is carried through the rooted lineage graph instead of
a renamed-path exact-line fallback. The three proposed negatives now carry exact
value digests (`PNM-001`/`PNM-002`/`PNJ-001`), and a digest-bearing negative matches
only that extraction. The proposed 184/89 document validates through the official
proposed-oracle profile, including source validation of all 184 records. Retained
RNC/Gitleaks/Betterleaks classifications are unchanged; the proposed RNC accounting
is 21 TP, 21 duplicates, 7 informative, 12 FP alerts, 4 unique nonsecret
exposures, 0 pending. The migration is not applied.

**CP5D:** The history matcher now roots value-preserving edits in the existing
source lineage, closing the local parent/child fallback that could attribute a
reintroduced value to the original occurrence. Exact-value negative references can
target a nonsecret extraction (`function(err`) on an informative/positive line
without marking the whole line negative. The four CP5C metadata-negative proposals
consolidate to two non-overlapping records at `9f1468c`; with one exact-value
Salesforce record, the proposed migration is 86→89 reviewed negatives and 181→184
total records while the 65/53 positive denominators remain unchanged. No oracle
change was applied. Current RNC remains 21/65 occurrences, 19/53 unique groups,
1 verified FP alert, 1 unique nonsecret exposure, and 11 pending alerts.

**CP5C:** The historical matcher now attributes unchanged-line source movement to
the original approved occurrence without double-crediting, uses the observed
snapshot for removed negative references, and requires expected-value identity for
informative/negative references. All retained RNC, Gitleaks, and Betterleaks
history evidence was rescored offline; no scanner was rerun. RNC remains 21/65
occurrences and 19/53 unique groups, with the original 19 unmatched observations
reconciled as 8 duplicates, 1 verified false positive, and 10 pending. Proposed
metadata negatives are recorded but not applied to the owner-approved oracle.

**CP5:** RNC Scanner `93b4dda` was built from the pinned source and a disposable
checkout, then exercised on Leaky Repo filesystem and Git-history sources with
native Windows AMD64 and Docker Linux AMD64 products. The report records the
37-rule / 22-family DEFAULT bundle digest, 166 inspected historical revisions
scoped to `HEAD` (25 commits), native/Docker classification parity, 61 observed
historical findings, and the existing owner-approved oracle score. No scoring
implementation, oracle, scanner source, or default rule was changed.

**CP3:** Each report is one scanner source commit and one experiment. Native and
Docker products are built from a disposable checkout; source HEAD is verified;
DEFAULT uses bundled rules. At CP3, Leaky history executed as
`COMPLETED_UNSCORED`; it is now rescored offline against the owner-approved source
oracle in [`history/`](history/). Run-owned images/checkouts are removed.
Cross-scanner comparison is not part of the harness. See the
[CP3 report](../docs/checkpoints/CP3-report.md).

**CP2 (historical):** Gitleaks and Betterleaks v1.8.1 were executed on Windows
AMD64, Docker Linux AMD64, and emulated Docker Linux ARM64. Betterleaks found
37/175 Leaky Repo truth items versus Gitleaks 22/175; all 22 Gitleaks hits were a
subset. Levain F1 was effectively tied (69.57 vs 69.63) with different
precision/recall. Leaky history truth was BLOCKED at CP2 (historical,
pre-integration). The comparison workflow was retired in CP3 but this evidence is
preserved.

**CP1E:** all three products executed Gitleaks fixtures, Levain, Leaky Repo
filesystem dual scoring, Leaky Repo history observation, and the controlled
synthetic Git-history suite. Filesystem Leaky remains 22/175 legacy / 22 matched
rich with 20 value-verified and 2 line-only identities. Leaky history truth was
BLOCKED at CP1E (historical, pre-integration; 26 observations across 25 commits);
it is now rescored offline. The controlled history corpus is
COMPLETE (3/3 unique, 5/5 occurrences). Synthetic scoring is 31/31 at 100%.
Performance is separate: native 0.675 s, Docker AMD64 2.129 s, emulated Docker
ARM64 5.377 s median on 610 files. Full per-finding artifacts remain outside Git.

**CP1D:** Active products are Windows AMD64 native, Docker Linux AMD64, and
Docker Linux ARM64 (emulated). All three executed Gitleaks fixtures, Levain, and
Leaky Repo. Leaky Repo reports the legacy upstream count score and the RNC
line-level rich score separately. The synthetic validation reports 25/25 cases
and 100.0% scoring accuracy. CP1C build-only macOS/native Linux evidence and the
Go-test mapping are historical, not active.

**Historical note:** the CP1 stub reports were generated before the CP1A
matching correction. Their permissive substring matching credited partial
findings and is superseded; their 85/85 stub figure is not comparable to the
CP1A baseline. They are not Gitleaks results. See
[`docs/checkpoints/CP1A-report.md`](../docs/checkpoints/CP1A-report.md) for the
corrected scoring rules and the genuine baseline.
