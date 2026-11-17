# Report and evidence lifecycle

This note records the intended roles of tracked and ignored benchmark evidence.
It does not authorise deletion, rewriting, or migration of existing historical
reports.

## Current inventory

At CP-HI1:

- tracked files under `reports/`: **204 files, 63.2 MiB**;
- all tracked files: **384 files, 66.3 MiB**;
- Git object store: **6.19 MiB loose plus 2.78 MiB packed** at the time of
  measurement;
- the largest tracked report is a 4.28 MiB per-run JSON experiment;
- the archived pre-scoring-fix zip is 2.69 MiB;
- a current full baseline JSON is typically 1.5-3.3 MiB.

The repository is not currently dominated by Git object growth, but the tracked
report payload is dominated by full per-run JSON. Repeated full baselines will
grow linearly unless a retention boundary is chosen.

## Roles

| Location | Role | Retention |
| --- | --- | --- |
| `reports/baselines-20261115/` | Current-scoring reference baselines and combined index | Immutable historical evidence; do not regenerate in place |
| `reports/archive/pre-scoring-fix/` | Hash-indexed archive of pre-remediation reports | Immutable; do not rewrite |
| Other `reports/cp*/`, `reports/baseline-*/` | Historical checkpoint evidence | Preserve at original paths |
| `reports/detection-gaps/` | Derived analysis over the pinned current-scoring reports | Regenerable; published as a complete set with `publication.json` |
| `reports/cp4c-matrix0/` | DEV Matrix 0 evidence | Preserve; not a release-timing baseline |
| `run/reports/` | Operator-local raw/retained scanner reports used by analysis | Git-ignored; may be large |
| `run/detection-gaps/` | Raw controlled reproductions and investigation work | Git-ignored; not a publication source |
| `work/` | Temporary run-owned work | Disposable; never commit |

## Rules

1. **Historical reports are immutable.** A new scanner run writes a new report.
   It does not overwrite a historical result or change the scoring epoch.
2. **Current baselines are selected, not fabricated.** Missing or mismatched
   operator artifacts are `BLOCKED`; raw evidence is never silently substituted.
3. **Derived reports are versioned.** Detection-gap summaries carry
   `analysis_version`; a material schema/classification change bumps it and
   records a migration note.
4. **Raw findings stay ignored.** Tracked reports may contain target IDs, source
   locators, redacted structural context and digests. They may not contain raw
   credential values or private keys.
5. **A report set is complete or explicitly incomplete.** Detection-gap output
   uses `publication.json` (`IN_PROGRESS`/`COMPLETE` plus file hashes). Experiment
   reports use atomic per-file writes; a failed report write is reported as a
   limitation or failure, not a successful run.
6. **Frozen inputs are pinned.** Detection-gap analysis uses
   `analysis-inputs.json`; report hashes and build identities are verified before
   any claim is made.
7. **No automatic cleanup.** Only the run-owned workspace and run-created
   containers are removed. Registered images/executables, unrelated containers,
   and historical files are never deleted.

## Future bulk-artifact architecture (proposal only)

No migration is approved or performed by CP-HI1. If report volume becomes a
problem, the recommended future design is:

- keep a small tracked index (run identity, artifact hashes, metrics, report hash)
  for every baseline;
- publish full JSON and raw finding bundles as release assets or an external
  evidence store;
- preserve existing report paths and hashes as immutable references;
- verify downloaded bundles against the tracked index before analysis;
- keep `reports/detection-gaps/` as a derived, versioned analysis of the pinned
  index rather than a copy of the raw reports.

This requires an explicit operator retention decision and a migration package.
It is not part of CP-HI1.
