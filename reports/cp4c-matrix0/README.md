# CP4C Matrix 0 — reported evidence

This directory contains the redacted Matrix 0 report for the native Windows AMD64
worker/profiler experiment.

- `matrix0-summary.md` — consolidated human report.
- `matrix0-summary.json` — machine-readable summaries, scaling, overhead, phase and
  integrity results.
- `matrix0-runs.csv` — 160 accepted measured runs; `raw_dir` is omitted from this
  tracked copy because the private reports remain under ignored `run/`.

The raw private reports, scanner profiles, exact commands and host-load samples
are retained under `run/reports/cp4c-matrix0/` and are not committed.

Environment is **DEV** (contended developer workstation): Intel Core i7-11375H,
4 physical cores / 8 logical processors, 34,047,959,040 bytes RAM, Windows 11
build 26300. Memory load was 64–71% and free disk was stable at ~116.8 GiB during
sampling. These timings are preliminary and are not release evidence. Experimental
harness code: `cfc1cb001eeb95cfccc57bb41c30ea156988ccb2`
(`feat/cp4c-matrix0`). Historical CP4B results remain unchanged; CP4C raw canonical
findings and source-unit dispositions are identical to the preserved CP4B
reference. Current scoring yields 347/640 filesystem and 120/160 Git targets; the
published 297/640 and 110/160 counts predate the scoring-integrity remediation.

Reproduce the report from retained evidence:

```powershell
python -m harness matrix --experiment cp4c --out-dir run/reports/cp4c-matrix0 --report-only
```
