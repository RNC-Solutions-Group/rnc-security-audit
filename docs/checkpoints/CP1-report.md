# CP1 report — Levain bootstrap and initial scoring

> **Historical checkpoint record.** CP1A superseded the permissive CP1 stub
> matching and produced the first real Gitleaks baseline. The stub figures below
> are retained as the CP1 record and are not comparable to CP1A. See
> [CP1A report](CP1A-report.md).

**Checkpoint:** CP1, executed under explicit authorization.

**Branch:** `test/scan-harness` (orphan; no application-source changes).

**Baseline before this checkpoint:** `20afb2ecfae8cc82295bb1363dcea58e14ed0b83`.

**CP1 implementation commit:** `eeaac59df475cf782241af638f0c2f25daf9ac07`.

**Live Gitleaks execution:** `BLOCKED` — no Gitleaks executable and no Go toolchain were available.

## Outcome

The CP1 harness is implemented in Python 3.13 using only the standard library.
It can fetch and verify the pinned Levain corpus, prepare an offline cache, execute
a user-supplied scanner, parse a Gitleaks-shaped JSON report, score the published
answer key, detect invocation/silent-scan failures with a positive control, and
write redacted JSON and Markdown reports.

The harness was validated end-to-end with a controlled test double. **The stub
numbers are harness-validation evidence, not Gitleaks detection results.** The
generated reports record `gitleaks_execution: BLOCKED`.

## Dataset provenance

| Field | Verified value |
| --- | --- |
| Source | <https://github.com/levainbot/fp-corpus> |
| Revision | `c130c321aa9046af17a6c876cb97e2ed71397110` |
| Tag / date | `v1` / 2026-09-10T18:05:41-04:00 |
| License | MIT, Copyright (c) 2026 Levain (an autonomous AI agent) |
| License SHA-256 | `77cc69213a9c08cbd96f731793cff881a4b40a1d0682c70c70a1846afc700043` |
| Manifest SHA-256 | `c456d2a4943494dea0ac3e5161193d91a77250c700c23e5113de12b2a311af3e` |
| Negative corpus | 116 sections, 866 published lines, 0 credentials, 57 personal-data spans |
| Positive corpus | 45 sections, 368 published lines, 85 credentials (82 core, 3 hard), 8 personal-data spans |

Artifact and derived hashes are pinned in [`datasets/manifest.toml`](../datasets/manifest.toml).
The MIT text and attribution are preserved in
[`datasets/THIRD_PARTY_NOTICES.md`](../datasets/THIRD_PARTY_NOTICES.md). The corpus
itself is fetched only into `datasets/cache/` (ignored) and is not committed.

Prepare verifies canonical Git-blob bytes, so a Windows CRLF checkout and a Linux
LF checkout verify identically. The two true-positive artifacts are decoded from
the upstream `.b64` files and checked against independently pinned digests.

A fresh acquisition into a throwaway cache was also executed against the real
GitHub URL. It cloned `c130c321aa9046af17a6c876cb97e2ed71397110`, verified all 7
pinned repository artifacts plus 2 decoded artifacts, and reproduced the
116/866/0/57 negative and 45/368/85/3/8 positive counts.

## Implemented components

| Path | Purpose |
| --- | --- |
| `harness/manifest.py` | TOML schema validation, full-SHA pinning, enabled/license gates |
| `harness/dataset.py` | `prepare` fetch/verify/decode/cache, offline verification, corruption quarantine, published-count checks |
| `harness/execution.py` | binary resolution and SHA-256, `dir`/`detect` command shapes, timeout, report parsing, failure classification |
| `harness/scoring.py` | positive/negative scoring, TP/FP/FN, duplicates, personal-data exclusion, control check, `NOT_RUN` semantics |
| `harness/report.py` | redacted JSON and Markdown generation, hashes and platform metadata |
| `harness/cli.py` | `prepare`, `verify`, `status`, and `run` commands with stable exit codes |
| `tests/` | 48 offline tests plus a controlled stub and a real-cache integration check |

The scorer counts the negative corpus by section/format (expected credentials are
zero) and the positive corpus by planted credential. `true_negatives` is reported
as `null`, not inferred from line counts. Hard-tier positives are reported
separately from core recall.

## Test evidence

Command:

```sh
python -m unittest discover -s tests -t . -v
```

Result: **48 tests, OK** (~28 s on this host), including:

- manifest rejection tests (disabled entry, short revision, non-MIT license);
- prepare/cache tests against a local Git repository, including offline operation,
  corrupted derived artifacts, a modified source tree, a tampered manifest hash,
  and refresh recovery;
- execution tests for success, non-zero exit, missing report, malformed report,
  timeout, missing binary, and JSON/JSON-lines parsing;
- scoring tests for false positives, personal-data exclusion, duplicates,
  multi-line matching, core/hard recall, control detection, and `NOT_RUN`;
- report tests asserting that no expected secret or control value appears in JSON
  or Markdown;
- CLI tests for exit 0, exit 3 (`NOT_RUN`), and exit 2 (harness error);
- three real-pinned-cache integration tests (published counts, clean negative
  control scan, positive answer-key scoring).

Test host: Windows 11 (10.0.26300), Python 3.13.5, Git 2.45.2.windows.1. The three
real-cache tests skip cleanly when the ignored cache has not been prepared.

Offline verification command:

```sh
python -m harness prepare --offline
```

Result: cache verified, 116/866/0/57 negative and 45/368/85/3 positive counts
confirmed.

## Demonstrated stub behavior

The committed reports were produced with `--scanner-kind stub`. The stub is
`tests/fixtures/stub_scanner.py`, a controlled Gitleaks-shaped test double.

| Run | Mode | Result |
| --- | --- | --- |
| [`CP1-stub-validation`](../reports/CP1-stub-validation.md) | all-lines stress double, both corpora | Negative: 833 unexpected findings, 49 personal-data matches, 115/116 sections tripped. Positive: 85/85 credentials found (82/82 core, 3/3 hard), 259 unexpected, 15 duplicates. |
| [`CP1-stub-negative-clean`](../reports/CP1-stub-negative-clean.md) | control-only, negative corpus | 0 false positives, control reported, clean |

The all-lines double deliberately reports ordinary lines, so its precision numbers
are meaningless as a scanner score. Its purpose is to exercise classification,
duplicate accounting, multi-line matching, and control separation. The negative
control-only report demonstrates the distinction between a witnessed clean zero
and a silent scan.

Committed report hashes (SHA-256 of the generated LF files on this host):

| File | SHA-256 |
| --- | --- |
| `CP1-stub-validation.json` | `59d8ce1619f69d7728a79f406e5ab0a8f5ef7efd88fa995d2e1eedff72c85498` |
| `CP1-stub-validation.md` | `2a8c2c5d31ca43f62a71c358be4ffcf71915f92da8dd48e1892c450cdee4a545` |
| `CP1-stub-negative-clean.json` | `a960516422f9be3438cea0c0eeabfc2417b383815d1585e30f26480abcac7757` |
| `CP1-stub-negative-clean.md` | `74f8f88a363aaa0f1e09b12dea70bdec767378481e3f7935839f0e3669655bb5` |

Automated tests also prove that a silent stub produces `NOT_RUN_UNSCORABLE`
(never a zero score), a non-zero exit produces `INVOCATION_FAILED`, a missing
report produces `REPORT_MISSING`, malformed JSON produces `REPORT_INVALID`, and an
over-time scanner produces `TIMEOUT`.

## Redaction check

Every committed report was scanned for all 85 expected positive values, the
personal-data spans, and the three control values. **No raw value was found.**
Reports contain section names, line numbers, rule IDs (when supplied), hashes,
counts, and platform metadata only. Raw scanner output is never written by default;
`--raw-artifacts-dir` is an explicit opt-in for an ignored location.

## What remains untested / limitations

- **No actual Gitleaks invocation.** `gitleaks` is not on `PATH`; no Go toolchain
  is installed; no built binary was found under `C:\Dev\gitleaks`.
- The Gitleaks command shape (`dir <target> --report-format json --report-path ... --no-banner`)
  and accepted exit codes (0 and 1) are based on documented Gitleaks behavior but
  have not been executed against a real binary in this environment.
- The parser accepts an array, a wrapper object with `findings`/`leaks`/`results`,
  and JSON-lines. Real Gitleaks field emission has not been observed yet.
- No Gitleaks configuration was supplied or hashed in these runs.
- The corpus is synthetic and finite; it is not a measure of real-world
  prevalence. Hard-tier secrets are reported separately and excluded from core
  recall.
- Testing ran on Windows with Python 3.13.5. Other platforms are expected to work
  but were not exercised here.
- Functional conformance, performance, and Go race/stability lanes are **not**
  part of CP1 and were not run.
- The `.cmd`/`.sh` stub wrappers are test fixtures, not Gitleaks replacements.

## Definition-of-done assessment

| Requirement | Status |
| --- | --- |
| Source and license verification recorded | Met |
| Revision and checksums pinned; entry enabled only after verification | Met |
| Prepare/cache/verify works and detects altered inputs | Met (automated tests) |
| Runner/scorer automated assertions, including error paths | Met (48 tests) |
| At least one actual scanner run documented or clearly marked BLOCKED | Met via `BLOCKED` + controlled stub validation |
| Report lists TP/FP/FN/TN and `NOT_RUN` where appropriate | Met; TN explicitly `null` |
| All changes on `test/scan-harness` | Met |

## Recommended next action

1. Provide a resolved Gitleaks executable and its full 40-character source SHA, or
   authorize a Go toolchain so a pinned revision can be built in a disposable
   checkout outside this harness.
2. Confirm the target CLI shape/version and the configuration under test.
3. Run both corpora through the real binary, then review the first genuine
   detection report and any out-of-scope positives.
4. Do **not** begin CP2 without separate authorization.

**Stop: CP1 complete. Awaiting review and explicit CP2 authorization.**
