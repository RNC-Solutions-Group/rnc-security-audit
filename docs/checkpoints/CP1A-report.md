# CP1A report — scoring integrity and live Gitleaks baseline

**Checkpoint:** CP1A, executed under explicit authorization.

**Branch:** `test/scan-harness` (orphan).

**Starting HEAD:** `299b1ab718cd05e4ad8c3c9abefe347f1df5791f`.

**Scope:** correct the three CP1 review findings, build the pinned Gitleaks baseline,
and record the first genuine detection baseline. CP2 was not started.

## Outcome

The three review findings are corrected:

1. **Scoring integrity.** Matching is now explicit and conservative: only complete
   or supported normalized evidence is credited. Line-only findings, partial
   matches, and ambiguous findings never become true positives. One finding can
   satisfy at most one credential.
2. **Pinned acquisition.** A fresh clone now explicitly detaches at the pinned
   immutable commit even when the upstream default branch has advanced.
3. **Positive control.** Encountering the control file is no longer enough. At
   least one expected control credential must appear in structured finding
   evidence. Raw echoed text is diagnostic only.

A real Gitleaks executable was built from the pinned `5f6ec56` source and run
against both Levain corpora with the built-in default configuration. The
corrected oracle reports 47/85 true positives, 0 unexpected findings, 1 partial
match, 2 duplicate findings, and 3 negative-corpus false positives.

**The CP1 stub reports are historical.** They used the superseded permissive
matcher; their 85/85 stub figure is not comparable to CP1A. They are not Gitleaks
results.

## A. Detection matching and scoring

New module [`harness/matching.py`](../harness/matching.py) classifies evidence as:

| Classification | Meaning | Credited |
| --- | --- | --- |
| Complete | Evidence equals the expected value byte-for-byte | Yes |
| Normalized | Equal after CRLF/LF, outer whitespace, one matching quote pair, or NFC normalization | Yes |
| Partial | One normalized value contains the other as a proper substring | No |
| Ambiguous | One finding is eligible for more than one expected credential | No |
| Miss | No eligible evidence | No |

Additional rules:

- The finding's `Secret` and `Match` fields are the only evidence; line numbers
  are never used to infer a detection.
- Findings are attributed by generated corpus filename and can only satisfy
  expected credentials in that same section.
- One finding is assigned to at most one credential. Eligible matches to multiple
  credentials are reported as ambiguous and credit neither.
- Extra findings for an already-credited credential are duplicates, not new TPs.
- Partial and ambiguous findings are counted as false positives for strict
  precision, but are broken out separately so the distinction is visible.
- Multiline findings are supported through newline normalization and exact
  multiline evidence.
- Corpus values and the frozen answer key were not changed.

Regression tests cover misleading partial matches, line-only attribution,
duplicate findings, overlapping credentials, one finding containing two expected
values, quote/newline normalization, multiline evidence, and ambiguous
multi-credential findings.

## B. Dataset acquisition

[`harness/dataset.py`](../harness/dataset.py) now performs `_checkout(source,
pinned_revision)` immediately after a fresh clone. Previously, a clone that
followed an advanced default branch could fail the pinned-revision check instead
of checking out the pin.

A new local Git fixture test commits a newer revision on the default branch after
the manifest pin, then asserts that `prepare`:

- checks out the pinned commit, not the advanced default branch;
- does not leave the newer revision's files in the checkout;
- still loads the pinned corpus counts.

Existing SHA-256 verification, offline operation, derived-artifact repair, and
corruption quarantine behavior are retained and still tested.

## C. Positive control

[`harness/control.py`](../harness/control.py) and
[`harness/model.py`](../harness/model.py) now record:

- `reported` — at least one expected control credential was detected in a
  structured finding;
- `file_encountered` — a finding named the control file;
- `findings_on_file`, `credential_findings`, `unmatched_findings`;
- `kinds_detected` versus `kinds_echoed`;
- diagnostic notes explaining a failed control.

An arbitrary finding on `000-control.log` does **not** validate the scan. A raw
control value echoed in stdout/stderr does **not** validate the scan. The PEM
control is accepted only when the finding evidence contains both the header and
the end marker.

Regression tests cover a valid AWS control detection, an arbitrary control-file
finding (not reported), raw echo only (not reported), a full PEM block
(detected), and a missing control file.

## Source and binary identity

| Field | Value |
| --- | --- |
| Source repository | `https://github.com/RNC-Solutions-Group/gitleaks` |
| Pinned source revision | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` |
| Source `go.mod` | `go 1.24.11` |
| Disposable checkout | `C:\Dev\gitleaks-cp1a-build\source` (clean after build) |
| Go toolchain | `go1.27.3 windows/amd64`, `GOTOOLCHAIN=local` |
| Build command | `go build -mod=readonly -trimpath -buildvcs=true -ldflags "-X=github.com/zricethezav/gitleaks/v8/version.Version=v8.0.0-20261023204459-5f6ec56cfa6f" -o C:\Dev\gitleaks-cp1a-build\bin\gitleaks.exe .` |
| Build exit | `0` (initial full build and metadata rebuild) |
| Binary SHA-256 | `54dd670dda5f6a84b9b195a2fab33a766ed5976b60dbd73e4b15eb6ffc2aff8a` |
| Binary size | 24,981,504 bytes |
| Executable version | `v8.0.0-20261023204459-5f6ec56cfa6f` |
| Embedded VCS | `vcs.revision=5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c`, `vcs.time=2026-10-23T20:44:59Z`, `vcs.modified=false` |
| Embedded module | `github.com/zricethezav/gitleaks/v8@v8.0.0-20261023204459-5f6ec56cfa6f` |

The binary, build checkout, module cache, and downloaded corpus are outside the
harness repository or in ignored cache paths. No application source or history was
modified by this checkpoint.

During final verification, the sibling application worktree showed unrelated
changes under `_assessment/` that this checkpoint did not create. They were left
untouched; only `test/scan-harness` was written.

Full build details are in
[`reports/CP1A-build-metadata.json`](../reports/CP1A-build-metadata.json).

## CLI and report contract

`gitleaks --help` exposes: `completion`, `dir`, `git`, `stdin`, `version`.
The validated invocation is:

```text
gitleaks.exe dir <corpus-dir> --report-format json --report-path <report> --no-banner
```

Observed behavior:

- Report is a JSON array of finding objects.
- Observed finding fields include `RuleID`, `File`, `StartLine`, `EndLine`,
  `StartColumn`, `EndColumn`, `Secret`, `Match`, `Entropy`, `Fingerprint`, and
  metadata fields.
- Exit code `1` when findings exist; exit code `0` for a clean scan.
- `--no-banner`, `--report-format json`, and `--report-path` all worked.
- No `--config` was supplied; the built-in default config was used. No
  `GITLEAKS_CONFIG` or `GITLEAKS_CONFIG_TOML` was set.

## Test evidence

```sh
python -m unittest discover -s tests -t . -v
```

Result: **60 tests, OK** (about 38 s on this host).

```sh
python -m harness prepare --offline
```

Result: pinned cache verified; negative 116/866/0/57 and positive 45/368/85/3/8
counts reproduced.

```sh
python -m harness run --gitleaks C:\Dev\gitleaks-cp1a-build\bin\gitleaks.exe \
  --scanner-kind gitleaks \
  --gitleaks-source-revision 5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c \
  --corpus both --out-dir reports --name CP1A-gitleaks-baseline
```

Result: both runs `COMPLETED`; harness exit `0`. See
[`CP1A-gitleaks-baseline.md`](../reports/CP1A-gitleaks-baseline.md) and
[`CP1A-gitleaks-baseline.json`](../reports/CP1A-gitleaks-baseline.json).

Committed evidence hashes (SHA-256):

| File | SHA-256 |
| --- | --- |
| `CP1A-gitleaks-baseline.json` | `5776e23d5b07d198feb656072773eb4b06468181b569e506c886829e2c792cdb` |
| `CP1A-gitleaks-baseline.md` | `d6536f35d9072e7810b87562494edcd2e1064cb2d61b959304e15e84e2d51ea7` |
| `CP1A-build-metadata.json` | `b45f6901645738f2724d1d22306ec5cbea487f695a858002cc2bd70e7e2c1bc6` |

## Genuine detection baseline

**Configuration:** built-in default (no config file). **Counting units:** negative
corpus by section/format; positive corpus by planted credential.

### Negative corpus — precision

| Metric | Value |
| --- | --- |
| Sections scanned | 116 |
| Lines scanned | 866 |
| Findings | 3 |
| False positives | 3 |
| Duplicates | 0 |
| Personal-data matches excluded | 0 |
| Sections tripped | 1 (`tailscale and wireguard status`) |
| Rule | `generic-api-key` (lines 4, 5, 8) |
| Clean | no |

The three negative-corpus findings are real scanner output on a corpus that
claims no credentials. They were not reclassified or allowlisted.

### Positive corpus — recall

| Metric | Value |
| --- | --- |
| Expected credentials | 85 (82 core, 3 hard) |
| True positives | 47 |
| False negatives | 38 |
| Core recall | 47/82 = 57.32% |
| Hard recall | 0/3 = 0.00% |
| Overall recall | 47/85 = 55.29% |
| Unexpected findings | 0 |
| Partial matches (not credited) | 1 |
| Ambiguous findings (not credited) | 0 |
| False positives (strict) | 1 (the partial match) |
| Duplicate findings | 2 |
| Findings without extracted evidence | 0 |
| Sections with a true positive | 29 |

Match classification:

| Class | Count |
| --- | --- |
| Complete | 46 |
| Normalized | 1 (`private_key_pem`, CRLF/LF normalization) |
| Partial | 1 |
| Ambiguous | 0 |
| Miss | 38 |

The single partial match is the `openai_project_key` case
`edge-openai-project-key-ends-in-hyphen`: a `generic-api-key` finding contains the
expected value but is not an exact extraction. It is not credited.

### Cases outside the configured detection scope

Scope annotation is separate from TP/FN scoring and uses a conservative manual
mapping to the pinned default rule IDs. It does not change the answer key.

| Scope class | Missed cases |
| --- | --- |
| Out of scope | 15 |
| Unknown | 7 |
| In scope but missed | 16 |

Out-of-scope examples: three hard-tier cases, wallet seed phrases, payment-card
numbers, email, Discord webhook, Google OAuth client secret, Resend, Supabase,
Tailscale, xAI, and the paired AWS secret key. Unknown cases are URL-password and
bearer-token shapes where a generic or adjacent rule might apply. The full lists
are in the generated report.

### Positive control

Both runs detected the AWS and GitHub control credentials in structured findings
(2 of 3 planted; the synthetic PEM body is not detected). `file_encountered` was
true, `credential_findings` was 2, and no unmatched control-file findings were
reported. Control values echoed in raw output are recorded as diagnostics only.

## Limitations and unresolved findings

- The baseline is one pinned revision plus the built-in default config. No custom
  configuration, version matrix, or other corpus was tested.
- Scope classification is a manual annotation, not scanner output. It is
  conservative and may under- or over-state coverage at the edges.
- 38 positives are missed. Fifteen are annotated out of scope; seven are unknown;
  sixteen are in scope. The in-scope misses were not individually root-caused
  (possible allowlists, entropy gates, placeholder words, or extraction limits).
  They must not be relabeled as successes.
- Three negative-corpus false positives from `generic-api-key` remain. They were
  not investigated or suppressed.
- The corpus is synthetic and finite; it is not a real-world prevalence measure.
- Windows-only execution; no functional-conformance, performance, or Go
  race/stability lane was run.
- CP1's stub reports use the superseded permissive matcher and are historical
  only.

## CP2 readiness disposition

**Ready for review, not automatic execution.** CP1A now provides a real pinned
binary, a validated CLI/report contract, corrected scoring, and a genuine
baseline. CP2 functional-conformance work can be planned against this baseline
after owner acceptance. Detection misses and the negative false positives should
remain open findings for later analysis, not blockers to CP2's separate CLI lane.

**Do not begin CP2 without a separate authorization.**
