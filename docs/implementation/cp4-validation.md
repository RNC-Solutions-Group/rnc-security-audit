# CP4 validation — detection expansion and Git history

> **Status:** **READY FOR OPERATOR REVIEW.** Implementation, local regression,
> CP0-CP3 compatibility, Git-history acquisition and pushed-branch CI are
> complete. Provider-format recognition is not proof of an active, authorized,
> complete or non-revoked credential.
>
> **CP4A follow-on:** the catalog was subsequently bumped to `2026.11.4` to add
> an optional database-password `component_extractor` and note. The CP4
> detection findings, rule identities and historical evidence below are
> unchanged. See [CP4A hardening](cp4a-hardening.md).
>
> **CP4B follow-on:** the five generic rule families were subsequently updated
> to `2026.11.5` and the ruleset to `2026.11.5` for contextual assignment
> validation. Provider, private-key and database findings remain unchanged;
> historical CP4 evidence below is preserved. See
> [CP4B contextual validation](cp4b-contextual-validation.md).

## Repository state

| Field | Value |
| --- | --- |
| Branch | `feat/cp4` |
| Starting baseline | `5391d8457ea091c45733920078a7f714ec61f678` |
| Final implementation head | `c442f3d5e801022b74ee0ac4c5651dc1ae9c2856` (CI-validated) |
| Final documentation head | The `docs(cp4)` evidence commit after CI; see PR |
| Pull request | [PR #11](https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/11) |
| Target | `main`; `feat/cp4` is based on the operator-merged CP3 baseline |
| Merge state at evidence head | OPEN, MERGEABLE, `CLEAN`; all checks pass |
| Merge | No merge performed by the developer |

CP3's synthetic v0/v1 truth, provider truth and one-to-one comparative evidence
are preserved. No independent truth was edited to make CP4 pass.

## Deliverables

| Deliverable | Location | State |
| --- | --- | --- |
| Generic assignment/authorization extraction | `rules/rnc-providers-v1.json`, `crates/rnc-core/src/validate.rs` | Implemented |
| Multi-alternative value capture | `value_capture_groups` in rule schema/backend | Implemented |
| Escaped/base64/PGP private-key handling | rules and validators | Implemented |
| Eight new documented provider families | rules and validators | Implemented; uncertainty documented |
| Read-only Git-history adapter | `crates/rnc-core/src/git.rs`, engine/CLI integration | Implemented |
| Generic/private/provider tests | `crates/rnc-core/tests/cp4_detection.rs` | 6 tests |
| Git-history tests | `crates/rnc-core/tests/cp4_git_history.rs` | 7 tests |
| CLI history tests | `crates/rnc-cli/tests/cp4_cli.rs` | 2 tests |
| Documentation | CP4 catalog, generic, private-key, Git-history and ADR-016 | Updated |
| CI workflow | `.github/workflows/cp4-validation.yml` | Added |

No benchmark, comparative scoring utility, competitor adapter or
harness-specific fixture was added. Formal performance measurement remains with
the independent harness.

## Rule catalog

- Provider schema `0.2.0`; ruleset `2026.11.3`.
- **37 rules / 22 families**; digest
  `sha256:4956b11f44090d472aa9254ed6489cf3dcf24e01816d724a07123703e6e1dc7e`.
- Every rule has a finite match bound and declared candidate bound.
- `value_capture_groups` lets one rule extract mutually exclusive quoted/unquoted
  values without including delimiters in the finding. The existing
  `capture_group` remains the default.
- Existing CP3 rule identities were preserved. The generic CP3 rule remains
  `generic-secret-assignment`; CP4 adds context-specific generic families.

## Local regression matrix

Environment: Windows, Rust 1.85.0, locked workspace.

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS |
| `cargo test --workspace --all-targets --locked` | PASS; see counts below |
| `cargo build --release --workspace --locked` | PASS |
| CP0 Python contracts | PASS (74 tests) |
| CP1 Python synthetic rules | PASS (5 tests) |
| CP3 Python catalog/scoring/security | PASS (55 tests) |
| CP3 24-case provider integration | PASS, all datasets/modes/strategies |
| CP3 Tier 2 | 27/27 |
| CP3 Tier 3 held out | 15/15 |
| CP3 independent challenge | 14/14 |
| CP4 generic/private/provider | 6/6 test functions |
| CP4 Git history | 7/7 test functions |
| CLI history | 2/2 test functions |

The Rust suite includes 110 tests on Windows after CP4 (95 before). Linux CI
includes the platform-gated tests: **121 Rust tests** passed in the CP4 quality
and cross-platform Linux jobs.

### Pushed-branch CI evidence

All required checks for PR #11 at `c442f3d` are green.

| Workflow | Run | Result |
| --- | --- | --- |
| CP4 quality/detection/history/filesystem | [43125714689](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43125714689) | Success, all 6 jobs |
| CP0 contracts/corpus | [43125714678](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43125714678) | Success |
| CP1 Rust quality/integration | [43125714767](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43125714767) | Success |
| CP2 engine/policy/classification | [43125714853](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43125714853) | Success |
| CP3 provider catalog and accuracy | [43125714941](https://github.com/RNC-Solutions-Group/rnc-security-audit/actions/runs/43125714941) | Success, including 88-profile benchmark regression |

CP4 sanitized evidence artifact: `cp4-validation-evidence`, ID `13902991923`,
digest `sha256:5e431f82b8051baf07d7d1087c3b542f580d8374ab5a191999de1fcce5a038a9`.

The CP3 benchmark initially exposed one over-broad generic behavior: a bare
`secret = ...` assignment duplicated the Terraform AWS secret finding. CP4
changed the generic name rule to require a qualified form such as
`secret_key`, `secret_token`, `client_secret`, `jwt_secret` or
`session_secret`; it did not change the benchmark expectation. The 88-profile
benchmark then passed without changing expected counts.

### Differential correctness

For generic values, escaped/base64/PGP private keys and all eight new provider
families, the same canonical findings (unit, rule, byte span, evidence digest,
finding ID, confidence and validation) are required across:

- `whole` and `stream`;
- `regex`, `regexset`, `prefilter` and `auto`.

The generic streaming boundary test places a credential across the 65,550-byte
overlap boundary and requires the same finding identity from whole and stream
paths.

### Git-history regression coverage

The committed Rust fixtures create repositories locally and cover:

- clean initial commit;
- credential introduced, modified and removed;
- repeated credential in different paths/commits;
- rename (delete + add under disabled rename detection);
- merge commit and branch-commit occurrences;
- detached HEAD and bare repository;
- submodule gitlink explicitly uninspected;
- binary/non-UTF-8 blob with exact byte offsets;
- empty repository, commit bound, shallow clone and corrupt/missing object;
- pre-scan block before blob read and post-scan exemption through the CLI;
- read-only repository digest, `HEAD` and `git status` checks;
- whole/stream and all four strategies.

## Security checks

- No real credential, token or private key is committed. Synthetic test values
  are generated in code; the PKCS#8 fixture is deliberately inconsistent and not
  a usable key.
- No provider API, token redemption or network validation occurs.
- Generic values are plausible-only; private-key and provider structural checks
  do not establish operational validity.
- Git commands are constructed without a shell; output is bounded; timeout
  kills the child; shallow, partial and alternate-object repositories are
  rejected.
- Missing/corrupt objects and limit exhaustion are fatal/incomplete, never
  `CLEAN`.
- Private reports remain outside the inspected repository root and contain the
  only repository path/locator detail. Sanitized reports contain scope/counts
  only.
- Existing Windows platform-hardening issues #7-#9 remain separately tracked;
  CP4 does not modify their status.

## Known limitations

- Git-history mode requires a local `git` executable and is therefore a runtime
  dependency, not a self-contained object reader.
- Default history is sorted by commit/path changed revisions, not full snapshots
  of every file in every commit. Unchanged content in a later commit is not a new
  occurrence.
- Reflogs and unreachable objects are excluded.
- Git revision ranges are not accepted; use explicit refs/commits.
- Submodules are explicitly uninspected; they are not traversed.
- Shallow and partial/promisor clones are rejected.
- Git object alternates are rejected.
- The history adapter cannot sandbox a hostile local Git executable; it controls
  arguments, environment and resource use.
- Generic assignment context can still produce low-confidence false positives.
- OpenAI, Perplexity, Groq, xAI and Doppler rules are prefix/example/structure
  based and remain experimental; official documentation does not provide a
  complete normative token grammar for several of them.
- Mailgun, Pinecone, Databricks, Vault, Terraform, Airtable and Azure SAS do not
  receive provider-specific rules because the vendor documentation does not
  support a reliable offline signature.
- No CP4 benchmark or competitor score is claimed. The independent harness will
  measure the next supplied source commit.

## Disposition

**READY FOR OPERATOR REVIEW.**

The implementation head `c442f3d` passed the full required matrix:

- 121 Rust tests on Linux and 110 on local Windows;
- formatting, warnings-denied Clippy and locked release build;
- CP0 74, CP1 5 and CP3 55 Python tests;
- 24/24 provider integration cases across three datasets, two modes and four
  strategies;
- seven Git-history tests, two CLI history tests and read-only history smoke;
- Ubuntu, Windows, macOS, static musl and dependency-audit lanes.

No merge was performed. `main` remains unchanged; the operator owns the CP4 PR
review and merge decision.
