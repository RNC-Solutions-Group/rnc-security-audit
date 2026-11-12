# CP4 validation — detection expansion and Git history

> **Status:** Implementation and local regression validation complete. Final CI
> evidence and operator review are recorded below when the branch is pushed.
> Provider-format recognition is not proof of an active, authorized, complete or
> non-revoked credential.

## Repository state

| Field | Value |
| --- | --- |
| Branch | `feat/cp4` |
| Starting baseline | `5391d8457ea091c45733920078a7f714ec61f678` |
| Final implementation head | Set by the CP4 commit(s); see PR |
| Pull request | [PR #10](https://github.com/RNC-Solutions-Group/rnc-security-audit/pull/10) once updated |
| Target | Authorized development target; operator owns merge |
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
  `sha256:3719a19d9b589ada93f7a1a9d75279dd9d275edb2d43ecc5af68c7d3f5b4573d`.
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

The Rust suite includes 110 tests on Windows after CP4 (95 before). Linux CI is
expected to include the platform-gated tests that do not run on Windows; the
final CI count is recorded after the push.

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

**CONDITIONAL GO pending final pushed-branch CI.** Local implementation,
regression, formatting, linting, release build, CP0-CP3 regressions and the
24-case provider integration pass. The CP4 workflow is added but its result on
the remote branch is not yet available. Operator approval and merge remain
outstanding.
