# CP4A — corrective hardening and release preparation

> **Status:** Implemented on `feat/cp4`; operator review pending. CP4A is a
> focused corrective pass over the complete CP4 implementation. It does not add
> detection families, orchestration, a GUI, a release tag or a production
> support claim.

## Scope

CP4A addresses four defects and deliverables that are independent of detection
recall:

1. Database URI findings retained the contextual `username:password` userinfo
   but offered no verifiable password-only evidence.
2. ANSI SGR decoration could enter that contextual evidence, including the
   evidence digest.
3. Windows private reports relied on inherited destination ACLs.
4. Internal benchmark execution duplicated the independent harness.

The pass also updates the roadmap and produces a minimal development evaluation
package. The primary database detection span, rule identity, finding ID and
contextual evidence digest are deliberately unchanged.

## Structured component evidence

### Root cause

The [`database-connection-credential`](../../rules/rnc-providers-v1.json)
rule captures group 1, the complete userinfo. The finding builder hashes exactly
that captured range. `DATABASE_URI` validation splits the userinfo into
components but previously discarded their offsets and did not expose a digest.
ANSI SGR bytes were accepted by the URI character classes, so a colored log
could place terminal escapes inside the captured userinfo.

Changing the rule capture to password-only would break the contextual meaning
and established CP3 truth. Adding a second database rule would duplicate
findings. CP4A therefore preserves the primary finding and derives supplementary
evidence after successful detection and validation.

### Private-only extension

The private report now contains:

```json
{
  "structured_evidence": {
    "version": "1",
    "components": [
      {
        "finding_id": "f-...",
        "unit_id": "u-...",
        "kind": "database-password",
        "start_byte": 137,
        "end_byte": 165,
        "line": 6,
        "line_end": 6,
        "source_sha256": "sha256:...",
        "normalized_sha256": "sha256:...",
        "normalization": "ansi-sgr-v1",
        "ansi": "TRIMMED"
      }
    ]
  }
}
```

| Field | Semantics |
| --- | --- |
| `version` | Independently versioned component-evidence contract; currently `1` |
| `finding_id` | Exact primary finding this component supplements |
| `unit_id` | Source unit identity used by the execution record |
| `kind` | Component kind; currently only `database-password` |
| `start_byte` / `end_byte` | Original source coordinates of the password component |
| `line` / `line_end` | Original line attribution; a single-line component reports the same start and end line |
| `source_sha256` | SHA-256 of the exact original component range |
| `normalized_sha256` | SHA-256 after supported SGR normalization; otherwise equal to source |
| `normalization` | `ansi-sgr-v1` when SGR was present; omitted when no supported normalization was needed |
| `ansi` | `NONE`, `TRIMMED`, `INTERNAL`, or absent component for unsupported input |

`structured_evidence` is additive to the private envelope. The finding schema
remains `0.2.0` with `additionalProperties: false`; components are not added to
findings. Sanitized output, console summaries, ordinary logs, CI annotations and
public evidence artifacts do not contain components, component digests or
password-only offsets.

### Dispatch metadata

The provider schema accepts an optional `component_extractor` on a `uri`-context
rule. The current value is `database-uri-password`. The ruleset digest binds the
declaration. Dispatch is not a second detection rule; unknown extractors are
rejected at load and no component is emitted for a rule that does not declare
one.

### ANSI SGR normalization

Only bounded CSI SGR sequences `ESC '[' [0-9;:]* 'm'` are recognized, with a
32-byte maximum per sequence. The parser maps visible bytes back to original
candidate offsets.

- **`NONE`**: no supported SGR in the candidate.
- **`TRIMMED`**: SGR exists outside the password component; outer decoration is
  excluded from the source range.
- **`INTERNAL`**: SGR exists inside the component range. `source_sha256` covers
  the original bytes including the internal sequence; `normalized_sha256` covers
  the visible password bytes.
- **Unsupported / malformed**: non-SGR or malformed ESC sequences do not
  produce a component. They are never silently stripped or normalized.

The parser does not decode percent escapes, JSON escapes or URI components.
`p%40ss%3Aword` remains a literal source component for hashing. IPv6 host text
is outside the userinfo capture. Empty passwords do not match the rule's
password class. Embedded literal colons in the password are supported by
splitting on the first visible colon.

### Digest and privacy risk

Component evidence uses SHA-256 for consistency with the existing finding
contract. A password-only SHA-256 is more susceptible to offline guessing than
the contextual userinfo digest because it removes username entropy. The digest
therefore remains exclusively in access-controlled private reports. Keyed HMAC
is a possible future design consideration, not an unrequested dependency.

## Windows private-report security

Unix private reports retain mode `0600`. Windows private publication now:

- builds an explicit protected DACL granting file-all-access only to the
  current user, `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`;
- supplies that security descriptor to `CreateFileW` at temporary-file creation,
  before any sensitive payload is written;
- inspects the opened handle's DACL before the first payload write and fails
  closed on unexpected, inherited, partial or duplicate ACEs;
- renames the same file object into place with `NtSetInformationFile`, preserving
  the restrictive DACL and preventing inherited permissions from broadening a
  replacement.

The Windows regression test grants `Everyone` full control on a deliberately
permissive parent, writes a private report over an existing destination, then
checks the final DACL and effective rights. The current user and LocalSystem
retain access; `Everyone` and `BUILTIN\Users` receive no access. Issue #8 remains
open for operator review and closure even though the implementation and test are
present.

## Benchmark retirement

`.github/workflows/cp3-provider.yml` no longer runs the required provider catalog
benchmark job. Historical CP3 benchmark results and `tools/cp3/bench.py` remain
as historical evidence/tooling. The independent RNC Scanner Harness owns
detection accuracy, comparative evaluation and performance measurement.

Retained CP3/CP4 CI coverage includes Rust formatting, warnings-denied Clippy,
locked tests, provider schema/truth checks, exact-byte provider integration,
whole/stream and strategy equivalence, Git-history behavior, privacy checks,
cross-platform builds, static musl build and dependency audit.

## Development package

`tools/package/build.py` creates a minimal `.zip` containing:

- `rnc` (`rnc.exe` on Windows);
- `rules/rnc-providers-v1.json`;
- `VERSION` and `SOURCE_COMMIT`;
- `PLATFORM`;
- `README.md`;
- `SHA256SUMS`.

`tools/package/smoke.py` extracts the archive into a clean directory and checks:
`--version`, rules validation, a controlled filesystem scan, private and
sanitized report generation, component offset accuracy, exit semantics and an
optional read-only Git-history scan. Git is documented as a history-mode runtime
dependency, not a universal package prerequisite.

Validated platform: Windows x86_64 locally; Linux x86_64 in a clean container
and in the CP4A CI package lane. macOS is buildable from source but was not
packaged or smoke-tested in this pass. The package is an evaluation artifact,
not an installer or production release.

## Validation

CP4A adds:

- six structured-extraction unit tests;
- four structured integration tests (edge cases, mode/strategy equivalence,
  primary-finding stability, private/sanitized isolation);
- one Git-history component attribution test;
- one CLI private/sanitized isolation test;
- one Windows private-report ACL test.

Existing CP0-CP4 tests and truth are unchanged except for the digest-only
provider catalog update. The CP3 provider digest was updated to
`sha256:dc1ab16f64a5dfb91262b46f321a9f5b219a13ed3bfb49e0f79c067de40bbc0f`
for ruleset `2026.11.4`.

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| warnings-denied Clippy | PASS |
| `cargo test --workspace --all-targets --locked` | PASS, 124 tests on local Windows |
| CP0 contracts | PASS, 74 tests |
| CP1 synthetic rules | PASS, 5 tests |
| CP3 catalog/schema/scoring/security | PASS, 55 tests |
| CP3 provider integration | PASS, 24 cases, all correct/equivalent |
| CP4A structured evidence | PASS, 6 unit + 4 integration tests |
| Git-history component attribution | PASS |
| CLI private/sanitized isolation | PASS |
| Windows private-report ACL | PASS, permissive-parent replacement and effective-rights checks |
| Clean-extraction package smoke | PASS on Windows x86_64 and Linux x86_64 |

## Known limitations

- Component evidence currently covers database URI passwords only.
- Password-only SHA-256 remains sensitive to offline guessing; private reports
  require access-controlled storage.
- ANSI support is limited to bounded CSI SGR sequences. Other terminal control
  sequences yield no component rather than a guessed normalization.
- Percent-encoded password bytes are hashed in source form and are not decoded.
- Git-history mode requires an installed Git executable.
- Independent benchmark scores are not produced or claimed by the scanner
  repository.
