# synthetic-v1 authored corpus

**All values are deliberately nonfunctional synthetic markers.** They are not credentials, tokens, keys or account identifiers. The `RNC_SYNTH_KEY_*` prefix is reserved for test data and is never valid for a real service.

The machine-readable truth is [`manifest.json`](manifest.json). The manifest declares each marker, rule ID, expected occurrence count and policy disposition. `tools/cp0/corpus.py` independently locates those markers in the committed bytes; the scanner stub and independent harness both use this truth, but the scorer does not trust the stub.

| Property | Value |
| --- | ---: |
| Targets | 21 |
| Inspected targets | 19 |
| Verified-blocked targets | 1 |
| Optional uninspected targets | 1 |
| Unique marker occurrences | 26 |
| Expected detection findings | 25 |
| Expected actionable / exempted | 23 / 2 |

The overlap between unique markers and expected findings is intentional: blocked and uninspected markers are not detection expectations, and the overlapping-rules target has one marker occurrence legitimately matched by two rules.

## Edge coverage

- clean/negative/decoy and case-sensitive decoys;
- true positives in env/JSON/TOML forms;
- duplicate marker occurrences at distinct offsets;
- two rules matching one marker span;
- a pre-scan blocked target that must not be inspected;
- an optional unavailable target that must not force incomplete coverage;
- post-scan exemptions that preserve the raw finding;
- LF, CRLF, CR-only, UTF-8 BOM, Unicode prefixes, no trailing newline;
- binary bytes, NULs and invalid UTF-8, with markers on distinct lines for line-addressed harness compatibility;
- empty file, nested path, PEM-like multiline value.

Symlink escape, permission denial and TOCTOU are CP1 adapter tests; they are not represented by committed Git fixtures because checkout behavior is platform-dependent.
