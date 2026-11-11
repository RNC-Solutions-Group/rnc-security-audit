# CP3 accuracy methodology

> The production detector never grades its own output. Truth manifests are
> authored outside the scanner input root and are read only by test tooling.

## Corpus tiers

| Tier | Source | Purpose | Accuracy claim |
| --- | --- | --- | --- |
| 1 | CP0–CP2 synthetic v0/v1/edge corpora | Contract, streaming, policy, reporting and cross-backend regression | Execution correctness only; not production credential accuracy |
| 2 | `tests/fixtures/providers/tier2` + `tests/cp3/provider-truth-tier2.json` | Controlled provider-format positives, negatives and edge cases | Exact byte-range provider-format accuracy on this authored corpus |
| 3 | `tests/fixtures/providers/tier3` + `tests/cp3/provider-truth-tier3-heldout.json` | Separately authored held-out challenge set, not tuned per rule | Reported separately; same limitations as Tier 2 |
| 4 | Levain FP/TP corpus, Leaky Repo, Gitleaks comparison | External, licensed, isolated evidence | Only the scoped metric stated for each corpus |

Tier 1 is preserved byte-for-byte where its contracts require it. It is never
counted as production credential accuracy.

## Truth ownership

`tools/cp3/fixtures.py` constructs source bytes from declared templates and
records placeholder byte spans while rendering. It does not invoke the detector.
The truth manifest is written outside the scan root. It contains:

- path, exact start/end byte, line start/end;
- expected rule and credential family;
- SHA-256 of the exact matched bytes;
- source-file SHA-256 and length;
- required scope.

`tools/cp3/score.py` re-verifies the truth against source bytes before scoring.
A missing file, changed hash, changed length, changed line mapping or duplicate
truth identity fails the scoring run. Detector output cannot alter truth.

## Byte-addressed classification

Each finding must match an expected item by:

1. source path;
2. exact `start_byte` and `end_byte`;
3. expected `rule_id` (strict true positive).

Classification:

| Classification | Meaning |
| --- | --- |
| `EXPECTED_DETECTION` | Exact byte span and rule match |
| `MISSED_EXPECTATION` | Expected item has no exact finding |
| `FALSE_POSITIVE` | Finding has no truth item at a known path/span |
| `MISALIGNED_MATCH` | Byte range overlaps but is not exact |
| `WRONG_RULE` | Span and family match, rule identity differs |
| `WRONG_FAMILY` | Span matches, credential family differs |
| `DUPLICATE` | Same expected occurrence claimed more than once |
| `AMBIGUOUS_MATCH` | Finding or truth overlaps multiple items |
| `UNMAPPED` | Finding path is outside the truth manifest |

`precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`, and
`F1 = 2PR/(P+R)`. Undefined denominators produce `null`, never a fabricated
100%. Wrong-family and wrong-rule findings are false positives for strict
precision; family-level TP is reported separately. Ambiguous and unmapped
observations are reported separately and are not silently folded into TP/FP.

Same-line occurrences are distinguished by byte range. A dedicated fixture and
negative control prove two occurrences on one physical line are two findings,
not a duplicate or an ambiguity.

## Execution gate

Accuracy is not scored when:

- execution is `ERROR`/`INTERRUPTED`, result is `FAILED` or `INCOMPLETE`;
- evidence is invalid;
- a required unit is uninspected;
- a truth file was not inspected;
- the result code is not a completed detection result.

A missed required file is an execution-coverage failure, not merely a false
negative. The two facts are reported separately and never double-counted.

## Independent external harness

The pinned harness revision is
`86de44bf1cb13abf9a0c375a8b91d102c9b6dc9f`. It is line-addressed. The adapter
preserves byte offsets in metadata and exports an independently generated
line-range truth manifest. On Tier 2 the line-only harness matches **25** of 27
expected items and reports **2 ambiguous** same-line occurrences because two
distinct token spans share a line. The byte scorer classifies both correctly.
The line-only result is compatibility evidence, not the authoritative accuracy
score. No external repository is modified.

## External corpora

### Levain

The MIT-licensed Levain corpus supplies 116 negative sections and 45 positive
sections. Only credential kinds matched by a declared RNC family are included in
the denominator; unsupported kinds are reported separately. A finding that
overlaps a corpus secret of an unsupported kind is marked out of scope rather
than false positive. The negative corpus is a precision stress test: every
reported finding is counted as a false positive.

Current scoped result on the pinned revision: **30/31 mapped positives** with
**0** negative-corpus findings, **0** false positives on mapped families and
**5** out-of-scope observations. The single mapped miss is a deliberately
malformed PEM whose base64 body is not decodable; RNC rejects it by design. This
is recorded as a false negative, not converted into success.

### Leaky Repo

Leaky Repo supplies count-based file inventory, not credential-level truth. RNC
reports actual findings and `min(observed, expected)` count coverage only. No
TP/FP/precision/recall is claimed. Excess findings are not automatically false
positives.

### Gitleaks comparison

A pinned local Gitleaks build is run with its native default configuration on
the same filesystem fixtures. Findings are matched by path and exact fixture
bytes, not by assuming rule-name identity. On Tier 2 Gitleaks scores 22 TP / 2 FP
/ 5 FN; on Tier 3 it scores 11 TP / 0 FP / 4 FN. RNC scores 27/27 and 15/15 under
the local byte scorer. This is a controlled-corpus coverage comparison, not a
general product ranking. Gitleaks supports families outside the RNC catalog and
has Git-history capability that RNC does not yet implement. Betterleaks was not
executed because no pinned binary or image was available.

## Held-out rule

Tier 3 was authored separately and scored without changing individual rules in
response to its results. If a rule is later tuned against Tier 3, that corpus is
no longer held out and a fresh set must be authored before making a held-out
claim.

## Reproduction

```sh
cargo build --release --workspace --locked
python -m tools.cp3.integration_check \
  --binary target/release/rnc --output artifacts/cp3/integration.json
python -m tools.cp3.score \
  --findings /private/tier2.json \
  --truth tests/cp3/provider-truth-tier2.json \
  --rules rules/rnc-providers-v1.json \
  --source-root tests/fixtures/providers/tier2 --require-perfect
python -m tools.cp3.external_check \
  --harness-root /pinned/scanner-harness \
  --findings /private/tier2.json \
  --truth tests/cp3/provider-truth-tier2.json \
  --rules rules/rnc-providers-v1.json
python -m tools.cp3.external_corpora --help
python -m tools.cp3.comparative --help
```
