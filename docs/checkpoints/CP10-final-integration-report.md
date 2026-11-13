# CP10 — Final harness integration and authoritative scanner baseline

**Starting HEAD:** `034feff1ac5444221e2d32ff5b959d5dcb1ed75f`

**Branch:** `test/scan-harness` (orphan)

**Execution date:** 2026-11-12

**Implementation checkpoint:** `a286af73e844a36b440665f0f36e99ff8f131545`
(this report is committed with the final CP10 documentation update).

**Ending HEAD:** see the final CP10 completion response; the report commit is the
documentation follow-up to the implementation checkpoint.

## 1. Outcome

CP10 implemented the remaining harness integration and executed a fresh,
source-only baseline. The new authoritative baseline is
[`reports/baseline-20261112/`](../../reports/baseline-20261112/README.md).

It is **not** a complete four-scanner × two-product baseline:

- Completed authoritatively: Gitleaks native + Docker AMD64; RNC CP3 native;
  RNC CP4A native.
- Blocked: Betterleaks (no local source at the pinned commit) and RNC Docker
  AMD64 (offline Cargo dependency/base-image gaps).
- No source, oracle, or synthetic-lab mutation was used to turn a blocked cell
  into a pass. No network acquisition was used.

## 2. Working tree and implementation summary

Final working tree is clean after the CP10 commits. Implementation changes:

| Area | Change |
| --- | --- |
| Oracle | Applied the approved `reports/cp5d/proposed-oracle-migration.json` records into the canonical oracle; now 184 total / 89 negatives / 65 positives / 53 unique groups / 30 informative / 0 lineage-only. Version `2026-11-12.3`. |
| Oracle validator | Removed the proposed-only profile and the 181/86 fallback. The official loader is strict at 184/89 and requires exact digests on `PNM-001`, `PNM-002`, `PNJ-001`. |
| Lab loader | New `harness/rnclab.py` verifies the certified manifest self-hash, oracle hash, 360 corpus files, 51-commit local Git lane, and the exact source span of all 1,602 items. |
| Lab scoring | Filesystem and Git lanes are independent. Exact path/value identity, Git ancestry, informative/negative attribution, private-key material policy, duplicates, pending review, unverified evidence, and complete finding accountability are implemented. `/scan/` container paths are normalized to the lane root. |
| Lab suite | New `rnclab` suite (standalone; not included in `all`). It registers canonical filesystem/Git performance and run-owned `legacy-5x`/`legacy-10x` load profiles. |
| Performance | Per-suite workloads now cover Levain, replicated Leaky Repo filesystem, Leaky Repo Git, and RNC Lab filesystem/Git. The scanner-specific fixture lane has no performance workload. Standard plan is 1 warm-up/5 measured runs; loads use 1 warm-up/3 measured runs. |
| Coverage caveats | RNC's 11 `SYMLINK_NOT_FOLLOWED` aliases and load-time `TOTAL_BYTE_LIMIT` exclusions are explicit coverage caveats, not silent omissions. |
| Builds | Gitleaks Docker uses an adapter source Dockerfile with local `golang:1.27.4`, an offline vendor tree, `--network none`, and `--pull=false`. Native builds use the pinned source checkout. |
| Reports/docs | Updated README, architecture, roadmap, history accountability, scoring contract, report index, and the CP10 baseline reports. |

## 3. Oracle finalization

The owner-approved migration was applied. The canonical document is
[`datasets/leaky-repo.history-oracle.json`](../../datasets/leaky-repo.history-oracle.json),
SHA-256 `bb6d24bfecd53c7208c2915c105a5b501cbb3af3390fac7a4e5fcf92e50a078c`.

| Check | Result |
| --- | --- |
| Total / positives / unique groups / negatives / informative | 184 / 65 / 53 / 89 / 30 |
| Source validation | PASS, 184/184 items and blobs |
| Exact negative identity | `PNM-001` `168f39bc…`, `PNM-002` `1e089e3c…`, `PNJ-001` `7a6d503c…` |
| Retained-evidence regression | 21 TP, 19 unique, 21 duplicates, 7 informative, 12 FP alerts, 4 unique exposures, 0 pending, 61/61 accounted |
| Precision/F1 | `null`, `BLOCKED_INCOMPLETE_NEGATIVE_ORACLE` |

Regression evidence is [`leaky-regression-rescore.json`](../../reports/baseline-20261112/leaky-regression-rescore.json).
It is retained-evidence regression only, not a CP10 scanner baseline.

## 4. RNC Synthetic Secrets Lab v3

Loaded from `datasets/cache/rnc-synth-lab/`; not rebuilt or modified.

| Item | Value |
| --- | --- |
| Lab / build | `rnc-synthetic-secrets-lab/1.2.0` / `v3` |
| Manifest SHA-256 | `691548588679f4a1e5e41ecd5d253d7137693337c1ddef2c6e8943bbb7cd7d0b` |
| Oracle SHA-256 | `83dea16b343ff7a9340ff463513f4bdb454cea6faaf3234696a78fe8e6b85214` |
| Corpus SHA-256 | `161cb863f22b817982d26113b3981bec24b30bc37dd881fc10e9e8cc48ac91f3` |
| Filesystem / Git items | 1,282 / 320 |
| Positive occurrences / unique identities | 800 / 496 |
| Source validation | PASS, 1,602/1,602 spans |
| Frozen-lab post-run verification | PASS on every RNC Lab experiment |

The lab suite does not scan `corpus/` as one root. `--suites all` remains Levain
+ Leaky Repo; `rnclab` is opt-in.

## 5. Full regression tests

| Result | Value |
| --- | --- |
| Tests | **284** |
| Failures / errors | 0 |
| Duration | **129.067 s** (final committed-HEAD run) |
| Command | `python -m unittest discover -s tests -t . -v` |

The suite includes the existing lineage/rename/exact-negative regressions, the
new lab loader/identity/private-key/accounting tests, Docker `/scan/` path
normalization, and all prior harness tests.

## 6. Source builds

| Baseline | Repository | Commit | Native AMD64 | Docker AMD64 |
| --- | --- | --- | --- | --- |
| Gitleaks | `RNC-Solutions-Group/gitleaks` | `5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c` | PASS | PASS |
| Betterleaks | `betterleaks/betterleaks` | `5eab48332cc48565864514e3bc6de89df091a7c4` | BLOCKED `MISSING_LOCAL_SOURCE` | BLOCKED `MISSING_LOCAL_SOURCE` |
| RNC CP3 | `RNC-Solutions-Group/rnc-security-audit` | `5391d8457ea091c45733920078a7f714ec61f678` | PASS | BLOCKED `MISSING_LOCAL_DEPENDENCY` |
| RNC CP4A | `RNC-Solutions-Group/rnc-security-audit` | `93b4dda909cb3b41606a4d0f36c8ef9d06b77fde` | PASS | BLOCKED `MISSING_LOCAL_DEPENDENCY` |

Fresh native artifacts are identified in each experiment JSON. Gitleaks Docker
builds used only local base images and an offline vendored module tree; the
reported image IDs are independently attributable to the source commit.

## 7. Detection matrix

See the baseline README for the full tables. Summary:

| Scanner/product | Levain | Leaky FS | Leaky Git | Lab FS (TP/unique) | Lab Git (TP/unique) |
| --- | --- | --- | --- | --- | --- |
| Gitleaks native / Docker | 47/85, 3 FP | 22/175 legacy | 21/65, 15/53 | 357/640, 220/366 | 120/160, 102/130 |
| RNC CP3 native | 32/85, 0 FP | 33/175 legacy | NOT_APPLICABLE | 260/640, 171/366 | NOT_APPLICABLE |
| RNC CP4A native | 43/85, 2 FP | 27/175 legacy | 21/65, 19/53 | 297/640, 194/366 | 105/160, 78/130 |
| Betterleaks | BLOCKED | BLOCKED | BLOCKED | BLOCKED | BLOCKED |

Gitleaks and RNC native/Docker detection classes were identical between
products where both products completed, including the RNC Lab 357/220
filesystem and 120/102 Git results. RNC filesystem reports an explicit
11-alias symlink coverage caveat; load reports expose `TOTAL_BYTE_LIMIT`
caveats.

## 8. Performance and load results

Median seconds under DEV:

| Scanner/product | Levain | Leaky FS ×10 | Leaky Git | Lab FS | Lab Git | Lab ×5 | Lab ×10 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Gitleaks native | 0.102 | 0.337 | 0.155 | 0.230 | 0.212 | 1.484 | 2.711 |
| Gitleaks Docker | 0.564 | 2.606 | 0.643 | 1.631 | 4.452 | 7.453 | 13.281 |
| RNC CP3 native | 0.134 | 0.415 | N/A | 0.313 | N/A | 2.077 | 3.210 |
| RNC CP4A native | 0.284 | 1.038 | 7.127 | 0.523 | 6.975 | 11.675 | 12.938 |

Docker Leaky filesystem/Git and Docker Lab Git were `UNSTABLE` at the DEV
coefficient-of-variation threshold. All other measured workloads were `STABLE`.
Loads are performance-only and were not scored against the canonical oracle.
RNC CP4A's load runtime is constrained by its declared `TOTAL_BYTE_LIMIT`; the
reported inspected-file count is reduced by the caveat and the load is not
presented as a linear runtime scaling.

## 9. Native vs Docker

Native and Docker detection results match for Gitleaks across Levain, Leaky,
and both RNC Lab lanes. Docker is materially slower (tens of milliseconds to
several seconds of container overhead) and is not merged into native timings.
RNC Docker could not be built without a prohibited network dependency, so no
RNC native/Docker comparison is claimed.

## 10. Blocked cells and exact reasons

1. **Betterleaks — `MISSING_LOCAL_SOURCE`.** No local source checkout, bare
   clone, worktree, module zip, or extracted module exists for
   `5eab48332cc48565864514e3bc6de89df091a7c4`. The Go module cache contains only
   `v1.8.1.info`. Network acquisition is prohibited. Evidence:
   [`betterleaks-5eab483-blocked.json`](../../reports/baseline-20261112/betterleaks-5eab483-blocked.json).
2. **RNC Docker AMD64 (both commits) — `MISSING_LOCAL_DEPENDENCY`.** Offline
   `cargo vendor` fails because `bitflags v2.13.2` is absent (only 2.6.0 is
   cached), and `debian:bookworm-slim` is absent locally. Evidence:
   [`rnc-5391d84-docker-amd64-blocked.json`](../../reports/baseline-20261112/rnc-5391d84-docker-amd64-blocked.json)
   and
   [`rnc-93b4dda-docker-amd64-blocked.json`](../../reports/baseline-20261112/rnc-93b4dda-docker-amd64-blocked.json).

## 11. Integrity and cleanup

- Leaky oracle source validation: 184/184.
- Lab source validation: 1,602/1,602; frozen verification PASS before and after
  every lab experiment.
- All experiment workspaces were cleaned; Docker images/containers created by
  the harness were removed by run-specific tag/label.
- No `docker system prune`, volume deletion, WSL start, or unrelated-resource
  modification occurred.
- Preflight build clones are confined to ignored `work/` and are removed after
  evidence extraction.
- Raw matched values remain in ignored temporary locations only; committed
  reports contain safe hashes, paths, and counts.

## 12. Baseline location

- [Baseline README](../../reports/baseline-20261112/README.md)
- [Machine-readable index](../../reports/baseline-20261112/index.json)
- Individual native/Docker experiment JSON+Markdown files in the same directory.
- Superseded development attempts: `reports/baseline-20261112/superseded/`.

## 13. Recommendation

**NO-GO for a complete four-scanner/two-product CP10 baseline.** Betterleaks
has no local source at the pinned commit, and both RNC Docker products have
unresolved offline dependency gaps. Those matrix cells are explicitly blocked.

**GO for the completed cells.** The Gitleaks native+Docker and RNC native
results are fresh, source-built, sequentially executed, independently scored,
and backed by the strict 184/89 oracle and certified RNC Lab v3 hashes. They are
accepted as CP10 authoritative results only with the partial-baseline
qualification above.
