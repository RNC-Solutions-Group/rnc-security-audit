# Blocked: Betterleaks Main v2.0.0-dev

`betterleaks-main` is registered as a Windows AMD64 executable in `run/manifest.toml`
but was not part of the requested measured-program list.

A compatibility probe was attempted with the current Betterleaks 1.8.1 adapter and
failed before producing any report:

```text
betterleaks: error: unknown flag --report-format
```

The v2 CLI exposes `filesystem` and `git` commands with `--output PATH`, not the
v1 `dir`/`git` plus `--report-format` contract. The current adapter therefore
cannot produce a normalized finding report for this binary. No v2 detection or
performance baseline is claimed.

- Artifact: `run/betterleaks-main.exe`
- Version: `v2.0.0-dev+git.1bc5aa7`
- Source commit: `1bc5aa71786921e02bc7e9456178cf739c7a29ed`
- Executable SHA-256: `666f721ed4accb67c7b79540be42c6c92033dda754a7d6b48161b96a7b8f1e53`
- Failed evidence: `run/reports/all-windows-baselines/betterleaks-main/betterleaks-main-current-baseline-1bc5aa717869-default.json`

Adding a v2 adapter/output contract is a separate harness integration task; it was
not required for the requested eight-program baseline.
