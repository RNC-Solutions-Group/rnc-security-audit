# Development package builder

`build.py` creates a minimal, reproducible development evaluation archive. It
is not a production installer, release tag or auto-update mechanism.

```sh
python tools/package/build.py
python tools/package/smoke.py artifacts/cp4a/packages/rnc-scanner-0.1.0-windows-x86_64.zip
```

The package contains the native `rnc` executable, `rules/rnc-providers-v1.json`,
`VERSION`, `SOURCE_COMMIT`, `PLATFORM`, `README.md` and `SHA256SUMS`. The builder
requires a clean working tree unless `--allow-dirty` is explicitly supplied.

Use `--skip-build --binary PATH --commit SHA --platform NAME` to package a
binary produced by another validated build environment. The smoke test runs
from a clean extraction directory and does not depend on the source checkout.
Git-history smoke coverage is skipped only when no `git` executable is
available; the package README documents Git as a history-mode runtime
dependency.

Private reports are sensitive. The Windows builder verifies an explicit
protected DACL on private report publication; Unix private reports use `0600`.
Do not copy private reports into public artifacts.
