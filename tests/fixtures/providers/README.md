# Provider fixture bundle

The committed `bundle.json` contains deterministic, harmless provider-format
fixtures as **hex-encoded bytes**. Raw token-shaped text is intentionally not
committed: GitHub secret scanning (correctly) treats format-valid lookalikes as
potential credentials, even when the values are synthetic.

Tests materialize the bundle into a temporary directory with
`tools.cp3.materialize.materialize("tier2" | "tier3", destination)`. The
independently authored truth manifests under `tests/cp3/` refer to the same
paths and byte offsets.

Regenerate with:

```sh
python -m tools.cp3.fixtures
```

This writes the raw fixture tree locally for review and rewrites `bundle.json`.
The raw `tier2/` and `tier3/` directories are ignored by Git. Never scan
`bundle.json` itself as a source tree; it is a transport format, not target
content.
