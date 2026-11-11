# Rule bundles

- [Synthetic rule bundle schema](rule-bundle.schema.json) — schema `0.1.0`, data-only format, finite match bounds.
- [Provider rule bundle schema](provider-rule-bundle.schema.json) — schema `0.2.0`, provider/family/credential metadata, candidate bounds and provenance.
- [Rule authoring and versioning](../../implementation/cp1-rule-authoring.md) — lifecycle, validators and commands.
- [Detection catalog](../../implementation/cp3-detection-catalog.md) — implemented, experimental and unsupported provider families.
- [`rules/rnc-synthetic-v0.json`](../../../rules/rnc-synthetic-v0.json) — preserved baseline synthetic rules.
- [`rules/rnc-synthetic-v1.json`](../../../rules/rnc-synthetic-v1.json) — expanded synthetic rules for CP1 integration.
- [`rules/rnc-providers-v1.json`](../../../rules/rnc-providers-v1.json) — CP3 first-party provider catalog.

The synthetic bundles are original RNC test rules, not third-party collections. The provider catalog is first-party detection logic with documented provider provenance; it is not a copy of another scanner's ruleset and is not suitable as proof that a credential is active.
