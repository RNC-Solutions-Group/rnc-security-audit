# Rule bundles

- [Synthetic rule bundle schema](rule-bundle.schema.json) — schema `0.1.0`, data-only format, finite match bounds.
- [Provider rule bundle schema](provider-rule-bundle.schema.json) — schema `0.2.0`, provider/family/credential metadata, candidate bounds, optional value capture groups, optional post-detection component extractors and provenance.
- [Rule authoring and versioning](../../implementation/cp1-rule-authoring.md) — lifecycle, validators and commands.
- [CP4 detection catalog](../../implementation/cp4-detection-catalog.md) — current implemented, experimental and unsupported provider families.
- [CP3 detection catalog](../../implementation/cp3-detection-catalog.md) — preserved historical catalog.
- [`rules/rnc-synthetic-v0.json`](../../../rules/rnc-synthetic-v0.json) — preserved baseline synthetic rules.
- [`rules/rnc-synthetic-v1.json`](../../../rules/rnc-synthetic-v1.json) — expanded synthetic rules for CP1 integration.
- [`rules/rnc-providers-v1.json`](../../../rules/rnc-providers-v1.json) — CP4/CP4A first-party provider catalog, ruleset `2026.11.4` (37 rules, 22 families).

The synthetic bundles are original RNC test rules, not third-party collections. The provider catalog is first-party detection logic with documented provider provenance; it is not a copy of another scanner's ruleset and is not suitable as proof that a credential is active.
