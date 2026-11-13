# CP2 Multi-Scanner Comparison

> Run: `cp2-comparative-20261111T025947Z`

## Scanner products

| Scanner | Version | Product | Build | Artifact |
| --- | --- | --- | --- | --- |
| Betterleaks | 1.8.1 | docker-linux-amd64 | PASS | `sha256:8b9d12db5e11ca798029da44923503de5d8cfff6992cffaaa6722fbeb9fc7797` |
| Betterleaks | 1.8.1 | docker-linux-arm64 | PASS | `sha256:12175773aede5b775478f8eb04dffc64ed1f6c29b8f3fd61851bcf2757d1e874` |
| Betterleaks | 1.8.1 | windows-amd64 | PASS | `727820f1a9f9264319cc50458b99f01acbb93e93df7a39b8eaa2715a7b1aaed5` |
| Gitleaks | v8.0.0-rnc.5f6ec56cfa6f | docker-linux-amd64 | PASS | `sha256:ae5f6c7e865c3123381775c8fc815e51dd5e1d3ac685f63e7269aa1f4160a096` |
| Gitleaks | v8.0.0-rnc.5f6ec56cfa6f | docker-linux-arm64 | PASS | `sha256:6d35d2b94822ddef97dee6e4b2574a884932575438de62258757c4fcebd8d9a2` |
| Gitleaks | v8.0.0-rnc.5f6ec56cfa6f | windows-amd64 | PASS | `e0831964099a20be3edaa5187f4f11a802821c2eea66a37acc6c09e0587724f2` |

## Detection

| Scanner | Leaky legacy | Leaky rich | History unique | Levain TP/FP | Levain P/R/F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| betterleaks | 37/175 | 37/175 | 3/3 | 48/5 | 90.57/56.47/69.57 |
| gitleaks | 22/175 | 22/175 | 3/3 | 47/3 | 94.0/55.29/69.63 |

## Capability matrix

| Suite | betterleaks | gitleaks |
| --- | --- | --- |
| git-history | PASS | PASS |
| gitleaks | NOT_APPLICABLE | PASS |
| leaky-repo | PASS | PASS |
| levain | PASS | PASS |
| synthetic-filesystem | PASS | PASS |

## Cross-scanner detection differences

### git-history

- betterleaks: 5/5 (100.0% recall), 0 unexpected, 0 duplicates
- gitleaks: 5/5 (100.0% recall), 0 unexpected, 0 duplicates
- gitleaks_vs_betterleaks: 0 only gitleaks; 0 only betterleaks; 5 both

### leaky-repo

- betterleaks: 37/175 (21.14% recall), 0 unexpected, 0 duplicates
- gitleaks: 22/175 (12.57% recall), 0 unexpected, 0 duplicates
- gitleaks_vs_betterleaks: 0 only gitleaks; 15 only betterleaks; 22 both

### synthetic-filesystem

- betterleaks: 4/4 (100.0% recall), 0 unexpected, 0 duplicates
- gitleaks: 4/4 (100.0% recall), 0 unexpected, 0 duplicates
- gitleaks_vs_betterleaks: 0 only gitleaks; 0 only betterleaks; 4 both

## Limitations

- Leaky Repo history remains observation-only; no historical recall is claimed.
- Leaky Repo precision/F1 remains unavailable without a negative oracle.
- Synthetic control recall is not real-world prevalence.
- Performance and detection are separate measurements.
