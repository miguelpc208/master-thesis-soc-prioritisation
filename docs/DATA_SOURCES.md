# Data sources and acquisition rules

Machine-readable source metadata lives in `configs/data_sources.yaml`. Populate retrieval dates,
snapshot dates, model/catalogue versions, checksums, and approved local paths for every acquired
snapshot.

| Source | Purpose | Bootstrap status | Key rule |
| --- | --- | --- | --- |
| VulZoo | Multi-dimensional public vulnerability data | Disabled/not downloaded | Shallow, processed-first inventory only after approval; capture commit SHA |
| FIRST EPSS | Date-pinned exploitation probability | Disabled/not downloaded | Bulk daily CSV; record date and model version |
| CISA KEV | Known-exploitation evidence | Disabled/not downloaded | Preserve `dateAdded`; enforce as-of logic |
| Qualys-like proxy | Transparent comparison only | Disabled | Never call it Qualys data or proprietary score reproduction |

The bundled VulZoo processed snapshot was described upstream as last updated on 2024-07-06 at
handoff. It must not be described as current 2026 intelligence. Inventory paths, sizes, formats,
encodings, schemas, nulls, and join keys before ingestion; do not load the full repository blindly.

Source anchors:

- https://github.com/NUS-Curiosity/VulZoo
- https://doi.org/10.1145/3691620.3695345
- https://www.first.org/epss/data
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog

