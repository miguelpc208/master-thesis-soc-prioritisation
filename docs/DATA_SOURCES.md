# Data sources and acquisition rules

Machine-readable source metadata lives in `configs/data_sources.yaml`. Populate retrieval dates,
snapshot dates, model/catalogue versions, checksums, and approved local paths for every acquired
snapshot.

| Source | Purpose | Bootstrap status | Key rule |
| --- | --- | --- | --- |
| VulZoo | Multi-dimensional public vulnerability data | acquired — approved processed subset | Shallow, processed-first inventory only after approval; capture commit SHA |
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

## VulZoo approved working snapshot

- Retrieval date: 2026-08-14.
- Upstream commit: `c504fa2537300a42fea1ff0adabfa9ca6687e435`.
- Upstream processed snapshot date: 2024-07-06.
- Acquisition mode: shallow partial sparse clone, processed-first, without submodules.
- Approved scope: all selected `processed/` collections except `processed/exploit-db-database`.
- Excluded scope: the complete Exploit-DB payload corpus.
- Inventory: 771,066 files and 5,314,758,884 bytes (4.95 GiB).
- Integrity status: clean working tree at the pinned upstream commit after applying the approved sparse paths.
- Limitation: this is a dated processed snapshot and must not be described as current 2026 vulnerability intelligence.
- Security note: two unavailable JavaScript files were confined to the Exploit-DB proof-of-concept corpus. No cause is asserted; the complete corpus is excluded by design.
