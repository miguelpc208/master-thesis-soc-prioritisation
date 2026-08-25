# Data sources and acquisition rules

Machine-readable source metadata lives in `configs/data_sources.yaml`. Populate retrieval dates,
snapshot dates, model/catalogue versions, checksums, and approved local paths for every acquired
snapshot.

| Source | Purpose | Bootstrap status | Key rule |
| --- | --- | --- | --- |
| VulZoo | Multi-dimensional public vulnerability data | acquired — approved processed subset | Shallow, processed-first inventory only after approval; capture commit SHA |
| DiverseVul | Function-level C/C++ vulnerability research labels | acquired — pinned dataset and metadata | Hash both JSONL files; preserve local source boundary and evidence provenance |
| FIRST EPSS | Date-pinned exploitation probability | Acquired — aligned 15-day panel plus retained archive | Bulk daily CSV; record date, model version, checksum and retrieval |
| CISA KEV | Known-exploitation evidence | Acquired inside approved VulZoo snapshot | Preserve `dateAdded`, catalogue date and retrieval time; enforce declared as-of mode |
| GitHub advisories via VulZoo | Authoritative remediation and affected-package metadata | Acquired — pinned processed metadata subtree | Verify authoritative CVE alias, non-withdrawal, conservative source availability and exact commit corroboration |
| Qualys-like proxy | Transparent comparison only | Disabled | Never call it Qualys data or proprietary score reproduction |

The bundled VulZoo processed snapshot was described upstream as last updated on 2024-07-06 at
handoff. It must not be described as current 2026 intelligence. Inventory paths, sizes, formats,
encodings, schemas, nulls, and join keys before ingestion; do not load the full repository blindly.

Source anchors:

- https://github.com/NUS-Curiosity/VulZoo
- https://doi.org/10.1145/3691620.3695345
- https://github.com/wagner-group/diversevul
- https://doi.org/10.1145/3607199.3607242
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

See [VULZOO_PROFILE.md](VULZOO_PROFILE.md) for the reproducible collection, format, temporal-provenance and relationship-contract profile.

See [VULNERABILITY_INGESTION_CONTRACT.md](VULNERABILITY_INGESTION_CONTRACT.md)
for the approved NVD, CVE and KEV normalisation boundary.

See [TEMPORAL_EVIDENCE_CONTRACT.md](TEMPORAL_EVIDENCE_CONTRACT.md) for strict retained-snapshot
availability, source-effective reconstruction, conservative date-only handling and claim limits.

## Approved GitHub advisory metadata collection

- Retrieval date: 2026-08-24; exact UTC collection time remains in the acquisition manifest.
- Parent pinned VulZoo commit: `c504fa2537300a42fea1ff0adabfa9ca6687e435`.
- Approved collection: `processed/github-advisory-database`.
- Pinned collection Git tree: `de870e011e777b200a49a77593438b0ebeb857e5`.
- Acquired advisory metadata files: 21,729; collection size: approximately 57.36 MiB.
- Source-audited GHSA relationship identifiers: 18,504; authoritative CVE alias links: 18,487;
  conflicting alias links: 17; withdrawn advisory documents: 138.
- Source-audited package entries: 34,177; source fixed-version range events: 30,541.
- Source-audited same-CVE direct-commit URL/hash corroborations: 12,435.
- A read-only anomaly audit found 987 valid records with `modified < published`; the approved
  availability bound is `max(published, modified)` while both source timestamps remain unchanged.
  Its fingerprint is `77458e225ef27558589512b0d773f4b6bc947d45f3d6bd29bdbffd7f1ada766d`.
- Accepted rows are stricter than the source-audit counts because withdrawn, future-timestamped,
  unknown-CVE and conflicting records are rejected.
- Advisory descriptions, patch bodies, Exploit-DB records and proof-of-concept payloads remain
  outside scope; the unrelated `rel-cve-poc.json` relationship is never opened.
- Local retrieval occurred after the aligned 2025 scenario. Source-effective reconstruction is
  possible only under the conservative retained source-availability time; strict historical
  availability and complete advisory-version history are not claimed.

See [GITHUB_ADVISORY_REMEDIATION_CONTRACT.md](GITHUB_ADVISORY_REMEDIATION_CONTRACT.md) for
canonical-CVE aliases, package versions, corroborated commit references and temporal rules.

## DiverseVul approved working snapshot

- Retrieval date: 2026-08-23.
- Upstream repository commit: `50a2c18b810252a79c892d8b5d96cd61a656b2da`.
- Dataset filename: `diversevul_20230702.json`; its contents are JSONL, not one JSON document.
- Dataset SHA-256: `7937c26003c4c24a396747432487e8abdd1c4622b5547ae93855bee15266bd57`.
- Metadata filename: `diversevul_20230702_metadata.json`; its contents are also JSONL.
- Metadata SHA-256: `974397b28f3f530e85faca31b27455a8bae0e1a114a6053368a4708d1c9c3454`.
- Observed functions: 330,492; 18,945 vulnerable labels and 311,547 non-vulnerable labels.
- Observed projects: 800; dataset commit identities: 7,653; metadata rows: 7,511.
- Forty-five metadata rows lack a valid direct Git commit ID; valid commit URLs may recover an
  identity when unambiguous, while unresolved identities are retained as bounded rejections.
- The paper's headline population and project/commit counts do not match the downloaded snapshot.
  Never substitute published figures for verified local counts.
- `20230702` is a filename token, not proof of source publication, retrieval, or decision-time
  availability. The source snapshot date remains unknown.
- Upstream redistribution terms have not been verified. Raw function source and metadata stay in
  the approved local dataset and must not enter Git, handoffs, reports, or SQLite.

See [DIVERSEVUL_INGESTION_CONTRACT.md](DIVERSEVUL_INGESTION_CONTRACT.md) for the
approved function-to-CVE evidence, provenance, rejection and non-redistribution rules.

## FIRST EPSS approved historical panels

- Acquisition date: 2026-08-24; exact UTC retrieval time is recorded in the local manifest.
- Official historical archive: `https://github.com/empiricalsec/epss_scores`.
- Pinned archive commit: `3b3ae5b793011090800848c75ceea4cecaa9d309`.
- Active contiguous score dates: 2025-03-21 through 2025-04-04, inclusive.
- Active daily files: 15; model version: `v2025.03.14`; compressed volume: 26.17 MiB.
- Active audited source rows: 4,083,075; approved VulZoo matches: 4,075,133.
- Active valid rows outside the pinned VulZoo CVE catalogue: 7,942; excluded, not malformed.
- Active approved fingerprint:
  `221e5281bf5929a0daa2cbf2b16a9792636ccc3770416d49c362d90484a20cb3`.
- Retained archival score dates: 2025-12-31 through 2026-01-14, inclusive; 4,152,416
  observations and all 15 dated source snapshots remain unchanged.
- Retained archival fingerprint:
  `1cec6b4591f0df289531778bc3e14fffa50dee396a0ff05aacfaa3472436b2b9`.
- Historical reconstruction remains incomplete for NVD/KEV because only one retained snapshot
  exists for those sources; neither EPSS panel establishes historical local availability.

See [EPSS_INGESTION_CONTRACT.md](EPSS_INGESTION_CONTRACT.md) for daily source snapshots,
probability bounds, temporal cut-offs and exclusion accounting.
