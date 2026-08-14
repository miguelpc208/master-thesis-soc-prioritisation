# VulZoo profiling contract

This document records an engineering profile of the approved VulZoo working
snapshot. It is not dissertation evidence and does not establish that the
underlying intelligence is current.

## Reproduction

    python -m thesis_pipeline.cli profile-vulzoo `
        --config configs/data_sources.yaml `
        --sample-limit 2 `
        --max-json-mib 50

Generated profile outputs remain outside Git under `outputs/`.

## Pinned scope

- Upstream commit: `c504fa2537300a42fea1ff0adabfa9ca6687e435`.
- Retrieval date: 2026-08-14.
- Acquisition: shallow partial sparse clone of approved `processed/` collections.
- Approved collections: 16.
- Approved collection files: 771,055.
- Approved collection bytes: 5,314,715,217.
- Excluded collection: `processed/exploit-db-database`.
- Raw message and patch bodies exported by the profiler: no.
- Dataset files executed by the profiler: no.

The repository-wide inventory reports another 11 files and 43,667 bytes outside
the approved collection directories. These are repository or control files and
are not part of the collection profile.

## Collection inventory

| Collection | Files | Bytes | Observed format |
| --- | ---: | ---: | --- |
| NVD | 286,123 | 1,814,146,268 | Per-CVE JSON |
| AttackerKB | 647 | 1,216,113,210 | Paginated JSON responses |
| CVE | 362,738 | 1,018,118,206 | Legacy per-CVE JSON |
| Patch | 28,465 | 710,579,046 | Extensionless Git diffs |
| Bugtraq | 17,404 | 125,459,630 | RFC822-like messages |
| Full Disclosure | 12,448 | 106,350,378 | RFC822-like messages |
| GitHub Advisory | 21,729 | 60,147,702 | OSV-like JSON |
| Linux vulnerabilities | 11,470 | 58,152,684 | Mixed CVE JSON and mail artefacts |
| ATT&CK | 3 | 55,102,481 | STIX bundles |
| Relationships | 20 | 43,517,910 | 16 JSON contracts plus auxiliary files |
| OSS Security | 15,502 | 37,519,491 | RFC822-like messages |
| D3FEND | 3 | 23,738,959 | JSON and JSON-LD |
| CWE | 1 | 20,140,440 | JSON catalogue |
| ZDI Advisory | 14,500 | 19,729,354 | Per-advisory JSON |
| CAPEC | 1 | 4,733,781 | JSON catalogue |
| CISA KEV | 1 | 1,165,677 | JSON catalogue |

## Temporal provenance

The `processed/README.md` date of 2024-07-06 is an upstream index date, not a
global snapshot date. Observed component evidence differs:

| Component | Observed version or date |
| --- | --- |
| CAPEC | Version 3.9, 2023-01-24 |
| CWE | Version 4.16, 2024-11-19 |
| ATT&CK | Latest observed object modification 2024-11-12 |
| CISA KEV | Catalogue 2025.03.19, released 2025-03-19 |
| NVD/CVE | Full temporal-coverage profiling still pending |

Every experiment must use source-specific evidence dates and enforce as-of
cut-offs. The processed README date must never be treated as global freshness.

## Relationship contracts

Dictionary-to-list mappings provide explicit targets for ATT&CK, CAPEC, CWE,
AttackerKB, GitHub advisories, mail and patch references.

The following files are CVE membership lists rather than value mappings:

- `rel-cve-cpe.json`;
- `rel-cve-cvss.json`;
- `rel-cve-cwe.json`;
- `rel-cve-kev.json`.

Consequently, CPE, CVSS and CWE values must be extracted from authoritative CVE
or NVD records. The KEV membership list must reconcile with the dated KEV
catalogue.

`temp-nvd-patch-links.json` contains duplicated URLs and requires
deduplication before use.

`rel-cve-patch.json` reports 28,469 approximate links against 28,465 physical
patch files and requires reconciliation before ingestion.

`rel-cve-poc.json` remains disabled. Its targets belong to the excluded
Exploit-DB payload corpus and must not be treated as available exploit evidence.

## Profiler safety contract

- deterministic bounded sampling;
- maximum 100 samples per collection;
- maximum JSON parse size of 100 MiB;
- default JSON parse size of 50 MiB;
- no message bodies, patch bodies or complete JSON records in output;
- only structural keys, identifiers and selected catalogue metadata are emitted;
- no dataset execution;
- no network downloads;
- no mutation of the VulZoo working tree;
- no research claims from profiling output.

## E1-E4 ingestion priority

1. NVD and CVE identifiers, timestamps, CVSS and CWE data.
2. Date-pinned CISA KEV membership.
3. Date-pinned FIRST EPSS acquired separately.
4. CWE, CAPEC and ATT&CK technical context.
5. GitHub advisory, mail and patch evidence only after validation.
6. PoC relations remain disabled.

## Known limitations

- Profiling uses bounded deterministic samples rather than parsing every record.
- Collection counts and sizes describe the pinned local snapshot only.
- NVD and CVE temporal coverage still requires a complete metadata-only scan.
- Membership in a relationship file does not prove causal relevance.
- Patch references require deduplication and target reconciliation.
- The snapshot must not be described as current 2026 intelligence.
