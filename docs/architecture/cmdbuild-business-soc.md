# CMDBuild business and SOC context

This component extends the existing `thesis_pipeline` package. It must not
duplicate the technical vulnerability ingestion pipeline or move its datasets.

## Authoritative layers

- Public technical evidence remains in the existing vulnerability pipeline.
- READY2USE and PostgreSQL provide synthetic business and operational context.
- Python integrates CVEs with asset-specific vulnerability occurrences.
- The existing simulation, synthetic organization, and storage modules remain
  the preferred integration points.

## Integration grain

`CVE -> vulnerability occurrence -> asset`

A single CVE can affect multiple assets. Technical severity can therefore be
identical while service criticality, SLA, and operational impact differ.

## READY2USE discovery contract

Class identifiers, process identifiers, domain identifiers, and internal field
names remain null until read-only discovery confirms the deployed schema.

## Data locations

Large technical datasets, generated synthetic records, exports, and database
backups belong under `THESIS_DATA_ROOT`, not in the Git repository.

## Reproducibility

Version configuration, generation code, source provenance, and simulation seed.
Comparison scenarios must share their population, capacity, and random seed.

The supported entry points are `cmdbuild-preview`, `cmdbuild-ingest-business`,
`cmdbuild-ingest-operational` and `cmdbuild-export-evidence`. They rebuild plans from the versioned
scenario, mapping and simulation contracts. Live writes remain behind an exact expected-fingerprint
gate and the existing rollback-capable writers. Evidence export contains metadata and counts only,
must target a path outside Git and never overwrites an existing file.
