# GitHub advisory and corroborated remediation contract

This contract authorises bounded remediation metadata from the already pinned VulZoo working
snapshot. It does not authorise patch bodies, exploit payloads, network lookups, deployment claims
or a claim of complete historical GitHub Advisory Database versions.

## Approved source and pre-ingestion audit

- Pinned VulZoo commit: `c504fa2537300a42fea1ff0adabfa9ca6687e435`.
- Approved sparse collection: `processed/github-advisory-database`.
- Pinned collection Git tree: `de870e011e777b200a49a77593438b0ebeb857e5`.
- Approved acquisition: 21,729 local metadata files, approximately 57.36 MiB.
- Aligned scenario cut-off: `2025-03-22T09:00:00Z`.
- Audited GHSA relationships: 18,504; authoritative matching CVE aliases: 18,487.
- Audited alias conflicts: 17; withdrawn advisory documents: 138.
- Audited affected-package entries: 34,177; upstream fixed-version events: 30,541.
- Audited exact same-CVE commit-hash/commit-URL corroborations: 12,435.
- Temporal-anomaly audit fingerprint:
  `77458e225ef27558589512b0d773f4b6bc947d45f3d6bd29bdbffd7f1ada766d`.
- The audit found 987 retained advisories whose authoritative `modified` timestamp precedes
  `published`; all 987 are recoverable by the conservative availability rule below.

These are source-audit counts, not promises that every audited advisory survives the stricter
canonical-CVE, non-withdrawal, modification-time and package-validation gates. Accepted counts
must be reported from the actual ingestion report.

Only these already audited relationship documents may be opened:

- `processed/relationships/rel-cve-github-advisory.json`;
- `processed/relationships/rel-cve-patch.json`;
- `processed/relationships/temp-nvd-patch-links.json`.

Their SHA-256 values must still match the approved read-only audit. Neither
`processed/relationships/rel-cve-poc.json` nor `processed/patch-database` nor
`processed/exploit-db-database` is in scope.

## Advisory acceptance

An advisory relationship is accepted only when all conditions hold:

1. Its source path resolves beneath the approved advisory collection and the document GHSA
   identifier agrees with the source path.
2. Its relationship CVE already exists in the pinned canonical VulZoo `cve` table.
3. That exact CVE also occurs in the authoritative advisory `aliases` array.
4. The advisory has not been withdrawn; all withdrawn records are conservatively excluded.
5. Both source `published` and `modified` timestamps are timezone-aware, valid and at or before
   the approved decision cut-off.
6. `source_available_at_utc` is the later of authoritative `published` and `modified`. Both raw
   timestamps are preserved unchanged; their ordering is not rewritten or inferred.

Missing source files, malformed documents, out-of-snapshot CVEs, alias conflicts, future source
versions and withdrawn advisories become bounded rejection events. A valid `modified < published`
record is not rejected because publication remains the later authoritative availability bound. No
canonical CVE may be created from an advisory relationship.

Acquisition contract `vulzoo-github-advisory-acquisition-v2` must enumerate every retained GHSA
body with its root-relative path, byte length and SHA-256. Its
`collection_fingerprint_sha256` is the SHA-256 of the canonical JSON inventory sorted by path, and
the separately approved audit must contain the same fingerprint. The importer compares the exact
manifest and filesystem inventories before opening an ingestion run, then authenticates and parses
the same byte sequence for every referenced body. Added, removed or modified bodies fail closed.

The normalized database retains only GHSA identity, authoritative timestamps, bounded severity,
source path/hash, canonical CVE links, package ecosystem/name/PURL, enumerated affected versions,
range-event type/value and approved snapshot/run identity. Raw advisory `summary`, `details`,
descriptions and other free-text bodies never enter SQLite, Git or generated reports.

## Version and patch evidence

Affected package entries are stored independently per source position. Ordered range events retain
their exact source kind: `introduced`, `fixed`, `last_affected` or `limit`. Fixed-version metadata
indicates that the advisory names a version boundary; it does not prove that a specific asset is
affected, that a vendor fix is deployable or that remediation has occurred.

A patch reference is accepted only when a valid complete 40-character SHA-1 in
`rel-cve-patch.json` exactly matches a direct commit URL associated with the same canonical CVE in
`temp-nvd-patch-links.json`. Bare hashes, unrelated URLs, issue links, pull requests and unmatched
commit candidates are excluded. One normalized reference is retained per approved snapshot, CVE
and commit SHA; no patch body or exploit reference is downloaded.

A corroborated commit gains a reconstruction timestamp only when its exact normalized commit URL
also occurs in an accepted advisory for the same CVE. Its conservative anchor is
`source_available_at_utc = max(published_at_utc, modified_at_utc)`, never an inferred commit time.
Otherwise the reference is retained as `undated_context_only` and is not eligible in historical
reconstruction. A later successful ingestion may reclassify that same stored reference when an
accepted exact same-CVE advisory anchor becomes available; the commit identity and total reference
count remain unchanged.

## Temporal and provenance boundary

Migration `008_github_advisory_remediation.sql` adds the normalized source structures. Migration
`009_advisory_source_availability.sql` replaces the invalid timestamp-order constraint, preserves
both authoritative timestamps, adds their conservative maximum and updates patch anchors without
weakening snapshot/run provenance. The three explicit evidence-time policies are:

- `github_advisory`;
- `github_advisory_fixed_version`;
- `corroborated_patch_commit`.

`strict_snapshot` never treats locally acquired 2026 advisory files as available during a 2025
scenario. `source_effective_reconstruction` uses the conservative advisory source-availability
time and excludes undated patch references. The snapshot is not a complete historical advisory
panel; neither mode establishes exact historical ground truth.

The importer is idempotent for accepted evidence, records each invocation as a separate run,
rolls back accepted rows on failed validation, rejects foreign-key inconsistency and never writes
outside the already approved SQLite database under `THESIS_DATA_ROOT`.

## Reproduction

```powershell
python -m thesis_pipeline.cli init-db `
    --path "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite"

python -m thesis_pipeline.cli ingest-github-advisories `
    --config configs/data_sources.yaml `
    --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" `
    --acquisition-manifest "$env:THESIS_DATA_ROOT\snapshots\vulzoo-github-advisory\manifests\APPROVED-MANIFEST.json" `
    --audit-report outputs/APPROVED-PATCH-ADVISORY-AUDIT.json `
    --decision-at "2025-03-22T09:00:00Z" `
    --progress-every 1000
```

Create and verify a consistent SQLite backup before applying migrations 008 or 009 to a populated
database. Generated JSON summaries belong under ignored `outputs/` and contain no raw source
records.
