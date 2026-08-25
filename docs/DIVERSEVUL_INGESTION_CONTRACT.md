# DiverseVul ingestion contract

This document defines the approved integration of pinned DiverseVul function-level research labels
with the canonical CVE catalogue already ingested from the approved VulZoo snapshot. It is an
engineering contract, not evidence of exploitation, enterprise exposure or current intelligence.

## Approved source boundary

- Upstream repository: `https://github.com/wagner-group/diversevul`.
- Pinned upstream commit: `50a2c18b810252a79c892d8b5d96cd61a656b2da`.
- Dataset SHA-256: `7937c26003c4c24a396747432487e8abdd1c4622b5547ae93855bee15266bd57`.
- Metadata SHA-256: `974397b28f3f530e85faca31b27455a8bae0e1a114a6053368a4708d1c9c3454`.
- Approved profile fingerprint:
  `5f937730b3ecef881920f7f5d6ccc1056c1729e8fc35552b3e99e84e741e31f4`.
- Both `.json` files contain JSON Lines and must be parsed one JSON object per line.
- The two approved source files and acquisition manifest remain beneath `THESIS_DATA_ROOT`.
- No network access, source execution, dataset mutation, Git publication or redistribution occurs.
- The SQLite database must remain beneath `THESIS_DATA_ROOT`, outside the dataset directory and
  outside OneDrive. It must already contain the profiled canonical VulZoo CVE catalogue.

The importer verifies the configured upstream commit, both source checksums, acquisition manifest,
read-only profile scope and deterministic joint fingerprint before accepting any source record.
An approved UTC-aware acquisition timestamp is used when available. When only the configured
retrieval date is available, conservative end-of-day UTC is used instead of inventing finer
precision. The filename token `20230702` is not a verified source-availability date.

## Observed source population

The pinned downloadable snapshot contains:

| Measure | Observed snapshot | Published reference |
| --- | ---: | ---: |
| Function records | 330,492 | 349,437 |
| Vulnerable labels | 18,945 | 18,945 |
| Non-vulnerable labels | 311,547 | 330,492 |
| Projects | 800 | 797 |
| Dataset commit identities | 7,653 | 7,514 |
| Metadata identities from permissive profiling | 7,491 | 7,512 |

The metadata file contains 7,511 JSONL rows. Sanitised field-level auditing found 7,466 valid
direct `commit_id` values and 45 invalid direct values. Permissive profiling identified 25
additional commit identities within URLs. The ingestion implementation validates every URL
recovery independently rather than assuming that all additional identities are safe.

These discrepancies must remain visible in research limitations. Counts from the paper do not
replace directly observed counts. The published vulnerable count matches, but this does not
validate the remaining population or establish why the snapshots differ.

## Commit identity and CVE evidence

Metadata commit identities follow this precedence:

1. Accept a valid hexadecimal `commit_id` of 7–40 characters.
2. Recover an identity from the metadata `commit_url` only when the direct value is invalid and
   the URL contains an unambiguous Git commit identifier.
3. Reject direct-versus-URL identity conflicts and metadata rows with no recoverable identifier.
4. Associate metadata to functions by the exact `(project, commit_sha)` pair. A shared commit with
   a different project is a bounded rejection, not a cross-project match.

Only identifiers in the explicit metadata `CVE` field are treated as metadata CVE evidence.
Identifiers found in the dataset commit message form a separate `commit_message` evidence channel.
The metadata `bug_info` field and other free text never create a CVE association. CVEs found by
the permissive engineering profiler therefore represent an upper-bound exploration, not the
acceptance contract for the stricter importer.

Every proposed CVE must match `CVE-YYYY-NNNN...` and already exist in the canonical VulZoo `cve`
table. Unknown IDs, including observed candidate `CVE-2018-100084`, are rejected once per run
without fabricating a canonical CVE. Foreign-key constraints enforce the final canonical match.
Matching on CWE, repository name or project name alone is prohibited.

## Function-level storage and interpretation

Each approved dataset record produces one `diversevul_function` metadata row containing:

- source snapshot and ingestion-run provenance;
- exact project, commit identifier and source JSONL line number;
- upstream integer hash stored as text to avoid overflow;
- SHA-256 and UTF-8 byte length of the source function;
- upstream size annotation, valid CWE identifiers and research target label;
- a SHA-256 digest of the commit message, never the raw message.

The single profiled record with empty source code remains present with a null function SHA-256 and
zero source bytes. Missing code is never replaced with invented source. Raw function bodies stay
only in the approved local dataset; they are not duplicated into SQLite, Git, handoff archives,
rejection tables, stdout or generated reports.

`target=1` and `target=0` are source-provided research labels. They are not proof of operational
vulnerability presence, successful exploitation, production exposure, exploit availability,
business impact or temporal availability. FIRST EPSS is integrated under its separate dated-panel
contract; Exploit-DB payloads remain excluded.

## Atomicity and migration

Migration `004_diversevul_integration.sql` adds:

- `diversevul_commit` for validated metadata identities and field-authoritative declarations;
- `diversevul_function` for bounded per-function metadata and research labels;
- `diversevul_function_cve` for exact canonical CVE associations with evidence provenance.

Approved input rows are written within one SQLite transaction. Changed source files, changed
canonical catalogue counts, profile-count mismatches, invalid function rows or foreign-key errors
roll back every newly inserted research row while retaining a failed ingestion-run audit record.
Rejections contain only relative paths, reason codes, bounded identifiers and hashes.

Repeated ingestion of the same approved snapshot preserves natural-key identities and records a
separate auditable run. Existing VulZoo CVEs, CVSS, KEV, CWE and CPE observations remain unchanged.

## Approved command

Initialise the existing database once to apply migration 004, then execute the separately approved
acquisition manifest and profile report:

```powershell
python -m thesis_pipeline.cli init-db `
    --path "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite"

python -m thesis_pipeline.cli ingest-diversevul `
    --config configs/data_sources.yaml `
    --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" `
    --acquisition-manifest "$env:THESIS_DATA_ROOT\DiverseVul\manifests\APPROVED.json" `
    --profile-report outputs/APPROVED-DIVERSEVUL-PROFILE.json `
    --progress-every 25000
```

The command writes a metadata-only summary to stdout and progress updates to stderr. Redirect
the summary only to ignored `outputs/`. Acceptance requires all 330,492 function rows, the
approved 18,945/311,547 label split, preservation of the empty-source record, unchanged VulZoo CVE
counts, bounded unresolved identities, valid canonical-CVE foreign keys and no raw source
persistence.
