# Technical evidence temporal contract

This contract defines how the integrated VulZoo and DiverseVul database may be queried at a
decision-time cut-off. It prevents later evidence from leaking into earlier decisions. It does not
turn a single retained snapshot into a complete historical panel.

## Three distinct times

Every external observation must keep these concepts separate:

1. **Effective time** — when the source says the fact applies, such as KEV `dateAdded` or an EPSS
   score date.
2. **Source-observed time** — the version timestamp of the retained source record or catalogue,
   such as NVD `lastModified` or the KEV catalogue date.
3. **Local retrieval time** — when the approved file became available to this project.

The `technical_evidence_availability` view exposes these times, plus two explicitly different
availability cut-offs. `evidence_time_policy` records the field-level semantics and history status
for every evidence kind.

## Approved as-of modes

### `strict_snapshot`

Evidence is eligible only when its strict availability timestamp is at or before the decision
cut-off. This timestamp is normally the later of the source-observed and local retrieval times.
Consequently, the current VulZoo observations cannot be treated as locally available before the
approved 2026-08-14 retrieval, even when their source dates are older.

This mode proves what the project could have seen from its retained snapshots. It does not prove
the exact state an external user would have seen on an earlier historical date.

### `source_effective_reconstruction`

Evidence is filtered by the conservative source-effective rule recorded for its type. For example,
KEV membership becomes eligible at 23:59:59 UTC on `dateAdded`, while the retained NVD CVSS and CPE
rows become eligible only at their `lastModified` observation time. DiverseVul labels have no
verified source time and therefore remain unavailable until local retrieval.

This mode is an engineering reconstruction. Because the database holds one VulZoo snapshot rather
than every historical version, it must never be described as exact historical ground truth.

## Source-specific rules

| Evidence | Effective time | Source-observed time | Strict availability | History status |
| --- | --- | --- | --- | --- |
| Canonical CVE row | NVD/CVE publication | Last modification, then publication fallback | Later of source observation and retrieval | Single snapshot |
| NVD CVSS | CVE `lastModified` | CVE `lastModified` | Later of observation and retrieval | Single snapshot |
| CISA KEV membership | `dateAdded` at UTC day end | Catalogue date at UTC day end | Later of catalogue date and retrieval | Single snapshot |
| NVD CPE configuration match | CVE `lastModified` | CVE `lastModified` | Later of observation and retrieval | Single snapshot |
| DiverseVul label | Unknown | Unknown | Local retrieval | Unknown snapshot date |
| FIRST EPSS score | Score date at UTC day end | Score date at UTC day end | Later of score date and retrieval | Daily panel required |
| Verified GitHub advisory | GHSA publication | Retained GHSA modification | Later of `max(publication, modification)` and collection retrieval | Single snapshot |
| GHSA fixed-version event | `max(GHSA publication, modification)` | Retained GHSA modification | Later of source availability and collection retrieval | Single snapshot |
| Corroborated patch commit | Matching GHSA source availability, otherwise unknown | Matching GHSA source availability, otherwise unknown | Later of verified anchor and collection retrieval | Single snapshot |

Date-only evidence is placed at 23:59:59 UTC, rather than at the start of the day, so a decision
cannot see a fact earlier than the source precision supports.

## Operational boundary

- CVSS, KEV and dated EPSS observations may support prioritisation only after the selected as-of
  rule admits them.
- CPE configuration matches support applicability evaluation only after admission and after a
  separate CMDB matcher proves the asset/product/version conditions.
- DiverseVul labels are offline research annotations. They are never live threat intelligence,
  exploit proof or business context.
- Advisory/package metadata supports bounded remediation context only after the later of retained
  GHSA publication and modification. A fixed version does not prove a deployed fix or actual asset
  applicability.
- Corroborated commit URLs without an exact same-CVE match in an accepted advisory remain undated
  and are excluded from historical reconstruction rather than inheriting an invented timestamp.
- The audit filters and counts evidence; the current synthetic E1/E2 simulator is not yet wired to
  the real SQLite observations.

## Read-only audit

After applying migration 006, run:

```powershell
python -m thesis_pipeline.cli audit-technical-as-of `
    --database "$env:THESIS_DATA_ROOT\databases\vulzoo-ingestion.sqlite" `
    --decision-at "2026-08-24T23:59:59Z" `
    --mode strict_snapshot
```

The JSON report contains no raw source records and is generated through a read-only SQLite
connection. It records the cut-off, mode, policy, source snapshots, per-evidence eligibility counts,
limitations and a deterministic SHA-256 fingerprint. Reports belong under ignored `outputs/`.

## Claim boundary

FIRST EPSS supplies a complete active dated panel for 2025-03-21 through 2025-04-04, covering the
scenario starting on 2025-03-22. The superseded 2025-12-31 through 2026-01-14 panel remains in the
database as immutable provenance but is ineligible at the earlier March decision cut-offs. NVD and
KEV remain single retained snapshots, so neither mode establishes exact historical ground truth
across all evidence. All experiments must record their mode, cut-off and approved EPSS model
version. Approved GitHub advisories are likewise one retained snapshot, not a complete historical
advisory-version panel. See [EPSS_INGESTION_CONTRACT.md](EPSS_INGESTION_CONTRACT.md) and
[GITHUB_ADVISORY_REMEDIATION_CONTRACT.md](GITHUB_ADVISORY_REMEDIATION_CONTRACT.md).
