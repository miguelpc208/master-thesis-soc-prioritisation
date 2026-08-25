# Logical data model

SQLite migration `001_initial.sql` establishes the base schema. Migration
`002_vulnerability_ingestion.sql` adds the source-snapshot, ingestion-run and rejection contracts,
normalised CVE-to-CWE/CPE relations, and the additional NVD/KEV fields required by Phase 3.
`003_ingestion_observation_identity.sql` extends CVSS natural keys with provider/type and CPE
relationship natural keys with criteria/version bounds, preserving distinct observations.
`004_diversevul_integration.sql` adds pinned research-commit metadata, function-label metadata and
evidence-qualified associations to existing canonical CVEs without copying source-code bodies.
`005_nvd_configuration_logic.sql` preserves the ordered NVD applicability tree, including parent
relationships, `AND`/`OR` operators, negation and the exact node containing each CPE match.
`006_temporal_evidence_contract.sql` adds EPSS snapshot/run provenance, a versioned evidence-time
policy and a normalized availability view for strict-snapshot and source-effective as-of queries.
`007_epss_daily_panel.sql` enforces valid EPSS probabilities and percentiles, dated source-snapshot
coherence, ingestion-run ownership and indexed score-date lookups.
`008_github_advisory_remediation.sql` adds normalized authoritative GHSA metadata, canonical CVE
alias links, affected packages, ordered version events and corroborated same-CVE patch commits,
with separate source/run provenance and conservative temporal-availability policies.
`009_advisory_source_availability.sql` preserves authoritative GHSA publication/modification
ordering, adds their conservative maximum as source availability and permits a later accepted
same-CVE advisory to re-anchor an existing undated commit without duplicating the reference.
Applied migrations are immutable and recorded in `schema_version`; database initialisation safely
skips versions already present. Every table has a primary key. Source-derived tables retain provenance
and retrieval/effective timestamps; synthetic and workflow tables retain a scenario/run identity
and creation timestamps. Null means unavailable or not applicable and must never be silently
converted to zero/false.

| Domain | Entities |
| --- | --- |
| Ingestion provenance and time policy | `source_snapshot`, `ingestion_run`, `ingestion_rejection`, `evidence_time_policy`, `technical_evidence_availability` view |
| Vulnerability intelligence | `cve`, `cvss_observation`, `epss_observation`, `kev_observation`, `cwe`, `cpe`, `cve_cwe`, `cve_cpe`, `cve_configuration_node`, `cve_configuration_match`, `exploit_reference`, `patch_reference`, `attack_mapping` |
| Advisory and remediation metadata | `github_advisory`, `github_advisory_cve`, `github_advisory_package`, `github_advisory_affected_version`, `github_advisory_version_event` |
| Function-level research labels | `diversevul_commit`, `diversevul_function`, `diversevul_function_cve` |
| Organisation | `department`, `business_service`, `application`, `asset`, `asset_service_map`, `data_classification`, `regulatory_scope`, `owner_team` |
| Findings/workflow | `vulnerability_finding`, `alert`, `case_ticket`, `triage_action`, `remediation_action`, `risk_acceptance`, `maintenance_window` |
| Capacity/simulation | `team`, `analyst`, `capacity_calendar`, `scenario`, `simulation_run`, `simulation_event`, `queue_snapshot` |
| Decisions/evaluation | `priority_decision`, `decision_explanation`, `experiment_run`, `run_manifest`, `metric_result` |
| Optional AI | `ai_request`, `ai_response`, `human_review` |
| Optional honeypot | `honeypot_scenario`, `honeypot_event`, `dynamic_exploit_evidence` |

Key relationships centre on CVE and organisational asset/service ownership. Vulnerability findings
join CVE to assets. Alerts/cases/actions form the operational lifecycle. Decisions retain policy,
score/evidence JSON, and the decision timestamp. External observations are append-only and resolved
with `observed_at <= decision_at`.

`source_snapshot` identifies the exact external snapshot independently of a run.
`ingestion_run` records a deterministic input fingerprint and accepted/rejected counts. Rejections
retain only relative paths, identifiers, reason codes and hashes; raw rejected records are not
copied into the database.

`cve_configuration_node` reconstructs the ordered NVD applicability tree for one CVE and source
snapshot. `cve_configuration_match` attaches each source occurrence to the corresponding
normalised `cve_cpe` relationship. The tree preserves source logic but does not itself prove that
an organisational asset has the product and version required by that logic.

`diversevul_commit` stores exact project/commit identities and field-authoritative CVEs.
`diversevul_function` stores one research-labelled source locator, bounded annotations and function
hash per approved JSONL record; raw source text never enters SQLite. `diversevul_function_cve`
references existing `cve.cve_id` values only and distinguishes explicit metadata-field evidence
from explicit commit-message evidence. Labels and associations do not establish exploitability,
asset applicability, business impact or decision-time availability.

`technical_evidence_availability` does not copy observations. It projects each retained CVE, CVSS,
KEV membership, CPE configuration occurrence, DiverseVul label, retained EPSS score, accepted GHSA
link, GHSA fixed-version event and corroborated patch commit onto effective, source-observed,
local-retrieval, strict-availability and reconstruction-availability timestamps. Undated commits
never receive a fabricated historical timestamp. Queries must filter the selected availability
field at or before `priority_decision.decision_at_utc`. Single-snapshot reconstruction remains
version-incomplete even when the date filter passes.

`epss_observation` retains one date-pinned probability and percentile per canonical CVE and
approved model/source snapshot. Each compressed FIRST daily file has its own `source_snapshot` and
transactional `ingestion_run`. Valid upstream CVEs absent from the pinned VulZoo catalogue remain
outside scope rather than becoming synthetic canonical vulnerabilities or data-quality rejections.

`github_advisory` retains bounded identity, publication/modification/source-availability time,
source path/hash and
snapshot/run provenance. `github_advisory_cve` requires an existing canonical CVE and an
authoritative matching source alias. The package, affected-version and ordered range-event tables
retain remediation metadata without copying advisory descriptions. `patch_reference` accepts an
exact same-CVE full commit hash and direct commit URL only; an identical URL in an accepted GHSA
can provide a conservative `max(publication, modification)` anchor, while other commits remain
undated.
