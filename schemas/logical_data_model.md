# Logical data model

SQLite migration `001_initial.sql` establishes the base schema. Migration
`002_vulnerability_ingestion.sql` adds the source-snapshot, ingestion-run and rejection contracts,
normalised CVE-to-CWE/CPE relations, and the additional NVD/KEV fields required by Phase 3.
`003_ingestion_observation_identity.sql` extends CVSS natural keys with provider/type and CPE
relationship natural keys with criteria/version bounds, preserving distinct observations. Applied
migrations are immutable and recorded in
`schema_version`; database initialisation safely skips versions already present. Every table has a
primary key. Source-derived tables retain provenance
and retrieval/effective timestamps; synthetic and workflow tables retain a scenario/run identity
and creation timestamps. Null means unavailable or not applicable and must never be silently
converted to zero/false.

| Domain | Entities |
| --- | --- |
| Ingestion provenance | `source_snapshot`, `ingestion_run`, `ingestion_rejection` |
| Vulnerability intelligence | `cve`, `cvss_observation`, `epss_observation`, `kev_observation`, `cwe`, `cpe`, `cve_cwe`, `cve_cpe`, `exploit_reference`, `patch_reference`, `attack_mapping` |
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
