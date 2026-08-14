# Phase 2 data dictionary

Null means unavailable/not applicable, never zero or false. External observations require source,
retrieval timestamp, effective/as-of date, and checksum or snapshot identity.

## Synthetic finding fields

| Field | Type | Meaning |
| --- | --- | --- |
| `finding_id` | string PK | Synthetic finding identifier |
| `correlation_key` | string | Synthetic CVE/asset grouping key |
| `cve_id` | string | `CVE-SYNTH-*`; never presented as a real CVE |
| `asset_id`, `service_id`, `team_id` | string FK-like | Fictional organisational mapping |
| `finding_created` | UTC datetime | Earliest lifecycle timestamp |
| `cvss` | float 0–10 | Synthetic technical severity proxy |
| `epss_probability` | float 0–1 | Synthetic enrichment used only for plumbing |
| `epss_observed_at` | UTC datetime | Availability timestamp used by temporal guard |
| `kev` | boolean | Synthetic known-exploitation flag |
| `kev_observed_at` | UTC datetime | Availability timestamp used by temporal guard |
| `actionable` | boolean | Synthetic independent evaluation proxy; not actual exploitation |
| `risk_weight` | float | Transparent synthetic exposure-weighting proxy |

## Workflow fields

The required lifecycle is `finding_created → alert_created → correlated → assigned →
triage_started → triage_completed → decision → remediation_started → remediation_completed`.
Records also retain priority rank, analyst/remediator ID, and SLA deadline.

## Metric semantics

- Cycle times use hours and UTC timestamps.
- Completed-only remediation mean states its censoring in the metric name.
- SLA rate denominator includes completed cases or cases whose deadline has elapsed by the horizon.
- Utilisation values are simulation proxies, not observed staff productivity.
- Ranking labels are synthetic and support engineering checks only.

See `schemas/logical_data_model.md` and `schemas/001_initial.sql` for the broader Phase 3 schema.

