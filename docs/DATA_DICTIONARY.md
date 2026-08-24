# Data dictionary

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

See `schemas/logical_data_model.md` and the numbered files under `schemas/` for the broader Phase 3
schema.

## Phase 3 vulnerability-intelligence fields

| Field | Type | Meaning |
| --- | --- | --- |
| `source_snapshot_id` | string FK | Exact source/checksum identity shared by imported records |
| `ingestion_run_id` | string FK | Deterministic ingestion execution that accepted the record |
| `vulnerability_status` | nullable string | NVD `vulnStatus`; no inferred replacement when absent |
| `observed_at_utc` | UTC datetime | Earliest conservative time at which the stored observation may be used |
| `metric_source`, `metric_type` | nullable string | NVD CVSS provider and metric classification |
| `base_score` | nullable float 0–10 | Stored CVSS value; missing is never converted to zero |
| `base_severity` | nullable string | Source-reported CVSS severity label |
| `exploitability_score` | nullable float | Source-reported CVSS exploitability component |
| `impact_score` | nullable float | Source-reported CVSS impact component |
| `date_added` | date | CISA KEV membership effective date |
| `catalogue_date` | date | Dated KEV catalogue version containing the observation |
| `vulnerable` | boolean | NVD CPE match flag; does not by itself prove asset exposure |
| `source_path` | string | Exact ordered path of an NVD configuration node or CPE match |
| `parent_node_id` | nullable string FK | Parent required to reconstruct the NVD applicability tree |
| `logical_operator` | nullable enum | Source-provided `AND` or `OR`; null only when the source omits it |
| `negate` | nullable boolean | Source-provided logical negation; null only when omitted |
| `node_kind` | enum | Top-level `configuration` or nested logical `node` |

See `VULNERABILITY_INGESTION_CONTRACT.md` for precedence, temporal and rejection rules.

## DiverseVul function-research fields

| Field | Type | Meaning |
| --- | --- | --- |
| `diversevul_commit_id` | string PK | Deterministic approved-snapshot/project/commit identity |
| `commit_sha` | string | Validated Git commit identifier; origin is recorded separately |
| `commit_identity_source` | enum | `metadata_commit_id` or unambiguous `metadata_commit_url` recovery |
| `declared_cve_ids_json` | JSON array | CVEs found only in the metadata row's explicit `CVE` field |
| `declared_cwe_ids_json` | JSON array | Valid CWE identifiers found in the metadata `CWE` field |
| `source_line_number` | integer | One-based source JSONL line; no raw function text is copied |
| `source_function_hash` | string | Dataset-reported integer function hash preserved without overflow |
| `function_sha256` | nullable SHA-256 | Hash of UTF-8 function source; null for the empty function |
| `function_size_bytes` | integer | UTF-8 byte length; zero identifies the retained empty function |
| `source_reported_size` | nullable integer | Upstream size annotation without inferred replacement |
| `vulnerability_label` | boolean | Upstream research target label; not proof of exploitation or exposure |
| `cwe_ids_json` | JSON array | Valid CWE identifiers supplied by the function-level source row |
| `commit_message_sha256` | SHA-256 | Message digest; raw commit messages are not persisted |
| `evidence_source` | enum | `metadata_cve_field` or separately traceable `commit_message` |

Each `diversevul_function_cve.cve_id` must already exist in the canonical VulZoo `cve` table.
Unknown CVEs are bounded rejections, never fabricated canonical records. See
`DIVERSEVUL_INGESTION_CONTRACT.md` for label limitations and exact matching rules.
