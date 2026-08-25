PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

ALTER TABLE epss_observation ADD COLUMN source_snapshot_id TEXT
    REFERENCES source_snapshot(source_snapshot_id);
ALTER TABLE epss_observation ADD COLUMN ingestion_run_id TEXT
    REFERENCES ingestion_run(ingestion_run_id);

CREATE TABLE evidence_time_policy (
    evidence_kind TEXT PRIMARY KEY,
    source_name TEXT NOT NULL,
    operational_role TEXT NOT NULL CHECK (
        operational_role IN ('catalogue', 'prioritisation', 'applicability', 'offline_label')
    ),
    effective_time_semantics TEXT NOT NULL,
    source_observed_time_semantics TEXT NOT NULL,
    strict_availability_semantics TEXT NOT NULL,
    reconstruction_availability_semantics TEXT NOT NULL,
    history_status TEXT NOT NULL CHECK (
        history_status IN ('single_snapshot', 'unknown_snapshot', 'daily_panel')
    ),
    created_at_utc TEXT NOT NULL
);

INSERT INTO evidence_time_policy(
    evidence_kind,
    source_name,
    operational_role,
    effective_time_semantics,
    source_observed_time_semantics,
    strict_availability_semantics,
    reconstruction_availability_semantics,
    history_status,
    created_at_utc
) VALUES
    (
        'cve_record',
        'nvd_or_legacy_cve',
        'catalogue',
        'published_at_utc',
        'modified_at_utc, falling back to published_at_utc',
        'later of source-observed and local retrieval timestamps',
        'source-observed timestamp because only the retained row version is known',
        'single_snapshot',
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    (
        'cvss',
        'nvd',
        'prioritisation',
        'NVD CVE lastModified represented by observed_at_utc',
        'observed_at_utc',
        'later of observed_at_utc and retrieved_at_utc',
        'observed_at_utc',
        'single_snapshot',
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    (
        'kev_membership',
        'cisa_kev',
        'prioritisation',
        'date_added at conservative end of UTC day',
        'catalogue_date at conservative end of UTC day',
        'later of catalogue date and local retrieval timestamp',
        'date_added at conservative end of UTC day',
        'single_snapshot',
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    (
        'cpe_configuration_match',
        'nvd',
        'applicability',
        'NVD CVE lastModified represented by observed_at_utc',
        'observed_at_utc',
        'later of observed_at_utc and retrieved_at_utc',
        'observed_at_utc',
        'single_snapshot',
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    (
        'diversevul_label',
        'diversevul',
        'offline_label',
        'unknown; filename token is not temporal evidence',
        'unknown',
        'local retrieval timestamp',
        'local retrieval timestamp',
        'unknown_snapshot',
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ),
    (
        'epss_score',
        'first_epss',
        'prioritisation',
        'score_date at conservative end of UTC day',
        'score_date at conservative end of UTC day',
        'later of score date and local retrieval timestamp',
        'score date at conservative end of UTC day',
        'daily_panel',
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    );

CREATE VIEW technical_evidence_availability AS
SELECT
    'cve_record' AS evidence_kind,
    cve.cve_id AS evidence_id,
    cve.cve_id AS cve_id,
    cve.published_at_utc AS effective_at_utc,
    COALESCE(cve.modified_at_utc, cve.published_at_utc, cve.retrieved_at_utc)
        AS source_observed_at_utc,
    cve.retrieved_at_utc AS retrieved_at_utc,
    CASE
        WHEN COALESCE(cve.modified_at_utc, cve.published_at_utc, cve.retrieved_at_utc)
            > cve.retrieved_at_utc
        THEN COALESCE(cve.modified_at_utc, cve.published_at_utc, cve.retrieved_at_utc)
        ELSE cve.retrieved_at_utc
    END AS strict_available_at_utc,
    COALESCE(cve.modified_at_utc, cve.published_at_utc, cve.retrieved_at_utc)
        AS reconstruction_available_at_utc,
    cve.source_snapshot_id AS source_snapshot_id,
    policy.operational_role AS operational_role,
    policy.history_status AS history_status
FROM cve
JOIN evidence_time_policy AS policy
  ON policy.evidence_kind = 'cve_record'
WHERE cve.source_snapshot_id IS NOT NULL

UNION ALL

SELECT
    'cvss',
    cvss.cvss_observation_id,
    cvss.cve_id,
    cvss.observed_at_utc,
    cvss.observed_at_utc,
    cvss.retrieved_at_utc,
    CASE
        WHEN cvss.observed_at_utc > cvss.retrieved_at_utc
        THEN cvss.observed_at_utc
        ELSE cvss.retrieved_at_utc
    END,
    cvss.observed_at_utc,
    cvss.source_snapshot_id,
    policy.operational_role,
    policy.history_status
FROM cvss_observation AS cvss
JOIN evidence_time_policy AS policy
  ON policy.evidence_kind = 'cvss'
WHERE cvss.source_snapshot_id IS NOT NULL

UNION ALL

SELECT
    'kev_membership',
    kev.kev_observation_id,
    kev.cve_id,
    kev.date_added || 'T23:59:59Z',
    kev.catalogue_date || 'T23:59:59Z',
    kev.retrieved_at_utc,
    CASE
        WHEN kev.catalogue_date || 'T23:59:59Z' > kev.retrieved_at_utc
        THEN kev.catalogue_date || 'T23:59:59Z'
        ELSE kev.retrieved_at_utc
    END,
    kev.date_added || 'T23:59:59Z',
    kev.source_snapshot_id,
    policy.operational_role,
    policy.history_status
FROM kev_observation AS kev
JOIN evidence_time_policy AS policy
  ON policy.evidence_kind = 'kev_membership'
WHERE kev.source_snapshot_id IS NOT NULL

UNION ALL

SELECT
    'cpe_configuration_match',
    configuration_match.cve_configuration_match_id,
    configuration_match.cve_id,
    mapping.observed_at_utc,
    mapping.observed_at_utc,
    mapping.retrieved_at_utc,
    CASE
        WHEN mapping.observed_at_utc > mapping.retrieved_at_utc
        THEN mapping.observed_at_utc
        ELSE mapping.retrieved_at_utc
    END,
    mapping.observed_at_utc,
    configuration_match.source_snapshot_id,
    policy.operational_role,
    policy.history_status
FROM cve_configuration_match AS configuration_match
JOIN cve_cpe AS mapping
  ON mapping.cve_cpe_id = configuration_match.cve_cpe_id
JOIN evidence_time_policy AS policy
  ON policy.evidence_kind = 'cpe_configuration_match'

UNION ALL

SELECT
    'diversevul_label',
    function.diversevul_function_id,
    NULL,
    NULL,
    NULL,
    snapshot.retrieved_at_utc,
    snapshot.retrieved_at_utc,
    snapshot.retrieved_at_utc,
    function.source_snapshot_id,
    policy.operational_role,
    policy.history_status
FROM diversevul_function AS function
JOIN source_snapshot AS snapshot
  ON snapshot.source_snapshot_id = function.source_snapshot_id
JOIN evidence_time_policy AS policy
  ON policy.evidence_kind = 'diversevul_label'

UNION ALL

SELECT
    'epss_score',
    epss.epss_observation_id,
    epss.cve_id,
    epss.score_date || 'T23:59:59Z',
    epss.score_date || 'T23:59:59Z',
    epss.retrieved_at_utc,
    CASE
        WHEN epss.score_date || 'T23:59:59Z' > epss.retrieved_at_utc
        THEN epss.score_date || 'T23:59:59Z'
        ELSE epss.retrieved_at_utc
    END,
    epss.score_date || 'T23:59:59Z',
    epss.source_snapshot_id,
    policy.operational_role,
    policy.history_status
FROM epss_observation AS epss
JOIN evidence_time_policy AS policy
  ON policy.evidence_kind = 'epss_score'
WHERE epss.source_snapshot_id IS NOT NULL;

CREATE INDEX ix_epss_cve_score_date
ON epss_observation(cve_id, score_date);

CREATE UNIQUE INDEX uq_epss_observation_natural
ON epss_observation(
    cve_id,
    score_date,
    COALESCE(model_version, ''),
    source_name,
    COALESCE(source_snapshot_id, '')
);

INSERT INTO schema_version(version, applied_at_utc, source)
VALUES (
    6,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    'schemas/006_temporal_evidence_contract.sql'
);

COMMIT;
