PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

DROP INDEX uq_cvss_observation_natural;

CREATE UNIQUE INDEX uq_cvss_observation_natural
ON cvss_observation(
    cve_id,
    version,
    COALESCE(vector, ''),
    observed_at_utc,
    source_name,
    COALESCE(metric_source, ''),
    COALESCE(metric_type, ''),
    COALESCE(source_snapshot_id, '')
);

ALTER TABLE cve_cpe RENAME TO cve_cpe_previous;

CREATE TABLE cve_cpe (
    cve_cpe_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    cpe_id TEXT NOT NULL REFERENCES cpe(cpe_id),
    vulnerable INTEGER NOT NULL CHECK (vulnerable IN (0, 1)),
    criteria_id TEXT,
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    observed_at_utc TEXT NOT NULL,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshot(source_snapshot_id),
    ingestion_run_id TEXT NOT NULL REFERENCES ingestion_run(ingestion_run_id),
    created_at_utc TEXT NOT NULL
);

INSERT INTO cve_cpe(
    cve_cpe_id, cve_id, cpe_id, vulnerable, criteria_id,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding, observed_at_utc,
    source_name, retrieved_at_utc, source_snapshot_id, ingestion_run_id, created_at_utc
)
SELECT
    cve_cpe_id, cve_id, cpe_id, vulnerable, criteria_id,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding, observed_at_utc,
    source_name, retrieved_at_utc, source_snapshot_id, ingestion_run_id, created_at_utc
FROM cve_cpe_previous;

DROP TABLE cve_cpe_previous;

CREATE UNIQUE INDEX uq_cve_cpe_natural
ON cve_cpe(
    cve_id,
    cpe_id,
    vulnerable,
    COALESCE(criteria_id, ''),
    COALESCE(version_start_including, ''),
    COALESCE(version_start_excluding, ''),
    COALESCE(version_end_including, ''),
    COALESCE(version_end_excluding, ''),
    observed_at_utc,
    source_name,
    source_snapshot_id
);

CREATE INDEX ix_cve_cpe_cve ON cve_cpe(cve_id);
CREATE INDEX ix_cve_cpe_cpe ON cve_cpe(cpe_id);

INSERT INTO schema_version(version, applied_at_utc, source)
VALUES (
    3,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    'schemas/003_ingestion_observation_identity.sql'
);

COMMIT;
