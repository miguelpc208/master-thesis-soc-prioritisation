PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE epss_panel_ingestion (
    epss_panel_ingestion_id TEXT PRIMARY KEY,
    panel_fingerprint_sha256 TEXT NOT NULL,
    first_score_date TEXT NOT NULL,
    last_score_date TEXT NOT NULL,
    expected_days INTEGER NOT NULL CHECK (expected_days > 0),
    completed_days INTEGER NOT NULL DEFAULT 0
        CHECK (completed_days >= 0 AND completed_days <= expected_days),
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    started_at_utc TEXT NOT NULL,
    completed_at_utc TEXT,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE epss_panel_ingestion_day (
    epss_panel_ingestion_id TEXT NOT NULL,
    score_date TEXT NOT NULL,
    source_snapshot_id TEXT NOT NULL,
    ingestion_run_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    created_at_utc TEXT NOT NULL,
    completed_at_utc TEXT,
    PRIMARY KEY (epss_panel_ingestion_id, score_date),
    FOREIGN KEY (epss_panel_ingestion_id)
        REFERENCES epss_panel_ingestion(epss_panel_ingestion_id),
    FOREIGN KEY (source_snapshot_id) REFERENCES source_snapshot(source_snapshot_id),
    FOREIGN KEY (ingestion_run_id) REFERENCES ingestion_run(ingestion_run_id)
);

CREATE INDEX ix_epss_complete_panel_date
ON epss_panel_ingestion(status, last_score_date, panel_fingerprint_sha256);

CREATE INDEX ix_epss_complete_panel_day
ON epss_panel_ingestion_day(status, score_date, source_snapshot_id);

INSERT INTO schema_version(version, applied_at_utc, source)
VALUES (
    10,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    'schemas/010_epss_panel_completion.sql'
);

COMMIT;
