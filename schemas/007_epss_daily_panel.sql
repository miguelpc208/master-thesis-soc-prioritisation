PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE INDEX ix_epss_score_date_cve
ON epss_observation(score_date, cve_id);

CREATE TRIGGER enforce_epss_observation_insert
BEFORE INSERT ON epss_observation
BEGIN
    SELECT CASE
        WHEN NEW.source_name <> 'first_epss'
            THEN RAISE(ABORT, 'EPSS source must be first_epss')
        WHEN NEW.score IS NULL OR typeof(NEW.score) NOT IN ('integer', 'real')
             OR NEW.score < 0 OR NEW.score > 1
            THEN RAISE(ABORT, 'EPSS probability must be between zero and one')
        WHEN NEW.percentile IS NULL OR typeof(NEW.percentile) NOT IN ('integer', 'real')
             OR NEW.percentile < 0 OR NEW.percentile > 1
            THEN RAISE(ABORT, 'EPSS percentile must be between zero and one')
        WHEN NEW.score_date IS NULL OR length(NEW.score_date) <> 10
             OR date(NEW.score_date) IS NULL OR date(NEW.score_date) <> NEW.score_date
            THEN RAISE(ABORT, 'EPSS score date must be an ISO calendar date')
        WHEN NEW.model_version IS NULL OR trim(NEW.model_version) = ''
            THEN RAISE(ABORT, 'EPSS model version must be preserved')
        WHEN NEW.source_snapshot_id IS NULL OR NEW.ingestion_run_id IS NULL
            THEN RAISE(ABORT, 'EPSS observations require snapshot and run provenance')
        WHEN NOT EXISTS (
            SELECT 1
            FROM source_snapshot
            WHERE source_snapshot_id = NEW.source_snapshot_id
              AND source_name = 'first_epss'
              AND source_version = NEW.model_version
              AND snapshot_date = NEW.score_date
              AND retrieved_at_utc = NEW.retrieved_at_utc
        )
            THEN RAISE(ABORT, 'EPSS snapshot does not match score provenance')
        WHEN NOT EXISTS (
            SELECT 1
            FROM ingestion_run
            WHERE ingestion_run_id = NEW.ingestion_run_id
              AND source_snapshot_id = NEW.source_snapshot_id
        )
            THEN RAISE(ABORT, 'EPSS ingestion run does not match its snapshot')
    END;
END;

CREATE TRIGGER enforce_epss_observation_update
BEFORE UPDATE ON epss_observation
BEGIN
    SELECT CASE
        WHEN NEW.source_name <> 'first_epss'
            THEN RAISE(ABORT, 'EPSS source must be first_epss')
        WHEN NEW.score IS NULL OR typeof(NEW.score) NOT IN ('integer', 'real')
             OR NEW.score < 0 OR NEW.score > 1
            THEN RAISE(ABORT, 'EPSS probability must be between zero and one')
        WHEN NEW.percentile IS NULL OR typeof(NEW.percentile) NOT IN ('integer', 'real')
             OR NEW.percentile < 0 OR NEW.percentile > 1
            THEN RAISE(ABORT, 'EPSS percentile must be between zero and one')
        WHEN NEW.score_date IS NULL OR length(NEW.score_date) <> 10
             OR date(NEW.score_date) IS NULL OR date(NEW.score_date) <> NEW.score_date
            THEN RAISE(ABORT, 'EPSS score date must be an ISO calendar date')
        WHEN NEW.model_version IS NULL OR trim(NEW.model_version) = ''
            THEN RAISE(ABORT, 'EPSS model version must be preserved')
        WHEN NEW.source_snapshot_id IS NULL OR NEW.ingestion_run_id IS NULL
            THEN RAISE(ABORT, 'EPSS observations require snapshot and run provenance')
        WHEN NOT EXISTS (
            SELECT 1
            FROM source_snapshot
            WHERE source_snapshot_id = NEW.source_snapshot_id
              AND source_name = 'first_epss'
              AND source_version = NEW.model_version
              AND snapshot_date = NEW.score_date
              AND retrieved_at_utc = NEW.retrieved_at_utc
        )
            THEN RAISE(ABORT, 'EPSS snapshot does not match score provenance')
        WHEN NOT EXISTS (
            SELECT 1
            FROM ingestion_run
            WHERE ingestion_run_id = NEW.ingestion_run_id
              AND source_snapshot_id = NEW.source_snapshot_id
        )
            THEN RAISE(ABORT, 'EPSS ingestion run does not match its snapshot')
    END;
END;

INSERT INTO schema_version(version, applied_at_utc, source)
VALUES (
    7,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    'schemas/007_epss_daily_panel.sql'
);

COMMIT;
