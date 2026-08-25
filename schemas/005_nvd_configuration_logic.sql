PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE cve_configuration_node (
    cve_configuration_node_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    parent_node_id TEXT,
    node_kind TEXT NOT NULL CHECK (node_kind IN ('configuration', 'node')),
    source_path TEXT NOT NULL,
    depth INTEGER NOT NULL CHECK (depth >= 0),
    sibling_position INTEGER NOT NULL CHECK (sibling_position >= 0),
    logical_operator TEXT CHECK (logical_operator IS NULL OR logical_operator IN ('AND', 'OR')),
    negate INTEGER CHECK (negate IS NULL OR negate IN (0, 1)),
    observed_at_utc TEXT NOT NULL,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshot(source_snapshot_id),
    ingestion_run_id TEXT NOT NULL REFERENCES ingestion_run(ingestion_run_id),
    created_at_utc TEXT NOT NULL,
    CHECK (
        (node_kind = 'configuration' AND parent_node_id IS NULL AND depth = 0)
        OR
        (node_kind = 'node' AND parent_node_id IS NOT NULL AND depth > 0)
    ),
    UNIQUE (source_snapshot_id, cve_id, source_path),
    FOREIGN KEY (parent_node_id)
        REFERENCES cve_configuration_node(cve_configuration_node_id)
);

CREATE TABLE cve_configuration_match (
    cve_configuration_match_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    cve_configuration_node_id TEXT NOT NULL
        REFERENCES cve_configuration_node(cve_configuration_node_id),
    cve_cpe_id TEXT NOT NULL REFERENCES cve_cpe(cve_cpe_id),
    source_path TEXT NOT NULL,
    match_position INTEGER NOT NULL CHECK (match_position >= 0),
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshot(source_snapshot_id),
    ingestion_run_id TEXT NOT NULL REFERENCES ingestion_run(ingestion_run_id),
    created_at_utc TEXT NOT NULL,
    UNIQUE (source_snapshot_id, cve_id, source_path)
);

CREATE TRIGGER validate_cve_configuration_node_context
BEFORE INSERT ON cve_configuration_node
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM ingestion_run AS run
            WHERE run.ingestion_run_id = NEW.ingestion_run_id
              AND run.source_snapshot_id = NEW.source_snapshot_id
        )
        THEN RAISE(ABORT, 'configuration node ingestion run does not match snapshot')
    END;
    SELECT CASE
        WHEN NEW.parent_node_id IS NOT NULL AND NOT EXISTS (
            SELECT 1
            FROM cve_configuration_node AS parent
            WHERE parent.cve_configuration_node_id = NEW.parent_node_id
              AND parent.cve_id = NEW.cve_id
              AND parent.source_snapshot_id = NEW.source_snapshot_id
        )
        THEN RAISE(ABORT, 'configuration node parent does not match CVE snapshot')
    END;
END;

CREATE TRIGGER validate_cve_configuration_match_context
BEFORE INSERT ON cve_configuration_match
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM ingestion_run AS run
            WHERE run.ingestion_run_id = NEW.ingestion_run_id
              AND run.source_snapshot_id = NEW.source_snapshot_id
        )
        THEN RAISE(ABORT, 'configuration match ingestion run does not match snapshot')
    END;
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM cve_configuration_node AS node
            WHERE node.cve_configuration_node_id = NEW.cve_configuration_node_id
              AND node.cve_id = NEW.cve_id
              AND node.source_snapshot_id = NEW.source_snapshot_id
        )
        THEN RAISE(ABORT, 'configuration match node does not match CVE snapshot')
    END;
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM cve_cpe AS mapping
            WHERE mapping.cve_cpe_id = NEW.cve_cpe_id
              AND mapping.cve_id = NEW.cve_id
              AND mapping.source_snapshot_id = NEW.source_snapshot_id
        )
        THEN RAISE(ABORT, 'configuration match CPE does not match CVE snapshot')
    END;
END;

CREATE INDEX ix_cve_configuration_node_cve
ON cve_configuration_node(cve_id, source_snapshot_id);

CREATE INDEX ix_cve_configuration_node_parent
ON cve_configuration_node(parent_node_id);

CREATE INDEX ix_cve_configuration_match_cpe
ON cve_configuration_match(cve_cpe_id);

INSERT INTO schema_version(version, applied_at_utc, source)
VALUES (
    5,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    'schemas/005_nvd_configuration_logic.sql'
);

COMMIT;
