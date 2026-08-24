PRAGMA foreign_keys = ON;

BEGIN IMMEDIATE;

CREATE TABLE diversevul_commit (
    diversevul_commit_id TEXT PRIMARY KEY,
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshot(source_snapshot_id),
    ingestion_run_id TEXT NOT NULL REFERENCES ingestion_run(ingestion_run_id),
    project TEXT NOT NULL CHECK (length(project) > 0),
    commit_sha TEXT NOT NULL CHECK (length(commit_sha) BETWEEN 7 AND 40),
    commit_identity_source TEXT NOT NULL CHECK (
        commit_identity_source IN ('metadata_commit_id', 'metadata_commit_url')
    ),
    commit_url TEXT,
    repository_url TEXT,
    declared_cve_ids_json TEXT NOT NULL,
    declared_cwe_ids_json TEXT NOT NULL,
    metadata_line_number INTEGER NOT NULL CHECK (metadata_line_number > 0),
    created_at_utc TEXT NOT NULL,
    UNIQUE (source_snapshot_id, project, commit_sha)
);

CREATE TABLE diversevul_function (
    diversevul_function_id TEXT PRIMARY KEY,
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshot(source_snapshot_id),
    ingestion_run_id TEXT NOT NULL REFERENCES ingestion_run(ingestion_run_id),
    source_line_number INTEGER NOT NULL CHECK (source_line_number > 0),
    project TEXT NOT NULL CHECK (length(project) > 0),
    commit_sha TEXT NOT NULL CHECK (length(commit_sha) BETWEEN 7 AND 40),
    source_function_hash TEXT NOT NULL,
    function_sha256 TEXT CHECK (function_sha256 IS NULL OR length(function_sha256) = 64),
    function_size_bytes INTEGER NOT NULL CHECK (function_size_bytes >= 0),
    source_reported_size INTEGER CHECK (source_reported_size IS NULL OR source_reported_size >= 0),
    vulnerability_label INTEGER NOT NULL CHECK (vulnerability_label IN (0, 1)),
    cwe_ids_json TEXT NOT NULL,
    commit_message_sha256 TEXT NOT NULL CHECK (length(commit_message_sha256) = 64),
    created_at_utc TEXT NOT NULL,
    UNIQUE (source_snapshot_id, source_line_number)
);

CREATE TABLE diversevul_function_cve (
    diversevul_function_cve_id TEXT PRIMARY KEY,
    diversevul_function_id TEXT NOT NULL
        REFERENCES diversevul_function(diversevul_function_id),
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    evidence_source TEXT NOT NULL CHECK (
        evidence_source IN ('metadata_cve_field', 'commit_message')
    ),
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshot(source_snapshot_id),
    ingestion_run_id TEXT NOT NULL REFERENCES ingestion_run(ingestion_run_id),
    created_at_utc TEXT NOT NULL,
    UNIQUE (diversevul_function_id, cve_id, evidence_source)
);

CREATE INDEX ix_diversevul_commit_sha
ON diversevul_commit(commit_sha);

CREATE INDEX ix_diversevul_function_commit
ON diversevul_function(commit_sha, project);

CREATE INDEX ix_diversevul_function_label
ON diversevul_function(vulnerability_label);

CREATE INDEX ix_diversevul_function_snapshot
ON diversevul_function(source_snapshot_id, source_line_number);

CREATE INDEX ix_diversevul_function_cve_cve
ON diversevul_function_cve(cve_id, evidence_source);

INSERT INTO schema_version(version, applied_at_utc, source)
VALUES (
    4,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    'schemas/004_diversevul_integration.sql'
);

COMMIT;
