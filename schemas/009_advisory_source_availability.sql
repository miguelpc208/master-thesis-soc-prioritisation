PRAGMA foreign_keys = OFF;

BEGIN IMMEDIATE;

DROP VIEW technical_evidence_availability;
DROP TRIGGER enforce_corroborated_patch_reference;
DROP TRIGGER enforce_advisory_cve_snapshot;
DROP TRIGGER enforce_advisory_package_snapshot;

CREATE TABLE github_advisory_v2 (
    github_advisory_id TEXT PRIMARY KEY,
    ghsa_id TEXT NOT NULL,
    published_at_utc TEXT NOT NULL,
    modified_at_utc TEXT NOT NULL,
    source_available_at_utc TEXT NOT NULL,
    withdrawn_at_utc TEXT,
    severity TEXT,
    source_relative_path TEXT NOT NULL,
    record_sha256 TEXT NOT NULL CHECK (length(record_sha256) = 64),
    source_snapshot_id TEXT NOT NULL REFERENCES source_snapshot(source_snapshot_id),
    ingestion_run_id TEXT NOT NULL REFERENCES ingestion_run(ingestion_run_id),
    created_at_utc TEXT NOT NULL,
    CHECK (ghsa_id GLOB 'GHSA-????-????-????'),
    CHECK (withdrawn_at_utc IS NULL),
    CHECK (source_available_at_utc >= published_at_utc),
    CHECK (source_available_at_utc >= modified_at_utc),
    UNIQUE (ghsa_id, source_snapshot_id)
);

INSERT INTO github_advisory_v2(
    github_advisory_id, ghsa_id, published_at_utc, modified_at_utc,
    source_available_at_utc, withdrawn_at_utc, severity,
    source_relative_path, record_sha256, source_snapshot_id,
    ingestion_run_id, created_at_utc
)
SELECT
    github_advisory_id, ghsa_id, published_at_utc, modified_at_utc,
    CASE
        WHEN published_at_utc >= modified_at_utc THEN published_at_utc
        ELSE modified_at_utc
    END,
    withdrawn_at_utc, severity, source_relative_path, record_sha256,
    source_snapshot_id, ingestion_run_id, created_at_utc
FROM github_advisory;

DROP TABLE github_advisory;
ALTER TABLE github_advisory_v2 RENAME TO github_advisory;

CREATE TABLE patch_reference_v2 (
    patch_reference_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    reference_url TEXT,
    published_at_utc TEXT,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    source_snapshot_id TEXT REFERENCES source_snapshot(source_snapshot_id),
    ingestion_run_id TEXT REFERENCES ingestion_run(ingestion_run_id),
    commit_sha TEXT CHECK (commit_sha IS NULL OR length(commit_sha) = 40),
    reference_kind TEXT CHECK (
        reference_kind IS NULL OR reference_kind = 'corroborated_commit'
    ),
    evidence_time_status TEXT CHECK (
        evidence_time_status IS NULL OR evidence_time_status IN (
            'authoritative_advisory_available',
            'undated_context_only'
        )
    ),
    anchor_github_advisory_id TEXT REFERENCES github_advisory(github_advisory_id)
);

INSERT INTO patch_reference_v2(
    patch_reference_id, cve_id, reference_url, published_at_utc,
    source_name, retrieved_at_utc, created_at_utc, source_snapshot_id,
    ingestion_run_id, commit_sha, reference_kind, evidence_time_status,
    anchor_github_advisory_id
)
SELECT
    patch_reference_id, cve_id, reference_url, published_at_utc,
    source_name, retrieved_at_utc, created_at_utc, source_snapshot_id,
    ingestion_run_id, commit_sha, reference_kind,
    CASE
        WHEN evidence_time_status = 'authoritative_advisory_modified'
        THEN 'authoritative_advisory_available'
        ELSE evidence_time_status
    END,
    anchor_github_advisory_id
FROM patch_reference;

DROP TABLE patch_reference;
ALTER TABLE patch_reference_v2 RENAME TO patch_reference;

CREATE UNIQUE INDEX uq_patch_reference_cve_commit_snapshot
ON patch_reference(cve_id, commit_sha, source_snapshot_id)
WHERE commit_sha IS NOT NULL;

CREATE INDEX ix_github_advisory_published_available
ON github_advisory(published_at_utc, source_available_at_utc);

CREATE INDEX ix_patch_reference_availability
ON patch_reference(evidence_time_status, published_at_utc);

CREATE TRIGGER enforce_advisory_cve_snapshot
BEFORE INSERT ON github_advisory_cve
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM github_advisory
            WHERE github_advisory_id = NEW.github_advisory_id
              AND source_snapshot_id = NEW.source_snapshot_id
        )
            THEN RAISE(ABORT, 'advisory CVE link snapshot does not match advisory')
    END;
END;

CREATE TRIGGER enforce_advisory_package_snapshot
BEFORE INSERT ON github_advisory_package
BEGIN
    SELECT CASE
        WHEN NOT EXISTS (
            SELECT 1
            FROM github_advisory
            WHERE github_advisory_id = NEW.github_advisory_id
              AND source_snapshot_id = NEW.source_snapshot_id
        )
            THEN RAISE(ABORT, 'advisory package snapshot does not match advisory')
    END;
END;

CREATE TRIGGER enforce_corroborated_patch_reference
BEFORE INSERT ON patch_reference
WHEN NEW.reference_kind = 'corroborated_commit'
BEGIN
    SELECT CASE
        WHEN NEW.source_name <> 'vulzoo_corroborated_patch'
            THEN RAISE(ABORT, 'corroborated patch source is invalid')
        WHEN NEW.source_snapshot_id IS NULL OR NEW.ingestion_run_id IS NULL
            THEN RAISE(ABORT, 'corroborated patch requires snapshot and run provenance')
        WHEN NEW.commit_sha IS NULL OR NEW.reference_url IS NULL
            THEN RAISE(ABORT, 'corroborated patch requires a commit hash and URL')
        WHEN NEW.evidence_time_status = 'undated_context_only'
             AND (
                 NEW.published_at_utc IS NOT NULL
                 OR NEW.anchor_github_advisory_id IS NOT NULL
             )
            THEN RAISE(ABORT, 'undated patch cannot claim advisory timing')
        WHEN NEW.evidence_time_status = 'authoritative_advisory_available'
             AND (
                 NEW.published_at_utc IS NULL
                 OR NEW.anchor_github_advisory_id IS NULL
             )
            THEN RAISE(ABORT, 'dated patch requires an authoritative advisory anchor')
        WHEN NEW.evidence_time_status = 'authoritative_advisory_available'
             AND NOT EXISTS (
                 SELECT 1
                 FROM github_advisory AS advisory
                 JOIN github_advisory_cve AS link
                   ON link.github_advisory_id = advisory.github_advisory_id
                 WHERE advisory.github_advisory_id = NEW.anchor_github_advisory_id
                   AND advisory.source_snapshot_id = NEW.source_snapshot_id
                   AND link.cve_id = NEW.cve_id
                   AND advisory.source_available_at_utc = NEW.published_at_utc
             )
            THEN RAISE(ABORT, 'patch advisory anchor does not match CVE or availability time')
    END;
END;

CREATE TRIGGER enforce_corroborated_patch_reference_update
BEFORE UPDATE ON patch_reference
WHEN NEW.reference_kind = 'corroborated_commit'
BEGIN
    SELECT CASE
        WHEN NEW.source_name <> 'vulzoo_corroborated_patch'
            THEN RAISE(ABORT, 'corroborated patch source is invalid')
        WHEN NEW.source_snapshot_id IS NULL OR NEW.ingestion_run_id IS NULL
            THEN RAISE(ABORT, 'corroborated patch requires snapshot and run provenance')
        WHEN NEW.commit_sha IS NULL OR NEW.reference_url IS NULL
            THEN RAISE(ABORT, 'corroborated patch requires a commit hash and URL')
        WHEN NEW.evidence_time_status = 'undated_context_only'
             AND (
                 NEW.published_at_utc IS NOT NULL
                 OR NEW.anchor_github_advisory_id IS NOT NULL
             )
            THEN RAISE(ABORT, 'undated patch cannot claim advisory timing')
        WHEN NEW.evidence_time_status = 'authoritative_advisory_available'
             AND (
                 NEW.published_at_utc IS NULL
                 OR NEW.anchor_github_advisory_id IS NULL
             )
            THEN RAISE(ABORT, 'dated patch requires an authoritative advisory anchor')
        WHEN NEW.evidence_time_status = 'authoritative_advisory_available'
             AND NOT EXISTS (
                 SELECT 1
                 FROM github_advisory AS advisory
                 JOIN github_advisory_cve AS link
                   ON link.github_advisory_id = advisory.github_advisory_id
                 WHERE advisory.github_advisory_id = NEW.anchor_github_advisory_id
                   AND advisory.source_snapshot_id = NEW.source_snapshot_id
                   AND link.cve_id = NEW.cve_id
                   AND advisory.source_available_at_utc = NEW.published_at_utc
             )
            THEN RAISE(ABORT, 'patch advisory anchor does not match CVE or availability time')
    END;
END;

UPDATE evidence_time_policy
SET
    effective_time_semantics = 'authoritative GHSA published_at_utc',
    source_observed_time_semantics = 'authoritative GHSA modified_at_utc preserved verbatim',
    strict_availability_semantics =
        'later of max(published_at_utc, modified_at_utc) and local retrieval',
    reconstruction_availability_semantics =
        'max(published_at_utc, modified_at_utc); earlier versions are unavailable'
WHERE evidence_kind = 'github_advisory';

UPDATE evidence_time_policy
SET
    effective_time_semantics =
        'conservative advisory source availability; fix publication time is not inferred',
    source_observed_time_semantics = 'authoritative GHSA modified_at_utc preserved verbatim',
    strict_availability_semantics =
        'later of advisory source availability and local retrieval',
    reconstruction_availability_semantics =
        'max(advisory published_at_utc, advisory modified_at_utc)'
WHERE evidence_kind = 'github_advisory_fixed_version';

UPDATE evidence_time_policy
SET
    effective_time_semantics =
        'matching advisory source availability, or unknown for undated commits',
    source_observed_time_semantics =
        'matching advisory source availability, or unknown for undated commits',
    strict_availability_semantics =
        'later of authoritative advisory availability and local retrieval',
    reconstruction_availability_semantics =
        'matching advisory source availability; undated commits are ineligible'
WHERE evidence_kind = 'corroborated_patch_commit';

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
WHERE epss.source_snapshot_id IS NOT NULL

UNION ALL

SELECT
    'github_advisory',
    link.github_advisory_cve_id,
    link.cve_id,
    advisory.published_at_utc,
    advisory.modified_at_utc,
    snapshot.retrieved_at_utc,
    CASE
        WHEN advisory.source_available_at_utc > snapshot.retrieved_at_utc
        THEN advisory.source_available_at_utc
        ELSE snapshot.retrieved_at_utc
    END,
    advisory.source_available_at_utc,
    advisory.source_snapshot_id,
    policy.operational_role,
    policy.history_status
FROM github_advisory_cve AS link
JOIN github_advisory AS advisory
  ON advisory.github_advisory_id = link.github_advisory_id
JOIN source_snapshot AS snapshot
  ON snapshot.source_snapshot_id = advisory.source_snapshot_id
JOIN evidence_time_policy AS policy
  ON policy.evidence_kind = 'github_advisory'

UNION ALL

SELECT
    'github_advisory_fixed_version',
    event.github_advisory_version_event_id || ':' || link.cve_id,
    link.cve_id,
    advisory.source_available_at_utc,
    advisory.modified_at_utc,
    snapshot.retrieved_at_utc,
    CASE
        WHEN advisory.source_available_at_utc > snapshot.retrieved_at_utc
        THEN advisory.source_available_at_utc
        ELSE snapshot.retrieved_at_utc
    END,
    advisory.source_available_at_utc,
    advisory.source_snapshot_id,
    policy.operational_role,
    policy.history_status
FROM github_advisory_version_event AS event
JOIN github_advisory_package AS package
  ON package.github_advisory_package_id = event.github_advisory_package_id
JOIN github_advisory AS advisory
  ON advisory.github_advisory_id = package.github_advisory_id
JOIN github_advisory_cve AS link
  ON link.github_advisory_id = advisory.github_advisory_id
JOIN source_snapshot AS snapshot
  ON snapshot.source_snapshot_id = advisory.source_snapshot_id
JOIN evidence_time_policy AS policy
  ON policy.evidence_kind = 'github_advisory_fixed_version'
WHERE event.event_kind = 'fixed'

UNION ALL

SELECT
    'corroborated_patch_commit',
    patch.patch_reference_id,
    patch.cve_id,
    patch.published_at_utc,
    patch.published_at_utc,
    patch.retrieved_at_utc,
    CASE
        WHEN patch.published_at_utc > patch.retrieved_at_utc
        THEN patch.published_at_utc
        ELSE patch.retrieved_at_utc
    END,
    patch.published_at_utc,
    patch.source_snapshot_id,
    policy.operational_role,
    policy.history_status
FROM patch_reference AS patch
JOIN evidence_time_policy AS policy
  ON policy.evidence_kind = 'corroborated_patch_commit'
WHERE patch.reference_kind = 'corroborated_commit'
  AND patch.source_snapshot_id IS NOT NULL;

INSERT INTO schema_version(version, applied_at_utc, source)
VALUES (
    9,
    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
    'schemas/009_advisory_source_availability.sql'
);

COMMIT;

PRAGMA foreign_keys = ON;
