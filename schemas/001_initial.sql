PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at_utc TEXT NOT NULL,
    source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    published_at_utc TEXT,
    modified_at_utc TEXT,
    source_name TEXT NOT NULL,
    source_record_id TEXT,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cvss_observation (
    cvss_observation_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    version TEXT NOT NULL,
    base_score REAL,
    vector TEXT,
    observed_at_utc TEXT NOT NULL,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS epss_observation (
    epss_observation_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    score REAL,
    percentile REAL,
    score_date TEXT NOT NULL,
    model_version TEXT,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kev_observation (
    kev_observation_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    date_added TEXT NOT NULL,
    due_date TEXT,
    known_ransomware_use TEXT,
    catalogue_date TEXT NOT NULL,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cwe (
    cwe_id TEXT PRIMARY KEY,
    name TEXT,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cpe (
    cpe_id TEXT PRIMARY KEY,
    cpe_uri TEXT NOT NULL,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exploit_reference (
    exploit_reference_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    reference_url TEXT,
    published_at_utc TEXT,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS patch_reference (
    patch_reference_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    reference_url TEXT,
    published_at_utc TEXT,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_mapping (
    attack_mapping_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    framework TEXT NOT NULL,
    technique_id TEXT,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS department (
    department_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS owner_team (
    owner_team_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS business_service (
    business_service_id TEXT PRIMARY KEY,
    department_id TEXT REFERENCES department(department_id),
    owner_team_id TEXT REFERENCES owner_team(owner_team_id),
    criticality INTEGER,
    scenario_id TEXT NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS application (
    application_id TEXT PRIMARY KEY,
    business_service_id TEXT REFERENCES business_service(business_service_id),
    owner_team_id TEXT REFERENCES owner_team(owner_team_id),
    scenario_id TEXT NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS asset (
    asset_id TEXT PRIMARY KEY,
    application_id TEXT REFERENCES application(application_id),
    owner_team_id TEXT REFERENCES owner_team(owner_team_id),
    environment TEXT,
    network_zone TEXT,
    internet_exposed INTEGER,
    criticality INTEGER,
    scenario_id TEXT NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS asset_service_map (
    asset_service_map_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES asset(asset_id),
    business_service_id TEXT NOT NULL REFERENCES business_service(business_service_id),
    valid_from_utc TEXT NOT NULL,
    valid_to_utc TEXT,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS data_classification (
    data_classification_id TEXT PRIMARY KEY,
    asset_id TEXT REFERENCES asset(asset_id),
    classification TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS regulatory_scope (
    regulatory_scope_id TEXT PRIMARY KEY,
    business_service_id TEXT REFERENCES business_service(business_service_id),
    framework TEXT NOT NULL,
    in_scope INTEGER NOT NULL,
    scenario_id TEXT NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_finding (
    finding_id TEXT PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    asset_id TEXT NOT NULL REFERENCES asset(asset_id),
    finding_created_at_utc TEXT NOT NULL,
    correlation_key TEXT,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert (
    alert_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES vulnerability_finding(finding_id),
    alert_created_at_utc TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_ticket (
    case_ticket_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL REFERENCES alert(alert_id),
    owner_team_id TEXT REFERENCES owner_team(owner_team_id),
    status TEXT NOT NULL,
    sla_deadline_utc TEXT,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_action (
    triage_action_id TEXT PRIMARY KEY,
    case_ticket_id TEXT NOT NULL REFERENCES case_ticket(case_ticket_id),
    analyst_id TEXT,
    started_at_utc TEXT,
    completed_at_utc TEXT,
    outcome TEXT,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS remediation_action (
    remediation_action_id TEXT PRIMARY KEY,
    case_ticket_id TEXT NOT NULL REFERENCES case_ticket(case_ticket_id),
    owner_team_id TEXT REFERENCES owner_team(owner_team_id),
    started_at_utc TEXT,
    completed_at_utc TEXT,
    outcome TEXT,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_acceptance (
    risk_acceptance_id TEXT PRIMARY KEY,
    case_ticket_id TEXT NOT NULL REFERENCES case_ticket(case_ticket_id),
    approved_by_role TEXT,
    valid_from_utc TEXT NOT NULL,
    valid_to_utc TEXT,
    rationale TEXT,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS maintenance_window (
    maintenance_window_id TEXT PRIMARY KEY,
    asset_id TEXT REFERENCES asset(asset_id),
    starts_at_utc TEXT NOT NULL,
    ends_at_utc TEXT NOT NULL,
    window_type TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scenario (
    scenario_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    seed INTEGER NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS team (
    team_id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL REFERENCES scenario(scenario_id),
    team_type TEXT NOT NULL,
    skills_json TEXT,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analyst (
    analyst_id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES team(team_id),
    skills_json TEXT,
    scenario_id TEXT NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capacity_calendar (
    capacity_calendar_id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES team(team_id),
    starts_at_utc TEXT NOT NULL,
    ends_at_utc TEXT NOT NULL,
    available_capacity REAL NOT NULL,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS simulation_run (
    simulation_run_id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL REFERENCES scenario(scenario_id),
    seed INTEGER NOT NULL,
    started_at_utc TEXT NOT NULL,
    completed_at_utc TEXT,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS simulation_event (
    simulation_event_id TEXT PRIMARY KEY,
    simulation_run_id TEXT NOT NULL REFERENCES simulation_run(simulation_run_id),
    case_ticket_id TEXT REFERENCES case_ticket(case_ticket_id),
    event_type TEXT NOT NULL,
    event_at_utc TEXT NOT NULL,
    payload_json TEXT,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS queue_snapshot (
    queue_snapshot_id TEXT PRIMARY KEY,
    simulation_run_id TEXT NOT NULL REFERENCES simulation_run(simulation_run_id),
    queue_name TEXT NOT NULL,
    observed_at_utc TEXT NOT NULL,
    queue_size INTEGER NOT NULL,
    oldest_age_minutes REAL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS experiment_run (
    experiment_run_id TEXT PRIMARY KEY,
    simulation_run_id TEXT NOT NULL REFERENCES simulation_run(simulation_run_id),
    experiment_id TEXT NOT NULL,
    configuration_hash TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS priority_decision (
    priority_decision_id TEXT PRIMARY KEY,
    experiment_run_id TEXT NOT NULL REFERENCES experiment_run(experiment_run_id),
    finding_id TEXT NOT NULL REFERENCES vulnerability_finding(finding_id),
    decided_at_utc TEXT NOT NULL,
    policy TEXT NOT NULL,
    rank INTEGER NOT NULL,
    score_components_json TEXT NOT NULL,
    evidence_as_of_utc TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decision_explanation (
    decision_explanation_id TEXT PRIMARY KEY,
    priority_decision_id TEXT NOT NULL REFERENCES priority_decision(priority_decision_id),
    explanation TEXT NOT NULL,
    evidence_references_json TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_manifest (
    run_manifest_id TEXT PRIMARY KEY,
    experiment_run_id TEXT NOT NULL REFERENCES experiment_run(experiment_run_id),
    manifest_json TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS metric_result (
    metric_result_id TEXT PRIMARY KEY,
    experiment_run_id TEXT NOT NULL REFERENCES experiment_run(experiment_run_id),
    metric_name TEXT NOT NULL,
    metric_value REAL,
    unit TEXT,
    denominator INTEGER,
    censoring_rule TEXT,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_request (
    ai_request_id TEXT PRIMARY KEY,
    experiment_run_id TEXT REFERENCES experiment_run(experiment_run_id),
    model_name TEXT,
    model_version TEXT,
    prompt_template_version TEXT,
    parameters_json TEXT,
    evidence_references_json TEXT NOT NULL,
    requested_at_utc TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ai_response (
    ai_response_id TEXT PRIMARY KEY,
    ai_request_id TEXT NOT NULL REFERENCES ai_request(ai_request_id),
    output_text TEXT,
    output_hash TEXT NOT NULL,
    duration_ms INTEGER,
    responded_at_utc TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS human_review (
    human_review_id TEXT PRIMARY KEY,
    ai_response_id TEXT REFERENCES ai_response(ai_response_id),
    reviewer_role TEXT NOT NULL,
    decision TEXT NOT NULL,
    edited_output TEXT,
    reviewed_at_utc TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS honeypot_scenario (
    honeypot_scenario_id TEXT PRIMARY KEY,
    cve_id TEXT REFERENCES cve(cve_id),
    sensor_type TEXT,
    collection_start_utc TEXT,
    collection_end_utc TEXT,
    ethics_approval_status TEXT NOT NULL,
    authorised_replay_only INTEGER NOT NULL DEFAULT 1,
    provenance TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS honeypot_event (
    honeypot_event_id TEXT PRIMARY KEY,
    honeypot_scenario_id TEXT NOT NULL REFERENCES honeypot_scenario(honeypot_scenario_id),
    observed_at_utc TEXT NOT NULL,
    event_type TEXT NOT NULL,
    deduplication_key TEXT,
    payload_family TEXT,
    source_name TEXT NOT NULL,
    retrieved_at_utc TEXT,
    created_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dynamic_exploit_evidence (
    dynamic_exploit_evidence_id TEXT PRIMARY KEY,
    honeypot_scenario_id TEXT NOT NULL REFERENCES honeypot_scenario(honeypot_scenario_id),
    evidence_as_of_utc TEXT NOT NULL,
    time_to_first_attempt_minutes REAL,
    attempt_count INTEGER,
    unique_source_count INTEGER,
    ttp_diversity INTEGER,
    payload_diversity INTEGER,
    post_exploitation_severity REAL,
    limitations TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_version(version, applied_at_utc, source)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 'schemas/001_initial.sql');
