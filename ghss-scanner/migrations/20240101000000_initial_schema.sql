CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY,
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    cycle_number INTEGER NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    workflow_path TEXT,
    action_ref TEXT NOT NULL,
    resolved_sha TEXT,
    advisory_ids TEXT,
    severity TEXT,
    serialized_node TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS drift_events (
    id INTEGER PRIMARY KEY,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    action_ref TEXT NOT NULL,
    previous_sha TEXT NOT NULL,
    current_sha TEXT NOT NULL,
    detected_at TEXT NOT NULL
);
