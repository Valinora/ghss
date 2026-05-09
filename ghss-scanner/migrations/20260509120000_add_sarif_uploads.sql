-- Track SARIF uploads to GitHub Code Scanning. One row per upload attempt
-- (including skips). The combination of (repo_owner, repo_name, status,
-- sarif_sha256) drives the skip_unchanged optimization.
CREATE TABLE IF NOT EXISTS sarif_uploads (
    id INTEGER PRIMARY KEY,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    repo_owner TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    sarif_id TEXT,
    sarif_sha256 TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    ref TEXT NOT NULL,
    status TEXT NOT NULL,
    response_body TEXT,
    uploaded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sarif_uploads_repo_status
    ON sarif_uploads (repo_owner, repo_name, status);
