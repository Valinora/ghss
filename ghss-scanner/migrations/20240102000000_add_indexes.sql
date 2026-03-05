CREATE INDEX IF NOT EXISTS idx_scan_runs_repo ON scan_runs(repo_owner, repo_name);
CREATE INDEX IF NOT EXISTS idx_findings_scan_run_id ON findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_drift_events_scan_run_id ON drift_events(scan_run_id);
