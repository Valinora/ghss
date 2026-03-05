use std::str::FromStr;

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

/// Status of a completed scan cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Completed,
    Partial,
}

impl ScanStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Partial => "partial",
        }
    }
}

/// Persistent storage backed by `SQLite`.
pub struct Storage {
    pool: SqlitePool,
}

/// A row from the `findings` table, used for drift detection.
#[derive(Debug, Clone)]
pub struct FindingRow {
    pub action_ref: String,
    pub resolved_sha: Option<String>,
}

/// A drift event detected between two scan runs.
#[derive(Debug, Clone)]
pub struct DriftEvent {
    pub action_ref: String,
    pub previous_sha: String,
    pub current_sha: String,
}

impl Storage {
    /// Connect to the `SQLite` database at the given URL.
    ///
    /// The URL should be in the form `sqlite:///path/to/db.sqlite` or
    /// `sqlite::memory:` for in-memory databases.
    /// Creates parent directories if needed for file-based databases.
    pub async fn connect(url: &str) -> anyhow::Result<Self> {
        // Create parent directories for file-based SQLite databases
        if let Some(path) = url.strip_prefix("sqlite://")
            && path != ":memory:"
            && !path.is_empty()
        {
            let db_path = std::path::Path::new(path);
            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent).context(format!(
                    "failed to create parent directory for database: {}",
                    parent.display()
                ))?;
            }
        }

        let options = SqliteConnectOptions::from_str(url)
            .context(format!("invalid database URL: {url}"))?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .context(format!("failed to connect to database: {url}"))?;

        Ok(Self { pool })
    }

    /// Run embedded migrations to set up the schema.
    pub async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("failed to run database migrations")?;
        tracing::info!("Database migrations applied successfully");
        Ok(())
    }

    /// Insert a scan run record and return its row ID.
    pub async fn insert_scan_run(
        &self,
        repo_owner: &str,
        repo_name: &str,
        started_at: &str,
        completed_at: Option<&str>,
        cycle_number: u64,
        status: ScanStatus,
    ) -> anyhow::Result<i64> {
        let row = sqlx::query(
            "INSERT INTO scan_runs (repo_owner, repo_name, started_at, completed_at, cycle_number, status)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING id",
        )
        .bind(repo_owner)
        .bind(repo_name)
        .bind(started_at)
        .bind(completed_at)
        .bind(cycle_number.cast_signed())
        .bind(status.as_str())
        .fetch_one(&self.pool)
        .await
        .context("failed to insert scan run")?;

        Ok(row.get::<i64, _>("id"))
    }

    /// Insert a finding record.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_finding(
        &self,
        scan_run_id: i64,
        action_ref: &str,
        resolved_sha: Option<&str>,
        advisory_ids: Option<&str>,
        severity: Option<&str>,
        serialized_node: &str,
    ) -> anyhow::Result<i64> {
        let row = sqlx::query(
            "INSERT INTO findings (scan_run_id, workflow_path, action_ref, resolved_sha, advisory_ids, severity, serialized_node)
             VALUES (?, NULL, ?, ?, ?, ?, ?)
             RETURNING id",
        )
        .bind(scan_run_id)
        .bind(action_ref)
        .bind(resolved_sha)
        .bind(advisory_ids)
        .bind(severity)
        .bind(serialized_node)
        .fetch_one(&self.pool)
        .await
        .context("failed to insert finding")?;

        Ok(row.get::<i64, _>("id"))
    }

    /// Insert a drift event record.
    pub async fn insert_drift_event(
        &self,
        scan_run_id: i64,
        action_ref: &str,
        previous_sha: &str,
        current_sha: &str,
        detected_at: &str,
    ) -> anyhow::Result<i64> {
        let row = sqlx::query(
            "INSERT INTO drift_events (scan_run_id, action_ref, previous_sha, current_sha, detected_at)
             VALUES (?, ?, ?, ?, ?)
             RETURNING id",
        )
        .bind(scan_run_id)
        .bind(action_ref)
        .bind(previous_sha)
        .bind(current_sha)
        .bind(detected_at)
        .fetch_one(&self.pool)
        .await
        .context("failed to insert drift event")?;

        Ok(row.get::<i64, _>("id"))
    }

    /// Get the findings from the most recent scan run for a given repo.
    pub async fn get_latest_findings(
        &self,
        repo_owner: &str,
        repo_name: &str,
    ) -> anyhow::Result<Vec<FindingRow>> {
        let rows = sqlx::query(
            "SELECT f.action_ref, f.resolved_sha
             FROM findings f
             WHERE f.scan_run_id = (
                 SELECT MAX(sr.id) FROM scan_runs sr
                 WHERE sr.repo_owner = ? AND sr.repo_name = ?
             )",
        )
        .bind(repo_owner)
        .bind(repo_name)
        .fetch_all(&self.pool)
        .await
        .context("failed to get latest findings")?;

        Ok(rows
            .iter()
            .map(|row| FindingRow {
                action_ref: row.get("action_ref"),
                resolved_sha: row.get("resolved_sha"),
            })
            .collect())
    }

    /// Close the database pool.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// Compare current findings against previous findings to detect drift.
///
/// Drift is defined as a change in `resolved_sha` for the same `action_ref`.
pub fn detect_drift(previous: &[FindingRow], current: &[FindingRow]) -> Vec<DriftEvent> {
    let mut events = Vec::new();

    for curr in current {
        if let Some(prev) = previous.iter().find(|p| p.action_ref == curr.action_ref) {
            match (&prev.resolved_sha, &curr.resolved_sha) {
                (Some(prev_sha), Some(curr_sha)) if prev_sha != curr_sha => {
                    events.push(DriftEvent {
                        action_ref: curr.action_ref.clone(),
                        previous_sha: prev_sha.clone(),
                        current_sha: curr_sha.clone(),
                    });
                }
                _ => {}
            }
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_storage() -> Storage {
        let storage = Storage::connect("sqlite::memory:").await.unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    #[tokio::test]
    async fn migration_creates_tables() {
        let storage = test_storage().await;
        // Verify tables exist by attempting queries
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_runs")
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM drift_events")
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn insert_and_retrieve_scan_run() {
        let storage = test_storage().await;
        let id = storage
            .insert_scan_run(
                "my-org",
                "my-app",
                "2024-01-01T00:00:00Z",
                None,
                1,
                ScanStatus::Completed,
            )
            .await
            .unwrap();
        assert_eq!(id, 1);

        let row = sqlx::query("SELECT * FROM scan_runs WHERE id = ?")
            .bind(id)
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("repo_owner"), "my-org");
        assert_eq!(row.get::<String, _>("repo_name"), "my-app");
        assert_eq!(row.get::<String, _>("status"), "completed");
    }

    #[tokio::test]
    async fn insert_and_retrieve_findings() {
        let storage = test_storage().await;
        let run_id = storage
            .insert_scan_run(
                "org",
                "repo",
                "2024-01-01T00:00:00Z",
                None,
                1,
                ScanStatus::Completed,
            )
            .await
            .unwrap();

        let finding_id = storage
            .insert_finding(
                run_id,
                "actions/checkout@v4",
                Some("abc123"),
                Some("GHSA-1234"),
                Some("high"),
                r#"{"entry":{}}"#,
            )
            .await
            .unwrap();
        assert_eq!(finding_id, 1);

        let row = sqlx::query("SELECT * FROM findings WHERE id = ?")
            .bind(finding_id)
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("action_ref"), "actions/checkout@v4");
        assert_eq!(
            row.get::<Option<String>, _>("resolved_sha"),
            Some("abc123".to_string())
        );
    }

    #[tokio::test]
    async fn get_latest_findings_returns_most_recent_run() {
        let storage = test_storage().await;

        // First run
        let run1 = storage
            .insert_scan_run(
                "org",
                "repo",
                "2024-01-01T00:00:00Z",
                None,
                1,
                ScanStatus::Completed,
            )
            .await
            .unwrap();
        storage
            .insert_finding(
                run1,
                "actions/checkout@v4",
                Some("sha_old"),
                None,
                None,
                "{}",
            )
            .await
            .unwrap();

        // Second run
        let run2 = storage
            .insert_scan_run(
                "org",
                "repo",
                "2024-01-01T01:00:00Z",
                None,
                2,
                ScanStatus::Completed,
            )
            .await
            .unwrap();
        storage
            .insert_finding(
                run2,
                "actions/checkout@v4",
                Some("sha_new"),
                None,
                None,
                "{}",
            )
            .await
            .unwrap();

        let latest = storage.get_latest_findings("org", "repo").await.unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].resolved_sha.as_deref(), Some("sha_new"));
    }

    #[tokio::test]
    async fn drift_detection_same_sha_no_drift() {
        let previous = vec![FindingRow {
            action_ref: "actions/checkout@v4".to_string(),
            resolved_sha: Some("abc123".to_string()),
        }];
        let current = vec![FindingRow {
            action_ref: "actions/checkout@v4".to_string(),
            resolved_sha: Some("abc123".to_string()),
        }];
        let drift = detect_drift(&previous, &current);
        assert!(drift.is_empty());
    }

    #[tokio::test]
    async fn drift_detection_changed_sha() {
        let previous = vec![FindingRow {
            action_ref: "actions/checkout@v4".to_string(),
            resolved_sha: Some("abc123".to_string()),
        }];
        let current = vec![FindingRow {
            action_ref: "actions/checkout@v4".to_string(),
            resolved_sha: Some("def456".to_string()),
        }];
        let drift = detect_drift(&previous, &current);
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].action_ref, "actions/checkout@v4");
        assert_eq!(drift[0].previous_sha, "abc123");
        assert_eq!(drift[0].current_sha, "def456");
    }

    #[tokio::test]
    async fn drift_detection_first_run_no_previous() {
        let previous: Vec<FindingRow> = vec![];
        let current = vec![FindingRow {
            action_ref: "actions/checkout@v4".to_string(),
            resolved_sha: Some("abc123".to_string()),
        }];
        let drift = detect_drift(&previous, &current);
        assert!(drift.is_empty());
    }

    #[tokio::test]
    async fn insert_drift_event_persists() {
        let storage = test_storage().await;
        let run_id = storage
            .insert_scan_run(
                "org",
                "repo",
                "2024-01-01T00:00:00Z",
                None,
                1,
                ScanStatus::Completed,
            )
            .await
            .unwrap();

        let drift_id = storage
            .insert_drift_event(
                run_id,
                "actions/checkout@v4",
                "abc123",
                "def456",
                "2024-01-01T01:00:00Z",
            )
            .await
            .unwrap();
        assert_eq!(drift_id, 1);

        let row = sqlx::query("SELECT * FROM drift_events WHERE id = ?")
            .bind(drift_id)
            .fetch_one(&storage.pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("action_ref"), "actions/checkout@v4");
        assert_eq!(row.get::<String, _>("previous_sha"), "abc123");
        assert_eq!(row.get::<String, _>("current_sha"), "def456");
    }
}
