use std::io::Write;
use std::process::Command;

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::Row;
use tempfile::{NamedTempFile, TempDir};

fn scanner_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghss-scanner"))
}

fn write_config(db_path: &str) -> NamedTempFile {
    let config = format!(
        r#"
[scanner]
github_token = "ghp_test123"
schedule = "*/30 * * * *"

[[repos]]
owner = "my-org"
name = "my-app"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite://{db_path}"
"#
    );
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(config.as_bytes()).unwrap();
    f
}

#[tokio::test]
async fn once_mode_persists_to_sqlite() {
    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("test.db");
    let db_path_str = db_path.to_str().unwrap();

    let config_file = write_config(db_path_str);

    // Run the scanner in --once mode
    let output = scanner_bin()
        .args(["--once", "--config", config_file.path().to_str().unwrap(), "-vv"])
        .output()
        .expect("failed to run ghss-scanner");

    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "scanner exited with error: {stderr}"
    );

    // Open the SQLite database and verify rows exist
    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{db_path_str}"))
        .await
        .expect("failed to open test database");

    // Verify scan_runs table has rows
    let scan_run_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_runs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        scan_run_count > 0,
        "expected scan_runs rows, got {scan_run_count}"
    );

    // Verify findings table has rows
    let findings_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        findings_count > 0,
        "expected findings rows, got {findings_count}"
    );

    // Verify scan run has correct repo info
    let row = sqlx::query("SELECT repo_owner, repo_name, status FROM scan_runs LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("repo_owner"), "my-org");
    assert_eq!(row.get::<String, _>("repo_name"), "my-app");
    assert_eq!(row.get::<String, _>("status"), "completed");

    // Verify findings have action_ref and serialized_node
    let finding = sqlx::query("SELECT action_ref, serialized_node FROM findings LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    let action_ref: String = finding.get("action_ref");
    let serialized: String = finding.get("serialized_node");
    assert!(!action_ref.is_empty(), "action_ref should not be empty");
    assert!(!serialized.is_empty(), "serialized_node should not be empty");
    // Verify serialized_node is valid JSON
    serde_json::from_str::<serde_json::Value>(&serialized)
        .expect("serialized_node should be valid JSON");

    // Verify drift_events table exists (may be empty on first run, that's fine)
    let drift_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM drift_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        drift_count >= 0,
        "drift_events table should exist"
    );

    pool.close().await;
}
