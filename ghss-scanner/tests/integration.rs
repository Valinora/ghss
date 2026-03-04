use std::io::{BufRead, BufReader, Write};
use std::process::Command;

use sqlx::Row;
use sqlx::sqlite::SqlitePoolOptions;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn scanner_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghss-scanner"))
}

fn write_config(db_path: &str) -> NamedTempFile {
    write_config_with_schedule(db_path, "*/30 * * * *")
}

fn write_config_with_schedule(db_path: &str, schedule: &str) -> NamedTempFile {
    let config = format!(
        r#"
[scanner]
github_token = "ghp_test123"
schedule = "{schedule}"

[[repos]]
owner = "my-org"
name = "my-app"
workflows = ["ci.yml"]

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

/// Set up a mock server that serves a workflow file with a known action
/// and mocks ref resolution + advisory endpoints.
async fn setup_mock_server() -> MockServer {
    let server = MockServer::start().await;

    // Raw content: ci.yml workflow
    Mock::given(method("GET"))
        .and(path("/my-org/my-app/HEAD/.github/workflows/ci.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v3\n",
        ))
        .mount(&server)
        .await;

    // Ref resolution: actions/checkout@v4 — return a tag ref
    Mock::given(method("GET"))
        .and(path("/repos/actions/checkout/git/ref/tags/v4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ref": "refs/tags/v4",
            "object": {
                "type": "commit",
                "sha": "b4ffde65f46336ab88eb53be808477a3936bae11"
            }
        })))
        .mount(&server)
        .await;

    // Ref resolution: actions/setup-node@v3
    Mock::given(method("GET"))
        .and(path("/repos/actions/setup-node/git/ref/tags/v3"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ref": "refs/tags/v3",
            "object": {
                "type": "commit",
                "sha": "1a4442cacd436585916779fa0482e7ad73969eb2"
            }
        })))
        .mount(&server)
        .await;

    // Composite action check: actions/checkout — node20 (not composite)
    Mock::given(method("GET"))
        .and(path("/actions/checkout/v4/action.yml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("name: Checkout\nruns:\n  using: node20\n  main: index.js\n"),
        )
        .mount(&server)
        .await;

    // Composite action check: actions/setup-node — node20 (not composite)
    Mock::given(method("GET"))
        .and(path("/actions/setup-node/v3/action.yml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("name: Setup Node\nruns:\n  using: node20\n  main: index.js\n"),
        )
        .mount(&server)
        .await;

    // Advisory endpoints: GHSA (return empty)
    Mock::given(method("GET"))
        .and(path("/advisories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    // Advisory endpoints: OSV (return empty)
    Mock::given(method("POST"))
        .and(path("/osv-query/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"vulns": []})))
        .mount(&server)
        .await;

    server
}

#[tokio::test]
async fn once_mode_persists_to_sqlite() {
    let server = setup_mock_server().await;
    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("test.db");
    let db_path_str = db_path.to_str().unwrap();

    let config_file = write_config(db_path_str);

    // Run the scanner in --once mode
    let output = scanner_bin()
        .args([
            "--once",
            "--config",
            config_file.path().to_str().unwrap(),
            "-vv",
        ])
        .env("GHSS_API_BASE_URL", server.uri())
        .env("GHSS_RAW_BASE_URL", server.uri())
        .env("GHSS_OSV_BASE_URL", format!("{}/osv-query", server.uri()))
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
    assert!(
        !serialized.is_empty(),
        "serialized_node should not be empty"
    );
    // Verify serialized_node is valid JSON
    serde_json::from_str::<serde_json::Value>(&serialized)
        .expect("serialized_node should be valid JSON");

    // Verify drift_events table exists (may be empty on first run, that's fine)
    let drift_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM drift_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(drift_count >= 0, "drift_events table should exist");

    pool.close().await;
}

#[tokio::test]
async fn daemon_mode_sigterm_graceful_shutdown() {
    let server = setup_mock_server().await;
    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("daemon.db");
    let db_path_str = db_path.to_str().unwrap();

    // Use every-second schedule so we don't have to wait long
    let config_file = write_config_with_schedule(db_path_str, "* * * * * *");

    // Start in daemon mode (no --once)
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ghss-scanner"))
        .args(["--config", config_file.path().to_str().unwrap(), "-vv"])
        .env("GHSS_API_BASE_URL", server.uri())
        .env("GHSS_RAW_BASE_URL", server.uri())
        .env("GHSS_OSV_BASE_URL", format!("{}/osv-query", server.uri()))
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("failed to start ghss-scanner");

    let pid = child.id() as i32;
    let stderr_handle = child.stderr.take().unwrap();

    // Collect stderr in a background thread so we don't block the main thread
    let reader_thread = std::thread::spawn(move || {
        let reader = BufReader::new(stderr_handle);
        let mut lines = Vec::new();
        for line in reader.lines() {
            match line {
                Ok(l) => lines.push(l),
                Err(_) => break,
            }
        }
        lines
    });

    // Wait enough time for at least one scan cycle to complete
    std::thread::sleep(std::time::Duration::from_secs(5));

    // Send SIGTERM
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }

    let status = child.wait().expect("failed to wait for child");
    let stderr_lines = reader_thread.join().expect("stderr reader thread panicked");
    let stderr_output = stderr_lines.join("\n");

    assert!(
        status.success(),
        "expected exit code 0 after SIGTERM, got: {status}\nstderr:\n{stderr_output}"
    );
    assert!(
        stderr_output.contains("Persisted"),
        "expected scan cycle completion in stderr:\n{stderr_output}"
    );
    assert!(
        stderr_output.contains("shutting down"),
        "expected shutdown message in stderr:\n{stderr_output}"
    );
    assert!(
        stderr_output.contains("Shutdown complete"),
        "expected shutdown complete message in stderr:\n{stderr_output}"
    );
}

#[tokio::test]
async fn once_mode_full_lifecycle() {
    let server = setup_mock_server().await;
    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("lifecycle.db");
    let db_path_str = db_path.to_str().unwrap();

    let config_file = write_config(db_path_str);

    // Run --once with verbose logging
    let output = scanner_bin()
        .args([
            "--once",
            "--config",
            config_file.path().to_str().unwrap(),
            "-vv",
        ])
        .env("GHSS_API_BASE_URL", server.uri())
        .env("GHSS_RAW_BASE_URL", server.uri())
        .env("GHSS_OSV_BASE_URL", format!("{}/osv-query", server.uri()))
        .output()
        .expect("failed to run ghss-scanner");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Assert clean exit
    assert!(
        output.status.success(),
        "scanner exited with error: {stderr}"
    );

    // Verify lifecycle logs: config parsing, migration, scan cycle, persistence
    assert!(
        stderr.contains("Config loaded"),
        "expected 'Config loaded' in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Starting scan cycle"),
        "expected scan cycle log in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Persisted"),
        "expected persistence log in stderr:\n{stderr}"
    );

    // Verify SQLite has correct data
    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{db_path_str}"))
        .await
        .expect("failed to open test database");

    // scan_runs should have exactly 1 row
    let scan_run_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_runs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(scan_run_count, 1, "expected exactly 1 scan run");

    // findings should have rows
    let findings_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(findings_count > 0, "expected findings rows");

    // Verify the scan run details
    let row = sqlx::query("SELECT repo_owner, repo_name, cycle_number, status FROM scan_runs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("repo_owner"), "my-org");
    assert_eq!(row.get::<String, _>("repo_name"), "my-app");
    assert_eq!(row.get::<i64, _>("cycle_number"), 1);
    assert_eq!(row.get::<String, _>("status"), "completed");

    // Verify each finding has valid serialized JSON
    let findings = sqlx::query("SELECT serialized_node FROM findings")
        .fetch_all(&pool)
        .await
        .unwrap();
    for finding in &findings {
        let json_str: String = finding.get("serialized_node");
        serde_json::from_str::<serde_json::Value>(&json_str)
            .expect("serialized_node should be valid JSON");
    }

    pool.close().await;
}
