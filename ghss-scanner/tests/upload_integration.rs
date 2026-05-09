//! Integration tests for SARIF upload behavior. Each test stands up a
//! wiremock instance that simulates the full set of GitHub endpoints
//! the scanner touches in one cycle: repo metadata, default-branch HEAD,
//! workflow YAML, advisory APIs, AND the Code Scanning sarifs endpoint.

use std::io::Write;
use std::process::Command;

use sqlx::Row;
use sqlx::sqlite::SqlitePoolOptions;
use tempfile::{NamedTempFile, TempDir};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn scanner_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghss-scanner"))
}

fn write_config(db_path: &str, extra_repo_toml: &str, upload_section: &str) -> NamedTempFile {
    let config = format!(
        r#"
[scanner]
github_token = "ghp_test123"
schedule = "*/30 * * * *"

[[repos]]
owner = "up-org"
name = "up-repo"
workflows = ["ci.yml"]
{extra_repo_toml}

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite://{db_path}"

{upload_section}
"#
    );
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(config.as_bytes()).unwrap();
    f
}

const COMMIT_SHA: &str = "feedfacefeedfacefeedfacefeedfacefeedface";

/// Mock the standard set of endpoints the scanner needs to complete a
/// scan cycle, *without* mounting the SARIF upload endpoint. Tests add
/// their own upload mock to assert on it.
async fn setup_upload_test_server() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/repos/up-org/up-repo"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"default_branch": "main"})),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/repos/up-org/up-repo/git/ref/heads/main"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": COMMIT_SHA}
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/up-org/up-repo/{COMMIT_SHA}/.github/workflows/ci.yml"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/repos/actions/checkout/git/ref/tags/v4"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ref": "refs/tags/v4",
            "object": {"type": "commit", "sha": "b4ffde65f46336ab88eb53be808477a3936bae11"}
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/actions/checkout/v4/action.yml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("name: Checkout\nruns:\n  using: node20\n  main: index.js\n"),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/advisories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/osv-query/v1/query"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"vulns": []})))
        .mount(&server)
        .await;

    server
}

async fn run_one_cycle(db_path_str: &str, config_file: &NamedTempFile, server: &MockServer) {
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
    assert!(
        output.status.success(),
        "scanner exited with error: {}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = db_path_str; // ensure consumed in case caller wants to query
}

#[tokio::test]
async fn upload_happy_path_inserts_accepted_row() {
    let server = setup_upload_test_server().await;

    Mock::given(method("POST"))
        .and(path("/repos/up-org/up-repo/code-scanning/sarifs"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": "sarif-id-123"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("upload-happy.db");
    let db_path_str = db_path.to_str().unwrap();
    let config_file = write_config(
        db_path_str,
        "",
        "[upload]\nenabled = true\nskip_unchanged = false\n",
    );

    run_one_cycle(db_path_str, &config_file, &server).await;

    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{db_path_str}"))
        .await
        .unwrap();
    let row = sqlx::query(
        "SELECT sarif_id, status, commit_sha, ref FROM sarif_uploads ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("expected a sarif_uploads row");
    assert_eq!(row.get::<String, _>("status"), "accepted");
    assert_eq!(row.get::<String, _>("sarif_id"), "sarif-id-123");
    assert_eq!(row.get::<String, _>("commit_sha"), COMMIT_SHA);
    assert_eq!(row.get::<String, _>("ref"), "refs/heads/main");
    pool.close().await;
}

#[tokio::test]
async fn upload_rejection_inserts_rejected_row_and_does_not_crash() {
    let server = setup_upload_test_server().await;

    Mock::given(method("POST"))
        .and(path("/repos/up-org/up-repo/code-scanning/sarifs"))
        .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "message": "sarif schema invalid"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("upload-reject.db");
    let db_path_str = db_path.to_str().unwrap();
    let config_file = write_config(
        db_path_str,
        "",
        "[upload]\nenabled = true\nskip_unchanged = false\n",
    );

    run_one_cycle(db_path_str, &config_file, &server).await;

    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{db_path_str}"))
        .await
        .unwrap();
    let row = sqlx::query(
        "SELECT status, response_body FROM sarif_uploads ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("expected a sarif_uploads row");
    assert_eq!(row.get::<String, _>("status"), "rejected");
    let body: Option<String> = row.get("response_body");
    assert!(
        body.unwrap_or_default().contains("sarif schema invalid"),
        "expected response body in rejected row"
    );
    pool.close().await;
}

#[tokio::test]
async fn upload_per_repo_opt_out_skips_post_entirely() {
    let server = setup_upload_test_server().await;

    // Mount the upload endpoint with expect(0) — opting out should mean
    // it's never called. wiremock will fail the test if it is.
    Mock::given(method("POST"))
        .and(path("/repos/up-org/up-repo/code-scanning/sarifs"))
        .respond_with(ResponseTemplate::new(202))
        .expect(0)
        .mount(&server)
        .await;

    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("upload-optout.db");
    let db_path_str = db_path.to_str().unwrap();
    let config_file = write_config(
        db_path_str,
        "upload_sarif = false\n",
        "[upload]\nenabled = true\n",
    );

    run_one_cycle(db_path_str, &config_file, &server).await;

    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{db_path_str}"))
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sarif_uploads")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "per-repo opt-out should prevent any sarif_uploads row"
    );
    pool.close().await;
}

#[tokio::test]
async fn upload_skip_unchanged_skips_post_when_hash_matches() {
    let server = setup_upload_test_server().await;

    // First cycle accepts; second cycle should match hash and skip
    // entirely. Mount the upload endpoint expecting exactly 1 call
    // across both cycles.
    Mock::given(method("POST"))
        .and(path("/repos/up-org/up-repo/code-scanning/sarifs"))
        .respond_with(
            ResponseTemplate::new(202).set_body_json(serde_json::json!({"id": "first"})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("upload-skip.db");
    let db_path_str = db_path.to_str().unwrap();
    let config_file = write_config(
        db_path_str,
        "",
        "[upload]\nenabled = true\nskip_unchanged = true\n",
    );

    // First cycle — POST happens, accepted.
    run_one_cycle(db_path_str, &config_file, &server).await;
    // Second cycle — same SARIF, no POST.
    run_one_cycle(db_path_str, &config_file, &server).await;

    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{db_path_str}"))
        .await
        .unwrap();
    let rows = sqlx::query("SELECT status FROM sarif_uploads ORDER BY id ASC")
        .fetch_all(&pool)
        .await
        .unwrap();
    let statuses: Vec<String> = rows.iter().map(|r| r.get::<String, _>("status")).collect();
    assert_eq!(
        statuses,
        vec!["accepted".to_string(), "skipped".to_string()],
        "expected accepted then skipped, got: {statuses:?}"
    );
    pool.close().await;
}

#[tokio::test]
async fn upload_disabled_globally_does_not_post() {
    let server = setup_upload_test_server().await;

    Mock::given(method("POST"))
        .and(path("/repos/up-org/up-repo/code-scanning/sarifs"))
        .respond_with(ResponseTemplate::new(202))
        .expect(0)
        .mount(&server)
        .await;

    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("upload-off.db");
    let db_path_str = db_path.to_str().unwrap();
    let config_file = write_config(db_path_str, "", "[upload]\nenabled = false\n");

    run_one_cycle(db_path_str, &config_file, &server).await;

    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{db_path_str}"))
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sarif_uploads")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    pool.close().await;
}
