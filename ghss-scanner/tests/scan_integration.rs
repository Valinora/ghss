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

fn write_config(db_path: &str, repos_toml: &str) -> NamedTempFile {
    let config = format!(
        r#"
[scanner]
github_token = "ghp_test123"
schedule = "*/30 * * * *"

{repos_toml}

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

/// Set up a mock server that simulates:
/// - Contents API returning a workflow listing
/// - Raw content returning workflow YAML
/// - Ref resolution for each action
/// - Advisory endpoints (empty results)
/// - Composite action checks (leaf nodes)
async fn setup_scan_mock_server() -> MockServer {
    let server = MockServer::start().await;

    // Contents API: list workflow files for test-org/test-repo
    Mock::given(method("GET"))
        .and(path("/repos/test-org/test-repo/contents/.github/workflows"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"name": "ci.yml", "type": "file"},
            {"name": "deploy.yml", "type": "file"},
            {"name": "README.md", "type": "file"}
        ])))
        .mount(&server)
        .await;

    // Raw content: ci.yml
    Mock::given(method("GET"))
        .and(path(
            "/test-org/test-repo/HEAD/.github/workflows/ci.yml",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: CI\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v3\n",
        ))
        .mount(&server)
        .await;

    // Raw content: deploy.yml (has one overlapping action + one unique)
    Mock::given(method("GET"))
        .and(path(
            "/test-org/test-repo/HEAD/.github/workflows/deploy.yml",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Deploy\non:\n  push:\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: aws-actions/configure-aws-credentials@v4\n",
        ))
        .mount(&server)
        .await;

    // Ref resolution: actions/checkout@v4
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

    // Ref resolution: aws-actions/configure-aws-credentials@v4
    Mock::given(method("GET"))
        .and(path(
            "/repos/aws-actions/configure-aws-credentials/git/ref/tags/v4",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ref": "refs/tags/v4",
            "object": {
                "type": "commit",
                "sha": "e3dd6a429d7300a6a4c196c26e071d42e0343502"
            }
        })))
        .mount(&server)
        .await;

    // Composite action checks: all are leaf nodes (node20)
    for action_path in [
        "/actions/checkout/v4/action.yml",
        "/actions/setup-node/v3/action.yml",
        "/aws-actions/configure-aws-credentials/v4/action.yml",
    ] {
        Mock::given(method("GET"))
            .and(path(action_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("name: Action\nruns:\n  using: node20\n  main: index.js\n"),
            )
            .mount(&server)
            .await;
    }

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
async fn real_scan_discovers_workflows_and_produces_findings() {
    let server = setup_scan_mock_server().await;
    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("scan-test.db");
    let db_path_str = db_path.to_str().unwrap();

    // Config without explicit workflows — scanner should discover them via Contents API
    let repos_toml = r#"
[[repos]]
owner = "test-org"
name = "test-repo"
"#;

    let config_file = write_config(db_path_str, repos_toml);

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

    // Open the SQLite database and verify findings
    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{db_path_str}"))
        .await
        .expect("failed to open test database");

    // Should have exactly 1 scan run
    let scan_run_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_runs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(scan_run_count, 1);

    // Should have 3 unique action findings (checkout, setup-node, configure-aws-credentials)
    let findings_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        findings_count, 3,
        "expected 3 findings (deduplicated across workflows)"
    );

    // Verify the action refs are real (not fake)
    let findings: Vec<_> =
        sqlx::query("SELECT action_ref, resolved_sha FROM findings ORDER BY action_ref")
            .fetch_all(&pool)
            .await
            .unwrap();

    let action_refs: Vec<String> = findings
        .iter()
        .map(|r| r.get::<String, _>("action_ref"))
        .collect();

    assert!(
        action_refs.iter().any(|r| r.contains("actions/checkout")),
        "expected actions/checkout in findings, got: {action_refs:?}"
    );
    assert!(
        action_refs.iter().any(|r| r.contains("actions/setup-node")),
        "expected actions/setup-node in findings, got: {action_refs:?}"
    );
    assert!(
        action_refs
            .iter()
            .any(|r| r.contains("aws-actions/configure-aws-credentials")),
        "expected aws-actions/configure-aws-credentials in findings, got: {action_refs:?}"
    );

    // Verify resolved SHAs are present (not None)
    for finding in &findings {
        let sha: Option<String> = finding.get("resolved_sha");
        assert!(sha.is_some(), "expected resolved SHA for each finding");
        assert!(
            sha.as_ref().unwrap().len() == 40,
            "expected 40-char SHA, got: {:?}",
            sha
        );
    }

    // Verify each finding has valid serialized JSON
    let serialized_findings = sqlx::query("SELECT serialized_node FROM findings")
        .fetch_all(&pool)
        .await
        .unwrap();
    for row in &serialized_findings {
        let json_str: String = row.get("serialized_node");
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("serialized_node should be valid JSON");
        // Verify it has expected fields
        assert!(
            parsed.get("owner").is_some(),
            "expected owner field in serialized node"
        );
        assert!(
            parsed.get("repo").is_some(),
            "expected repo field in serialized node"
        );
    }

    pool.close().await;
}

#[tokio::test]
async fn explicit_workflows_config_skips_contents_api() {
    let server = setup_scan_mock_server().await;
    let tmp_dir = TempDir::new().unwrap();
    let db_path = tmp_dir.path().join("explicit-test.db");
    let db_path_str = db_path.to_str().unwrap();

    // Config with explicit workflows — should NOT call Contents API
    let repos_toml = r#"
[[repos]]
owner = "test-org"
name = "test-repo"
workflows = ["ci.yml"]
"#;

    let config_file = write_config(db_path_str, repos_toml);

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

    let pool = SqlitePoolOptions::new()
        .connect(&format!("sqlite://{db_path_str}"))
        .await
        .expect("failed to open test database");

    // Only ci.yml was scanned — should have 2 findings (checkout + setup-node)
    let findings_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(findings_count, 2, "expected 2 findings from ci.yml only");

    pool.close().await;
}
