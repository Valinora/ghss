use std::process::Command;

use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn ghss() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghss"))
}

/// Start a wiremock server with mocked action.yml and advisory responses.
///
/// Fixture hierarchy (3 levels):
/// ```text
/// test-org/composite-a@v1       (depth 0, root — composite)
/// ├── test-org/composite-b@v1   (depth 1 — composite)
/// │   └── test-org/deep-leaf@v1 (depth 2 — leaf)
/// └── test-org/leaf-x@v1        (depth 1 — leaf)
/// test-org/leaf-action@v1        (depth 0, root — leaf)
/// ```
async fn setup_mock_server() -> MockServer {
    let server = MockServer::start().await;

    // composite-a: composite action with two children
    Mock::given(method("GET"))
        .and(path("/test-org/composite-a/v1/action.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Composite A\n\
             runs:\n\
             \x20 using: composite\n\
             \x20 steps:\n\
             \x20\x20\x20 - uses: test-org/composite-b@v1\n\
             \x20\x20\x20 - uses: test-org/leaf-x@v1\n",
        ))
        .mount(&server)
        .await;

    // composite-b: composite action with one child
    Mock::given(method("GET"))
        .and(path("/test-org/composite-b/v1/action.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Composite B\n\
             runs:\n\
             \x20 using: composite\n\
             \x20 steps:\n\
             \x20\x20\x20 - uses: test-org/deep-leaf@v1\n",
        ))
        .mount(&server)
        .await;

    // deep-leaf: leaf node (node20)
    Mock::given(method("GET"))
        .and(path("/test-org/deep-leaf/v1/action.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Deep Leaf\nruns:\n  using: node20\n  main: index.js\n",
        ))
        .mount(&server)
        .await;

    // leaf-x: leaf node (node20)
    Mock::given(method("GET"))
        .and(path("/test-org/leaf-x/v1/action.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Leaf X\nruns:\n  using: node20\n  main: index.js\n",
        ))
        .mount(&server)
        .await;

    // leaf-action: leaf node (node20)
    Mock::given(method("GET"))
        .and(path("/test-org/leaf-action/v1/action.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Leaf Action\nruns:\n  using: node20\n  main: index.js\n",
        ))
        .mount(&server)
        .await;

    // Advisory API: return empty array for all GHSA advisory queries
    Mock::given(method("GET"))
        .and(path("/advisories"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([])),
        )
        .mount(&server)
        .await;

    server
}

fn run_ghss_with_mock(server: &MockServer, args: &[&str]) -> std::process::Output {
    ghss()
        .args(args)
        .env("GHSS_API_BASE_URL", server.uri())
        .env("GHSS_RAW_BASE_URL", server.uri())
        .env("GHSS_OSV_BASE_URL", format!("{}/osv-query", server.uri()))
        .env_remove("GITHUB_TOKEN")
        .output()
        .expect("failed to execute")
}

fn run_ghss_with_mock_and_token(server: &MockServer, args: &[&str]) -> std::process::Output {
    ghss()
        .args(args)
        .env("GHSS_API_BASE_URL", server.uri())
        .env("GHSS_RAW_BASE_URL", server.uri())
        .env("GHSS_OSV_BASE_URL", format!("{}/osv-query", server.uri()))
        .env("GITHUB_TOKEN", "fake-token")
        .output()
        .expect("failed to execute")
}

fn stdout_of_mock_with_token(server: &MockServer, args: &[&str]) -> String {
    let output = run_ghss_with_mock_and_token(server, args);
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn stdout_of_mock(server: &MockServer, args: &[&str]) -> String {
    let output = run_ghss_with_mock(server, args);
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

// ---------------------------------------------------------------------------
// Text output tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn depth_0_produces_flat_output() {
    let server = setup_mock_server().await;
    let stdout = stdout_of_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--provider",
            "ghsa",
            "--depth",
            "0",
        ],
    );

    // Only root actions at column 0
    let action_lines: Vec<&str> =
        stdout.lines().filter(|l| !l.starts_with(' ')).collect();
    assert_eq!(
        action_lines,
        vec!["test-org/composite-a@v1", "test-org/leaf-action@v1"],
        "depth 0 should only show root actions"
    );

    // No indented child action lines
    assert!(
        !stdout.contains("  test-org/"),
        "depth 0 should have no indented child actions, got:\n{stdout}"
    );
}

#[tokio::test]
async fn depth_1_expands_one_level() {
    let server = setup_mock_server().await;
    let stdout = stdout_of_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--provider",
            "ghsa",
            "--depth",
            "1",
        ],
    );

    // Root actions present at column 0
    assert!(
        stdout.contains("\ntest-org/leaf-action@v1\n")
            || stdout.starts_with("test-org/leaf-action@v1\n"),
        "leaf-action should be at column 0"
    );

    // Depth-1 children are indented (2 spaces) under composite-a
    assert!(
        stdout.contains("  test-org/composite-b@v1\n"),
        "composite-b should be indented at depth 1, got:\n{stdout}"
    );
    assert!(
        stdout.contains("  test-org/leaf-x@v1\n"),
        "leaf-x should be indented at depth 1, got:\n{stdout}"
    );

    // Depth-2 grandchild (deep-leaf) should NOT appear anywhere
    assert!(
        !stdout.contains("deep-leaf"),
        "depth 1 should not include grandchildren (deep-leaf), got:\n{stdout}"
    );
}

#[tokio::test]
async fn depth_unlimited_expands_full_tree() {
    let server = setup_mock_server().await;
    let stdout = stdout_of_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--provider",
            "ghsa",
            "--depth",
            "unlimited",
        ],
    );

    // Root at column 0
    assert!(
        stdout.starts_with("test-org/composite-a@v1\n"),
        "composite-a should be the first root at column 0, got:\n{stdout}"
    );

    // Depth-1 children indented by 2 spaces
    assert!(
        stdout.contains("  test-org/composite-b@v1\n"),
        "composite-b at depth 1, got:\n{stdout}"
    );
    assert!(
        stdout.contains("  test-org/leaf-x@v1\n"),
        "leaf-x at depth 1, got:\n{stdout}"
    );

    // Depth-2 grandchild indented by 4 spaces
    assert!(
        stdout.contains("    test-org/deep-leaf@v1\n"),
        "deep-leaf should be indented at depth 2 (4 spaces), got:\n{stdout}"
    );

    // Verify overall structure: composite-b's advisory line at depth 1
    // and deep-leaf's advisory line at depth 2
    assert!(
        stdout.contains("      advisories: none"),
        "deep-leaf's advisories should be indented 6 spaces (depth 2 enrichment), got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// JSON output tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn depth_1_json_omits_grandchildren() {
    let server = setup_mock_server().await;
    let stdout = stdout_of_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--provider",
            "ghsa",
            "--depth",
            "1",
            "--json",
        ],
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    let arr = parsed.as_array().expect("top-level should be an array");
    assert_eq!(arr.len(), 2, "should have 2 root entries");

    // composite-a should have children
    let composite_a = arr
        .iter()
        .find(|e| e["raw"] == "test-org/composite-a@v1")
        .expect("composite-a should be present");
    let children = composite_a["children"]
        .as_array()
        .expect("composite-a should have children array");
    assert_eq!(children.len(), 2, "composite-a should have 2 children");

    // composite-b (child) should NOT have children key (grandchildren omitted)
    let composite_b = children
        .iter()
        .find(|e| e["raw"] == "test-org/composite-b@v1")
        .expect("composite-b should be a child");
    assert!(
        composite_b.get("children").is_none(),
        "composite-b should have no children key at depth 1 (grandchildren omitted)"
    );

    // leaf-action should NOT have children key
    let leaf_action = arr
        .iter()
        .find(|e| e["raw"] == "test-org/leaf-action@v1")
        .expect("leaf-action should be present");
    assert!(
        leaf_action.get("children").is_none(),
        "leaf-action should have no children key"
    );
}

#[tokio::test]
async fn depth_unlimited_json_has_nested_children() {
    let server = setup_mock_server().await;
    let stdout = stdout_of_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--provider",
            "ghsa",
            "--depth",
            "unlimited",
            "--json",
        ],
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    let arr = parsed.as_array().expect("top-level should be an array");
    assert_eq!(arr.len(), 2, "should have 2 root entries");

    // Navigate the full tree: composite-a → composite-b → deep-leaf
    let composite_a = arr
        .iter()
        .find(|e| e["raw"] == "test-org/composite-a@v1")
        .expect("composite-a should be present");
    let a_children = composite_a["children"]
        .as_array()
        .expect("composite-a should have children");
    assert_eq!(a_children.len(), 2);

    let composite_b = a_children
        .iter()
        .find(|e| e["raw"] == "test-org/composite-b@v1")
        .expect("composite-b should be a child of composite-a");
    let b_children = composite_b["children"]
        .as_array()
        .expect("composite-b should have children at unlimited depth");
    assert_eq!(b_children.len(), 1);
    assert_eq!(b_children[0]["raw"], "test-org/deep-leaf@v1");

    // deep-leaf is a leaf — no children key
    assert!(
        b_children[0].get("children").is_none(),
        "deep-leaf should have no children key"
    );

    // leaf-x is a leaf — no children key
    let leaf_x = a_children
        .iter()
        .find(|e| e["raw"] == "test-org/leaf-x@v1")
        .expect("leaf-x should be a child of composite-a");
    assert!(
        leaf_x.get("children").is_none(),
        "leaf-x should have no children key"
    );

    // leaf-action root — no children key
    let leaf_action = arr
        .iter()
        .find(|e| e["raw"] == "test-org/leaf-action@v1")
        .expect("leaf-action should be present");
    assert!(
        leaf_action.get("children").is_none(),
        "leaf-action should have no children key"
    );
}

// ---------------------------------------------------------------------------
// 2a: Reusable workflow test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reusable_workflow_includes_job_level_refs() {
    let server = setup_mock_server().await;
    let stdout = stdout_of_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/reusable-workflow.yml",
            "--provider",
            "ghsa",
        ],
    );

    // Step-level actions
    assert!(
        stdout.contains("actions/checkout@v4"),
        "should contain step-level actions/checkout@v4, got:\n{stdout}"
    );
    assert!(
        stdout.contains("actions/setup-node@v4"),
        "should contain step-level actions/setup-node@v4, got:\n{stdout}"
    );
    // Job-level reusable workflow refs
    assert!(
        stdout.contains("org/shared-workflows/.github/workflows/ci.yml@main"),
        "should contain job-level reusable workflow ci.yml, got:\n{stdout}"
    );
    assert!(
        stdout.contains("org/shared-workflows/.github/workflows/deploy.yml@v1"),
        "should contain job-level reusable workflow deploy.yml, got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// 2b: Local-only/docker workflow (empty output edge case)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn local_only_workflow_produces_empty_output() {
    let server = setup_mock_server().await;
    let output = run_ghss_with_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/local-only-workflow.yml",
            "--provider",
            "ghsa",
        ],
    );

    assert!(output.status.success(), "should exit 0");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.is_empty(),
        "stdout should be empty for local-only workflow, got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// 2c: --select flag tests
// ---------------------------------------------------------------------------

/// Mock server extended with GraphQL response for scan queries.
async fn setup_scan_mock_server() -> MockServer {
    let server = setup_mock_server().await;

    // GraphQL endpoint: return language + ecosystem data
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "repository": {
                    "languages": {
                        "edges": [
                            {"size": 50000, "node": {"name": "TypeScript"}},
                            {"size": 10000, "node": {"name": "JavaScript"}}
                        ]
                    },
                    "packageJson": {"__typename": "Blob"},
                    "cargoToml": null,
                    "goMod": null,
                    "requirementsTxt": null,
                    "pyprojectToml": null,
                    "pomXml": null,
                    "buildGradle": null,
                    "gemfile": null,
                    "composerJson": null,
                    "dockerfile": null
                }
            }
        })))
        .mount(&server)
        .await;

    // OSV query endpoint: return empty for all queries
    Mock::given(method("POST"))
        .and(path("/osv-query"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;

    server
}

#[tokio::test]
async fn deps_shows_language_and_ecosystems() {
    let server = setup_scan_mock_server().await;
    let stdout = stdout_of_mock_with_token(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--provider",
            "ghsa",
            "--deps",
        ],
    );

    assert!(
        stdout.contains("language: TypeScript"),
        "should show primary language, got:\n{stdout}"
    );
    assert!(
        stdout.contains("ecosystems: npm"),
        "should show detected ecosystems, got:\n{stdout}"
    );
}

#[tokio::test]
async fn select_filters_root_actions() {
    let server = setup_mock_server().await;
    let stdout = stdout_of_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--provider",
            "ghsa",
            "--select",
            "1",
        ],
    );

    // Only the first root action should appear
    let action_lines: Vec<&str> = stdout.lines().filter(|l| !l.starts_with(' ')).collect();
    assert_eq!(
        action_lines,
        vec!["test-org/composite-a@v1"],
        "--select 1 should only include the first root action, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("leaf-action"),
        "--select 1 should exclude the second root action, got:\n{stdout}"
    );
}

#[tokio::test]
async fn select_with_deps() {
    let server = setup_scan_mock_server().await;
    let stdout = stdout_of_mock_with_token(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--provider",
            "ghsa",
            "--select",
            "1",
            "--deps",
        ],
    );

    // Only the first root action should appear
    assert!(
        stdout.contains("test-org/composite-a@v1"),
        "selected action should appear, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("leaf-action"),
        "unselected action should not appear, got:\n{stdout}"
    );
    // Scan data should be present for the selected action
    assert!(
        stdout.contains("language: TypeScript"),
        "--deps should enable scanning for selected action, got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// 2d: Mocked advisory test
// ---------------------------------------------------------------------------

async fn setup_advisory_mock_server() -> MockServer {
    let server = MockServer::start().await;

    // Return action.yml for leaf actions
    Mock::given(method("GET"))
        .and(path("/test-org/composite-a/v1/action.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Composite A\nruns:\n  using: node20\n  main: index.js\n",
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/test-org/leaf-action/v1/action.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Leaf Action\nruns:\n  using: node20\n  main: index.js\n",
        ))
        .mount(&server)
        .await;

    // GHSA advisory endpoint: return advisory for composite-a
    Mock::given(method("GET"))
        .and(path("/advisories"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "ghsa_id": "GHSA-test-adv1-0001",
                "summary": "Test composite vulnerability",
                "severity": "high",
                "html_url": "https://github.com/advisories/GHSA-test-adv1-0001",
                "vulnerabilities": [{
                    "package": {
                        "ecosystem": "actions",
                        "name": "test-org/composite-a"
                    },
                    "vulnerable_version_range": ">= 1.0.0, < 2.0.0"
                }]
            }
        ])))
        .mount(&server)
        .await;

    // OSV endpoint: return empty
    Mock::given(method("POST"))
        .and(path("/osv-query"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
        )
        .mount(&server)
        .await;

    server
}

#[tokio::test]
async fn mocked_advisory_appears_in_text_output() {
    let server = setup_advisory_mock_server().await;
    let stdout = stdout_of_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
        ],
    );

    assert!(
        stdout.contains("GHSA-test-adv1-0001"),
        "advisory ID should appear in text output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("high"),
        "advisory severity should appear in text output, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Test composite vulnerability"),
        "advisory summary should appear in text output, got:\n{stdout}"
    );
}

#[tokio::test]
async fn mocked_advisory_appears_in_json_output() {
    let server = setup_advisory_mock_server().await;
    let stdout = stdout_of_mock(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--json",
        ],
    );

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    let arr = parsed.as_array().expect("top-level should be array");

    // Find an entry with advisories
    let has_advisory = arr.iter().any(|entry| {
        entry["advisories"]
            .as_array()
            .is_some_and(|advs| {
                advs.iter()
                    .any(|a| a["id"] == "GHSA-test-adv1-0001")
            })
    });
    assert!(
        has_advisory,
        "JSON output should contain GHSA-test-adv1-0001 advisory, got:\n{stdout}"
    );

    // Verify advisory fields
    let advisory = arr
        .iter()
        .flat_map(|e| e["advisories"].as_array().unwrap().iter())
        .find(|a| a["id"] == "GHSA-test-adv1-0001")
        .expect("should find the advisory");
    assert_eq!(advisory["severity"], "high");
    assert_eq!(advisory["summary"], "Test composite vulnerability");
}

// ---------------------------------------------------------------------------
// 2e: --deps flag test
// ---------------------------------------------------------------------------

async fn setup_deps_mock_server() -> MockServer {
    let server = MockServer::start().await;

    // composite-a with package.json ecosystem for scan
    Mock::given(method("GET"))
        .and(path("/test-org/composite-a/v1/action.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Composite A\nruns:\n  using: node20\n  main: index.js\n",
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/test-org/leaf-action/v1/action.yml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "name: Leaf Action\nruns:\n  using: node20\n  main: index.js\n",
        ))
        .mount(&server)
        .await;

    // package.json for composite-a
    Mock::given(method("GET"))
        .and(path("/test-org/composite-a/v1/package.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"name": "composite-a", "dependencies": {"lodash": "^4.17.20"}}"#,
        ))
        .mount(&server)
        .await;

    // package.json for leaf-action
    Mock::given(method("GET"))
        .and(path("/test-org/leaf-action/v1/package.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{"name": "leaf-action", "dependencies": {}}"#,
        ))
        .mount(&server)
        .await;

    // GHSA advisory endpoint: return empty
    Mock::given(method("GET"))
        .and(path("/advisories"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([])),
        )
        .mount(&server)
        .await;

    // GraphQL endpoint for scan: shows npm ecosystem
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "repository": {
                    "languages": {
                        "edges": [
                            {"size": 30000, "node": {"name": "JavaScript"}}
                        ]
                    },
                    "packageJson": {"__typename": "Blob"},
                    "cargoToml": null,
                    "goMod": null,
                    "requirementsTxt": null,
                    "pyprojectToml": null,
                    "pomXml": null,
                    "buildGradle": null,
                    "gemfile": null,
                    "composerJson": null,
                    "dockerfile": null
                }
            }
        })))
        .mount(&server)
        .await;

    // OSV query for lodash: return a vulnerability
    Mock::given(method("POST"))
        .and(path("/osv-query"))
        .and(body_string_contains("lodash"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "vulns": [{
                "id": "GHSA-dep-lodash-0001",
                "summary": "Prototype pollution in lodash",
                "references": [
                    {"type": "ADVISORY", "url": "https://example.com/lodash-vuln"}
                ],
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.17.21"}
                        ]
                    }]
                }],
                "database_specific": {"severity": "HIGH"}
            }]
        })))
        .mount(&server)
        .await;

    // OSV: return empty for everything else
    Mock::given(method("POST"))
        .and(path("/osv-query"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
        )
        .expect(0..)
        .mount(&server)
        .await;

    server
}

#[tokio::test]
async fn deps_flag_shows_dependency_vulnerability() {
    let server = setup_deps_mock_server().await;
    let stdout = stdout_of_mock_with_token(
        &server,
        &[
            "--file",
            "tests/fixtures/depth-test-workflow.yml",
            "--provider",
            "all",
            "--deps",
        ],
    );

    assert!(
        stdout.contains("dependency vulnerabilities:"),
        "should show dependency vulnerabilities section, got:\n{stdout}"
    );
    assert!(
        stdout.contains("lodash"),
        "should mention lodash dependency, got:\n{stdout}"
    );
    assert!(
        stdout.contains("GHSA-dep-lodash-0001"),
        "should show lodash advisory ID, got:\n{stdout}"
    );
}
