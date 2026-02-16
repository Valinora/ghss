use std::process::Command;

fn ghss() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghss"))
}

fn run_ghss(args: &[&str]) -> std::process::Output {
    ghss()
        .args(args)
        .output()
        .expect("failed to execute")
}

fn stdout_of(args: &[&str]) -> String {
    let output = run_ghss(args);
    assert!(output.status.success(), "command failed: {}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

#[allow(dead_code)]
fn stderr_of(args: &[&str]) -> String {
    let output = run_ghss(args);
    String::from_utf8(output.stderr).unwrap()
}

#[test]
fn sample_workflow_lists_sorted_third_party_actions() {
    let stdout = stdout_of(&["--file", "tests/fixtures/sample-workflow.yml"]);
    let action_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.starts_with("  "))
        .collect();
    assert_eq!(
        action_lines,
        vec![
            "actions/checkout@v4",
            "actions/setup-node@v4",
            "codecov/codecov-action@v3",
        ]
    );
}

#[test]
fn sample_workflow_excludes_docker_actions() {
    let stdout = stdout_of(&["--file", "tests/fixtures/sample-workflow.yml"]);
    assert!(
        !stdout.contains("docker://"),
        "docker actions should be filtered out"
    );
}

#[test]
fn sample_workflow_excludes_local_actions() {
    let stdout = stdout_of(&["--file", "tests/fixtures/sample-workflow.yml"]);
    assert!(
        !stdout.contains("./"),
        "local actions should be filtered out"
    );
}

#[test]
fn sample_workflow_deduplicates_actions() {
    let stdout = stdout_of(&["--file", "tests/fixtures/sample-workflow.yml"]);
    let checkout_count = stdout
        .lines()
        .filter(|l| *l == "actions/checkout@v4")
        .count();
    assert_eq!(checkout_count, 1, "actions/checkout@v4 appears 3 times in the fixture but should be deduplicated to 1");
}

#[test]
fn malformed_workflow_still_extracts_valid_actions() {
    let stdout = stdout_of(&["--file", "tests/fixtures/malformed-workflow.yml"]);
    let action_lines: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.starts_with("  "))
        .collect();
    assert_eq!(
        action_lines,
        vec!["actions/checkout@v4", "actions/setup-node@v4",]
    );
}

#[test]
fn malformed_workflow_warns_on_stderr() {
    let output = run_ghss(&["--file", "tests/fixtures/malformed-workflow.yml"]);

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("WARN"),
        "should warn about malformed job"
    );
    assert!(
        stderr.contains("broken-steps"),
        "should name the broken job"
    );
}

#[test]
fn missing_file_exits_with_error() {
    let output = run_ghss(&["--file", "tests/fixtures/nonexistent.yml"]);

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("file not found"));
}

#[test]
fn no_file_arg_exits_with_error() {
    let output = run_ghss(&[]);

    assert!(!output.status.success());
}

#[test]
fn advisories_without_token_does_not_require_token() {
    let output = ghss()
        .args([
            "--file",
            "tests/fixtures/sample-workflow.yml",
            "--advisories",
        ])
        .env_remove("GITHUB_TOKEN")
        .output()
        .expect("failed to execute");

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        !stderr.contains("--github-token or GITHUB_TOKEN"),
        "should not hard-fail on missing token"
    );
}

#[test]
fn sha_pinned_workflow_lists_actions() {
    let stdout = stdout_of(&["--file", "tests/fixtures/sha-pinned-workflow.yml"]);
    assert!(stdout.contains("actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"));
    assert!(stdout.contains("actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8"));
    assert!(stdout.contains("codecov/codecov-action@v3"));
}

#[test]
fn json_flag_outputs_valid_json_array() {
    let stdout = stdout_of(&["--file", "tests/fixtures/sample-workflow.yml", "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout should be valid JSON");
    let arr = parsed.as_array().expect("should be a JSON array");
    assert_eq!(arr.len(), 3);

    // Verify expected fields are present
    for entry in arr {
        assert!(entry.get("raw").is_some(), "each entry should have 'raw'");
        assert!(entry.get("owner").is_some(), "each entry should have 'owner'");
        assert!(entry.get("repo").is_some(), "each entry should have 'repo'");
        assert!(entry.get("git_ref").is_some(), "each entry should have 'git_ref'");
        assert!(entry.get("ref_type").is_some(), "each entry should have 'ref_type'");
    }

    // Verify specific actions are present
    let raws: Vec<&str> = arr.iter().map(|e| e["raw"].as_str().unwrap()).collect();
    assert!(raws.contains(&"actions/checkout@v4"));
    assert!(raws.contains(&"actions/setup-node@v4"));
    assert!(raws.contains(&"codecov/codecov-action@v3"));
}

#[test]
fn json_output_omits_advisories_when_not_requested() {
    let stdout = stdout_of(&["--file", "tests/fixtures/sample-workflow.yml", "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().unwrap();

    for entry in arr {
        assert!(
            entry.get("advisories").is_none(),
            "advisories should be absent when --advisories not used"
        );
    }
}

/// Requires network access and a GitHub token to avoid rate limits.
/// Run with: cargo test -- --ignored
#[test]
#[ignore]
fn vulnerable_workflow_reports_known_advisories() {
    let stdout = stdout_of(&[
        "--file",
        "tests/fixtures/vulnerable-workflow.yml",
        "--advisories",
    ]);

    // tj-actions/changed-files@v35 has known advisories
    assert!(
        stdout.contains("GHSA-mrrh-fwg8-r2c3"),
        "should report tj-actions/changed-files secret disclosure advisory"
    );
    assert!(
        stdout.contains("GHSA-mcph-m25j-8j63"),
        "should report tj-actions/changed-files command injection advisory"
    );

    // super-linter/super-linter@v6 has a known advisory
    assert!(
        stdout.contains("GHSA-r79c-pqj3-577x"),
        "should report super-linter command injection advisory"
    );

    // actions/checkout@v4 should have no advisories
    assert!(
        stdout.contains("actions/checkout@v4\n  sha:") && stdout.contains("advisories: none"),
        "actions/checkout@v4 should have no advisories"
    );
}

#[test]
fn json_flag_produces_json_tracing_on_stderr() {
    let output = run_ghss(&["--file", "tests/fixtures/malformed-workflow.yml", "--json"]);

    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    // Each non-empty line on stderr should be valid JSON (structured tracing)
    let lines: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "malformed workflow should produce log output");
    for line in &lines {
        assert!(
            serde_json::from_str::<serde_json::Value>(line).is_ok(),
            "stderr line should be valid JSON: {line}"
        );
    }
}
