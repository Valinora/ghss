use std::process::Command;

fn fixture(name: &str) -> String {
    let dir = env!("CARGO_MANIFEST_DIR");
    format!("{dir}/tests/fixtures/{name}")
}

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
    let stdout = stdout_of(&["--file", &fixture("sample-workflow.yml")]);
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
    let stdout = stdout_of(&["--file", &fixture("sample-workflow.yml")]);
    assert!(
        !stdout.contains("docker://"),
        "docker actions should be filtered out"
    );
}

#[test]
fn sample_workflow_excludes_local_actions() {
    let stdout = stdout_of(&["--file", &fixture("sample-workflow.yml")]);
    assert!(
        !stdout.contains("./"),
        "local actions should be filtered out"
    );
}

#[test]
fn sample_workflow_deduplicates_actions() {
    let stdout = stdout_of(&["--file", &fixture("sample-workflow.yml")]);
    let checkout_count = stdout
        .lines()
        .filter(|l| *l == "actions/checkout@v4")
        .count();
    assert_eq!(checkout_count, 1, "actions/checkout@v4 appears 3 times in the fixture but should be deduplicated to 1");
}

#[test]
fn malformed_workflow_still_extracts_valid_actions() {
    let stdout = stdout_of(&["--file", &fixture("malformed-workflow.yml")]);
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
    let output = run_ghss(&["--file", &fixture("malformed-workflow.yml")]);

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
    let output = run_ghss(&["--file", &fixture("nonexistent.yml")]);

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
fn advisories_run_without_token() {
    let output = ghss()
        .args([
            "--file",
            &fixture("sample-workflow.yml"),
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
    let stdout = stdout_of(&["--file", &fixture("sha-pinned-workflow.yml")]);
    assert!(stdout.contains("actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"));
    assert!(stdout.contains("actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8"));
    assert!(stdout.contains("codecov/codecov-action@v3"));
}

#[test]
fn json_flag_outputs_valid_json_array() {
    let stdout = stdout_of(&["--file", &fixture("sample-workflow.yml"), "--json"]);
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
fn json_output_always_includes_advisories_key() {
    let stdout = stdout_of(&["--file", &fixture("sample-workflow.yml"), "--json"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = parsed.as_array().unwrap();

    for entry in arr {
        assert!(
            entry.get("advisories").is_some(),
            "advisories should always be present in JSON output"
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
        &fixture("vulnerable-workflow.yml"),
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
fn provider_osv_flag_is_accepted() {
    let output = run_ghss(&["--file", &fixture("sample-workflow.yml"), "--provider", "osv"]);
    assert!(output.status.success(), "--provider osv should be accepted");
}

#[test]
fn provider_ghsa_flag_is_accepted() {
    let output = run_ghss(&["--file", &fixture("sample-workflow.yml"), "--provider", "ghsa"]);
    assert!(output.status.success(), "--provider ghsa should be accepted");
}

#[test]
fn provider_all_flag_is_accepted() {
    let output = run_ghss(&["--file", &fixture("sample-workflow.yml"), "--provider", "all"]);
    assert!(output.status.success(), "--provider all should be accepted");
}

#[test]
fn unknown_provider_exits_with_error() {
    let output = run_ghss(&["--file", &fixture("sample-workflow.yml"), "--provider", "bogus"]);
    assert!(!output.status.success(), "unknown provider should fail");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("unknown provider"), "should mention unknown provider");
}

#[test]
#[ignore] // hits live GitHub API; flaky under rate limiting
fn depth_zero_explicit_matches_default_output() {
    // --depth 0 explicitly should produce identical output to no --depth flag
    let default_stdout = stdout_of(&["--file", &fixture("sample-workflow.yml")]);
    let depth0_stdout = stdout_of(&["--file", &fixture("sample-workflow.yml"), "--depth", "0"]);
    assert_eq!(
        default_stdout, depth0_stdout,
        "--depth 0 should produce identical output to default (no --depth)"
    );
}

#[test]
fn depth_default_matches_current_behavior() {
    // No --depth flag (default) should behave like --depth 0
    let stdout = stdout_of(&["--file", &fixture("sample-workflow.yml")]);
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
fn depth_unlimited_is_accepted() {
    let output = run_ghss(&["--file", &fixture("sample-workflow.yml"), "--depth", "unlimited"]);
    assert!(
        output.status.success(),
        "--depth unlimited should be accepted, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn depth_invalid_exits_with_error() {
    let output = run_ghss(&["--file", &fixture("sample-workflow.yml"), "--depth", "invalid"]);
    assert!(
        !output.status.success(),
        "--depth invalid should fail"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("invalid"),
        "error message should mention invalid input, got: {stderr}"
    );
}

#[test]
#[ignore] // hits live GitHub API; flaky under rate limiting
fn depth_zero_json_matches_default_json_output() {
    let default_stdout = stdout_of(&["--file", &fixture("sample-workflow.yml"), "--json"]);
    let depth0_stdout = stdout_of(&["--file", &fixture("sample-workflow.yml"), "--json", "--depth", "0"]);
    assert_eq!(
        default_stdout, depth0_stdout,
        "--depth 0 --json should produce identical output to default --json"
    );
}

#[test]
fn json_flag_produces_json_tracing_on_stderr() {
    let output = run_ghss(&["--file", &fixture("malformed-workflow.yml"), "--json"]);

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

// ── Depth demo tests (require network + GITHUB_TOKEN) ──

/// Requires network access and a GitHub token.
/// Run with: cargo test --test integration -- --ignored depth_demo
#[test]
#[ignore]
fn depth_demo_expands_composite_at_depth_1() {
    let stdout = stdout_of(&[
        "--file",
        &fixture("depth-demo-workflow.yml"),
        "--depth",
        "1",
    ]);

    // At depth 0 the composite action itself should appear
    assert!(
        stdout.contains("tj-actions/changed-files@v35"),
        "should list the composite action itself"
    );

    // At depth 1 the composite's child actions should appear indented
    assert!(
        stdout.contains("tj-actions/glob"),
        "should expand composite to reveal tj-actions/glob child action"
    );
}

/// Requires network access and a GitHub token.
/// Run with: cargo test --test integration -- --ignored depth_demo
#[test]
#[ignore]
fn depth_demo_expands_reusable_workflow_at_depth_1() {
    let stdout = stdout_of(&[
        "--file",
        &fixture("depth-demo-workflow.yml"),
        "--depth",
        "1",
    ]);

    // The reusable workflow ref itself should appear
    assert!(
        stdout.contains("slsa-framework/slsa-github-generator"),
        "should list the reusable workflow ref"
    );

    // At depth 1 the workflow's internal actions should appear as children.
    // The SLSA generator workflow uses actions/checkout internally.
    // Check for at least one child action from the expanded workflow.
    let lines: Vec<&str> = stdout.lines().collect();
    let slsa_idx = lines.iter().position(|l| l.contains("slsa-framework/slsa-github-generator"));
    assert!(
        slsa_idx.is_some(),
        "should find the slsa-framework ref in output"
    );

    // There should be indented children after the SLSA workflow ref
    let after_slsa: Vec<&&str> = lines[slsa_idx.unwrap() + 1..]
        .iter()
        .take_while(|l| l.starts_with("  "))
        .collect();
    assert!(
        !after_slsa.is_empty(),
        "reusable workflow should have indented child actions at depth 1"
    );
}
