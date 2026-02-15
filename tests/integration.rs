use std::process::Command;

fn ghss() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghss"))
}

#[test]
fn sample_workflow_lists_sorted_third_party_actions() {
    let output = ghss()
        .args(["--file", "tests/fixtures/sample-workflow.yml"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        vec![
            "actions/checkout@v4",
            "actions/setup-node@v4",
            "codecov/codecov-action@v3",
        ]
    );
}

#[test]
fn sample_workflow_excludes_docker_actions() {
    let output = ghss()
        .args(["--file", "tests/fixtures/sample-workflow.yml"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("docker://"),
        "docker actions should be filtered out"
    );
}

#[test]
fn sample_workflow_excludes_local_actions() {
    let output = ghss()
        .args(["--file", "tests/fixtures/sample-workflow.yml"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        !stdout.contains("./"),
        "local actions should be filtered out"
    );
}

#[test]
fn sample_workflow_deduplicates_actions() {
    let output = ghss()
        .args(["--file", "tests/fixtures/sample-workflow.yml"])
        .output()
        .expect("failed to execute");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let checkout_count = stdout
        .lines()
        .filter(|l| *l == "actions/checkout@v4")
        .count();
    assert_eq!(checkout_count, 1, "actions/checkout@v4 appears 3 times in the fixture but should be deduplicated to 1");
}

#[test]
fn malformed_workflow_still_extracts_valid_actions() {
    let output = ghss()
        .args(["--file", "tests/fixtures/malformed-workflow.yml"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        vec!["actions/checkout@v4", "actions/setup-node@v4",]
    );
}

#[test]
fn malformed_workflow_warns_on_stderr() {
    let output = ghss()
        .args(["--file", "tests/fixtures/malformed-workflow.yml"])
        .output()
        .expect("failed to execute");

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("warning"),
        "should warn about malformed job"
    );
    assert!(
        stderr.contains("broken-steps"),
        "should name the broken job"
    );
}

#[test]
fn missing_file_exits_with_error() {
    let output = ghss()
        .args(["--file", "tests/fixtures/nonexistent.yml"])
        .output()
        .expect("failed to execute");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("file not found"));
}

#[test]
fn no_file_arg_exits_with_error() {
    let output = ghss().output().expect("failed to execute");

    assert!(!output.status.success());
}

#[test]
fn resolve_without_token_does_not_require_token() {
    let output = ghss()
        .args(["--file", "tests/fixtures/sample-workflow.yml", "--resolve"])
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
    let output = ghss()
        .args(["--file", "tests/fixtures/sha-pinned-workflow.yml"])
        .output()
        .expect("failed to execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"));
    assert!(stdout.contains("actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8"));
    assert!(stdout.contains("codecov/codecov-action@v3"));
}
