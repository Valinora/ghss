use std::collections::HashMap;

use serde::Deserialize;
use tracing::warn;

#[derive(Debug, Deserialize)]
struct Workflow {
    #[serde(default)]
    jobs: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct Job {
    #[serde(default)]
    uses: Option<String>,
    #[serde(default)]
    steps: Option<Vec<Step>>,
}

#[derive(Debug, Deserialize)]
struct Step {
    uses: Option<String>,
}

pub fn parse_workflow(yaml: &str) -> anyhow::Result<Vec<String>> {
    let workflow: Workflow = serde_yaml::from_str(yaml)?;

    let mut uses_refs = Vec::new();

    for (job_name, job_value) in workflow.jobs {
        match serde_yaml::from_value::<Job>(job_value) {
            Ok(job) => {
                if let Some(uses) = job.uses {
                    uses_refs.push(uses);
                }
                if let Some(steps) = job.steps {
                    for step in steps {
                        if let Some(uses) = step.uses {
                            uses_refs.push(uses);
                        }
                    }
                }
            }
            Err(e) => {
                warn!(job = %job_name, error = %e, "failed to parse job");
            }
        }
    }

    Ok(uses_refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn read_fixture(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        std::fs::read_to_string(path).expect("fixture not found")
    }

    #[test]
    fn parse_sample_workflow_extracts_all_uses() {
        let refs = parse_workflow(&read_fixture("sample-workflow.yml")).unwrap();
        assert!(refs.contains(&"actions/checkout@v4".to_string()));
        assert!(refs.contains(&"actions/setup-node@v4".to_string()));
        assert!(refs.contains(&"docker://node:18".to_string()));
        assert!(refs.contains(&"codecov/codecov-action@v3".to_string()));
        assert!(refs.contains(&"./local-action".to_string()));
    }

    #[test]
    fn parse_sample_workflow_includes_duplicates() {
        let refs = parse_workflow(&read_fixture("sample-workflow.yml")).unwrap();
        let checkout_count = refs.iter().filter(|r| *r == "actions/checkout@v4").count();
        assert_eq!(checkout_count, 3);
    }

    #[test]
    fn parse_malformed_workflow_extracts_valid_jobs() {
        let refs = parse_workflow(&read_fixture("malformed-workflow.yml")).unwrap();
        assert!(refs.contains(&"actions/checkout@v4".to_string()));
        assert!(refs.contains(&"actions/setup-node@v4".to_string()));
        assert!(refs.contains(&"docker://alpine:3.18".to_string()));
    }

    #[test]
    fn parse_malformed_workflow_does_not_fail() {
        let result = parse_workflow(&read_fixture("malformed-workflow.yml"));
        assert!(result.is_ok());
    }

    #[test]
    fn parse_invalid_yaml_returns_error() {
        let result = parse_workflow("not: [valid: yaml: {{{");
        assert!(result.is_err());
    }

    #[test]
    fn parse_reusable_workflow_extracts_step_and_job_level_uses() {
        let refs = parse_workflow(&read_fixture("reusable-workflow.yml")).unwrap();
        // Step-level uses
        assert!(refs.contains(&"actions/checkout@v4".to_string()));
        assert!(refs.contains(&"actions/setup-node@v4".to_string()));
        // Job-level reusable workflow calls
        assert!(refs.contains(
            &"org/shared-workflows/.github/workflows/ci.yml@main".to_string()
        ));
        assert!(refs.contains(
            &"org/shared-workflows/.github/workflows/deploy.yml@v1".to_string()
        ));
        // Total: 2 step-level + 2 job-level = 4
        assert_eq!(refs.len(), 4);
    }
}
