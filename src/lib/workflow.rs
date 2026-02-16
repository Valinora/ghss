use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use tracing::{instrument, warn};

#[derive(Debug, Deserialize)]
struct Workflow {
    #[serde(default)]
    jobs: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct Job {
    #[serde(default)]
    steps: Option<Vec<Step>>,
}

#[derive(Debug, Deserialize)]
struct Step {
    uses: Option<String>,
}

#[instrument(skip(path), fields(path = %path.display()))]
pub fn parse_workflow(path: &Path) -> anyhow::Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)?;
    let workflow: Workflow = serde_yaml::from_str(&contents)?;

    let mut uses_refs = Vec::new();

    for (job_name, job_value) in workflow.jobs {
        match serde_yaml::from_value::<Job>(job_value) {
            Ok(job) => {
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

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn parse_sample_workflow_extracts_all_uses() {
        let refs = parse_workflow(&fixture_path("sample-workflow.yml")).unwrap();
        assert!(refs.contains(&"actions/checkout@v4".to_string()));
        assert!(refs.contains(&"actions/setup-node@v4".to_string()));
        assert!(refs.contains(&"docker://node:18".to_string()));
        assert!(refs.contains(&"codecov/codecov-action@v3".to_string()));
        assert!(refs.contains(&"./local-action".to_string()));
    }

    #[test]
    fn parse_sample_workflow_includes_duplicates() {
        let refs = parse_workflow(&fixture_path("sample-workflow.yml")).unwrap();
        let checkout_count = refs.iter().filter(|r| *r == "actions/checkout@v4").count();
        assert_eq!(checkout_count, 3);
    }

    #[test]
    fn parse_malformed_workflow_extracts_valid_jobs() {
        let refs = parse_workflow(&fixture_path("malformed-workflow.yml")).unwrap();
        assert!(refs.contains(&"actions/checkout@v4".to_string()));
        assert!(refs.contains(&"actions/setup-node@v4".to_string()));
        assert!(refs.contains(&"docker://alpine:3.18".to_string()));
    }

    #[test]
    fn parse_malformed_workflow_does_not_fail() {
        let result = parse_workflow(&fixture_path("malformed-workflow.yml"));
        assert!(result.is_ok());
    }

    #[test]
    fn parse_nonexistent_file_returns_error() {
        let result = parse_workflow(Path::new("nonexistent.yml"));
        assert!(result.is_err());
    }
}
