use std::collections::HashMap;

use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, instrument, warn};

use crate::action_ref::ActionRef;
use crate::context::{AuditContext, StageError};
use crate::github::GitHubClient;

use super::Stage;

#[derive(Debug, Deserialize)]
struct RemoteWorkflow {
    #[serde(default)]
    jobs: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct RemoteJob {
    #[serde(default)]
    uses: Option<String>,
    #[serde(default)]
    steps: Option<Vec<RemoteStep>>,
}

#[derive(Debug, Deserialize)]
struct RemoteStep {
    uses: Option<String>,
}

/// Extract child `ActionRef`s from a reusable workflow YAML string.
///
/// Parses both step-level `uses:` values and job-level reusable workflow calls.
/// Filters out local (`./`) and Docker (`docker://`) references.
fn parse_workflow_children(yaml: &str) -> anyhow::Result<Vec<ActionRef>> {
    let workflow: RemoteWorkflow = serde_yaml::from_str(yaml)?;

    let mut children = Vec::new();

    for (job_name, job_value) in workflow.jobs {
        match serde_yaml::from_value::<RemoteJob>(job_value) {
            Ok(job) => {
                // Job-level reusable workflow call
                if let Some(uses) = job.uses {
                    if !uses.starts_with("./") && !uses.starts_with("docker://") {
                        match uses.parse::<ActionRef>() {
                            Ok(action_ref) => children.push(action_ref),
                            Err(e) => {
                                warn!(
                                    job = %job_name,
                                    uses = %uses,
                                    error = %e,
                                    "failed to parse job-level uses in remote workflow"
                                );
                            }
                        }
                    }
                }

                // Step-level uses
                if let Some(steps) = job.steps {
                    for step in steps {
                        if let Some(uses) = step.uses {
                            if uses.starts_with("./") || uses.starts_with("docker://") {
                                continue;
                            }
                            match uses.parse::<ActionRef>() {
                                Ok(action_ref) => children.push(action_ref),
                                Err(e) => {
                                    warn!(
                                        job = %job_name,
                                        uses = %uses,
                                        error = %e,
                                        "failed to parse step-level uses in remote workflow"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(job = %job_name, error = %e, "failed to parse job in remote workflow");
            }
        }
    }

    Ok(children)
}

pub struct WorkflowExpandStage {
    client: GitHubClient,
}

impl WorkflowExpandStage {
    pub fn new(client: GitHubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Stage for WorkflowExpandStage {
    #[instrument(skip(self, ctx), fields(action = %ctx.action.raw))]
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()> {
        // Only process if this action ref points to a workflow file
        let path = match &ctx.action.path {
            Some(p) if p.contains(".github/workflows/") => p.clone(),
            _ => {
                debug!(action = %ctx.action.raw, "not a reusable workflow path, skipping");
                return Ok(());
            }
        };

        let owner = &ctx.action.owner;
        let repo = &ctx.action.repo;
        let git_ref = &ctx.action.git_ref;

        let yaml_content = match self.client.get_raw_content(owner, repo, git_ref, &path).await {
            Ok(content) => content,
            Err(e) if e.to_string().contains("not found") => {
                debug!(action = %ctx.action.raw, "workflow file not found, skipping");
                return Ok(());
            }
            Err(e) => {
                warn!(action = %ctx.action.raw, error = %e, "failed to fetch workflow file");
                ctx.errors.push(StageError {
                    stage: self.name().to_string(),
                    message: e.to_string(),
                });
                return Ok(());
            }
        };

        match parse_workflow_children(&yaml_content) {
            Ok(children) => {
                debug!(action = %ctx.action.raw, count = children.len(), "discovered workflow children");
                ctx.children.extend(children);
            }
            Err(e) => {
                warn!(action = %ctx.action.raw, error = %e, "failed to parse remote workflow YAML");
                ctx.errors.push(StageError {
                    stage: self.name().to_string(),
                    message: e.to_string(),
                });
            }
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "WorkflowExpand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_workflow_with_step_level_actions() {
        let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm test
      - uses: codecov/codecov-action@v3
"#;
        let children = parse_workflow_children(yaml).unwrap();
        assert_eq!(children.len(), 3);

        let raws: Vec<&str> = children.iter().map(|c| c.raw.as_str()).collect();
        assert!(raws.contains(&"actions/checkout@v4"));
        assert!(raws.contains(&"actions/setup-node@v4"));
        assert!(raws.contains(&"codecov/codecov-action@v3"));
    }

    #[test]
    fn parse_workflow_with_job_level_reusable_calls() {
        let yaml = r#"
name: Orchestrator
on: push
jobs:
  call-ci:
    uses: org/workflows/.github/workflows/ci.yml@main
  call-deploy:
    uses: org/workflows/.github/workflows/deploy.yml@v1
"#;
        let children = parse_workflow_children(yaml).unwrap();
        assert_eq!(children.len(), 2);

        let raws: Vec<&str> = children.iter().map(|c| c.raw.as_str()).collect();
        assert!(raws.contains(&"org/workflows/.github/workflows/ci.yml@main"));
        assert!(raws.contains(&"org/workflows/.github/workflows/deploy.yml@v1"));
    }

    #[test]
    fn parse_workflow_filters_local_and_docker() {
        let yaml = r#"
name: Mixed
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./local-action
      - uses: docker://node:18
      - uses: some-org/action@v2
"#;
        let children = parse_workflow_children(yaml).unwrap();
        assert_eq!(children.len(), 2);

        let raws: Vec<&str> = children.iter().map(|c| c.raw.as_str()).collect();
        assert!(raws.contains(&"actions/checkout@v4"));
        assert!(raws.contains(&"some-org/action@v2"));
    }

    #[test]
    fn parse_workflow_mixed_step_and_job_level() {
        let yaml = r#"
name: Full Example
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
  call-lint:
    uses: org/shared/.github/workflows/lint.yml@v2
"#;
        let children = parse_workflow_children(yaml).unwrap();
        assert_eq!(children.len(), 2);

        let raws: Vec<&str> = children.iter().map(|c| c.raw.as_str()).collect();
        assert!(raws.contains(&"actions/checkout@v4"));
        assert!(raws.contains(&"org/shared/.github/workflows/lint.yml@v2"));
    }

    #[test]
    fn parse_invalid_workflow_yaml_returns_error() {
        let yaml = "not: valid: yaml: [[[";
        let result = parse_workflow_children(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_workflow_returns_empty() {
        let yaml = r#"
name: Empty
on: push
jobs: {}
"#;
        let children = parse_workflow_children(yaml).unwrap();
        assert!(children.is_empty());
    }
}
