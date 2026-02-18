use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, instrument, warn};

use crate::action_ref::ActionRef;
use crate::context::AuditContext;
use crate::github::GitHubClient;

use super::Stage;

#[derive(Debug, Deserialize)]
struct ActionYaml {
    #[serde(default)]
    runs: Option<ActionRuns>,
}

#[derive(Debug, Deserialize)]
struct ActionRuns {
    using: String,
    #[serde(default)]
    steps: Option<Vec<ActionStep>>,
}

#[derive(Debug, Deserialize)]
struct ActionStep {
    uses: Option<String>,
}

/// Extract child `ActionRef`s from a composite action YAML string.
///
/// Returns `None` if the action is not composite (e.g., `runs.using` is `"node20"`).
/// Returns `Some(vec)` with discovered third-party action refs if composite.
fn parse_composite_action(yaml: &str) -> anyhow::Result<Option<Vec<ActionRef>>> {
    let action: ActionYaml = serde_yaml::from_str(yaml)?;

    let Some(runs) = action.runs else {
        debug!("action.yml has no 'runs' field, skipping");
        return Ok(None);
    };

    if runs.using != "composite" {
        debug!(using = %runs.using, "action is not composite, skipping");
        return Ok(None);
    }

    let Some(steps) = runs.steps else {
        debug!("composite action has no steps");
        return Ok(Some(Vec::new()));
    };

    let mut children = Vec::new();
    for step in steps {
        if let Some(uses) = step.uses {
            if uses.starts_with("./") || uses.starts_with("docker://") {
                continue;
            }
            match uses.parse::<ActionRef>() {
                Ok(action_ref) => children.push(action_ref),
                Err(e) => {
                    warn!(uses = %uses, error = %e, "failed to parse action reference in composite action");
                }
            }
        }
    }

    Ok(Some(children))
}

pub struct CompositeExpandStage {
    client: GitHubClient,
}

impl CompositeExpandStage {
    pub fn new(client: GitHubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Stage for CompositeExpandStage {
    #[instrument(skip(self, ctx), fields(action = %ctx.action))]
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()> {
        let owner = &ctx.action.owner;
        let repo = &ctx.action.repo;
        let git_ref = &ctx.action.git_ref;

        // Try action.yml first, then action.yaml
        let mut content = None;
        for filename in ["action.yml", "action.yaml"] {
            if let Some(c) = self.client.get_raw_content_optional(owner, repo, git_ref, filename).await? {
                content = Some(c);
                break;
            }
        }

        let Some(yaml_content) = content else {
            debug!(action = %ctx.action, "no action.yml or action.yaml found, treating as leaf node");
            return Ok(());
        };

        if let Some(children) = parse_composite_action(&yaml_content)? {
            debug!(action = %ctx.action, count = children.len(), "discovered composite action children");
            ctx.children.extend(children);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "CompositeExpand"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_composite_action_discovers_children() {
        let yaml = r#"
name: My Composite Action
description: A composite action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
    - run: echo "hello"
    - uses: some-org/some-action@v1
"#;
        let result = parse_composite_action(yaml).unwrap();
        let children = result.expect("should be Some for composite action");
        assert_eq!(children.len(), 3);
        assert_eq!(children[0].to_string(), "actions/checkout@v4");
        assert_eq!(children[1].to_string(), "actions/setup-node@v4");
        assert_eq!(children[2].to_string(), "some-org/some-action@v1");
    }

    #[test]
    fn parse_non_composite_action_returns_none() {
        let yaml = r#"
name: Node Action
description: A node action
runs:
  using: node20
  main: index.js
"#;
        let result = parse_composite_action(yaml).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_composite_action_filters_local_and_docker() {
        let yaml = r#"
name: Mixed Action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: ./local-action
    - uses: docker://alpine:3.18
    - uses: some-org/real-action@v2
"#;
        let result = parse_composite_action(yaml).unwrap();
        let children = result.expect("should be Some for composite action");
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].to_string(), "actions/checkout@v4");
        assert_eq!(children[1].to_string(), "some-org/real-action@v2");
    }

    #[test]
    fn parse_invalid_yaml_returns_error() {
        let yaml = "this is not valid yaml: [[[";
        let result = parse_composite_action(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_composite_action_no_steps() {
        let yaml = r#"
name: Empty Composite
runs:
  using: composite
"#;
        let result = parse_composite_action(yaml).unwrap();
        let children = result.expect("should be Some for composite action");
        assert!(children.is_empty());
    }

    #[test]
    fn parse_action_without_runs_returns_none() {
        let yaml = r#"
name: Metadata Only
description: No runs key
"#;
        let result = parse_composite_action(yaml).unwrap();
        assert!(result.is_none());
    }
}
