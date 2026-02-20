use async_trait::async_trait;
use tracing::{debug, instrument};

use crate::context::AuditContext;
use crate::github::GitHubClient;
use crate::workflow;

use super::Stage;

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
    #[instrument(skip(self, ctx), fields(action = %ctx.action))]
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()> {
        // Only process if this action ref points to a workflow file
        let path = match &ctx.action.path {
            Some(p) if p.contains(".github/workflows/") => p.clone(),
            _ => {
                debug!(action = %ctx.action, "not a reusable workflow path, skipping");
                return Ok(());
            }
        };

        let owner = &ctx.action.owner;
        let repo = &ctx.action.repo;
        let git_ref = &ctx.action.git_ref;

        let yaml_content = match self.client.get_raw_content_optional(owner, repo, git_ref, &path).await? {
            Some(content) => content,
            None => {
                debug!(action = %ctx.action, "workflow file not found, skipping");
                return Ok(());
            }
        };

        let children = workflow::parse_workflow_refs(&yaml_content)?;
        debug!(action = %ctx.action, count = children.len(), "discovered workflow children");
        ctx.children.extend(children);

        Ok(())
    }

    fn name(&self) -> &'static str {
        "WorkflowExpand"
    }
}
