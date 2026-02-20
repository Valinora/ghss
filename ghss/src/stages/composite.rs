use async_trait::async_trait;
use tracing::{debug, instrument};

use crate::context::AuditContext;
use crate::github::GitHubClient;
use crate::workflow;

use super::Stage;

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

        if let Some(children) = workflow::parse_composite_action(&yaml_content)? {
            debug!(action = %ctx.action, count = children.len(), "discovered composite action children");
            ctx.children.extend(children);
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "CompositeExpand"
    }
}
