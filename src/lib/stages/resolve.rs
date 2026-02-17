use async_trait::async_trait;
use tracing::warn;

use crate::context::{AuditContext, StageError};
use crate::github::GitHubClient;
use crate::stage::Stage;

pub struct RefResolveStage {
    client: GitHubClient,
}

impl RefResolveStage {
    pub fn new(client: GitHubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Stage for RefResolveStage {
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()> {
        match self.client.resolve_ref(&ctx.action).await {
            Ok(sha) => ctx.resolved_ref = Some(sha),
            Err(e) => {
                warn!(action = %ctx.action.raw, error = %e, "failed to resolve ref");
                ctx.errors.push(StageError {
                    stage: self.name().to_string(),
                    message: e.to_string(),
                });
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "RefResolve"
    }
}
