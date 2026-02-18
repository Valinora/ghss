use async_trait::async_trait;
use tracing::{instrument, warn};

use crate::context::{AuditContext, StageError};
use crate::github::GitHubClient;
use super::Stage;

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
    #[instrument(skip(self, ctx), fields(action = %ctx.action.raw))]
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

    fn name(&self) -> &'static str {
        "RefResolve"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_ref::ActionRef;
    use crate::context::AuditContext;

    fn make_ctx(action: ActionRef) -> AuditContext {
        AuditContext {
            action,
            depth: 0,
            parent: None,
            children: vec![],
            index: Some(0),
            resolved_ref: None,
            advisories: vec![],
            scan: None,
            dependencies: vec![],
            errors: vec![],
        }
    }

    #[tokio::test]
    async fn sha_ref_resolved_immediately() {
        let sha = "b4ffde65f46336ab88eb53be808477a3936bae11";
        let action: ActionRef = format!("actions/checkout@{sha}").parse().unwrap();
        let stage = RefResolveStage::new(GitHubClient::new(None));

        let mut ctx = make_ctx(action);
        stage.run(&mut ctx).await.unwrap();

        assert_eq!(ctx.resolved_ref, Some(sha.to_string()));
        assert!(ctx.errors.is_empty());
    }

    #[tokio::test]
    async fn records_error_on_failure() {
        // Point at a dead URL so the HTTP call fails
        // SAFETY: test-only; env var mutation is unsafe in Rust 2024
        unsafe { std::env::set_var("GHSS_API_BASE_URL", "http://127.0.0.1:1") };
        let client = GitHubClient::new(None);
        unsafe { std::env::remove_var("GHSS_API_BASE_URL") };

        let action: ActionRef = "actions/checkout@v4".parse().unwrap();
        let stage = RefResolveStage::new(client);

        let mut ctx = make_ctx(action);
        stage.run(&mut ctx).await.unwrap();

        assert!(ctx.resolved_ref.is_none());
        assert_eq!(ctx.errors.len(), 1);
        assert_eq!(ctx.errors[0].stage, "RefResolve");
    }
}
