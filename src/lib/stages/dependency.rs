use async_trait::async_trait;
use tracing::warn;

use crate::context::{AuditContext, StageError};
use crate::deps;
use crate::github::GitHubClient;
use crate::stage::Stage;

pub struct DependencyStage {
    client: GitHubClient,
}

impl DependencyStage {
    pub fn new(client: GitHubClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Stage for DependencyStage {
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()> {
        let ecosystems = ctx
            .scan
            .as_ref()
            .map(|s| s.ecosystems.as_slice())
            .unwrap_or(&[]);

        match deps::scan_dependencies(&ctx.action, ecosystems, &self.client).await {
            Ok(reports) => ctx.dependencies = reports,
            Err(e) => {
                warn!(action = %ctx.action.raw, error = %e, "failed to scan dependencies");
                ctx.errors.push(StageError {
                    stage: self.name().to_string(),
                    message: e.to_string(),
                });
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "Dependency"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_ref::ActionRef;
    use crate::context::AuditContext;

    #[tokio::test]
    async fn dependency_stage_skips_without_scan_data() {
        let stage = DependencyStage::new(GitHubClient::new(None));
        let action: ActionRef = "actions/checkout@v4".parse().unwrap();
        let mut ctx = AuditContext {
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
        };

        stage.run(&mut ctx).await.unwrap();
        assert!(ctx.dependencies.is_empty());
        assert!(ctx.errors.is_empty());
    }
}
