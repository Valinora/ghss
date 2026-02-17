use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use tracing::warn;

use crate::advisory::deduplicate_advisories;
use crate::context::{AuditContext, StageError};
use crate::providers::ActionAdvisoryProvider;
use crate::stage::Stage;

pub struct AdvisoryStage {
    providers: Vec<Arc<dyn ActionAdvisoryProvider>>,
}

impl AdvisoryStage {
    pub fn new(providers: Vec<Arc<dyn ActionAdvisoryProvider>>) -> Self {
        Self { providers }
    }
}

#[async_trait]
impl Stage for AdvisoryStage {
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()> {
        let results = join_all(self.providers.iter().map(|p| {
            let p = p.clone();
            let action = ctx.action.clone();
            async move { (p.name().to_string(), p.query(&action).await) }
        }))
        .await;

        let mut advisories = Vec::new();
        for (provider_name, result) in results {
            match result {
                Ok(advs) => advisories.extend(advs),
                Err(e) => {
                    warn!(action = %ctx.action.raw, provider = %provider_name, error = %e, "failed to query advisories");
                    ctx.errors.push(StageError {
                        stage: self.name().to_string(),
                        message: format!("{provider_name}: {e}"),
                    });
                }
            }
        }
        ctx.advisories = deduplicate_advisories(advisories);
        Ok(())
    }

    fn name(&self) -> &str {
        "Advisory"
    }
}
