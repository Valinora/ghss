use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use tracing::{debug, instrument, warn};

use crate::advisory::deduplicate_advisories;
use crate::context::AuditContext;
use crate::providers::ActionAdvisoryProvider;
use super::Stage;

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
    #[instrument(skip(self, ctx), fields(action = %ctx.action))]
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
                    warn!(action = %ctx.action, provider = %provider_name, error = %e, "failed to query advisories");
                    ctx.record_error(self.name(), format!("{provider_name}: {e}"));
                }
            }
        }
        ctx.advisories = deduplicate_advisories(advisories);
        debug!(action = %ctx.action, count = ctx.advisories.len(), "advisories collected");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "Advisory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_ref::ActionRef;
    use crate::advisory::Advisory;
    use crate::context::AuditContext;

    struct FakeProvider {
        name: &'static str,
        result: Result<Vec<Advisory>, String>,
    }

    #[async_trait]
    impl ActionAdvisoryProvider for FakeProvider {
        async fn query(&self, _action: &ActionRef) -> anyhow::Result<Vec<Advisory>> {
            self.result
                .clone()
                .map_err(|e| anyhow::anyhow!(e))
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn make_advisory(id: &str) -> Advisory {
        Advisory {
            id: id.to_string(),
            aliases: vec![],
            summary: format!("Advisory {id}"),
            severity: "high".to_string(),
            url: format!("https://example.com/{id}"),
            affected_range: None,
            source: "fake".to_string(),
        }
    }

    fn make_ctx() -> AuditContext {
        let action: ActionRef = "actions/checkout@v4".parse().unwrap();
        AuditContext {
            action,
            depth: 0,
            parent: None,
            children: vec![],
            resolved_ref: None,
            advisories: vec![],
            scan: None,
            dependencies: vec![],
            errors: vec![],
        }
    }

    #[tokio::test]
    async fn merges_results_from_multiple_providers() {
        let stage = AdvisoryStage::new(vec![
            Arc::new(FakeProvider {
                name: "ProviderA",
                result: Ok(vec![make_advisory("GHSA-0001")]),
            }),
            Arc::new(FakeProvider {
                name: "ProviderB",
                result: Ok(vec![make_advisory("GHSA-0002")]),
            }),
        ]);

        let mut ctx = make_ctx();
        stage.run(&mut ctx).await.unwrap();

        assert_eq!(ctx.advisories.len(), 2);
        let ids: Vec<&str> = ctx.advisories.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"GHSA-0001"));
        assert!(ids.contains(&"GHSA-0002"));
        assert!(ctx.errors.is_empty());
    }

    #[tokio::test]
    async fn records_error_on_provider_failure() {
        let stage = AdvisoryStage::new(vec![
            Arc::new(FakeProvider {
                name: "GoodProvider",
                result: Ok(vec![make_advisory("GHSA-0001")]),
            }),
            Arc::new(FakeProvider {
                name: "BadProvider",
                result: Err("connection refused".to_string()),
            }),
        ]);

        let mut ctx = make_ctx();
        stage.run(&mut ctx).await.unwrap();

        assert_eq!(ctx.advisories.len(), 1);
        assert_eq!(ctx.advisories[0].id, "GHSA-0001");
        assert_eq!(ctx.errors.len(), 1);
        assert!(ctx.errors[0].message.contains("BadProvider"));
        assert!(ctx.errors[0].message.contains("connection refused"));
    }
}
