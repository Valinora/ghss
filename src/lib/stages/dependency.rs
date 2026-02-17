use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use tracing::warn;

use crate::advisory::deduplicate_advisories;
use crate::context::{AuditContext, StageError};
use crate::deps::{self, DependencyReport};
use crate::github::GitHubClient;
use crate::providers::PackageAdvisoryProvider;
use crate::scan::Ecosystem;
use crate::stage::Stage;

pub struct DependencyStage {
    client: GitHubClient,
    providers: Vec<Arc<dyn PackageAdvisoryProvider>>,
}

impl DependencyStage {
    pub fn new(client: GitHubClient, providers: Vec<Arc<dyn PackageAdvisoryProvider>>) -> Self {
        Self { client, providers }
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

        let packages = match deps::fetch_npm_packages(&ctx.action, ecosystems, &self.client).await
        {
            Ok(pkgs) => pkgs,
            Err(e) => {
                warn!(action = %ctx.action.raw, error = %e, "failed to fetch dependencies");
                ctx.errors.push(StageError {
                    stage: self.name().to_string(),
                    message: e.to_string(),
                });
                return Ok(());
            }
        };

        if packages.is_empty() {
            return Ok(());
        }

        let mut reports = Vec::new();

        for (name, version) in packages {
            let results = join_all(self.providers.iter().map(|p| {
                let p = p.clone();
                let pkg = name.clone();
                async move { (p.name().to_string(), p.query(&pkg, "npm").await) }
            }))
            .await;

            let mut advisories = Vec::new();
            for (provider_name, result) in results {
                match result {
                    Ok(advs) => advisories.extend(advs),
                    Err(e) => {
                        warn!(
                            package = %name,
                            provider = %provider_name,
                            error = %e,
                            "failed to query advisories for npm package"
                        );
                        ctx.errors.push(StageError {
                            stage: self.name().to_string(),
                            message: format!("{provider_name}: {name}: {e}"),
                        });
                    }
                }
            }

            let advisories = deduplicate_advisories(advisories);
            if !advisories.is_empty() {
                reports.push(DependencyReport {
                    package: name,
                    version,
                    ecosystem: Ecosystem::Npm,
                    advisories,
                });
            }
        }

        ctx.dependencies = reports;
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
        let stage = DependencyStage::new(GitHubClient::new(None), vec![]);
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
