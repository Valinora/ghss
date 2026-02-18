mod npm;

use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use serde::Serialize;
use tracing::{debug, instrument, warn};

use crate::advisory::{deduplicate_advisories, Advisory};
use crate::context::{AuditContext, StageError};
use crate::github::GitHubClient;
use crate::providers::PackageAdvisoryProvider;
use super::Ecosystem;
use super::Stage;

#[derive(Debug, Clone, Serialize)]
pub struct DependencyReport {
    pub package: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub advisories: Vec<Advisory>,
}

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
    #[instrument(skip(self, ctx), fields(action = %ctx.action.raw))]
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()> {
        let ecosystems = ctx
            .scan
            .as_ref()
            .map_or(&[] as &[_], |s| s.ecosystems.as_slice());

        let packages =
            match npm::fetch_npm_packages(&ctx.action, ecosystems, &self.client).await {
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
            debug!(action = %ctx.action.raw, "no ecosystems to scan for dependencies");
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

    fn name(&self) -> &'static str {
        "Dependency"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_ref::ActionRef;
    use crate::context::AuditContext;
    use crate::stages::ScanResult;

    fn make_ctx() -> AuditContext {
        let action: ActionRef = "actions/checkout@v4".parse().unwrap();
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
    async fn dependency_stage_skips_without_scan_data() {
        let stage = DependencyStage::new(GitHubClient::new(None), vec![]);
        let mut ctx = make_ctx();

        stage.run(&mut ctx).await.unwrap();
        assert!(ctx.dependencies.is_empty());
        assert!(ctx.errors.is_empty());
    }

    #[tokio::test]
    async fn skips_with_empty_ecosystems() {
        let stage = DependencyStage::new(GitHubClient::new(None), vec![]);
        let mut ctx = make_ctx();
        ctx.scan = Some(ScanResult {
            primary_language: Some("JavaScript".to_string()),
            ecosystems: vec![],
        });

        stage.run(&mut ctx).await.unwrap();
        assert!(ctx.dependencies.is_empty());
        assert!(ctx.errors.is_empty());
    }
}
