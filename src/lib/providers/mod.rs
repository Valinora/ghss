use std::sync::Arc;

use anyhow::bail;
use async_trait::async_trait;

use crate::action_ref::ActionRef;
use crate::advisory::Advisory;
use crate::github::GitHubClient;

/// Advisory provider that queries by action reference (e.g. "owner/repo@ref").
#[async_trait]
pub trait ActionAdvisoryProvider: Send + Sync {
    async fn query(&self, action: &ActionRef) -> anyhow::Result<Vec<Advisory>>;
    fn name(&self) -> &str;
}

/// Advisory provider that queries by package name and ecosystem string.
#[async_trait]
pub trait PackageAdvisoryProvider: Send + Sync {
    async fn query(&self, package: &str, ecosystem: &str) -> anyhow::Result<Vec<Advisory>>;
    fn name(&self) -> &str;
}

pub mod ghsa;
pub mod osv;

use ghsa::GhsaProvider;
use osv::{OsvActionProvider, OsvClient, OsvPackageProvider};

pub fn create_action_providers(
    provider: &str,
    github_client: &GitHubClient,
) -> anyhow::Result<Vec<Arc<dyn ActionAdvisoryProvider>>> {
    match provider {
        "ghsa" => Ok(vec![Arc::new(GhsaProvider::new(github_client.clone()))]),
        "osv" => Ok(vec![Arc::new(OsvActionProvider::new(OsvClient::new()))]),
        "all" => Ok(vec![
            Arc::new(GhsaProvider::new(github_client.clone())),
            Arc::new(OsvActionProvider::new(OsvClient::new())),
        ]),
        other => bail!("unknown provider: {other} (valid: ghsa, osv, all)"),
    }
}

pub fn create_package_providers(
    provider: &str,
) -> anyhow::Result<Vec<Arc<dyn PackageAdvisoryProvider>>> {
    match provider {
        "ghsa" => Ok(vec![]),
        "osv" | "all" => Ok(vec![Arc::new(OsvPackageProvider::new(OsvClient::new()))]),
        other => bail!("unknown provider: {other} (valid: ghsa, osv, all)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_providers_ghsa() {
        let client = GitHubClient::new(None);
        let providers = create_action_providers("ghsa", &client).unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name(), "GHSA");
    }

    #[test]
    fn action_providers_osv() {
        let client = GitHubClient::new(None);
        let providers = create_action_providers("osv", &client).unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name(), "OSV");
    }

    #[test]
    fn action_providers_all() {
        let client = GitHubClient::new(None);
        let providers = create_action_providers("all", &client).unwrap();
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn action_providers_unknown_errors() {
        let client = GitHubClient::new(None);
        let result = create_action_providers("invalid", &client);
        let err = result.err().expect("should be an error");
        assert!(err.to_string().contains("unknown provider"));
    }

    #[test]
    fn package_providers_ghsa_returns_empty() {
        let providers = create_package_providers("ghsa").unwrap();
        assert!(providers.is_empty());
    }

    #[test]
    fn package_providers_osv() {
        let providers = create_package_providers("osv").unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name(), "OSV");
    }

    #[test]
    fn package_providers_all() {
        let providers = create_package_providers("all").unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name(), "OSV");
    }
}
