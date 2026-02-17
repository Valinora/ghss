use async_trait::async_trait;

use crate::action_ref::ActionRef;
use crate::advisory::Advisory;

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
