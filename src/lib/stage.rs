use async_trait::async_trait;

use crate::context::AuditContext;

#[async_trait]
pub trait Stage: Send + Sync {
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()>;
    fn name(&self) -> &str;
}
