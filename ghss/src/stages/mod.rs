pub mod advisory;
pub mod composite;
pub mod dependency;
pub mod resolve;
pub mod scan;
pub mod workflow_expand;

use async_trait::async_trait;

use crate::context::AuditContext;

#[async_trait]
pub trait Stage: Send + Sync {
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()>;
    fn name(&self) -> &'static str;
}

pub use advisory::AdvisoryStage;
pub use composite::CompositeExpandStage;
pub use dependency::DependencyReport;
pub use dependency::DependencyStage;
pub use resolve::RefResolveStage;
pub use scan::{Ecosystem, ScanResult, ScanStage};
pub use workflow_expand::WorkflowExpandStage;
