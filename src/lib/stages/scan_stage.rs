use async_trait::async_trait;
use tracing::{debug, instrument, warn};

use crate::context::{AuditContext, StageError};
use crate::github::GitHubClient;
use crate::scan;
use crate::stage::Stage;
use crate::ScanSelection;

pub struct ScanStage {
    client: GitHubClient,
    selection: ScanSelection,
}

impl ScanStage {
    pub fn new(client: GitHubClient, selection: ScanSelection) -> Self {
        Self { client, selection }
    }
}

#[async_trait]
impl Stage for ScanStage {
    #[instrument(skip(self, ctx), fields(action = %ctx.action.raw))]
    async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()> {
        let should_scan = match ctx.index {
            Some(idx) => self.selection.should_scan(idx),
            None => matches!(self.selection, ScanSelection::All),
        };

        if !should_scan {
            debug!(action = %ctx.action.raw, "scan skipped");
            return Ok(());
        }

        match scan::scan_action(&ctx.action, &self.client).await {
            Ok(s) => ctx.scan = Some(s),
            Err(e) => {
                warn!(action = %ctx.action.raw, error = %e, "failed to scan action");
                ctx.errors.push(StageError {
                    stage: self.name().to_string(),
                    message: e.to_string(),
                });
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "Scan"
    }
}
