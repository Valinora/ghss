use std::fmt;

use async_trait::async_trait;
use serde::Serialize;

use crate::action_ref::ActionRef;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Advisory {
    pub id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: String,
    pub url: String,
    pub affected_range: Option<String>,
    pub source: String,
}

impl fmt::Display for Advisory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} ({}): {}", self.id, self.severity, self.summary)?;
        write!(f, "    {}", self.url)?;
        if let Some(range) = &self.affected_range {
            write!(f, "\n    affected: {range}")?;
        }
        Ok(())
    }
}

#[async_trait]
pub trait AdvisoryProvider: Send + Sync {
    async fn query(&self, action: &ActionRef) -> anyhow::Result<Vec<Advisory>>;
    fn name(&self) -> &str;
}
