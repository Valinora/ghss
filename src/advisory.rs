use serde::Serialize;

use crate::action_ref::ActionRef;

#[derive(Serialize)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: String,
    pub url: String,
    pub affected_range: Option<String>,
    pub source: String,
}

pub trait AdvisoryProvider {
    fn query(&self, action: &ActionRef) -> anyhow::Result<Vec<Advisory>>;
    fn name(&self) -> &str;
}
