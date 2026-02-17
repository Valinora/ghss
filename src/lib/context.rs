use crate::action_ref::ActionRef;
use crate::advisory::Advisory;
use crate::deps::DependencyReport;
use crate::scan::ActionScan;

pub struct AuditContext {
    pub action: ActionRef,
    pub depth: usize,
    pub parent: Option<String>,
    pub children: Vec<ActionRef>,
    pub index: Option<usize>,
    // Enrichment results
    pub resolved_ref: Option<String>,
    pub advisories: Vec<Advisory>,
    pub scan: Option<ActionScan>,
    pub dependencies: Vec<DependencyReport>,
    pub errors: Vec<StageError>,
}

pub struct StageError {
    pub stage: String,
    pub message: String,
}
