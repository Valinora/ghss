#[path = "lib/action_ref.rs"]
pub mod action_ref;
#[path = "lib/advisory.rs"]
pub mod advisory;
#[path = "lib/ghsa.rs"]
pub mod ghsa;
#[path = "lib/github.rs"]
pub mod github;
#[path = "lib/osv.rs"]
pub mod osv;
#[path = "lib/output.rs"]
pub mod output;
#[path = "lib/workflow.rs"]
pub mod workflow;

use std::collections::BTreeSet;
use std::path::Path;

use tracing::warn;

use action_ref::ActionRef;

fn is_third_party(uses: &str) -> bool {
    !uses.starts_with("./") && !uses.starts_with("docker://")
}

pub fn parse_actions(path: &Path) -> anyhow::Result<Vec<ActionRef>> {
    let uses_refs = workflow::parse_workflow(path)?;

    let unique: BTreeSet<ActionRef> = uses_refs
        .into_iter()
        .filter(|u| is_third_party(u))
        .filter_map(|raw| match raw.parse::<ActionRef>() {
            Ok(ar) => Some(ar),
            Err(e) => {
                warn!(action = %raw, error = %e, "failed to parse action reference");
                None
            }
        })
        .collect();

    Ok(unique.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn third_party_actions_are_detected() {
        assert!(is_third_party("actions/checkout@v4"));
        assert!(is_third_party("codecov/codecov-action@v3"));
    }

    #[test]
    fn local_actions_are_not_third_party() {
        assert!(!is_third_party("./local-action"));
        assert!(!is_third_party("./path/to/action"));
    }

    #[test]
    fn docker_actions_are_not_third_party() {
        assert!(!is_third_party("docker://node:18"));
        assert!(!is_third_party("docker://alpine:3.18"));
    }
}
