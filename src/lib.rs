#[path = "lib/action_ref.rs"]
pub mod action_ref;
#[path = "lib/advisory.rs"]
pub mod advisory;
#[path = "lib/ghsa.rs"]
pub mod ghsa;
#[path = "lib/github.rs"]
pub mod github;
#[path = "lib/output.rs"]
pub mod output;
#[path = "lib/workflow.rs"]
pub mod workflow;

pub fn is_third_party(uses: &str) -> bool {
    !uses.starts_with("./") && !uses.starts_with("docker://")
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
