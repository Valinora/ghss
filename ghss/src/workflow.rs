use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use tracing::warn;

use crate::action_ref::ActionRef;

/// A classified `uses:` reference from a GitHub Actions workflow or composite action.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum UsesRef {
    /// Local action path (`./path`)
    Local(String),
    /// Docker image reference (`docker://image`)
    Docker(String),
    /// Third-party action (parsed into ActionRef)
    ThirdParty(ActionRef),
}

impl FromStr for UsesRef {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("./") {
            Ok(UsesRef::Local(s.to_string()))
        } else if s.starts_with("docker://") {
            Ok(UsesRef::Docker(s.to_string()))
        } else {
            Ok(UsesRef::ThirdParty(s.parse::<ActionRef>()?))
        }
    }
}

impl UsesRef {
    pub fn into_third_party(self) -> Option<ActionRef> {
        match self {
            Self::ThirdParty(ar) => Some(ar),
            _ => None,
        }
    }
}

impl fmt::Display for UsesRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(s) | Self::Docker(s) => f.write_str(s),
            Self::ThirdParty(ar) => write!(f, "{ar}"),
        }
    }
}

/// A single step that may reference an action via `uses:`.
/// Shared between workflow steps and composite action steps.
#[derive(Debug, Deserialize)]
pub(crate) struct Step {
    pub uses: Option<String>,
}

// ─── Workflow schema ───

#[derive(Debug, Deserialize)]
pub(crate) struct Job {
    #[serde(default)]
    pub uses: Option<String>,
    #[serde(default)]
    pub steps: Option<Vec<Step>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Workflow {
    #[serde(default)]
    jobs: HashMap<String, serde_yaml::Value>,
}

// ─── Composite action schema ───

#[derive(Debug, Deserialize)]
pub(crate) struct ActionRuns {
    pub using: String,
    #[serde(default)]
    pub steps: Option<Vec<Step>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ActionYaml {
    #[serde(default)]
    pub runs: Option<ActionRuns>,
}

// ─── Trait impls ───

impl FromStr for Workflow {
    type Err = serde_yaml::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s)
    }
}

impl FromStr for ActionYaml {
    type Err = serde_yaml::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_yaml::from_str(s)
    }
}

impl TryFrom<serde_yaml::Value> for Job {
    type Error = serde_yaml::Error;
    fn try_from(value: serde_yaml::Value) -> Result<Self, Self::Error> {
        serde_yaml::from_value(value)
    }
}

// ─── Methods ───

impl Job {
    /// All raw `uses:` values from this job (job-level + step-level).
    pub fn uses_strings(self) -> Vec<String> {
        let mut refs = Vec::new();
        if let Some(uses) = self.uses {
            refs.push(uses);
        }
        if let Some(steps) = self.steps {
            for step in steps {
                if let Some(uses) = step.uses {
                    refs.push(uses);
                }
            }
        }
        refs
    }
}

impl Workflow {
    /// All raw `uses:` values. Malformed jobs warn and skip.
    /// Consumes self to avoid cloning serde_yaml::Value.
    pub fn uses_strings(self) -> Vec<String> {
        let mut refs = Vec::new();
        for (job_name, job_value) in self.jobs {
            match Job::try_from(job_value) {
                Ok(job) => refs.extend(job.uses_strings()),
                Err(e) => {
                    warn!(job = %job_name, error = %e, "failed to parse job");
                }
            }
        }
        refs
    }
}

impl ActionYaml {
    /// Returns composite steps, or None if not a composite action.
    /// Returns Some(vec![]) if composite but has no steps.
    pub fn into_composite_steps(self) -> Option<Vec<Step>> {
        let runs = self.runs?;
        (runs.using == "composite").then(|| runs.steps.unwrap_or_default())
    }
}

// ─── Helpers ───

/// Classify raw `uses:` strings into UsesRef variants. Warns and skips unparseable refs.
fn classify_uses(raw: impl IntoIterator<Item = String>) -> Vec<UsesRef> {
    raw.into_iter()
        .filter_map(|s| match s.parse::<UsesRef>() {
            Ok(r) => Some(r),
            Err(e) => {
                warn!(uses = %s, error = %e, "failed to parse uses reference");
                None
            }
        })
        .collect()
}

// ─── Public API ───

/// Parse a workflow YAML and return all classified uses refs.
/// Malformed jobs warn and skip. Unparseable third-party refs warn and skip.
pub fn parse_workflow(yaml: &str) -> anyhow::Result<Vec<UsesRef>> {
    let workflow: Workflow = yaml.parse()?;
    Ok(classify_uses(workflow.uses_strings()))
}

/// Parse a workflow YAML and return only third-party ActionRefs.
/// Convenience wrapper — replaces parse_workflow_children in workflow_expand.rs.
pub fn parse_workflow_refs(yaml: &str) -> anyhow::Result<Vec<ActionRef>> {
    Ok(parse_workflow(yaml)?
        .into_iter()
        .filter_map(UsesRef::into_third_party)
        .collect())
}

/// Parse a composite action YAML.
/// Returns None if not composite. Returns Some(refs) with third-party ActionRefs if composite.
pub fn parse_composite_action(yaml: &str) -> anyhow::Result<Option<Vec<ActionRef>>> {
    let action: ActionYaml = yaml.parse()?;

    let Some(steps) = action.into_composite_steps() else {
        return Ok(None);
    };

    let children = classify_uses(steps.into_iter().filter_map(|step| step.uses))
        .into_iter()
        .filter_map(UsesRef::into_third_party)
        .collect();

    Ok(Some(children))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn read_fixture(name: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../ghss-cli/tests/fixtures")
            .join(name);
        std::fs::read_to_string(path).expect("fixture not found")
    }

    // ─── UsesRef classification tests ───

    #[test]
    fn uses_ref_parses_local() {
        let r: UsesRef = "./local-action".parse().unwrap();
        assert_eq!(r, UsesRef::Local("./local-action".to_string()));
    }

    #[test]
    fn uses_ref_parses_docker() {
        let r: UsesRef = "docker://node:18".parse().unwrap();
        assert_eq!(r, UsesRef::Docker("docker://node:18".to_string()));
    }

    #[test]
    fn uses_ref_parses_third_party() {
        let r: UsesRef = "actions/checkout@v4".parse().unwrap();
        assert_eq!(
            r,
            UsesRef::ThirdParty("actions/checkout@v4".parse().unwrap())
        );
    }

    #[test]
    fn uses_ref_invalid_third_party_is_error() {
        let result = "not-a-valid-ref".parse::<UsesRef>();
        assert!(result.is_err());
    }

    // ─── parse_workflow tests (fixture-based) ───

    #[test]
    fn parse_sample_workflow_extracts_all_uses() {
        let refs = parse_workflow(&read_fixture("sample-workflow.yml")).unwrap();
        let raw: Vec<String> = refs.iter().map(|r| r.to_string()).collect();
        assert!(raw.contains(&"actions/checkout@v4".to_string()));
        assert!(raw.contains(&"actions/setup-node@v4".to_string()));
        assert!(raw.contains(&"docker://node:18".to_string()));
        assert!(raw.contains(&"codecov/codecov-action@v3".to_string()));
        assert!(raw.contains(&"./local-action".to_string()));
    }

    #[test]
    fn parse_sample_workflow_includes_duplicates() {
        let refs = parse_workflow(&read_fixture("sample-workflow.yml")).unwrap();
        let expected = UsesRef::ThirdParty("actions/checkout@v4".parse().unwrap());
        let checkout_count = refs.iter().filter(|r| **r == expected).count();
        assert_eq!(checkout_count, 3);
    }

    #[test]
    fn parse_malformed_workflow_extracts_valid_jobs() {
        let refs = parse_workflow(&read_fixture("malformed-workflow.yml")).unwrap();
        let raw: Vec<String> = refs.iter().map(|r| r.to_string()).collect();
        assert!(raw.contains(&"actions/checkout@v4".to_string()));
        assert!(raw.contains(&"actions/setup-node@v4".to_string()));
        assert!(raw.contains(&"docker://alpine:3.18".to_string()));
    }

    #[test]
    fn parse_malformed_workflow_does_not_fail() {
        let result = parse_workflow(&read_fixture("malformed-workflow.yml"));
        assert!(result.is_ok());
    }

    #[test]
    fn parse_invalid_yaml_returns_error() {
        let result = parse_workflow("not: [valid: yaml: {{{");
        assert!(result.is_err());
    }

    #[test]
    fn parse_reusable_workflow_extracts_step_and_job_level_uses() {
        let refs = parse_workflow(&read_fixture("reusable-workflow.yml")).unwrap();
        let raw: Vec<String> = refs.iter().map(|r| r.to_string()).collect();
        assert!(raw.contains(&"actions/checkout@v4".to_string()));
        assert!(raw.contains(&"actions/setup-node@v4".to_string()));
        assert!(raw.contains(
            &"org/shared-workflows/.github/workflows/ci.yml@main".to_string()
        ));
        assert!(raw.contains(
            &"org/shared-workflows/.github/workflows/deploy.yml@v1".to_string()
        ));
        assert_eq!(refs.len(), 4);
    }

    // ─── parse_workflow_refs tests (migrated from workflow_expand.rs) ───

    #[test]
    fn parse_workflow_refs_step_level_actions() {
        let yaml = r#"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm test
      - uses: codecov/codecov-action@v3
"#;
        let children = parse_workflow_refs(yaml).unwrap();
        assert_eq!(children.len(), 3);

        let names: Vec<String> = children.iter().map(|c| c.to_string()).collect();
        assert!(names.contains(&"actions/checkout@v4".to_string()));
        assert!(names.contains(&"actions/setup-node@v4".to_string()));
        assert!(names.contains(&"codecov/codecov-action@v3".to_string()));
    }

    #[test]
    fn parse_workflow_refs_job_level_reusable_calls() {
        let yaml = r#"
name: Orchestrator
on: push
jobs:
  call-ci:
    uses: org/workflows/.github/workflows/ci.yml@main
  call-deploy:
    uses: org/workflows/.github/workflows/deploy.yml@v1
"#;
        let children = parse_workflow_refs(yaml).unwrap();
        assert_eq!(children.len(), 2);

        let names: Vec<String> = children.iter().map(|c| c.to_string()).collect();
        assert!(names.contains(&"org/workflows/.github/workflows/ci.yml@main".to_string()));
        assert!(names.contains(&"org/workflows/.github/workflows/deploy.yml@v1".to_string()));
    }

    #[test]
    fn parse_workflow_refs_filters_local_and_docker() {
        let yaml = r#"
name: Mixed
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./local-action
      - uses: docker://node:18
      - uses: some-org/action@v2
"#;
        let children = parse_workflow_refs(yaml).unwrap();
        assert_eq!(children.len(), 2);

        let names: Vec<String> = children.iter().map(|c| c.to_string()).collect();
        assert!(names.contains(&"actions/checkout@v4".to_string()));
        assert!(names.contains(&"some-org/action@v2".to_string()));
    }

    #[test]
    fn parse_workflow_refs_mixed_step_and_job_level() {
        let yaml = r#"
name: Full Example
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make build
  call-lint:
    uses: org/shared/.github/workflows/lint.yml@v2
"#;
        let children = parse_workflow_refs(yaml).unwrap();
        assert_eq!(children.len(), 2);

        let names: Vec<String> = children.iter().map(|c| c.to_string()).collect();
        assert!(names.contains(&"actions/checkout@v4".to_string()));
        assert!(names.contains(&"org/shared/.github/workflows/lint.yml@v2".to_string()));
    }

    #[test]
    fn parse_workflow_refs_invalid_yaml_returns_error() {
        let yaml = "not: valid: yaml: [[[";
        let result = parse_workflow_refs(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_workflow_refs_empty_workflow_returns_empty() {
        let yaml = r#"
name: Empty
on: push
jobs: {}
"#;
        let children = parse_workflow_refs(yaml).unwrap();
        assert!(children.is_empty());
    }

    // ─── parse_composite_action tests (migrated from stages/composite.rs) ───

    #[test]
    fn parse_composite_action_discovers_children() {
        let yaml = r#"
name: My Composite Action
description: A composite action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
    - run: echo "hello"
    - uses: some-org/some-action@v1
"#;
        let result = parse_composite_action(yaml).unwrap();
        let children = result.expect("should be Some for composite action");
        assert_eq!(children.len(), 3);
        assert_eq!(children[0].to_string(), "actions/checkout@v4");
        assert_eq!(children[1].to_string(), "actions/setup-node@v4");
        assert_eq!(children[2].to_string(), "some-org/some-action@v1");
    }

    #[test]
    fn parse_non_composite_action_returns_none() {
        let yaml = r#"
name: Node Action
description: A node action
runs:
  using: node20
  main: index.js
"#;
        let result = parse_composite_action(yaml).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_composite_action_filters_local_and_docker() {
        let yaml = r#"
name: Mixed Action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: ./local-action
    - uses: docker://alpine:3.18
    - uses: some-org/real-action@v2
"#;
        let result = parse_composite_action(yaml).unwrap();
        let children = result.expect("should be Some for composite action");
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].to_string(), "actions/checkout@v4");
        assert_eq!(children[1].to_string(), "some-org/real-action@v2");
    }

    #[test]
    fn parse_composite_invalid_yaml_returns_error() {
        let yaml = "this is not valid yaml: [[[";
        let result = parse_composite_action(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_composite_action_no_steps() {
        let yaml = r#"
name: Empty Composite
runs:
  using: composite
"#;
        let result = parse_composite_action(yaml).unwrap();
        let children = result.expect("should be Some for composite action");
        assert!(children.is_empty());
    }

    #[test]
    fn parse_action_without_runs_returns_none() {
        let yaml = r#"
name: Metadata Only
description: No runs key
"#;
        let result = parse_composite_action(yaml).unwrap();
        assert!(result.is_none());
    }
}
