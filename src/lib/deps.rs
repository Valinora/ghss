use anyhow::{Context, Result};
use serde::Serialize;

use crate::action_ref::ActionRef;
use crate::advisory::Advisory;
use crate::github::GitHubClient;
use crate::scan::Ecosystem;

#[derive(Debug, Clone, Serialize)]
pub struct DependencyReport {
    pub package: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub advisories: Vec<Advisory>,
}

/// Fetch and parse npm dependencies from an action's package.json.
///
/// Returns an empty Vec if the action's ecosystems don't include npm.
pub async fn fetch_npm_packages(
    action: &ActionRef,
    ecosystems: &[Ecosystem],
    client: &GitHubClient,
) -> Result<Vec<(String, String)>> {
    if !ecosystems.contains(&Ecosystem::Npm) {
        return Ok(vec![]);
    }

    let content = client
        .get_raw_content(&action.owner, &action.repo, &action.git_ref, "package.json")
        .await
        .with_context(|| {
            format!(
                "failed to fetch package.json for {}/{}",
                action.owner, action.repo
            )
        })?;

    let deps = parse_npm_dependencies(&content)?;
    tracing::debug!(count = deps.len(), "found npm dependencies");
    Ok(deps)
}

fn parse_npm_dependencies(content: &str) -> Result<Vec<(String, String)>> {
    let pkg: serde_json::Value =
        serde_json::from_str(content).context("failed to parse package.json")?;

    let Some(deps) = pkg.get("dependencies").and_then(|d| d.as_object()) else {
        return Ok(vec![]);
    };

    Ok(deps
        .iter()
        .filter_map(|(name, version)| {
            version
                .as_str()
                .map(|v| (name.clone(), v.to_string()))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dependencies_basic() {
        let content = r#"{
            "name": "my-action",
            "dependencies": {
                "lodash": "^4.17.20",
                "express": "~4.18.0"
            }
        }"#;
        let deps = parse_npm_dependencies(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&("lodash".to_string(), "^4.17.20".to_string())));
        assert!(deps.contains(&("express".to_string(), "~4.18.0".to_string())));
    }

    #[test]
    fn parse_dependencies_empty_deps() {
        let content = r#"{"name": "my-action", "dependencies": {}}"#;
        let deps = parse_npm_dependencies(content).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_dependencies_no_deps_field() {
        let content = r#"{"name": "my-action", "devDependencies": {"jest": "^29.0.0"}}"#;
        let deps = parse_npm_dependencies(content).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_dependencies_ignores_dev_dependencies() {
        let content = r#"{
            "name": "my-action",
            "dependencies": {"lodash": "^4.17.20"},
            "devDependencies": {"jest": "^29.0.0"}
        }"#;
        let deps = parse_npm_dependencies(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "lodash");
    }

    #[test]
    fn parse_dependencies_invalid_json() {
        let result = parse_npm_dependencies("not json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_dependencies_skips_non_string_versions() {
        let content = r#"{
            "dependencies": {
                "lodash": "^4.17.20",
                "broken": 123
            }
        }"#;
        let deps = parse_npm_dependencies(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "lodash");
    }

    #[test]
    fn fetch_npm_packages_skips_non_npm() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let action: ActionRef = "actions/checkout@v4".parse().unwrap();
            let client = GitHubClient::new(None);
            let result =
                fetch_npm_packages(&action, &[Ecosystem::Cargo, Ecosystem::Go], &client).await;
            assert!(result.unwrap().is_empty());
        });
    }
}
