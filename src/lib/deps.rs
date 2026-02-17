use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::Semaphore;
use tracing::{instrument, warn};

use crate::action_ref::ActionRef;
use crate::advisory::Advisory;
use crate::github::GitHubClient;
use crate::osv;
use crate::scan::Ecosystem;

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";
const DEP_QUERY_CONCURRENCY: usize = 5;

#[derive(Debug, Clone, Serialize)]
pub struct DependencyReport {
    pub package: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub advisories: Vec<Advisory>,
}

#[instrument(skip(client))]
pub async fn scan_dependencies(
    action: &ActionRef,
    ecosystems: &[Ecosystem],
    client: &GitHubClient,
) -> Result<Vec<DependencyReport>> {
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
    if deps.is_empty() {
        return Ok(vec![]);
    }

    let http = reqwest::Client::new();
    let sem = Semaphore::new(DEP_QUERY_CONCURRENCY);

    let futures: Vec<_> = deps
        .into_iter()
        .map(|(name, version)| {
            let http = http.clone();
            let sem = &sem;
            async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                match query_osv_npm(&http, &name).await {
                    Ok(advisories) if !advisories.is_empty() => Some(DependencyReport {
                        package: name,
                        version,
                        ecosystem: Ecosystem::Npm,
                        advisories,
                    }),
                    Ok(_) => None,
                    Err(e) => {
                        warn!(package = %name, error = %e, "failed to query OSV for npm package");
                        None
                    }
                }
            }
        })
        .collect();

    let results = futures::future::join_all(futures).await;
    Ok(results.into_iter().flatten().collect())
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

async fn query_osv_npm(client: &reqwest::Client, package_name: &str) -> Result<Vec<Advisory>> {
    let body = serde_json::json!({
        "package": {
            "name": package_name,
            "ecosystem": "npm"
        }
    });

    let response = client
        .post(OSV_API_URL)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("failed to query OSV for npm package {package_name}"))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("OSV API returned HTTP {status} for npm package {package_name}");
    }

    let json: serde_json::Value = response
        .json()
        .await
        .context("failed to parse OSV response")?;

    osv::parse_osv_response(json)
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
    fn scan_dependencies_skips_non_npm() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let action: ActionRef = "actions/checkout@v4".parse().unwrap();
            let client = GitHubClient::new(None);
            let result =
                scan_dependencies(&action, &[Ecosystem::Cargo, Ecosystem::Go], &client).await;
            assert!(result.unwrap().is_empty());
        });
    }
}
