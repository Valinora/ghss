use std::fmt;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::action_ref::ActionRef;
use crate::github::GitHubClient;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Cargo,
    Go,
    Pip,
    Maven,
    Gradle,
    RubyGems,
    Composer,
    Docker,
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::Cargo => write!(f, "cargo"),
            Ecosystem::Go => write!(f, "go"),
            Ecosystem::Pip => write!(f, "pip"),
            Ecosystem::Maven => write!(f, "maven"),
            Ecosystem::Gradle => write!(f, "gradle"),
            Ecosystem::RubyGems => write!(f, "rubygems"),
            Ecosystem::Composer => write!(f, "composer"),
            Ecosystem::Docker => write!(f, "docker"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub primary_language: Option<String>,
    pub ecosystems: Vec<Ecosystem>,
}

/// Mapping from GraphQL alias to Ecosystem variant.
const MANIFEST_ALIASES: &[(&str, Ecosystem)] = &[
    ("packageJson", Ecosystem::Npm),
    ("cargoToml", Ecosystem::Cargo),
    ("goMod", Ecosystem::Go),
    ("requirementsTxt", Ecosystem::Pip),
    ("pyprojectToml", Ecosystem::Pip),
    ("pomXml", Ecosystem::Maven),
    ("buildGradle", Ecosystem::Gradle),
    ("gemfile", Ecosystem::RubyGems),
    ("composerJson", Ecosystem::Composer),
    ("dockerfile", Ecosystem::Docker),
];

fn build_query(owner: &str, repo: &str) -> String {
    format!(
        r#"query {{
  repository(owner: "{owner}", name: "{repo}") {{
    languages(first: 10) {{
      edges {{ size node {{ name }} }}
    }}
    packageJson: object(expression: "HEAD:package.json") {{ __typename }}
    cargoToml: object(expression: "HEAD:Cargo.toml") {{ __typename }}
    goMod: object(expression: "HEAD:go.mod") {{ __typename }}
    requirementsTxt: object(expression: "HEAD:requirements.txt") {{ __typename }}
    pyprojectToml: object(expression: "HEAD:pyproject.toml") {{ __typename }}
    pomXml: object(expression: "HEAD:pom.xml") {{ __typename }}
    buildGradle: object(expression: "HEAD:build.gradle") {{ __typename }}
    gemfile: object(expression: "HEAD:Gemfile") {{ __typename }}
    composerJson: object(expression: "HEAD:composer.json") {{ __typename }}
    dockerfile: object(expression: "HEAD:Dockerfile") {{ __typename }}
  }}
}}"#
    )
}

/// Extract the primary language (highest byte count) from the GraphQL response.
fn extract_primary_language(repo: &Value) -> Option<String> {
    let edges = repo.get("languages")?.get("edges")?.as_array()?;

    edges
        .iter()
        .filter_map(|edge| {
            let size = edge.get("size")?.as_u64()?;
            let name = edge.get("node")?.get("name")?.as_str()?;
            Some((name.to_string(), size))
        })
        .max_by_key(|(_, size)| *size)
        .map(|(name, _)| name)
}

/// Extract ecosystems by checking which manifest file aliases are non-null.
fn extract_ecosystems(repo: &Value) -> Vec<Ecosystem> {
    let mut seen = Vec::new();

    for (alias, ecosystem) in MANIFEST_ALIASES {
        if repo.get(*alias).is_some_and(|v| !v.is_null()) && !seen.contains(ecosystem) {
            seen.push(ecosystem.clone());
        }
    }

    seen
}

/// Scan an action's repository to detect languages and package ecosystems.
#[tracing::instrument(skip(client), fields(action = %action.raw))]
pub async fn scan_action(
    action: &ActionRef,
    client: &GitHubClient,
) -> Result<ScanResult> {
    let query = build_query(&action.owner, &action.repo);
    let data = client.graphql_post(&query).await?;

    let repo = data
        .get("repository")
        .ok_or_else(|| anyhow::anyhow!("repository not found: {}/{}", action.owner, action.repo))?;

    Ok(ScanResult {
        primary_language: extract_primary_language(repo),
        ecosystems: extract_ecosystems(repo),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mock_graphql_response(
        languages: Vec<(&str, u64)>,
        manifests: Vec<&str>,
    ) -> Value {
        let edges: Vec<Value> = languages
            .into_iter()
            .map(|(name, size)| {
                json!({ "size": size, "node": { "name": name } })
            })
            .collect();

        let mut repo = json!({
            "languages": { "edges": edges },
        });

        // All possible aliases start as null
        for (alias, _) in MANIFEST_ALIASES {
            repo[alias] = Value::Null;
        }

        // Set present manifests to non-null
        for alias in manifests {
            repo[alias] = json!({ "__typename": "Blob" });
        }

        repo
    }

    #[test]
    fn parses_languages_and_ecosystems() {
        let repo = mock_graphql_response(
            vec![("TypeScript", 50000), ("JavaScript", 30000), ("Shell", 1000)],
            vec!["packageJson", "dockerfile"],
        );

        let primary = extract_primary_language(&repo);
        assert_eq!(primary, Some("TypeScript".to_string()));

        let ecosystems = extract_ecosystems(&repo);
        assert_eq!(ecosystems, vec![Ecosystem::Npm, Ecosystem::Docker]);
    }

    #[test]
    fn no_languages_returns_none() {
        let repo = mock_graphql_response(vec![], vec!["cargoToml"]);

        let primary = extract_primary_language(&repo);
        assert_eq!(primary, None);
    }

    #[test]
    fn no_manifests_returns_empty_ecosystems() {
        let repo = mock_graphql_response(
            vec![("Rust", 10000)],
            vec![],
        );

        let ecosystems = extract_ecosystems(&repo);
        assert!(ecosystems.is_empty());
    }

    #[test]
    fn pip_deduplicates_requirements_and_pyproject() {
        let repo = mock_graphql_response(
            vec![("Python", 20000)],
            vec!["requirementsTxt", "pyprojectToml"],
        );

        let ecosystems = extract_ecosystems(&repo);
        assert_eq!(ecosystems, vec![Ecosystem::Pip]);
    }

    #[test]
    fn ecosystem_display() {
        assert_eq!(Ecosystem::Npm.to_string(), "npm");
        assert_eq!(Ecosystem::Cargo.to_string(), "cargo");
        assert_eq!(Ecosystem::Go.to_string(), "go");
        assert_eq!(Ecosystem::Pip.to_string(), "pip");
        assert_eq!(Ecosystem::Maven.to_string(), "maven");
        assert_eq!(Ecosystem::Gradle.to_string(), "gradle");
        assert_eq!(Ecosystem::RubyGems.to_string(), "rubygems");
        assert_eq!(Ecosystem::Composer.to_string(), "composer");
        assert_eq!(Ecosystem::Docker.to_string(), "docker");
    }

    #[test]
    fn all_ecosystems_detected() {
        let repo = mock_graphql_response(
            vec![("Java", 40000)],
            vec![
                "packageJson",
                "cargoToml",
                "goMod",
                "requirementsTxt",
                "pomXml",
                "buildGradle",
                "gemfile",
                "composerJson",
                "dockerfile",
            ],
        );

        let ecosystems = extract_ecosystems(&repo);
        assert_eq!(
            ecosystems,
            vec![
                Ecosystem::Npm,
                Ecosystem::Cargo,
                Ecosystem::Go,
                Ecosystem::Pip,
                Ecosystem::Maven,
                Ecosystem::Gradle,
                Ecosystem::RubyGems,
                Ecosystem::Composer,
                Ecosystem::Docker,
            ]
        );
    }
}
