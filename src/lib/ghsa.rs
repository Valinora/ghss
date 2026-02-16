use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use tracing::instrument;

use crate::action_ref::ActionRef;
use crate::advisory::{Advisory, AdvisoryProvider};
use crate::github::{GitHubClient, GITHUB_API_BASE};

#[derive(Deserialize)]
struct GhsaAdvisoryResponse {
    ghsa_id: Option<String>,
    summary: Option<String>,
    severity: Option<String>,
    html_url: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<GhsaVulnerability>,
}

#[derive(Deserialize)]
struct GhsaVulnerability {
    vulnerable_version_range: Option<String>,
}

pub struct GhsaProvider<'a> {
    client: &'a GitHubClient,
}

impl<'a> GhsaProvider<'a> {
    pub fn new_borrowed(client: &'a GitHubClient) -> Self {
        Self { client }
    }
}

impl AdvisoryProvider for GhsaProvider<'_> {
    #[instrument(skip(self), fields(action = %action.raw))]
    fn query(&self, action: &ActionRef) -> Result<Vec<Advisory>> {
        let package_name = action.package_name();
        let json = self
            .client
            .api_get(&format!(
                "{GITHUB_API_BASE}/advisories?ecosystem=actions&affects={package_name}"
            ))
            .with_context(|| format!("failed to query advisories for {package_name}"))?;

        parse_advisories(json)
    }

    fn name(&self) -> &str {
        "GHSA"
    }
}

#[instrument(skip(json))]
fn parse_advisories(json: Value) -> Result<Vec<Advisory>> {
    let responses: Vec<GhsaAdvisoryResponse> = serde_json::from_value(json)
        .context("expected JSON array from advisory API")?;

    let advisories = responses
        .into_iter()
        .map(|item| {
            let affected_range = item
                .vulnerabilities
                .into_iter()
                .find_map(|v| v.vulnerable_version_range);

            Advisory {
                id: item.ghsa_id.unwrap_or_else(|| "unknown".to_string()),
                aliases: vec![],
                summary: item.summary.unwrap_or_default(),
                severity: item.severity.unwrap_or_else(|| "unknown".to_string()),
                url: item.html_url.unwrap_or_default(),
                affected_range,
                source: "GHSA".to_string(),
            }
        })
        .collect();

    Ok(advisories)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_empty_advisory_response() {
        let json = json!([]);
        let advisories = parse_advisories(json).unwrap();
        assert!(advisories.is_empty());
    }

    #[test]
    fn parse_advisory_with_all_fields() {
        // Based on real GHSA-r79c-pqj3-577x (super-linter command injection)
        let json = json!([{
            "ghsa_id": "GHSA-r79c-pqj3-577x",
            "summary": "Super-linter is vulnerable to command injection via crafted filenames",
            "severity": "high",
            "html_url": "https://github.com/advisories/GHSA-r79c-pqj3-577x",
            "vulnerabilities": [{
                "package": {
                    "ecosystem": "actions",
                    "name": "super-linter/super-linter"
                },
                "vulnerable_version_range": ">= 6.0.0, < 8.3.1"
            }]
        }]);

        let advisories = parse_advisories(json).unwrap();
        assert_eq!(advisories.len(), 1);

        let a = &advisories[0];
        assert_eq!(a.id, "GHSA-r79c-pqj3-577x");
        assert_eq!(a.summary, "Super-linter is vulnerable to command injection via crafted filenames");
        assert_eq!(a.severity, "high");
        assert_eq!(a.url, "https://github.com/advisories/GHSA-r79c-pqj3-577x");
        assert_eq!(a.affected_range, Some(">= 6.0.0, < 8.3.1".to_string()));
        assert_eq!(a.source, "GHSA");
    }

    #[test]
    fn parse_advisory_with_missing_optional_fields() {
        let json = json!([{
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Some issue",
            "severity": "high",
            "html_url": "https://example.com"
        }]);

        let advisories = parse_advisories(json).unwrap();
        assert_eq!(advisories.len(), 1);
        assert!(advisories[0].affected_range.is_none());
    }

    #[test]
    fn parse_multiple_advisories() {
        let json = json!([
            {
                "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                "summary": "First",
                "severity": "low",
                "html_url": "https://example.com/1"
            },
            {
                "ghsa_id": "GHSA-dddd-eeee-ffff",
                "summary": "Second",
                "severity": "medium",
                "html_url": "https://example.com/2"
            }
        ]);

        let advisories = parse_advisories(json).unwrap();
        assert_eq!(advisories.len(), 2);
        assert_eq!(advisories[0].id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(advisories[1].id, "GHSA-dddd-eeee-ffff");
    }

    #[test]
    fn parse_non_array_returns_error() {
        let json = json!({"error": "bad request"});
        assert!(parse_advisories(json).is_err());
    }
}
