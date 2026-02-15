use anyhow::{Context, Result};
use serde_json::Value;
use tracing::instrument;

use crate::action_ref::ActionRef;
use crate::advisory::{Advisory, AdvisoryProvider};
use crate::github::GitHubClient;

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
            .api_get_public(&format!(
                "https://api.github.com/advisories?ecosystem=actions&affects={}",
                package_name
            ))
            .with_context(|| format!("failed to query advisories for {}", package_name))?;

        parse_advisories(&json)
    }

    fn name(&self) -> &str {
        "GHSA"
    }
}

#[instrument(skip(json))]
fn parse_advisories(json: &Value) -> Result<Vec<Advisory>> {
    let arr = json.as_array().context("expected JSON array from advisory API")?;

    let mut advisories = Vec::new();
    for item in arr {
        let id = item
            .get("ghsa_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let summary = item
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let severity = item
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let url = item
            .get("html_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Extract affected version range from vulnerabilities array
        let affected_range = item
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|vuln| {
                    vuln.get("vulnerable_version_range")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
            });

        advisories.push(Advisory {
            id,
            summary,
            severity,
            url,
            affected_range,
            source: "GHSA".to_string(),
        });
    }

    Ok(advisories)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_empty_advisory_response() {
        let json = json!([]);
        let advisories = parse_advisories(&json).unwrap();
        assert!(advisories.is_empty());
    }

    #[test]
    fn parse_advisory_with_all_fields() {
        let json = json!([{
            "ghsa_id": "GHSA-7943-82jg-wmw5",
            "summary": "Tokenless upload may expose secrets",
            "severity": "critical",
            "html_url": "https://github.com/advisories/GHSA-7943-82jg-wmw5",
            "vulnerabilities": [{
                "package": {
                    "ecosystem": "actions",
                    "name": "codecov/codecov-action"
                },
                "vulnerable_version_range": "< 4.0.0"
            }]
        }]);

        let advisories = parse_advisories(&json).unwrap();
        assert_eq!(advisories.len(), 1);

        let a = &advisories[0];
        assert_eq!(a.id, "GHSA-7943-82jg-wmw5");
        assert_eq!(a.summary, "Tokenless upload may expose secrets");
        assert_eq!(a.severity, "critical");
        assert_eq!(a.url, "https://github.com/advisories/GHSA-7943-82jg-wmw5");
        assert_eq!(a.affected_range, Some("< 4.0.0".to_string()));
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

        let advisories = parse_advisories(&json).unwrap();
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

        let advisories = parse_advisories(&json).unwrap();
        assert_eq!(advisories.len(), 2);
        assert_eq!(advisories[0].id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(advisories[1].id, "GHSA-dddd-eeee-ffff");
    }

    #[test]
    fn parse_non_array_returns_error() {
        let json = json!({"error": "bad request"});
        assert!(parse_advisories(&json).is_err());
    }
}
