use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::instrument;

use crate::action_ref::ActionRef;
use crate::advisory::{Advisory, AdvisoryProvider};

const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

#[derive(Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    database_specific: Option<OsvDatabaseSpecific>,
}

#[derive(Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    ref_type: Option<String>,
    url: Option<String>,
}

#[derive(Deserialize)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Deserialize)]
struct OsvEvent {
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Deserialize)]
struct OsvDatabaseSpecific {
    severity: Option<String>,
}

pub struct OsvProvider {
    client: reqwest::Client,
}

impl OsvProvider {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl AdvisoryProvider for OsvProvider {
    #[instrument(skip(self), fields(action = %action.raw))]
    async fn query(&self, action: &ActionRef) -> Result<Vec<Advisory>> {
        let package_name = action.package_name();
        let body = serde_json::json!({
            "package": {
                "name": package_name,
                "ecosystem": "GitHub Actions"
            }
        });

        let response = self
            .client
            .post(OSV_API_URL)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("failed to query OSV for {package_name}"))?;

        let status = response.status();
        if !status.is_success() {
            bail!("OSV API returned HTTP {status} for {package_name}");
        }

        let json: serde_json::Value = response
            .json()
            .await
            .context("failed to parse OSV response")?;

        parse_osv_response(json)
    }

    fn name(&self) -> &str {
        "OSV"
    }
}

fn parse_osv_response(json: serde_json::Value) -> Result<Vec<Advisory>> {
    let response: OsvResponse =
        serde_json::from_value(json).context("failed to deserialize OSV response")?;

    let advisories = response
        .vulns
        .into_iter()
        .map(|vuln| {
            let severity = vuln
                .database_specific
                .as_ref()
                .and_then(|db| db.severity.as_ref())
                .map(|s| s.to_lowercase())
                .unwrap_or_else(|| "unknown".to_string());

            let url = vuln
                .references
                .iter()
                .find(|r| r.ref_type.as_deref() == Some("ADVISORY"))
                .or_else(|| {
                    vuln.references
                        .iter()
                        .find(|r| r.ref_type.as_deref() == Some("WEB"))
                })
                .and_then(|r| r.url.clone())
                .unwrap_or_default();

            let affected_range = vuln
                .affected
                .first()
                .and_then(|a| a.ranges.first())
                .map(|r| format_range_events(&r.events));

            Advisory {
                id: vuln.id,
                aliases: vuln.aliases,
                summary: vuln.summary,
                severity,
                url,
                affected_range,
                source: "OSV".to_string(),
            }
        })
        .collect();

    Ok(advisories)
}

fn format_range_events(events: &[OsvEvent]) -> String {
    let mut parts = Vec::new();

    for event in events {
        if let Some(introduced) = &event.introduced {
            if introduced != "0" {
                parts.push(format!(">= {introduced}"));
            }
        }
        if let Some(fixed) = &event.fixed {
            parts.push(format!("< {fixed}"));
        }
        if let Some(last_affected) = &event.last_affected {
            parts.push(format!("<= {last_affected}"));
        }
    }

    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_empty_response() {
        let json = json!({});
        let advisories = parse_osv_response(json).unwrap();
        assert!(advisories.is_empty());
    }

    #[test]
    fn parse_empty_vulns_array() {
        let json = json!({"vulns": []});
        let advisories = parse_osv_response(json).unwrap();
        assert!(advisories.is_empty());
    }

    #[test]
    fn parse_vuln_with_all_fields() {
        let json = json!({
            "vulns": [{
                "id": "GHSA-mcph-m25j-8j63",
                "summary": "tj-actions/changed-files workflow compromise",
                "references": [
                    {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-mcph-m25j-8j63"},
                    {"type": "WEB", "url": "https://example.com/other"}
                ],
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "46.0.1"}
                        ]
                    }]
                }],
                "database_specific": {
                    "severity": "CRITICAL"
                }
            }]
        });

        let advisories = parse_osv_response(json).unwrap();
        assert_eq!(advisories.len(), 1);

        let a = &advisories[0];
        assert_eq!(a.id, "GHSA-mcph-m25j-8j63");
        assert_eq!(a.summary, "tj-actions/changed-files workflow compromise");
        assert_eq!(a.severity, "critical");
        assert_eq!(
            a.url,
            "https://github.com/advisories/GHSA-mcph-m25j-8j63"
        );
        assert_eq!(a.affected_range, Some("< 46.0.1".to_string()));
        assert_eq!(a.source, "OSV");
    }

    #[test]
    fn parse_vuln_falls_back_to_web_url() {
        let json = json!({
            "vulns": [{
                "id": "OSV-1234",
                "summary": "Some issue",
                "references": [
                    {"type": "WEB", "url": "https://example.com/web"}
                ],
                "affected": [],
                "database_specific": null
            }]
        });

        let advisories = parse_osv_response(json).unwrap();
        assert_eq!(advisories[0].url, "https://example.com/web");
        assert_eq!(advisories[0].severity, "unknown");
    }

    #[test]
    fn parse_vuln_with_introduced_and_fixed_range() {
        let json = json!({
            "vulns": [{
                "id": "OSV-5678",
                "summary": "Range test",
                "references": [],
                "affected": [{
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "6.0.0"},
                            {"fixed": "8.3.1"}
                        ]
                    }]
                }],
                "database_specific": {"severity": "HIGH"}
            }]
        });

        let advisories = parse_osv_response(json).unwrap();
        assert_eq!(
            advisories[0].affected_range,
            Some(">= 6.0.0, < 8.3.1".to_string())
        );
    }

    #[test]
    fn parse_vuln_with_missing_fields() {
        let json = json!({
            "vulns": [{
                "id": "OSV-MINIMAL",
                "summary": "",
                "references": [],
                "affected": []
            }]
        });

        let advisories = parse_osv_response(json).unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "OSV-MINIMAL");
        assert_eq!(advisories[0].severity, "unknown");
        assert!(advisories[0].url.is_empty());
        assert!(advisories[0].affected_range.is_none());
    }

    #[test]
    fn format_range_introduced_zero_and_fixed() {
        let events = vec![
            OsvEvent {
                introduced: Some("0".to_string()),
                fixed: None,
                last_affected: None,
            },
            OsvEvent {
                introduced: None,
                fixed: Some("7.0.7".to_string()),
                last_affected: None,
            },
        ];
        assert_eq!(format_range_events(&events), "< 7.0.7");
    }

    #[test]
    fn format_range_introduced_and_fixed() {
        let events = vec![
            OsvEvent {
                introduced: Some("2.0.0".to_string()),
                fixed: None,
                last_affected: None,
            },
            OsvEvent {
                introduced: None,
                fixed: Some("3.1.0".to_string()),
                last_affected: None,
            },
        ];
        assert_eq!(format_range_events(&events), ">= 2.0.0, < 3.1.0");
    }

    #[test]
    fn format_range_last_affected() {
        let events = vec![
            OsvEvent {
                introduced: Some("0".to_string()),
                fixed: None,
                last_affected: None,
            },
            OsvEvent {
                introduced: None,
                fixed: None,
                last_affected: Some("5.0.0".to_string()),
            },
        ];
        assert_eq!(format_range_events(&events), "<= 5.0.0");
    }

    #[test]
    fn parse_multiple_vulns() {
        let json = json!({
            "vulns": [
                {
                    "id": "FIRST-001",
                    "summary": "First",
                    "references": [],
                    "affected": []
                },
                {
                    "id": "SECOND-002",
                    "summary": "Second",
                    "references": [],
                    "affected": []
                }
            ]
        });

        let advisories = parse_osv_response(json).unwrap();
        assert_eq!(advisories.len(), 2);
        assert_eq!(advisories[0].id, "FIRST-001");
        assert_eq!(advisories[1].id, "SECOND-002");
    }

    #[test]
    fn parse_vuln_with_aliases() {
        let json = json!({
            "vulns": [{
                "id": "GHSA-mcph-m25j-8j63",
                "aliases": ["CVE-2025-30066"],
                "summary": "tj-actions/changed-files workflow compromise",
                "references": [],
                "affected": [],
                "database_specific": {"severity": "CRITICAL"}
            }]
        });

        let advisories = parse_osv_response(json).unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].aliases, vec!["CVE-2025-30066"]);
    }

    #[test]
    fn parse_vuln_without_aliases_defaults_empty() {
        let json = json!({
            "vulns": [{
                "id": "OSV-NOALIAS",
                "summary": "No aliases",
                "references": [],
                "affected": []
            }]
        });

        let advisories = parse_osv_response(json).unwrap();
        assert!(advisories[0].aliases.is_empty());
    }
}
