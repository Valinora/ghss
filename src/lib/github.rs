use anyhow::{bail, Context, Result};
use serde_json::Value;
use tracing::instrument;

use crate::action_ref::{ActionRef, RefType};

pub const GITHUB_API_BASE: &str = "https://api.github.com";

pub struct GitHubClient {
    agent: ureq::Agent,
    token: Option<String>,
}

impl GitHubClient {
    pub fn new(token: Option<String>) -> Self {
        Self {
            agent: ureq::Agent::new(),
            token,
        }
    }

    #[instrument(skip(self), fields(action = %action.raw))]
    pub fn resolve_ref(&self, action: &ActionRef) -> Result<String> {
        if action.ref_type == RefType::Sha {
            return Ok(action.git_ref.clone());
        }

        // Try as a tag first
        let tag_url = format!(
            "{GITHUB_API_BASE}/repos/{}/{}/git/ref/tags/{}",
            action.owner, action.repo, action.git_ref
        );

        if let Some(json) = self.api_get_optional(&tag_url)? {
            return self.extract_commit_sha(&json, &action.owner, &action.repo);
        }

        // Fall back to branch
        let branch_url = format!(
            "{GITHUB_API_BASE}/repos/{}/{}/git/ref/heads/{}",
            action.owner, action.repo, action.git_ref
        );

        let json = self
            .api_get(&branch_url)
            .with_context(|| format!("ref '{}' not found as tag or branch", action.git_ref))?;

        self.extract_commit_sha(&json, &action.owner, &action.repo)
    }

    #[instrument(skip(self, ref_json))]
    fn extract_commit_sha(&self, ref_json: &Value, owner: &str, repo: &str) -> Result<String> {
        let obj = ref_json
            .get("object")
            .context("missing 'object' in ref response")?;

        let obj_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .context("missing 'type' in ref object")?;

        let sha = obj
            .get("sha")
            .and_then(|v| v.as_str())
            .context("missing 'sha' in ref object")?;

        if obj_type == "commit" {
            return Ok(sha.to_string());
        }

        // Annotated tag — dereference to get the commit
        if obj_type == "tag" {
            let tag_url = format!(
                "{GITHUB_API_BASE}/repos/{owner}/{repo}/git/tags/{sha}"
            );
            let tag_json = self.api_get(&tag_url)?;

            let commit_sha = tag_json
                .get("object")
                .and_then(|o| o.get("sha"))
                .and_then(|v| v.as_str())
                .context("missing commit sha in annotated tag")?;

            return Ok(commit_sha.to_string());
        }

        bail!("unexpected ref object type: {obj_type}");
    }

    fn api_get_optional(&self, url: &str) -> Result<Option<Value>> {
        let mut request = self
            .agent
            .get(url)
            .set("Accept", "application/vnd.github+json")
            .set("User-Agent", "ghss");
        if let Some(token) = &self.token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        match request.call() {
            Ok(response) => Ok(Some(response.into_json()?)),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(status, _)) => bail!("{url} returned HTTP {status}"),
            Err(other) => bail!("request to {url} failed: {other}"),
        }
    }

    #[instrument(skip(self))]
    pub fn api_get(&self, url: &str) -> Result<Value> {
        self.api_get_optional(url)?
            .ok_or_else(|| anyhow::anyhow!("{url} returned HTTP 404"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sha_ref_returns_immediately() {
        let client = GitHubClient::new(Some("fake".into()));
        let action: ActionRef =
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"
                .parse()
                .unwrap();
        let result = client.resolve_ref(&action).unwrap();
        assert_eq!(result, "b4ffde65f46336ab88eb53be808477a3936bae11");
    }

    #[test]
    fn extract_commit_sha_lightweight_tag() {
        let client = GitHubClient::new(Some("fake".into()));
        let ref_json = json!({
            "ref": "refs/tags/v4",
            "object": {
                "type": "commit",
                "sha": "abc123def456abc123def456abc123def456abc1"
            }
        });

        let sha = client.extract_commit_sha(&ref_json, "actions", "checkout").unwrap();
        assert_eq!(sha, "abc123def456abc123def456abc123def456abc1");
    }

    #[test]
    fn extract_commit_sha_unexpected_type() {
        let client = GitHubClient::new(Some("fake".into()));
        let ref_json = json!({
            "ref": "refs/tags/v4",
            "object": {
                "type": "tree",
                "sha": "abc123"
            }
        });

        let result = client.extract_commit_sha(&ref_json, "actions", "checkout");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unexpected"));
    }

    #[test]
    fn extract_commit_sha_missing_object() {
        let client = GitHubClient::new(Some("fake".into()));
        let ref_json = json!({"ref": "refs/tags/v4"});

        let result = client.extract_commit_sha(&ref_json, "actions", "checkout");
        assert!(result.is_err());
    }
}
