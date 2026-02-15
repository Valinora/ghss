use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::action_ref::{ActionRef, RefType};

pub struct GitHubClient {
    agent: ureq::Agent,
    token: String,
}

impl GitHubClient {
    pub fn new(token: String) -> Self {
        Self {
            agent: ureq::Agent::new(),
            token,
        }
    }

    pub fn resolve_ref(&self, action: &ActionRef) -> Result<String> {
        if action.ref_type == RefType::Sha {
            return Ok(action.git_ref.clone());
        }

        // Try as a tag first
        let tag_url = format!(
            "https://api.github.com/repos/{}/{}/git/ref/tags/{}",
            action.owner, action.repo, action.git_ref
        );

        match self.api_get(&tag_url) {
            Ok(json) => return self.extract_commit_sha(&json, &action.owner, &action.repo),
            Err(e) => {
                // If not a 404, propagate the error
                if !e.to_string().contains("404") {
                    return Err(e);
                }
            }
        }

        // Fall back to branch
        let branch_url = format!(
            "https://api.github.com/repos/{}/{}/git/ref/heads/{}",
            action.owner, action.repo, action.git_ref
        );

        let json = self
            .api_get(&branch_url)
            .with_context(|| format!("ref '{}' not found as tag or branch", action.git_ref))?;

        self.extract_commit_sha(&json, &action.owner, &action.repo)
    }

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
                "https://api.github.com/repos/{}/{}/git/tags/{}",
                owner, repo, sha
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

    pub fn api_get_public(&self, url: &str) -> Result<Value> {
        self.api_get(url)
    }

    fn api_get(&self, url: &str) -> Result<Value> {
        let response = self
            .agent
            .get(url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Accept", "application/vnd.github+json")
            .set("User-Agent", "ghss")
            .call()
            .map_err(|e| match e {
                ureq::Error::Status(status, _resp) => {
                    anyhow::anyhow!("{} returned HTTP {}", url, status)
                }
                other => anyhow::anyhow!("request to {} failed: {}", url, other),
            })?;

        let json: Value = response.into_json()?;
        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sha_ref_returns_immediately() {
        let client = GitHubClient::new("fake".into());
        let action = ActionRef::parse(
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
        )
        .unwrap();
        let result = client.resolve_ref(&action).unwrap();
        assert_eq!(result, "b4ffde65f46336ab88eb53be808477a3936bae11");
    }

    #[test]
    fn extract_commit_sha_lightweight_tag() {
        let client = GitHubClient::new("fake".into());
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
        let client = GitHubClient::new("fake".into());
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
        let client = GitHubClient::new("fake".into());
        let ref_json = json!({"ref": "refs/tags/v4"});

        let result = client.extract_commit_sha(&ref_json, "actions", "checkout");
        assert!(result.is_err());
    }
}
