use anyhow::{bail, Context, Result};
use serde_json::Value;
use tracing::instrument;

use crate::action_ref::{ActionRef, RefType};

pub const GITHUB_API_BASE: &str = "https://api.github.com";

#[derive(Clone)]
pub struct GitHubClient {
    client: reqwest::Client,
    token: Option<String>,
}

impl GitHubClient {
    pub fn new(token: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("ghss")
                .build()
                .expect("failed to build HTTP client"),
            token,
        }
    }

    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    #[instrument(skip(self), fields(action = %action.raw))]
    pub async fn resolve_ref(&self, action: &ActionRef) -> Result<String> {
        if action.ref_type == RefType::Sha {
            return Ok(action.git_ref.clone());
        }

        // Try as a tag first
        let tag_url = format!(
            "{GITHUB_API_BASE}/repos/{}/{}/git/ref/tags/{}",
            action.owner, action.repo, action.git_ref
        );

        if let Some(json) = self.api_get_optional(&tag_url).await? {
            return self.extract_commit_sha(&json, &action.owner, &action.repo).await;
        }

        // Fall back to branch
        let branch_url = format!(
            "{GITHUB_API_BASE}/repos/{}/{}/git/ref/heads/{}",
            action.owner, action.repo, action.git_ref
        );

        let json = self
            .api_get(&branch_url)
            .await
            .with_context(|| format!("ref '{}' not found as tag or branch", action.git_ref))?;

        self.extract_commit_sha(&json, &action.owner, &action.repo).await
    }

    #[instrument(skip(self, ref_json))]
    async fn extract_commit_sha(&self, ref_json: &Value, owner: &str, repo: &str) -> Result<String> {
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
            let tag_json = self.api_get(&tag_url).await?;

            let commit_sha = tag_json
                .get("object")
                .and_then(|o| o.get("sha"))
                .and_then(|v| v.as_str())
                .context("missing commit sha in annotated tag")?;

            return Ok(commit_sha.to_string());
        }

        bail!("unexpected ref object type: {obj_type}");
    }

    #[tracing::instrument(skip(self))]
    async fn api_get_optional(&self, url: &str) -> Result<Option<Value>> {
        let mut request = self
            .client
            .get(url)
            .header("Accept", "application/vnd.github+json");
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            bail!("{url} returned HTTP {status}");
        }

        let json = response
            .json()
            .await
            .with_context(|| format!("failed to parse JSON from {url}"))?;
        Ok(Some(json))
    }

    #[instrument(skip(self))]
    pub async fn api_get(&self, url: &str) -> Result<Value> {
        self.api_get_optional(url)
            .await?
            .ok_or_else(|| anyhow::anyhow!("{url} returned HTTP 404"))
    }

    /// Fetch raw file content from a repository via raw.githubusercontent.com.
    #[instrument(skip(self))]
    pub async fn get_raw_content(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
        path: &str,
    ) -> Result<String> {
        let url = format!(
            "https://raw.githubusercontent.com/{owner}/{repo}/{git_ref}/{path}"
        );

        let mut request = self.client.get(&url);
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("failed to fetch {url}"))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            bail!("{path} not found in {owner}/{repo}@{git_ref}");
        }
        if !status.is_success() {
            bail!("{url} returned HTTP {status}");
        }

        response
            .text()
            .await
            .with_context(|| format!("failed to read body from {url}"))
    }

    /// Send a GraphQL query to the GitHub API. Requires authentication.
    #[instrument(skip(self, query))]
    pub async fn graphql_post(&self, query: &str) -> Result<Value> {
        let token = self
            .token
            .as_ref()
            .context("GitHub token is required for GraphQL API")?;

        let body = serde_json::json!({ "query": query });

        let response = self
            .client
            .post("https://api.github.com/graphql")
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .json(&body)
            .send()
            .await
            .context("GraphQL request failed")?;

        let status = response.status();
        if !status.is_success() {
            bail!("GraphQL API returned HTTP {status}");
        }

        let json: Value = response
            .json()
            .await
            .context("failed to parse GraphQL response")?;

        if let Some(errors) = json.get("errors") {
            bail!("GraphQL errors: {errors}");
        }

        json.get("data")
            .cloned()
            .context("missing 'data' field in GraphQL response")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn has_token_returns_true_when_set() {
        let client = GitHubClient::new(Some("tok".into()));
        assert!(client.has_token());
    }

    #[test]
    fn has_token_returns_false_when_none() {
        let client = GitHubClient::new(None);
        assert!(!client.has_token());
    }

    #[tokio::test]
    async fn sha_ref_returns_immediately() {
        let client = GitHubClient::new(Some("fake".into()));
        let action: ActionRef =
            "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"
                .parse()
                .unwrap();
        let result = client.resolve_ref(&action).await.unwrap();
        assert_eq!(result, "b4ffde65f46336ab88eb53be808477a3936bae11");
    }

    #[tokio::test]
    async fn extract_commit_sha_lightweight_tag() {
        let client = GitHubClient::new(Some("fake".into()));
        let ref_json = json!({
            "ref": "refs/tags/v4",
            "object": {
                "type": "commit",
                "sha": "abc123def456abc123def456abc123def456abc1"
            }
        });

        let sha = client.extract_commit_sha(&ref_json, "actions", "checkout").await.unwrap();
        assert_eq!(sha, "abc123def456abc123def456abc123def456abc1");
    }

    #[tokio::test]
    async fn extract_commit_sha_unexpected_type() {
        let client = GitHubClient::new(Some("fake".into()));
        let ref_json = json!({
            "ref": "refs/tags/v4",
            "object": {
                "type": "tree",
                "sha": "abc123"
            }
        });

        let result = client.extract_commit_sha(&ref_json, "actions", "checkout").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unexpected"));
    }

    #[tokio::test]
    async fn extract_commit_sha_missing_object() {
        let client = GitHubClient::new(Some("fake".into()));
        let ref_json = json!({"ref": "refs/tags/v4"});

        let result = client.extract_commit_sha(&ref_json, "actions", "checkout").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn graphql_post_errors_without_token() {
        let client = GitHubClient::new(None);
        let result = client.graphql_post("{ viewer { login } }").await;
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("token is required"),
            "expected token error, got: {err}"
        );
    }
}
