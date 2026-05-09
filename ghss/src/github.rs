use std::sync::Arc;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
pub use reqwest::StatusCode;
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::instrument;

use crate::action_ref::{ActionRef, RefType};

pub const GITHUB_API_BASE: &str = "https://api.github.com";
const RAW_CONTENT_BASE: &str = "https://raw.githubusercontent.com";

/// Token refresh buffer — mint a new token when the cached one expires within this window.
const TOKEN_REFRESH_BUFFER_SECS: i64 = 5 * 60;

/// Maximum bytes of an upstream response body we'll preserve in error
/// diagnostics. Larger bodies are truncated before being logged or
/// returned to callers to avoid log/disk spam from misbehaving servers.
pub const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024;

/// Typed error returned by the REST helpers (`api_get_optional`,
/// `api_post_json`) when the upstream returns a non-2xx status.
/// Callers can downcast via `anyhow::Error::downcast_ref::<GitHubApiError>`
/// to branch on the actual `StatusCode` rather than parsing the
/// formatted error string.
#[derive(Debug)]
pub struct GitHubApiError {
    pub status: StatusCode,
    pub url: String,
    /// Already truncated to `MAX_DIAGNOSTIC_BYTES` and stripped of
    /// non-printable control characters (except `\n`/`\t`).
    pub body: String,
}

impl GitHubApiError {
    pub fn from_response(url: &str, status: StatusCode, raw_body: String) -> Self {
        Self {
            url: url.to_string(),
            status,
            body: truncate_for_diagnostic(&raw_body, MAX_DIAGNOSTIC_BYTES),
        }
    }
}

impl std::fmt::Display for GitHubApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.body.is_empty() {
            write!(f, "{} returned {}", self.url, self.status)
        } else {
            write!(f, "{} returned {}: {}", self.url, self.status, self.body)
        }
    }
}

impl std::error::Error for GitHubApiError {}

/// Strip non-printable control characters (except `\n` and `\t`), then
/// truncate the result to `max_bytes`. Operates on UTF-8 char boundaries
/// so we never produce invalid UTF-8.
pub fn truncate_for_diagnostic(s: &str, max_bytes: usize) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !c.is_control() || matches!(*c, '\n' | '\t'))
        .collect();
    if out.len() > max_bytes {
        // Find the largest char boundary <= max_bytes.
        let mut cut = max_bytes;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("…[truncated]");
    }
    out
}

/// Validate that an API/raw base URL uses HTTPS, or HTTP only against
/// the loopback host. Bearer tokens flow over both surfaces; cleartext
/// HTTP to a remote host would leak credentials.
pub fn validate_base_url(env_name: &str, url: &str) -> Result<()> {
    if url.starts_with("https://") {
        return Ok(());
    }
    if url.starts_with("http://localhost")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://[::1]")
    {
        tracing::warn!(
            "{env_name}={url} uses cleartext HTTP — only safe for local testing"
        );
        return Ok(());
    }
    bail!("{env_name}={url} must use https://");
}

struct AppCredentials {
    app_id: u64,
    installation_id: u64,
    encoding_key: jsonwebtoken::EncodingKey,
}

struct CachedToken {
    token: String,
    expires_at: DateTime<Utc>,
}

#[derive(Clone)]
enum AuthState {
    Pat(Option<String>),
    App {
        credentials: Arc<AppCredentials>,
        cached_token: Arc<RwLock<Option<CachedToken>>>,
    },
}

#[derive(Clone)]
pub struct GitHubClient {
    client: reqwest::Client,
    auth: AuthState,
    api_base_url: String,
    raw_base_url: String,
}

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("ghss")
        .build()
        .expect("failed to build HTTP client")
}

fn resolve_base_urls() -> (String, String) {
    let api_base_url =
        std::env::var("GHSS_API_BASE_URL").unwrap_or_else(|_| GITHUB_API_BASE.to_string());
    let raw_base_url =
        std::env::var("GHSS_RAW_BASE_URL").unwrap_or_else(|_| RAW_CONTENT_BASE.to_string());
    // Fail-fast on cleartext HTTP to a remote host. Bearer tokens flow
    // over both surfaces under App auth.
    validate_base_url("GHSS_API_BASE_URL", &api_base_url)
        .expect("invalid GHSS_API_BASE_URL configuration");
    validate_base_url("GHSS_RAW_BASE_URL", &raw_base_url)
        .expect("invalid GHSS_RAW_BASE_URL configuration");
    (api_base_url, raw_base_url)
}

impl GitHubClient {
    pub fn new(token: Option<String>) -> Self {
        let (api_base_url, raw_base_url) = resolve_base_urls();
        Self {
            client: build_http_client(),
            auth: AuthState::Pat(token),
            api_base_url,
            raw_base_url,
        }
    }

    /// Construct a client that authenticates as a GitHub App.
    ///
    /// `pem_key` should be the raw bytes of the App's PEM private key file.
    pub fn from_app(app_id: u64, installation_id: u64, pem_key: &[u8]) -> Result<Self> {
        if app_id == 0 {
            bail!("app_id must be non-zero");
        }
        if installation_id == 0 {
            bail!("installation_id must be non-zero");
        }
        let trimmed = pem_key
            .strip_suffix(b"\n")
            .or_else(|| pem_key.strip_suffix(b"\r\n"))
            .unwrap_or(pem_key);
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(trimmed)
            .context("invalid RSA private key PEM")?;
        let (api_base_url, raw_base_url) = resolve_base_urls();
        Ok(Self {
            client: build_http_client(),
            auth: AuthState::App {
                credentials: Arc::new(AppCredentials {
                    app_id,
                    installation_id,
                    encoding_key,
                }),
                cached_token: Arc::new(RwLock::new(None)),
            },
            api_base_url,
            raw_base_url,
        })
    }

    pub fn has_token(&self) -> bool {
        match &self.auth {
            AuthState::Pat(token) => token.is_some(),
            AuthState::App { .. } => true,
        }
    }

    pub fn api_base_url(&self) -> &str {
        &self.api_base_url
    }

    /// Return a valid Bearer token, minting or refreshing as needed for App auth.
    #[instrument(skip(self))]
    async fn get_token(&self) -> Result<Option<String>> {
        match &self.auth {
            AuthState::Pat(token) => Ok(token.clone()),
            AuthState::App {
                credentials,
                cached_token,
            } => {
                // Fast path: read lock, check if cached token is still valid
                {
                    let cache = cached_token.read().await;
                    if let Some(ref ct) = *cache
                        && is_token_valid(ct)
                    {
                        return Ok(Some(ct.token.clone()));
                    }
                }
                // Slow path: write lock, double-check, then mint
                let mut cache = cached_token.write().await;
                if let Some(ref ct) = *cache
                    && is_token_valid(ct)
                {
                    return Ok(Some(ct.token.clone()));
                }
                let new_token = self.mint_installation_token(credentials).await?;
                let token_str = new_token.token.clone();
                *cache = Some(new_token);
                Ok(Some(token_str))
            }
        }
    }

    /// Exchange a JWT for a GitHub App installation access token.
    #[instrument(skip(self, creds), fields(app_id = creds.app_id, installation_id = creds.installation_id))]
    async fn mint_installation_token(&self, creds: &AppCredentials) -> Result<CachedToken> {
        let jwt = generate_jwt(creds.app_id, &creds.encoding_key)?;
        let url = format!(
            "{}/app/installations/{}/access_tokens",
            self.api_base_url, creds.installation_id
        );
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .context("failed to request installation access token")?;

        let response = response
            .error_for_status()
            .context("installation access token request returned non-success status")?;

        let body: Value = response
            .json()
            .await
            .context("failed to parse installation access token response")?;

        let token = body
            .get("token")
            .and_then(|v| v.as_str())
            .context("missing 'token' in installation access token response")?
            .to_string();

        let expires_at_str = body
            .get("expires_at")
            .and_then(|v| v.as_str())
            .context("missing 'expires_at' in installation access token response")?;

        let expires_at = DateTime::parse_from_rfc3339(expires_at_str)
            .context("invalid 'expires_at' timestamp in installation access token response")?
            .with_timezone(&Utc);

        Ok(CachedToken { token, expires_at })
    }

    #[instrument(skip(self), fields(action = %action))]
    pub async fn resolve_ref(&self, action: &ActionRef) -> Result<String> {
        if action.ref_type == RefType::Sha {
            return Ok(action.git_ref.clone());
        }

        // Try as a tag first
        let api = &self.api_base_url;
        let tag_url = format!(
            "{api}/repos/{}/{}/git/ref/tags/{}",
            action.owner, action.repo, action.git_ref
        );

        if let Some(json) = self.api_get_optional(&tag_url).await? {
            return self
                .extract_commit_sha(&json, &action.owner, &action.repo)
                .await;
        }

        // Fall back to branch
        let branch_url = format!(
            "{api}/repos/{}/{}/git/ref/heads/{}",
            action.owner, action.repo, action.git_ref
        );

        let json = self
            .api_get(&branch_url)
            .await
            .with_context(|| format!("ref '{}' not found as tag or branch", action.git_ref))?;

        self.extract_commit_sha(&json, &action.owner, &action.repo)
            .await
    }

    #[instrument(skip(self, ref_json))]
    async fn extract_commit_sha(
        &self,
        ref_json: &Value,
        owner: &str,
        repo: &str,
    ) -> Result<String> {
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
            let api = &self.api_base_url;
            let tag_url = format!("{api}/repos/{owner}/{repo}/git/tags/{sha}");
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
        if let Some(token) = self.get_token().await? {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("request to {url} failed"))?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow::Error::new(GitHubApiError::from_response(
                url, status, body,
            )));
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

    /// Fetch raw file content from a repository, returning `None` on 404.
    #[instrument(skip(self))]
    pub async fn get_raw_content_optional(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
        path: &str,
    ) -> Result<Option<String>> {
        let raw_base = &self.raw_base_url;
        let url = format!("{raw_base}/{owner}/{repo}/{git_ref}/{path}");

        let mut request = self.client.get(&url);
        if let Some(token) = self.get_token().await? {
            request = request.header("Authorization", format!("Bearer {token}"));
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("failed to fetch {url}"))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let response = response
            .error_for_status()
            .with_context(|| format!("{url} returned non-success status"))?;

        let text = response
            .text()
            .await
            .with_context(|| format!("failed to read body from {url}"))?;

        Ok(Some(text))
    }

    /// Fetch raw file content from a repository. Returns an error on 404.
    #[instrument(skip(self))]
    pub async fn get_raw_content(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
        path: &str,
    ) -> Result<String> {
        self.get_raw_content_optional(owner, repo, git_ref, path)
            .await?
            .ok_or_else(|| anyhow::anyhow!("{path} not found in {owner}/{repo}@{git_ref}"))
    }

    /// Send a GraphQL query to the GitHub API. Requires authentication.
    #[instrument(skip(self, query))]
    pub async fn graphql_post(&self, query: &str) -> Result<Value> {
        let token = self
            .get_token()
            .await?
            .context("GitHub token is required for GraphQL API")?;

        let body = serde_json::json!({ "query": query });

        let graphql_url = format!("{}/graphql", self.api_base_url);
        let response = self
            .client
            .post(&graphql_url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .json(&body)
            .send()
            .await
            .context("GraphQL request failed")?;

        let response = response
            .error_for_status()
            .context("GraphQL API returned non-success status")?;

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

    /// POST a JSON body to a GitHub REST endpoint and parse the response as JSON.
    /// Requires authentication.
    #[instrument(skip(self, body))]
    pub async fn api_post_json(&self, url: &str, body: Value) -> Result<Value> {
        let token = self
            .get_token()
            .await?
            .context("GitHub token is required for POST")?;

        let response = self
            .client
            .post(url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Authorization", format!("Bearer {token}"))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {url} failed"))?;

        let status = response.status();
        let response_body = response
            .text()
            .await
            .with_context(|| format!("failed to read body from {url}"))?;

        if !status.is_success() {
            return Err(anyhow::Error::new(GitHubApiError::from_response(
                url,
                status,
                response_body,
            )));
        }

        if response_body.is_empty() {
            return Ok(Value::Null);
        }

        serde_json::from_str(&response_body)
            .with_context(|| format!("failed to parse JSON from {url}"))
    }
}

/// Check whether a cached token is still usable (expires more than 5 minutes from now).
fn is_token_valid(ct: &CachedToken) -> bool {
    ct.expires_at > Utc::now() + chrono::Duration::seconds(TOKEN_REFRESH_BUFFER_SECS)
}

/// Generate a short-lived RS256 JWT for GitHub App authentication.
///
/// - `iat` is backdated 60 seconds per GitHub's recommendation to tolerate clock skew.
/// - `exp` is set to 10 minutes (the maximum GitHub allows for App JWTs).
fn generate_jwt(app_id: u64, key: &jsonwebtoken::EncodingKey) -> Result<String> {
    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": app_id.to_string(),
        "iat": now - 60,
        "exp": now + (10 * 60),
    });
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    jsonwebtoken::encode(&header, &claims, key).context("failed to sign JWT")
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
        let action: ActionRef = "actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11"
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

        let sha = client
            .extract_commit_sha(&ref_json, "actions", "checkout")
            .await
            .unwrap();
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

        let result = client
            .extract_commit_sha(&ref_json, "actions", "checkout")
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unexpected"));
    }

    #[tokio::test]
    async fn extract_commit_sha_missing_object() {
        let client = GitHubClient::new(Some("fake".into()));
        let ref_json = json!({"ref": "refs/tags/v4"});

        let result = client
            .extract_commit_sha(&ref_json, "actions", "checkout")
            .await;
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

    // ── GitHub App auth tests ──

    const TEST_PEM: &[u8] = include_bytes!("../tests/fixtures/test-rsa-key.pem");
    const TEST_PUB_PEM: &[u8] = include_bytes!("../tests/fixtures/test-rsa-key.pub");

    #[test]
    fn generate_jwt_produces_valid_rs256_token() {
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PEM).unwrap();
        let token = generate_jwt(12345, &key).unwrap();

        // Decode and verify with the matching public key
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_PUB_PEM).unwrap();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_required_spec_claims::<String>(&[]);
        validation.set_issuer(&["12345"]);
        validation.validate_exp = false; // we just want to inspect claims

        let data = jsonwebtoken::decode::<serde_json::Value>(&token, &decoding_key, &validation)
            .expect("JWT should decode with matching public key");

        assert_eq!(data.claims["iss"], "12345");

        let now = Utc::now().timestamp();
        let iat = data.claims["iat"].as_i64().unwrap();
        let exp = data.claims["exp"].as_i64().unwrap();
        // iat should be backdated ~60s
        assert!((now - 65..now - 55).contains(&iat), "iat={iat} now={now}");
        // exp should be ~10 minutes from now
        assert!((now + 535..now + 605).contains(&exp), "exp={exp} now={now}");
    }

    #[test]
    fn generate_jwt_with_invalid_key_fails() {
        let key_result = jsonwebtoken::EncodingKey::from_rsa_pem(b"not-a-pem");
        assert!(key_result.is_err());
    }

    #[test]
    fn from_app_valid_pem_succeeds() {
        let client = GitHubClient::from_app(1, 1, TEST_PEM).unwrap();
        assert!(client.has_token());
    }

    #[test]
    fn from_app_invalid_pem_fails() {
        match GitHubClient::from_app(1, 1, b"not-a-pem") {
            Ok(_) => panic!("should fail with invalid PEM"),
            Err(err) => assert!(
                err.to_string().contains("invalid RSA private key"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    fn from_app_rejects_zero_app_id() {
        match GitHubClient::from_app(0, 1, TEST_PEM) {
            Ok(_) => panic!("should reject app_id 0"),
            Err(err) => assert!(
                err.to_string().contains("app_id must be non-zero"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    fn from_app_rejects_zero_installation_id() {
        match GitHubClient::from_app(1, 0, TEST_PEM) {
            Ok(_) => panic!("should reject installation_id 0"),
            Err(err) => assert!(
                err.to_string().contains("installation_id must be non-zero"),
                "unexpected error: {err}"
            ),
        }
    }

    #[test]
    fn has_token_app_auth_returns_true() {
        let client = GitHubClient::from_app(1, 1, TEST_PEM).unwrap();
        assert!(client.has_token());
    }

    #[test]
    fn is_token_valid_checks_expiry_buffer() {
        let valid = CachedToken {
            token: "t".into(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        };
        assert!(is_token_valid(&valid));

        let expiring_soon = CachedToken {
            token: "t".into(),
            expires_at: Utc::now() + chrono::Duration::minutes(3),
        };
        assert!(!is_token_valid(&expiring_soon));

        let expired = CachedToken {
            token: "t".into(),
            expires_at: Utc::now() - chrono::Duration::minutes(1),
        };
        assert!(!is_token_valid(&expired));
    }

    /// Helper: build a GitHubClient from App credentials pointed at a custom API base URL.
    fn app_client_with_base_url(base_url: &str) -> GitHubClient {
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PEM).unwrap();
        GitHubClient {
            client: build_http_client(),
            auth: AuthState::App {
                credentials: Arc::new(AppCredentials {
                    app_id: 99,
                    installation_id: 42,
                    encoding_key: key,
                }),
                cached_token: Arc::new(RwLock::new(None)),
            },
            api_base_url: base_url.to_string(),
            raw_base_url: "http://unused".to_string(),
        }
    }

    #[tokio::test]
    async fn app_auth_mints_and_caches_token() {
        use wiremock::matchers::{header_regex, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let expires = (Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        // Mock the installation token endpoint — verify JWT is sent as Bearer token
        Mock::given(method("POST"))
            .and(path("/app/installations/42/access_tokens"))
            .and(header_regex("authorization", r"^Bearer ey"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "token": "ghs_test_token_abc",
                "expires_at": expires,
                "permissions": { "contents": "read" }
            })))
            .expect(1) // exactly one call — second request should use cache
            .mount(&mock_server)
            .await;

        // Mock an API endpoint — verify the minted token is forwarded
        Mock::given(method("GET"))
            .and(path("/repos/test/repo/contents/file.txt"))
            .and(header_regex(
                "authorization",
                r"^Bearer ghs_test_token_abc$",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"content": "ok"})))
            .mount(&mock_server)
            .await;

        let client = app_client_with_base_url(&mock_server.uri());

        // First call: should mint a token, then use it
        let result = client
            .api_get(&format!(
                "{}/repos/test/repo/contents/file.txt",
                mock_server.uri()
            ))
            .await;
        assert!(result.is_ok());

        // Second call: should reuse the cached token (mock expects exactly 1 mint call)
        let result = client
            .api_get(&format!(
                "{}/repos/test/repo/contents/file.txt",
                mock_server.uri()
            ))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn api_post_json_success_path() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/o/r/code-scanning/sarifs"))
            .and(header("authorization", "Bearer pat"))
            .and(header("x-github-api-version", "2022-11-28"))
            .and(body_json(json!({"hello": "world"})))
            .respond_with(
                ResponseTemplate::new(202).set_body_json(json!({"id": "abc-123"})),
            )
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new(Some("pat".to_string()));
        let url = format!("{}/repos/o/r/code-scanning/sarifs", mock_server.uri());
        let resp = client
            .api_post_json(&url, json!({"hello": "world"}))
            .await
            .unwrap();
        assert_eq!(resp["id"], "abc-123");
    }

    #[tokio::test]
    async fn api_post_json_returns_typed_error_on_4xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sarifs"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_string("{\"message\":\"sarif schema invalid\"}"),
            )
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new(Some("pat".to_string()));
        let url = format!("{}/sarifs", mock_server.uri());
        let err = client
            .api_post_json(&url, json!({}))
            .await
            .unwrap_err();
        let api_err = err
            .downcast_ref::<GitHubApiError>()
            .expect("expected typed GitHubApiError");
        assert_eq!(api_err.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(api_err.url, url);
        assert!(
            api_err.body.contains("sarif schema invalid"),
            "expected response body to be carried: {body}",
            body = api_err.body
        );
    }

    #[tokio::test]
    async fn api_post_json_returns_typed_error_on_5xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/blip"))
            .respond_with(ResponseTemplate::new(503).set_body_string("upstream down"))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new(Some("pat".to_string()));
        let url = format!("{}/blip", mock_server.uri());
        let err = client.api_post_json(&url, json!({})).await.unwrap_err();
        let api_err = err
            .downcast_ref::<GitHubApiError>()
            .expect("expected typed GitHubApiError");
        assert_eq!(api_err.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(api_err.status.is_server_error());
        assert!(!api_err.status.is_client_error());
    }

    #[tokio::test]
    async fn api_post_json_truncates_huge_response_bodies() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Build a 64 KiB body of printable ASCII — larger than the
        // 8 KiB diagnostic cap.
        let huge: String = "X".repeat(64 * 1024);
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/spew"))
            .respond_with(ResponseTemplate::new(400).set_body_string(huge))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new(Some("pat".to_string()));
        let url = format!("{}/spew", mock_server.uri());
        let err = client.api_post_json(&url, json!({})).await.unwrap_err();
        let api_err = err.downcast_ref::<GitHubApiError>().unwrap();
        assert!(
            api_err.body.len() <= MAX_DIAGNOSTIC_BYTES + "…[truncated]".len(),
            "body should be truncated to ~8 KiB, got {}",
            api_err.body.len()
        );
        assert!(api_err.body.ends_with("…[truncated]"));
    }

    #[tokio::test]
    async fn api_post_json_strips_control_chars_from_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Response containing ANSI escape + bell + null
        let nasty = "hello\x1b[31mRED\x07\x00world";
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/nasty"))
            .respond_with(ResponseTemplate::new(400).set_body_string(nasty))
            .mount(&mock_server)
            .await;

        let client = GitHubClient::new(Some("pat".to_string()));
        let url = format!("{}/nasty", mock_server.uri());
        let err = client.api_post_json(&url, json!({})).await.unwrap_err();
        let api_err = err.downcast_ref::<GitHubApiError>().unwrap();
        assert!(!api_err.body.contains('\x1b'));
        assert!(!api_err.body.contains('\x07'));
        assert!(!api_err.body.contains('\x00'));
        assert!(api_err.body.contains("hello"));
        assert!(api_err.body.contains("world"));
    }

    #[test]
    fn truncate_for_diagnostic_strips_control_chars_and_caps_length() {
        let s = "ok\nstill ok\ttab\x07bell\x1b[31mred\x00null";
        let out = truncate_for_diagnostic(s, 1024);
        assert!(out.contains('\n'));
        assert!(out.contains('\t'));
        assert!(!out.contains('\x07'));
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x00'));

        let huge = "z".repeat(20_000);
        let out = truncate_for_diagnostic(&huge, 8192);
        assert!(out.len() <= 8192 + "…[truncated]".len());
        assert!(out.ends_with("…[truncated]"));
    }

    #[test]
    fn validate_base_url_accepts_https() {
        assert!(validate_base_url("X", "https://api.github.com").is_ok());
        assert!(validate_base_url("X", "https://ghe.example.com").is_ok());
    }

    #[test]
    fn validate_base_url_accepts_http_to_loopback() {
        assert!(validate_base_url("X", "http://localhost:8080").is_ok());
        assert!(validate_base_url("X", "http://127.0.0.1:9000").is_ok());
        assert!(validate_base_url("X", "http://[::1]:1234").is_ok());
    }

    #[test]
    fn validate_base_url_rejects_http_to_remote() {
        let err = validate_base_url("GHSS_API_BASE_URL", "http://malicious.example.com")
            .unwrap_err()
            .to_string();
        assert!(err.contains("must use https://"), "got: {err}");
        assert!(err.contains("GHSS_API_BASE_URL"), "got: {err}");
    }

    #[tokio::test]
    async fn api_post_json_requires_token() {
        let client = GitHubClient::new(None);
        let err = client
            .api_post_json("http://example.invalid/", json!({}))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("token is required"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn app_auth_refreshes_expired_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let fresh_expires = (Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        // Token endpoint — will be called twice (initial + refresh)
        Mock::given(method("POST"))
            .and(path("/app/installations/42/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "token": "ghs_refreshed",
                "expires_at": fresh_expires
            })))
            .expect(2)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/test/repo/contents/file.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&mock_server)
            .await;

        let client = app_client_with_base_url(&mock_server.uri());

        // First call — mints a token
        client
            .api_get(&format!(
                "{}/repos/test/repo/contents/file.txt",
                mock_server.uri()
            ))
            .await
            .unwrap();

        // Force the cached token to be expired
        if let AuthState::App { cached_token, .. } = &client.auth {
            let mut cache = cached_token.write().await;
            if let Some(ref mut ct) = *cache {
                ct.expires_at = Utc::now() - chrono::Duration::minutes(10);
            }
        }

        // Second call — should detect expired token and mint a new one
        client
            .api_get(&format!(
                "{}/repos/test/repo/contents/file.txt",
                mock_server.uri()
            ))
            .await
            .unwrap();
    }
}
