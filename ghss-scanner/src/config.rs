use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerConfig {
    pub scanner: ScannerSection,
    pub repos: Vec<RepoEntry>,
    pub pipeline: PipelineSection,
    pub storage: StorageSection,
    pub telemetry: Option<TelemetrySection>,
    pub health: Option<HealthSection>,
    pub upload: Option<UploadSection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAppSection {
    pub app_id: u64,
    pub installation_id: u64,
    pub private_key_path: String,
}

impl std::fmt::Debug for GitHubAppSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubAppSection")
            .field("app_id", &self.app_id)
            .field("installation_id", &self.installation_id)
            .field("private_key_path", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerSection {
    pub github_token: Option<String>,
    pub github_app: Option<GitHubAppSection>,
    pub schedule: String,
    #[serde(default)]
    pub max_repo_concurrency: Option<usize>,
}

impl std::fmt::Debug for ScannerSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token_display = if self.github_token.is_some() {
            "<set>"
        } else {
            "<unset>"
        };
        f.debug_struct("ScannerSection")
            .field("github_token", &token_display)
            .field("github_app", &self.github_app)
            .field("schedule", &self.schedule)
            .field("max_repo_concurrency", &self.max_repo_concurrency)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoEntry {
    pub owner: String,
    pub name: String,
    pub workflows: Option<Vec<String>>,
    /// Per-repo override for SARIF upload. `None` falls through to
    /// `[upload].enabled`. `Some(false)` opts out even when the global
    /// flag is on (e.g. private repos without GHAS).
    #[serde(default)]
    pub upload_sarif: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineSection {
    pub depth: String,
    pub provider: String,
    pub deps: bool,
    #[serde(default)]
    pub concurrency: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    pub url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetrySection {
    pub endpoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSection {
    pub bind: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadSection {
    /// Master switch. Even if this section is present, no uploads happen
    /// unless `enabled = true`.
    pub enabled: bool,
    /// Tool name advertised in the SARIF driver. Surfaces in the GHAS
    /// "tool" filter on the Security tab.
    #[serde(default = "default_tool_name")]
    pub tool_name: String,
    /// When true, suppress uploads whose payload hash matches the most
    /// recent successful upload for that repo. Default true.
    #[serde(default = "default_skip_unchanged")]
    pub skip_unchanged: bool,
    /// Override the SARIF tool's `informationUri`. Defaults to the
    /// canonical project URL when unset.
    #[serde(default)]
    pub information_uri: Option<String>,
}

fn default_tool_name() -> String {
    "ghss".to_string()
}

fn default_skip_unchanged() -> bool {
    true
}

impl UploadSection {
    /// Two-layer opt-in: global `enabled = true` AND per-repo
    /// `upload_sarif != Some(false)`.
    pub fn enabled_for(&self, repo: &RepoEntry) -> bool {
        self.enabled && !matches!(repo.upload_sarif, Some(false))
    }

    /// Build the `ToolMetadata` the SARIF library expects. Pulls the
    /// tool name from this section and falls back to the library's
    /// `TOOL_INFORMATION_URI` constant when the operator hasn't
    /// configured an override.
    pub fn tool_metadata(&self) -> ghss::output::sarif::ToolMetadata<'_> {
        ghss::output::sarif::ToolMetadata {
            name: &self.tool_name,
            version: env!("CARGO_PKG_VERSION"),
            information_uri: self
                .information_uri
                .as_deref()
                .unwrap_or(ghss::output::sarif::TOOL_INFORMATION_URI),
        }
    }
}

impl ScannerConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents =
            std::fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;
        let mut config: Self = toml::from_str(&contents).context("failed to parse config")?;

        expand_env_vars(&mut config)?;
        validate(&config)?;

        Ok(config)
    }
}

/// Expand `${VAR_NAME}` patterns in credential fields.
fn expand_env_vars(config: &mut ScannerConfig) -> anyhow::Result<()> {
    if let Some(ref token) = config.scanner.github_token
        && let Some(var_name) = token.strip_prefix("${").and_then(|s| s.strip_suffix('}'))
    {
        let value = std::env::var(var_name).context(format!(
            "env var {var_name} referenced in github_token is not set"
        ))?;
        config.scanner.github_token = Some(value);
    }

    if let Some(ref mut app) = config.scanner.github_app
        && let Some(var_name) = app
            .private_key_path
            .strip_prefix("${")
            .and_then(|s| s.strip_suffix('}'))
    {
        let var_name = var_name.to_string();
        let value = std::env::var(&var_name).context(format!(
            "env var {var_name} referenced in github_app.private_key_path is not set"
        ))?;
        app.private_key_path = value;
    }

    Ok(())
}

/// Convert a 5-field cron expression to the 6-field format expected by the `cron` crate
/// by prepending "0 " (seconds = 0). If already 6+ fields, return as-is.
pub fn normalize_cron(expr: &str) -> String {
    let field_count = expr.split_whitespace().count();
    if field_count == 5 {
        format!("0 {expr}")
    } else {
        expr.to_string()
    }
}

/// Validate config after parsing.
fn validate(config: &ScannerConfig) -> anyhow::Result<()> {
    // Validate cron expression (normalize 5-field → 6-field)
    use std::str::FromStr;
    let cron_expr = normalize_cron(&config.scanner.schedule);
    cron::Schedule::from_str(&cron_expr).context(format!(
        "invalid cron expression: {}",
        config.scanner.schedule
    ))?;

    // Validate auth config: token and app are mutually exclusive
    if config.scanner.github_token.is_some() && config.scanner.github_app.is_some() {
        bail!(
            "cannot specify both github_token and [scanner.github_app]; \
             use one authentication method"
        );
    }

    // Validate concurrency fields
    if config.scanner.max_repo_concurrency == Some(0) {
        bail!("max_repo_concurrency must be a positive integer (got 0)");
    }
    if config.pipeline.concurrency == Some(0) {
        bail!("pipeline concurrency must be a positive integer (got 0)");
    }

    // Log effective values
    tracing::info!(
        max_repo_concurrency = config.scanner.max_repo_concurrency.unwrap_or(1),
        pipeline_concurrency = config.pipeline.concurrency.unwrap_or(10),
        "Effective concurrency settings"
    );

    // Validate storage URL scheme
    if config.storage.url.starts_with("postgresql://") {
        bail!("PostgreSQL storage is not yet supported; use sqlite://");
    }
    if !config.storage.url.starts_with("sqlite://") {
        bail!(
            "invalid storage URL: must start with sqlite:// (got {})",
            config.storage.url
        );
    }

    Ok(())
}

/// Resolve config file path by precedence:
/// 1. CLI --config flag
/// 2. `GHSS_SCANNER_CONFIG` env var
/// 3. /opt/ghss/config.toml default
pub fn resolve_config_path(cli_path: Option<&Path>) -> anyhow::Result<PathBuf> {
    let path = cli_path.map_or_else(
        || {
            std::env::var("GHSS_SCANNER_CONFIG")
                .map_or_else(|_| PathBuf::from("/opt/ghss/config.toml"), PathBuf::from)
        },
        Path::to_path_buf,
    );

    if !path.exists() {
        bail!("config file not found: {}", path.display());
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    const VALID_CONFIG: &str = r#"
[scanner]
github_token = "ghp_test123"
schedule = "*/30 * * * *"

[[repos]]
owner = "my-org"
name = "my-app"

[[repos]]
owner = "my-org"
name = "my-service"
workflows = ["ci.yml", "deploy.yml"]

[pipeline]
depth = "unlimited"
provider = "all"
deps = true

[storage]
url = "sqlite:///tmp/ghss-test.db"

[telemetry]
endpoint = "http://otel-collector:4317"

[health]
bind = "0.0.0.0:8080"
"#;

    #[test]
    fn test_valid_config() {
        let f = write_temp_config(VALID_CONFIG);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        assert_eq!(config.scanner.schedule, "*/30 * * * *");
        assert_eq!(config.repos.len(), 2);
        assert_eq!(config.repos[0].owner, "my-org");
        assert_eq!(config.repos[0].name, "my-app");
        assert_eq!(config.repos[1].workflows.as_ref().unwrap().len(), 2);
        assert_eq!(config.pipeline.depth, "unlimited");
        assert_eq!(config.pipeline.provider, "all");
        assert!(config.pipeline.deps);
        assert_eq!(config.storage.url, "sqlite:///tmp/ghss-test.db");
        assert!(config.telemetry.is_some());
        assert!(config.health.is_some());
    }

    #[test]
    fn test_minimal_config() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "ghsa"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        assert!(config.scanner.github_token.is_none());
        assert!(config.telemetry.is_none());
        assert!(config.health.is_none());
    }

    #[test]
    fn test_missing_required_fields() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("repos") || msg.contains("missing field"),
            "expected repos/missing field error, got: {msg}"
        );
    }

    #[test]
    fn test_unknown_keys_rejected() {
        let content = r#"
[scanner]
schedule = "0 * * * *"
unknown_key = "bad"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("unknown") || msg.contains("Unknown"),
            "expected unknown field error, got: {msg}"
        );
    }

    #[test]
    fn test_invalid_cron_expression() {
        let content = r#"
[scanner]
schedule = "not a cron"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("invalid cron"),
            "expected cron error, got: {err}"
        );
    }

    #[test]
    fn test_invalid_storage_url() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "mysql://localhost/db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("invalid storage URL"),
            "expected storage URL error, got: {err}"
        );
    }

    #[test]
    fn test_postgresql_not_yet_supported() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "postgresql://user:pass@host/db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("not yet supported"),
            "expected postgresql error, got: {err}"
        );
    }

    #[test]
    fn test_env_var_expansion() {
        let content = r#"
[scanner]
github_token = "${GHSS_TEST_TOKEN}"
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        // Set the env var, parse, then clean up
        unsafe { std::env::set_var("GHSS_TEST_TOKEN", "ghp_expanded_value") };
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        assert_eq!(
            config.scanner.github_token.as_deref(),
            Some("ghp_expanded_value")
        );
        unsafe { std::env::remove_var("GHSS_TEST_TOKEN") };
    }

    #[test]
    fn test_env_var_expansion_unset() {
        let content = r#"
[scanner]
github_token = "${GHSS_NONEXISTENT_VAR_12345}"
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("not set"),
            "expected env var not set error, got: {err}"
        );
    }

    #[test]
    fn test_resolve_config_path_cli_flag() {
        let f = write_temp_config("dummy");
        let result = resolve_config_path(Some(f.path())).unwrap();
        assert_eq!(result, f.path());
    }

    #[test]
    fn test_resolve_config_path_env_var() {
        let f = write_temp_config("dummy");
        unsafe {
            std::env::set_var("GHSS_SCANNER_CONFIG", f.path().to_str().unwrap());
        }
        let result = resolve_config_path(None).unwrap();
        assert_eq!(result, f.path());
        unsafe { std::env::remove_var("GHSS_SCANNER_CONFIG") };
    }

    #[test]
    fn test_resolve_config_path_not_found() {
        let err = resolve_config_path(Some(Path::new("/nonexistent/path.toml"))).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "expected not found error, got: {err}"
        );
    }

    #[test]
    fn test_concurrency_fields_missing_defaults() {
        // Missing concurrency fields should parse successfully (defaults to None)
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        assert_eq!(config.scanner.max_repo_concurrency, None);
        assert_eq!(config.pipeline.concurrency, None);
    }

    #[test]
    fn test_concurrency_fields_valid_positive() {
        let content = r#"
[scanner]
schedule = "0 * * * *"
max_repo_concurrency = 4

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false
concurrency = 20

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        assert_eq!(config.scanner.max_repo_concurrency, Some(4));
        assert_eq!(config.pipeline.concurrency, Some(20));
    }

    #[test]
    fn test_max_repo_concurrency_zero_rejected() {
        let content = r#"
[scanner]
schedule = "0 * * * *"
max_repo_concurrency = 0

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("max_repo_concurrency"),
            "expected max_repo_concurrency error, got: {err}"
        );
    }

    #[test]
    fn test_pipeline_concurrency_zero_rejected() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false
concurrency = 0

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("pipeline concurrency"),
            "expected pipeline concurrency error, got: {err}"
        );
    }

    #[test]
    fn test_github_app_config() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[scanner.github_app]
app_id = 12345
installation_id = 67890
private_key_path = "/path/to/key.pem"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "ghsa"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        let app = config.scanner.github_app.unwrap();
        assert_eq!(app.app_id, 12345);
        assert_eq!(app.installation_id, 67890);
        assert_eq!(app.private_key_path, "/path/to/key.pem");
        assert!(config.scanner.github_token.is_none());
    }

    #[test]
    fn test_github_app_and_token_rejected() {
        let content = r#"
[scanner]
github_token = "ghp_test"
schedule = "0 * * * *"

[scanner.github_app]
app_id = 1
installation_id = 1
private_key_path = "/key.pem"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("cannot specify both"),
            "expected mutual exclusivity error, got: {err}"
        );
    }

    #[test]
    fn test_github_app_missing_field() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[scanner.github_app]
app_id = 1

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        let f = write_temp_config(content);
        let err = ScannerConfig::from_file(f.path()).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing field") || msg.contains("installation_id"),
            "expected missing field error, got: {msg}"
        );
    }

    #[test]
    fn test_upload_section_absent_means_no_uploads() {
        let f = write_temp_config(VALID_CONFIG);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        assert!(config.upload.is_none());
    }

    #[test]
    fn test_upload_section_enabled_with_defaults() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"

[upload]
enabled = true
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        let upload = config.upload.expect("[upload] should be present");
        assert!(upload.enabled);
        assert_eq!(upload.tool_name, "ghss");
        assert!(upload.skip_unchanged);
    }

    #[test]
    fn test_upload_section_overrides() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"

[upload]
enabled = true
tool_name = "ghss-internal"
skip_unchanged = false
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        let upload = config.upload.unwrap();
        assert_eq!(upload.tool_name, "ghss-internal");
        assert!(!upload.skip_unchanged);
    }

    #[test]
    fn test_upload_per_repo_override() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo-a"

[[repos]]
owner = "org"
name = "repo-b"
upload_sarif = false

[[repos]]
owner = "org"
name = "repo-c"
upload_sarif = true

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"

[upload]
enabled = true
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        let upload = config.upload.as_ref().unwrap();
        assert!(upload.enabled_for(&config.repos[0]));
        assert!(!upload.enabled_for(&config.repos[1]));
        assert!(upload.enabled_for(&config.repos[2]));
    }

    #[test]
    fn test_upload_global_disabled_disables_all() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"
upload_sarif = true

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"

[upload]
enabled = false
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        let upload = config.upload.as_ref().unwrap();
        assert!(
            !upload.enabled_for(&config.repos[0]),
            "global enabled=false must override per-repo opt-in"
        );
    }

    #[test]
    fn test_tool_metadata_uses_default_when_information_uri_unset() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"

[upload]
enabled = true
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        let upload = config.upload.as_ref().unwrap();
        let tool = upload.tool_metadata();
        assert_eq!(tool.name, "ghss");
        assert_eq!(tool.information_uri, ghss::output::sarif::TOOL_INFORMATION_URI);
        // Version is the crate's CARGO_PKG_VERSION; just sanity-check it's non-empty.
        assert!(!tool.version.is_empty());
    }

    #[test]
    fn test_tool_metadata_uses_override_when_information_uri_set() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"

[upload]
enabled = true
tool_name = "acme-scanner"
information_uri = "https://example.com/acme"
"#;
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        let upload = config.upload.as_ref().unwrap();
        let tool = upload.tool_metadata();
        assert_eq!(tool.name, "acme-scanner");
        assert_eq!(tool.information_uri, "https://example.com/acme");
    }

    #[test]
    fn test_github_app_env_var_expansion() {
        let content = r#"
[scanner]
schedule = "0 * * * *"

[scanner.github_app]
app_id = 1
installation_id = 2
private_key_path = "${GHSS_TEST_KEY_PATH}"

[[repos]]
owner = "org"
name = "repo"

[pipeline]
depth = "0"
provider = "all"
deps = false

[storage]
url = "sqlite:///tmp/ghss.db"
"#;
        unsafe { std::env::set_var("GHSS_TEST_KEY_PATH", "/expanded/key.pem") };
        let f = write_temp_config(content);
        let config = ScannerConfig::from_file(f.path()).unwrap();
        assert_eq!(
            config.scanner.github_app.unwrap().private_key_path,
            "/expanded/key.pem"
        );
        unsafe { std::env::remove_var("GHSS_TEST_KEY_PATH") };
    }
}
