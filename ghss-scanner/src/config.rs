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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerSection {
    pub github_token: Option<String>,
    pub schedule: String,
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
            .field("schedule", &self.schedule)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoEntry {
    pub owner: String,
    pub name: String,
    pub workflows: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipelineSection {
    pub depth: String,
    pub provider: String,
    pub deps: bool,
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

impl ScannerConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<ScannerConfig> {
        let contents =
            std::fs::read_to_string(path).context(format!("failed to read {}", path.display()))?;
        let mut config: ScannerConfig =
            toml::from_str(&contents).context("failed to parse config")?;

        expand_env_vars(&mut config)?;
        validate(&config)?;

        Ok(config)
    }
}

/// Expand `${VAR_NAME}` patterns in the github_token field.
fn expand_env_vars(config: &mut ScannerConfig) -> anyhow::Result<()> {
    if let Some(ref token) = config.scanner.github_token
        && let Some(var_name) = token.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
            let value = std::env::var(var_name).context(format!(
                "env var {var_name} referenced in github_token is not set"
            ))?;
            config.scanner.github_token = Some(value);
        }
    Ok(())
}

/// Convert a 5-field cron expression to the 6-field format expected by the `cron` crate
/// by prepending "0 " (seconds = 0). If already 6+ fields, return as-is.
pub fn normalize_cron(expr: &str) -> String {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() == 5 {
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
/// 2. GHSS_SCANNER_CONFIG env var
/// 3. /opt/ghss/config.toml default
pub fn resolve_config_path(cli_path: Option<&Path>) -> anyhow::Result<PathBuf> {
    let path = if let Some(p) = cli_path {
        p.to_path_buf()
    } else if let Ok(env_path) = std::env::var("GHSS_SCANNER_CONFIG") {
        PathBuf::from(env_path)
    } else {
        PathBuf::from("/opt/ghss/config.toml")
    };

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
}
