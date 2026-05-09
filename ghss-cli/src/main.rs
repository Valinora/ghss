use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Parser, ValueEnum};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use tracing_subscriber::{EnvFilter, fmt};

use ghss::depth::DepthLimit;
use ghss::github::GitHubClient;
use ghss::output::{self, AuditNode, OutputFormat};
use ghss::pipeline::PipelineBuilder;
use ghss::providers;
use ghss::stages::{
    AdvisoryStage, CompositeExpandStage, DependencyStage, RefResolveStage, ScanStage,
    WorkflowExpandStage,
};
use ghss::walker::Walker;

/// Output format for audit results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
enum CliOutputFormat {
    Text,
    Json,
    Sarif,
}

impl From<CliOutputFormat> for OutputFormat {
    fn from(value: CliOutputFormat) -> Self {
        match value {
            CliOutputFormat::Text => OutputFormat::Text,
            CliOutputFormat::Json => OutputFormat::Json,
            CliOutputFormat::Sarif => OutputFormat::Sarif,
        }
    }
}

/// Audit GitHub Actions workflows for third-party action usage
#[derive(Parser)]
#[command(name = "ghss", version)]
struct Cli {
    /// Path to a GitHub Actions workflow YAML file
    #[arg(short, long)]
    file: PathBuf,

    /// Advisory provider to use (ghsa, osv, or all)
    #[arg(long, default_value = "all")]
    provider: String,

    /// Output format for results (text, json, sarif).
    /// SARIF output expects --file to be a repo-relative path so the
    /// emitted artifactLocation is usable by GitHub Code Scanning.
    #[arg(long, value_enum, default_value_t = CliOutputFormat::Text, conflicts_with = "json")]
    format: CliOutputFormat,

    /// Deprecated: use --format json. Kept for back-compat with existing scripts.
    #[arg(long, hide = true)]
    json: bool,

    /// Recursive expansion depth for composite actions and reusable workflows (0 = no expansion, "unlimited" = full traversal)
    #[arg(long, default_value = "0")]
    depth: DepthLimit,

    /// Select which root actions to audit (all, or 1-indexed ranges like 1-3,5)
    #[arg(long)]
    select: Option<ghss::ActionSelection>,

    /// Scan action ecosystems and npm dependencies for known vulnerabilities
    #[arg(long)]
    deps: bool,

    /// Fail with exit code 2 if any advisory meets or exceeds this severity (critical, high, medium, low)
    #[arg(long, value_name = "LEVEL")]
    fail_on_severity: Option<ghss::advisory::Severity>,

    /// GitHub personal access token (or set `GITHUB_TOKEN` env var)
    #[arg(long, env = "GITHUB_TOKEN")]
    github_token: Option<String>,

    /// GitHub App ID (alternative to --github-token)
    #[arg(long, env = "GITHUB_APP_ID")]
    github_app_id: Option<u64>,

    /// GitHub App installation ID (alternative to --github-token)
    #[arg(long, env = "GITHUB_APP_INSTALLATION_ID")]
    github_app_installation_id: Option<u64>,

    /// Path to GitHub App private key PEM file (alternative to --github-token)
    #[arg(long, env = "GITHUB_APP_PRIVATE_KEY_PATH")]
    github_app_private_key_path: Option<PathBuf>,

    #[command(flatten)]
    verbosity: Verbosity<WarnLevel>,
}

#[tokio::main]
async fn main() {
    let mut args = Cli::parse();

    // Back-compat: --json overrides --format. clap's `conflicts_with` already
    // rejects passing both, so this only fires when only --json is set.
    if args.json {
        args.format = CliOutputFormat::Json;
    }

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = args.verbosity.tracing_level_filter();
        EnvFilter::new(level.to_string())
    });

    let base = fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time();

    // Use JSON-formatted log output to stderr whenever the result format is
    // machine-readable, so operators piping --format json or --format sarif
    // also get structured logs.
    let structured_logs = matches!(args.format, CliOutputFormat::Json | CliOutputFormat::Sarif);
    if structured_logs {
        base.json().init();
    } else {
        base.init();
    }

    if args.json {
        tracing::warn!("--json is deprecated; use --format json instead");
    }

    match run(&args).await {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::exit(1);
        }
    }
}

async fn run(args: &Cli) -> anyhow::Result<i32> {
    if !args.file.exists() {
        bail!("file not found: {}", args.file.display());
    }

    let contents = std::fs::read_to_string(&args.file)?;
    let actions = ghss::parse_actions(&contents)?;
    let client = build_client(args)?;

    // Filter root actions by --select
    let actions = match &args.select {
        Some(sel) => actions
            .into_iter()
            .enumerate()
            .filter(|(i, _)| sel.includes(*i))
            .map(|(_, a)| a)
            .collect(),
        None => actions,
    };

    let has_token = client.has_token();
    let action_providers = providers::create_action_providers(&args.provider, &client)?;
    let package_providers = providers::create_package_providers(&args.provider)?;

    let mut builder = PipelineBuilder::default()
        .stage(CompositeExpandStage::new(client.clone()))
        .stage(WorkflowExpandStage::new(client.clone()))
        .stage(RefResolveStage::new(client.clone()))
        .stage(AdvisoryStage::new(action_providers));

    if args.deps {
        if has_token {
            builder = builder
                .stage(ScanStage::new(client.clone()))
                .stage(DependencyStage::new(client.clone(), package_providers));
        } else {
            tracing::warn!(
                "--deps requires a GitHub token; skipping ecosystem scan and dependency audit"
            );
        }
    }

    let pipeline = builder.build();
    let max_concurrency = pipeline.max_concurrency();
    let walker = Walker::new(pipeline, args.depth.to_max_depth(), max_concurrency);
    let nodes: Vec<AuditNode> = walker.walk(actions).await;

    let formatter = output::formatter(OutputFormat::from(args.format), args.file.clone());
    formatter
        .write_results(&nodes, &mut std::io::stdout().lock())
        .expect("failed to write output");

    if let Some(threshold) = args.fail_on_severity {
        let violations = output::collect_severity_violations(&nodes, threshold);
        if !violations.is_empty() {
            eprintln!(
                "\n{} advisory violation(s) at or above {threshold} severity:\n",
                violations.len()
            );
            for v in &violations {
                eprintln!(
                    "  {} - {} ({}): {}",
                    v.action, v.advisory_id, v.severity, v.summary
                );
            }
            eprintln!();
            return Ok(2);
        }
    }

    Ok(0)
}

fn build_client(args: &Cli) -> anyhow::Result<GitHubClient> {
    let has_app = args.github_app_id.is_some()
        || args.github_app_installation_id.is_some()
        || args.github_app_private_key_path.is_some();

    if args.github_token.is_some() && has_app {
        bail!("cannot specify both --github-token and GitHub App credentials");
    }

    if has_app {
        let app_id = args
            .github_app_id
            .context("--github-app-id is required when using GitHub App authentication")?;
        let installation_id = args.github_app_installation_id.context(
            "--github-app-installation-id is required when using GitHub App authentication",
        )?;
        let key_path = args.github_app_private_key_path.as_ref().context(
            "--github-app-private-key-path is required when using GitHub App authentication",
        )?;
        let pem_key = std::fs::read(key_path)
            .with_context(|| format!("failed to read private key: {}", key_path.display()))?;
        GitHubClient::from_app(app_id, installation_id, &pem_key)
    } else {
        Ok(GitHubClient::new(args.github_token.clone()))
    }
}
