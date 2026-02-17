use std::path::PathBuf;

use anyhow::bail;
use clap::Parser;
use clap_verbosity_flag::{Verbosity, WarnLevel};
use tracing_subscriber::{fmt, EnvFilter};

use ghss::github::GitHubClient;
use ghss::output;

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

    /// Output results and logs in JSON format
    #[arg(long)]
    json: bool,

    /// GitHub personal access token (or set GITHUB_TOKEN env var)
    #[arg(long, env = "GITHUB_TOKEN")]
    github_token: Option<String>,

    #[command(flatten)]
    verbosity: Verbosity<WarnLevel>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = args.verbosity.tracing_level_filter();
        EnvFilter::new(level.to_string())
    });

    let base = fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time();

    if args.json {
        base.json().init();
    } else {
        base.init();
    }

    run(&args).await
}

async fn run(args: &Cli) -> anyhow::Result<()> {
    if !args.file.exists() {
        bail!("file not found: {}", args.file.display());
    }

    let actions = ghss::parse_actions(&args.file)?;
    let github_client = GitHubClient::new(args.github_token.clone());
    let providers = ghss::create_providers(&args.provider, &github_client)?;
    let entries =
        ghss::audit_actions(actions, &providers, &github_client, &ghss::AuditOptions::default())
            .await;

    let formatter = output::formatter(args.json);
    formatter
        .write_results(&entries, &mut std::io::stdout().lock())
        .expect("failed to write output");

    Ok(())
}
