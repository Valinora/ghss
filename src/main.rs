use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::bail;
use clap::Parser;
use clap_verbosity_flag::{Verbosity, WarnLevel};
use futures::future::join_all;
use tokio::sync::Semaphore;
use tracing::warn;
use tracing_subscriber::{fmt, EnvFilter};

use ghss::advisory::AdvisoryProvider;
use ghss::ghsa::GhsaProvider;
use ghss::github::GitHubClient;
use ghss::osv::OsvProvider;
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

    let providers: Vec<Arc<dyn AdvisoryProvider>> = match args.provider.as_str() {
        "ghsa" => vec![Arc::new(GhsaProvider::new(github_client.clone()))],
        "osv" => vec![Arc::new(OsvProvider::new())],
        "all" => vec![
            Arc::new(GhsaProvider::new(github_client.clone())),
            Arc::new(OsvProvider::new()),
        ],
        other => bail!("unknown provider: {other} (valid: ghsa, osv, all)"),
    };

    let sem = Arc::new(Semaphore::new(10));

    let futures: Vec<_> = actions
        .into_iter()
        .map(|action| {
            let client = github_client.clone();
            let providers = providers.clone();
            let sem = sem.clone();

            async move {
                let _permit = sem.acquire().await.expect("semaphore closed");

                let resolved_sha = match client.resolve_ref(&action).await {
                    Ok(sha) => Some(sha),
                    Err(e) => {
                        warn!(action = %action.raw, error = %e, "failed to resolve ref");
                        None
                    }
                };

                let advisory_results = join_all(providers.iter().map(|p| {
                    let p = p.clone();
                    let action = action.clone();
                    async move { (p.name().to_string(), p.query(&action).await) }
                }))
                .await;

                let mut advisories = Vec::new();
                let mut seen_ids: HashSet<String> = HashSet::new();
                for (provider_name, result) in advisory_results {
                    match result {
                        Ok(advs) => advisories.extend(advs),
                        Err(e) => {
                            warn!(action = %action.raw, provider = %provider_name, error = %e, "failed to query advisories");
                        }
                    }
                }
                advisories.retain(|adv| {
                    if seen_ids.contains(&adv.id) {
                        return false;
                    }
                    if adv.aliases.iter().any(|a| seen_ids.contains(a)) {
                        return false;
                    }
                    seen_ids.insert(adv.id.clone());
                    seen_ids.extend(adv.aliases.iter().cloned());
                    true
                });

                output::ActionEntry {
                    action,
                    resolved_sha,
                    advisories,
                }
            }
        })
        .collect();

    let entries: Vec<output::ActionEntry> = join_all(futures).await;

    let formatter = output::formatter(args.json);
    formatter
        .write_results(&entries, &mut std::io::stdout().lock())
        .expect("failed to write output");

    Ok(())
}
