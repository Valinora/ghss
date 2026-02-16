use std::path::PathBuf;

use anyhow::bail;
use clap::Parser;
use clap_verbosity_flag::{Verbosity, WarnLevel};
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

fn main() -> anyhow::Result<()> {
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

    run(&args)
}

fn run(args: &Cli) -> anyhow::Result<()> {
    if !args.file.exists() {
        bail!("file not found: {}", args.file.display());
    }

    let actions = ghss::parse_actions(&args.file)?;

    let github_client = GitHubClient::new(args.github_token.clone());

    let providers: Vec<Box<dyn AdvisoryProvider + '_>> = match args.provider.as_str() {
        "ghsa" => vec![Box::new(GhsaProvider::new_borrowed(&github_client))],
        "osv" => vec![Box::new(OsvProvider::new())],
        "all" => vec![
            Box::new(GhsaProvider::new_borrowed(&github_client)),
            Box::new(OsvProvider::new()),
        ],
        other => bail!("unknown provider: {other} (valid: ghsa, osv, all)"),
    };

    let entries: Vec<output::ActionEntry> = actions
        .into_iter()
        .map(|action| {
            let resolved_sha = match github_client.resolve_ref(&action) {
                Ok(sha) => Some(sha),
                Err(e) => {
                    warn!(action = %action.raw, error = %e, "failed to resolve ref");
                    None
                }
            };

            let mut advisories = Vec::new();
            let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
            for provider in &providers {
                match provider.query(&action) {
                    Ok(advs) => advisories.extend(advs),
                    Err(e) => {
                        warn!(action = %action.raw, provider = provider.name(), error = %e, "failed to query advisories");
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
        })
        .collect();

    let formatter = output::formatter(args.json);
    formatter
        .write_results(&entries, &mut std::io::stdout().lock())
        .expect("failed to write output");

    Ok(())
}
