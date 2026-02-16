use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::bail;
use clap::Parser;
use clap_verbosity_flag::{Verbosity, WarnLevel};
use tracing::warn;
use tracing_subscriber::{fmt, EnvFilter};

use ghss::action_ref::ActionRef;
use ghss::advisory::{Advisory, AdvisoryProvider};
use ghss::ghsa::GhsaProvider;
use ghss::github::GitHubClient;
use ghss::output;

/// Audit GitHub Actions workflows for third-party action usage
#[derive(Parser)]
#[command(name = "ghss", version)]
struct Cli {
    /// Path to a GitHub Actions workflow YAML file
    #[arg(short, long)]
    file: PathBuf,

    /// Resolve action refs to their commit SHAs via the GitHub API
    #[arg(long)]
    resolve: bool,

    /// Look up known security advisories for each action
    #[arg(long)]
    advisories: bool,

    /// Output results and logs in JSON format
    #[arg(long)]
    json: bool,

    /// GitHub personal access token (or set GITHUB_TOKEN env var)
    #[arg(long, env = "GITHUB_TOKEN")]
    github_token: Option<String>,

    #[command(flatten)]
    verbosity: Verbosity<WarnLevel>,
}

struct ActionResult {
    action: ActionRef,
    resolved_sha: Option<String>,
    advisories: Option<Vec<Advisory>>,
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

    if !args.file.exists() {
        bail!("file not found: {}", args.file.display());
    }

    let uses_refs = ghss::workflow::parse_workflow(&args.file)?;

    let unique: BTreeSet<_> = uses_refs
        .into_iter()
        .filter(|u| ghss::is_third_party(u))
        .collect();

    // Build GitHub client if needed for --resolve or --advisories
    let github_client = if args.resolve || args.advisories {
        Some(GitHubClient::new(args.github_token.clone()))
    } else {
        None
    };

    let advisory_provider: Option<GhsaProvider> = if args.advisories {
        Some(GhsaProvider::new_borrowed(github_client.as_ref().unwrap()))
    } else {
        None
    };

    let results: Vec<ActionResult> = unique
        .iter()
        .filter_map(|raw| match raw.parse::<ActionRef>() {
            Ok(ar) => Some(ar),
            Err(e) => {
                warn!(action = %raw, error = %e, "failed to parse action reference");
                None
            }
        })
        .map(|action| {
            let resolved_sha = if args.resolve {
                let client = github_client.as_ref().unwrap();
                match client.resolve_ref(&action) {
                    Ok(sha) => Some(sha),
                    Err(e) => {
                        warn!(action = %action.raw, error = %e, "failed to resolve ref");
                        None
                    }
                }
            } else {
                None
            };

            let advisories = if let Some(provider) = &advisory_provider {
                match provider.query(&action) {
                    Ok(advs) => Some(advs),
                    Err(e) => {
                        warn!(action = %action.raw, error = %e, "failed to query advisories");
                        Some(Vec::new())
                    }
                }
            } else {
                None
            };

            ActionResult {
                action,
                resolved_sha,
                advisories,
            }
        })
        .collect();

    // Output
    let entries: Vec<output::ActionEntry> = results
        .iter()
        .map(|r| output::ActionEntry {
            action: &r.action,
            resolved_sha: r.resolved_sha.as_deref(),
            advisories: r.advisories.as_deref(),
        })
        .collect();

    let formatter = output::formatter(args.json, args.advisories);
    formatter
        .write_results(&entries, &mut std::io::stdout().lock())
        .expect("failed to write output");

    Ok(())
}
