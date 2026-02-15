mod cli;

use std::collections::BTreeSet;
use std::process;

use clap::Parser;
use tracing::{error, warn};
use tracing_subscriber::{fmt, EnvFilter};

use cli::Cli;
use ghss::action_ref::ActionRef;
use ghss::advisory::{Advisory, AdvisoryProvider};
use ghss::ghsa::GhsaProvider;
use ghss::github::GitHubClient;
use ghss::output;

fn main() {
    let args = Cli::parse();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = args.verbosity.tracing_level_filter();
        EnvFilter::new(level.to_string())
    });

    if args.json {
        fmt()
            .json()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .without_time()
            .init();
    } else {
        fmt()
            .with_env_filter(env_filter)
            .with_writer(std::io::stderr)
            .with_target(false)
            .without_time()
            .init();
    }

    if !args.file.exists() {
        error!(path = %args.file.display(), "file not found");
        process::exit(1);
    }

    let result = ghss::workflow::parse_workflow(&args.file);
    let Ok(uses_refs) = result else {
        error!(error = %result.unwrap_err(), "failed to parse workflow");
        process::exit(1);
    };

    let unique: BTreeSet<_> = uses_refs
        .into_iter()
        .filter(|u| ghss::is_third_party(u))
        .collect();

    let action_refs: Vec<ActionRef> = unique
        .iter()
        .filter_map(|raw| match ActionRef::parse(raw) {
            Ok(ar) => Some(ar),
            Err(e) => {
                warn!(action = %raw, error = %e, "failed to parse action reference");
                None
            }
        })
        .collect();

    // Build GitHub client if needed for --resolve or --advisories
    let github_client = if args.resolve || args.advisories {
        Some(GitHubClient::new(args.github_token.clone()))
    } else {
        None
    };

    // Resolve refs to commit SHAs
    let resolved_shas: Vec<Option<String>> = if args.resolve {
        let client = github_client.as_ref().unwrap();
        action_refs
            .iter()
            .map(|action| match client.resolve_ref(action) {
                Ok(sha) => Some(sha),
                Err(e) => {
                    warn!(action = %action.raw, error = %e, "failed to resolve ref");
                    None
                }
            })
            .collect()
    } else {
        vec![None; action_refs.len()]
    };

    // Look up advisories
    let advisories_per_action: Vec<Vec<Advisory>> = if args.advisories {
        let client = github_client.as_ref().unwrap();
        let provider = GhsaProvider::new_borrowed(client);
        action_refs
            .iter()
            .map(|action| match provider.query(action) {
                Ok(advisories) => advisories,
                Err(e) => {
                    warn!(action = %action.raw, error = %e, "failed to query advisories");
                    Vec::new()
                }
            })
            .collect()
    } else {
        (0..action_refs.len()).map(|_| Vec::new()).collect()
    };

    // Output
    let entries: Vec<output::ActionEntry> = action_refs
        .iter()
        .enumerate()
        .map(|(i, action)| output::ActionEntry {
            action,
            resolved_sha: resolved_shas[i].as_deref(),
            advisories: if args.advisories {
                Some(&advisories_per_action[i])
            } else {
                None
            },
        })
        .collect();

    let formatter = output::formatter(args.json, args.advisories);
    formatter
        .write_results(&entries, &mut std::io::stdout().lock())
        .expect("failed to write output");
}
