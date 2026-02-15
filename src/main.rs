mod cli;

use std::collections::BTreeSet;
use std::process;

use clap::Parser;

use cli::Cli;
use ghss::action_ref::ActionRef;
use ghss::advisory::{Advisory, AdvisoryProvider};
use ghss::ghsa::GhsaProvider;
use ghss::github::GitHubClient;

fn main() {
    let args = Cli::parse();

    if !args.file.exists() {
        eprintln!("error: file not found: {}", args.file.display());
        process::exit(1);
    }

    let result = ghss::workflow::parse_workflow(&args.file);
    let Ok(uses_refs) = result else {
        eprintln!("error: failed to parse workflow: {}", result.unwrap_err());
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
                eprintln!("warning: failed to parse action reference '{}': {}", raw, e);
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
                    eprintln!("warning: failed to resolve '{}': {}", action.raw, e);
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
                    eprintln!("warning: failed to query advisories for '{}': {}", action.raw, e);
                    Vec::new()
                }
            })
            .collect()
    } else {
        (0..action_refs.len()).map(|_| Vec::new()).collect()
    };

    // Output
    for (i, action) in action_refs.iter().enumerate() {
        println!("{}", action.raw);

        if let Some(sha) = &resolved_shas[i] {
            println!("  sha: {sha}");
        }

        if args.advisories {
            let advs = &advisories_per_action[i];
            if advs.is_empty() {
                println!("  advisories: none");
            } else {
                for adv in advs {
                    print!("  {} ({}): {}", adv.id, adv.severity, adv.summary);
                    println!();
                    println!("    {}", adv.url);
                    if let Some(range) = &adv.affected_range {
                        println!("    affected: {range}");
                    }
                }
            }
        }
    }
}
