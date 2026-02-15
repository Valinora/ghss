mod action_ref;
mod advisory;
mod cli;
mod ghsa;
mod github;
mod workflow;

use std::collections::BTreeSet;
use std::process;

use clap::Parser;

use action_ref::ActionRef;
use advisory::{Advisory, AdvisoryProvider};
use cli::Cli;
use ghsa::GhsaProvider;
use github::GitHubClient;

fn is_third_party(uses: &str) -> bool {
    !uses.starts_with("./") && !uses.starts_with("docker://")
}

fn main() {
    let args = Cli::parse();

    if !args.file.exists() {
        eprintln!("error: file not found: {}", args.file.display());
        process::exit(1);
    }

    let result = workflow::parse_workflow(&args.file);
    let Ok(uses_refs) = result else {
        eprintln!("error: failed to parse workflow: {}", result.unwrap_err());
        process::exit(1);
    };

    let unique: BTreeSet<_> = uses_refs
        .into_iter()
        .filter(|u| is_third_party(u))
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
        let Some(token) = &args.github_token else {
            eprintln!("error: --github-token or GITHUB_TOKEN env var is required for --resolve/--advisories");
            process::exit(1);
        };
        Some(GitHubClient::new(token.clone()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn third_party_actions_are_detected() {
        assert!(is_third_party("actions/checkout@v4"));
        assert!(is_third_party("codecov/codecov-action@v3"));
    }

    #[test]
    fn local_actions_are_not_third_party() {
        assert!(!is_third_party("./local-action"));
        assert!(!is_third_party("./path/to/action"));
    }

    #[test]
    fn docker_actions_are_not_third_party() {
        assert!(!is_third_party("docker://node:18"));
        assert!(!is_third_party("docker://alpine:3.18"));
    }
}
