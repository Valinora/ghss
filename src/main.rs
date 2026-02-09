mod cli;
mod workflow;

use std::collections::BTreeSet;
use std::process;

use clap::Parser;

use cli::Cli;

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
    for uses in &unique {
        println!("{uses}");
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
