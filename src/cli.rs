use std::path::PathBuf;

use clap::Parser;

/// Audit GitHub Actions workflows for third-party action usage
#[derive(Parser)]
#[command(name = "ghss", version)]
pub struct Cli {
    /// Path to a GitHub Actions workflow YAML file
    #[arg(short, long)]
    pub file: PathBuf,

    /// Resolve action refs to their commit SHAs via the GitHub API
    #[arg(long)]
    pub resolve: bool,

    /// Look up known security advisories for each action
    #[arg(long)]
    pub advisories: bool,

    /// GitHub personal access token (or set GITHUB_TOKEN env var)
    #[arg(long, env = "GITHUB_TOKEN")]
    pub github_token: Option<String>,
}
