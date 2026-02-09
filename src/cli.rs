use std::path::PathBuf;

use clap::Parser;

/// Audit GitHub Actions workflows for third-party action usage
#[derive(Parser)]
#[command(name = "ghss", version)]
pub struct Cli {
    /// Path to a GitHub Actions workflow YAML file
    #[arg(short, long)]
    pub file: PathBuf,
}
