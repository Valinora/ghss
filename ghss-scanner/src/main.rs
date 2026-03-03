mod config;

use std::path::PathBuf;

use clap::Parser;
use clap_verbosity_flag::{Verbosity, WarnLevel};
use tracing_subscriber::{fmt, EnvFilter};

/// Kubernetes-native GitHub Actions supply-chain scanner
#[derive(Parser)]
#[command(name = "ghss-scanner", version)]
struct Cli {
    /// Path to TOML configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Run one scan cycle and exit (instead of daemon mode)
    #[arg(long)]
    once: bool,

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

    fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    let config_path = config::resolve_config_path(args.config.as_deref())?;
    let config = config::ScannerConfig::from_file(&config_path)?;

    let token_status = if config.scanner.github_token.is_some() {
        "<set>"
    } else {
        "<unset>"
    };
    tracing::debug!(?config_path, github_token = token_status, "Config loaded");
    tracing::debug!(?config, "Parsed config");

    Ok(())
}
