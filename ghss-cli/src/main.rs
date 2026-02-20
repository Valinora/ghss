use std::path::PathBuf;

use anyhow::bail;
use clap::Parser;
use clap_verbosity_flag::{Verbosity, WarnLevel};
use tracing_subscriber::{fmt, EnvFilter};

use ghss::depth::DepthLimit;
use ghss::github::GitHubClient;
use ghss::output::{self, AuditNode};
use ghss::pipeline::PipelineBuilder;
use ghss::providers;
use ghss::stages::{
    AdvisoryStage, CompositeExpandStage, DependencyStage, RefResolveStage, ScanStage, WorkflowExpandStage,
};
use ghss::walker::Walker;

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

    /// Recursive expansion depth for composite actions and reusable workflows (0 = no expansion, "unlimited" = full traversal)
    #[arg(long, default_value = "0")]
    depth: DepthLimit,

    /// Select which root actions to audit (all, or 1-indexed ranges like 1-3,5)
    #[arg(long)]
    select: Option<ghss::ActionSelection>,

    /// Scan action ecosystems and npm dependencies for known vulnerabilities
    #[arg(long)]
    deps: bool,

    /// GitHub personal access token (or set `GITHUB_TOKEN` env var)
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

    let contents = std::fs::read_to_string(&args.file)?;
    let actions = ghss::parse_actions(&contents)?;
    let client = GitHubClient::new(args.github_token.clone());

    // Filter root actions by --select
    let actions = match &args.select {
        Some(sel) => actions
            .into_iter()
            .enumerate()
            .filter(|(i, _)| sel.includes(*i))
            .map(|(_, a)| a)
            .collect(),
        None => actions,
    };

    let has_token = client.has_token();
    let action_providers = providers::create_action_providers(&args.provider, &client)?;
    let package_providers = providers::create_package_providers(&args.provider)?;

    let mut builder = PipelineBuilder::default()
        .stage(CompositeExpandStage::new(client.clone()))
        .stage(WorkflowExpandStage::new(client.clone()))
        .stage(RefResolveStage::new(client.clone()))
        .stage(AdvisoryStage::new(action_providers));

    if args.deps {
        if has_token {
            builder = builder
                .stage(ScanStage::new(client.clone()))
                .stage(DependencyStage::new(client.clone(), package_providers));
        } else {
            tracing::warn!(
                "--deps requires a GitHub token; skipping ecosystem scan and dependency audit"
            );
        }
    }

    let pipeline = builder.build();
    let max_concurrency = pipeline.max_concurrency();
    let walker = Walker::new(pipeline, args.depth.to_max_depth(), max_concurrency);
    let nodes: Vec<AuditNode> = walker.walk(actions).await;

    let formatter = output::formatter(args.json);
    formatter
        .write_results(&nodes, &mut std::io::stdout().lock())
        .expect("failed to write output");

    Ok(())
}
