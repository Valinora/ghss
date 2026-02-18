use std::path::PathBuf;

use anyhow::bail;
use clap::Parser;
use clap_verbosity_flag::{Verbosity, WarnLevel};
use tracing_subscriber::{fmt, EnvFilter};

use ghss::context::AuditContext;
use ghss::github::GitHubClient;
use ghss::output::{self, ActionEntry, AuditNode};
use ghss::pipeline::PipelineBuilder;
use ghss::providers;
use ghss::stages::{AdvisoryStage, DependencyStage, RefResolveStage, ScanStage};

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

    /// Scan action repositories for languages and ecosystems (all, or 1-indexed ranges like 1-3,5)
    #[arg(long)]
    scan: Option<ghss::ScanSelection>,

    /// Scan npm dependencies for known vulnerabilities (auto-enables --scan all)
    #[arg(long)]
    deps: bool,

    /// GitHub personal access token (or set GITHUB_TOKEN env var)
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

    let actions = ghss::parse_actions(&args.file)?;
    let client = GitHubClient::new(args.github_token.clone());
    let scan = match (&args.scan, args.deps) {
        (Some(sel), _) => sel.clone(),
        (None, true) => ghss::ScanSelection::All,
        (None, false) => ghss::ScanSelection::None,
    };
    let has_any_scan = !matches!(scan, ghss::ScanSelection::None);
    let has_token = client.has_token();
    if has_any_scan && !has_token {
        tracing::warn!("scan enabled but no GitHub token provided; skipping scan");
    }

    let action_providers = providers::create_action_providers(&args.provider, &client)?;
    let package_providers = providers::create_package_providers(&args.provider)?;

    let mut builder = PipelineBuilder::default()
        .stage(RefResolveStage::new(client.clone()))
        .stage(AdvisoryStage::new(action_providers));

    if has_any_scan && has_token {
        builder = builder.stage(ScanStage::new(client.clone(), scan));
    }
    if args.deps {
        builder = builder.stage(DependencyStage::new(client.clone(), package_providers));
    }

    let pipeline = builder.build();

    let mut entries = Vec::with_capacity(actions.len());
    for (idx, action) in actions.into_iter().enumerate() {
        let mut ctx = AuditContext {
            action,
            depth: 0,
            parent: None,
            children: vec![],
            index: Some(idx),
            resolved_ref: None,
            advisories: vec![],
            scan: None,
            dependencies: vec![],
            errors: vec![],
        };
        pipeline.run_one(&mut ctx).await;
        entries.push(ActionEntry::from(ctx));
    }

    let nodes: Vec<AuditNode> = entries
        .into_iter()
        .map(|e| AuditNode {
            entry: e,
            children: vec![],
        })
        .collect();

    let formatter = output::formatter(args.json);
    formatter
        .write_results(&nodes, &mut std::io::stdout().lock())
        .expect("failed to write output");

    Ok(())
}
