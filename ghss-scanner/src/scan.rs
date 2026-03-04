use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use futures::StreamExt;
use ghss::action_ref::ActionRef;
use ghss::depth::DepthLimit;
use ghss::github::GitHubClient;
use ghss::output::AuditNode;
use ghss::pipeline::PipelineBuilder;
use ghss::providers;
use ghss::stages::{
    AdvisoryStage, CompositeExpandStage, DependencyStage, RefResolveStage, ScanStage,
    WorkflowExpandStage,
};
use ghss::walker::Walker;

use crate::config::{PipelineSection, RepoEntry};

/// Run a single scan cycle over the configured repos using real GitHub API
/// calls and the `ghss` library pipeline.
pub async fn run_scan_cycle(
    repos: &[RepoEntry],
    cycle: u64,
    client: &GitHubClient,
    pipeline_config: &PipelineSection,
    max_repo_concurrency: usize,
) -> Vec<(String, Vec<AuditNode>)> {
    tracing::info!(cycle, repos = repos.len(), max_repo_concurrency, "Starting scan cycle");

    let Ok(pipeline) = build_pipeline(client, pipeline_config).inspect_err(|e| {
        tracing::error!(error = %e, "Failed to build pipeline");
    }) else {
        return vec![];
    };
    let pipeline = Arc::new(pipeline);

    let depth = DepthLimit::from_str(&pipeline_config.depth)
        .unwrap_or(DepthLimit::Bounded(0))
        .to_max_depth();
    let concurrency = pipeline.max_concurrency();

    let results: Vec<(String, Vec<AuditNode>)> = futures::stream::iter(repos.iter().map(|repo| {
        let pipeline = pipeline.clone();
        let client = client.clone();
        let repo_id = format!("{}/{}", repo.owner, repo.name);
        async move {
            tracing::info!(cycle, repo = %repo_id, "Scanning repo");
            let nodes = scan_repo(&client, repo, &pipeline, depth, concurrency)
                .await
                .inspect(|nodes| {
                    tracing::info!(cycle, repo = %repo_id, findings = nodes.len(), "Scan complete for repo");
                })
                .inspect_err(|e| {
                    tracing::error!(cycle, repo = %repo_id, error = %e, "Failed to scan repo");
                })
                .unwrap_or_default();
            (repo_id, nodes)
        }
    }))
    .buffer_unordered(max_repo_concurrency)
    .collect()
    .await;

    let total_findings: usize = results.iter().map(|(_, nodes)| nodes.len()).sum();
    tracing::info!(cycle, total_findings, "Scan cycle complete");

    results
}

/// Discover workflow files for a repo. If `repo.workflows` is set, use that
/// list directly. Otherwise, query the GitHub Contents API for `.github/workflows/`.
async fn discover_workflows(
    client: &GitHubClient,
    repo: &RepoEntry,
) -> anyhow::Result<Vec<String>> {
    if let Some(ref workflows) = repo.workflows {
        return Ok(workflows.clone());
    }

    let url = format!(
        "{}/repos/{}/{}/contents/.github/workflows",
        client.api_base_url(),
        repo.owner,
        repo.name
    );

    let json = client
        .api_get(&url)
        .await
        .context("failed to list workflow files")?;

    let entries = json
        .as_array()
        .context("expected array from Contents API")?;

    let workflows: Vec<String> = entries
        .iter()
        .filter_map(|entry| entry.get("name")?.as_str().map(String::from))
        .filter(|name| name.ends_with(".yml") || name.ends_with(".yaml"))
        .collect();

    Ok(workflows)
}

/// Fetch a single workflow YAML file from a repo via raw content.
async fn fetch_workflow_yaml(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    workflow: &str,
) -> anyhow::Result<String> {
    client
        .get_raw_content(
            owner,
            repo,
            "HEAD",
            &format!(".github/workflows/{workflow}"),
        )
        .await
        .context(format!("failed to fetch workflow {workflow}"))
}

/// Build the ghss pipeline from config, following the CLI assembly pattern.
fn build_pipeline(
    client: &GitHubClient,
    pipeline_config: &PipelineSection,
) -> anyhow::Result<ghss::pipeline::Pipeline> {
    let action_providers = providers::create_action_providers(&pipeline_config.provider, client)?;
    let package_providers = providers::create_package_providers(&pipeline_config.provider)?;

    let mut builder = PipelineBuilder::default()
        .stage(CompositeExpandStage::new(client.clone()))
        .stage(WorkflowExpandStage::new(client.clone()))
        .stage(RefResolveStage::new(client.clone()))
        .stage(AdvisoryStage::new(action_providers));

    if pipeline_config.deps {
        if client.has_token() {
            builder = builder
                .stage(ScanStage::new(client.clone()))
                .stage(DependencyStage::new(client.clone(), package_providers));
        } else {
            tracing::warn!(
                "deps=true requires a GitHub token; skipping ecosystem scan and dependency audit"
            );
        }
    }

    Ok(builder
        .max_concurrency(pipeline_config.concurrency.unwrap_or(10))
        .build())
}

/// Scan a single repo: discover workflows, fetch YAML, parse actions,
/// deduplicate, and run the walker pipeline.
async fn scan_repo(
    client: &GitHubClient,
    repo: &RepoEntry,
    pipeline: &ghss::pipeline::Pipeline,
    depth: Option<usize>,
    concurrency: usize,
) -> anyhow::Result<Vec<AuditNode>> {
    let workflows = discover_workflows(client, repo).await?;

    if workflows.is_empty() {
        tracing::debug!(
            repo = %format!("{}/{}", repo.owner, repo.name),
            "No workflow files found"
        );
        return Ok(vec![]);
    }

    let mut all_actions: BTreeSet<ActionRef> = BTreeSet::new();

    for workflow_name in &workflows {
        match fetch_workflow_yaml(client, &repo.owner, &repo.name, workflow_name)
            .await
            .and_then(|yaml| ghss::parse_actions(&yaml))
        {
            Ok(actions) => {
                tracing::debug!(workflow = %workflow_name, actions = actions.len(), "Parsed workflow");
                all_actions.extend(actions);
            }
            Err(e) => {
                tracing::warn!(workflow = %workflow_name, error = %e, "Failed to process workflow");
            }
        }
    }

    let actions: Vec<ActionRef> = all_actions.into_iter().collect();

    if actions.is_empty() {
        return Ok(vec![]);
    }

    tracing::debug!(
        repo = %format!("{}/{}", repo.owner, repo.name),
        actions = actions.len(),
        "Running pipeline"
    );

    let walker = Walker::new(pipeline.clone(), depth, concurrency);
    let nodes = walker.walk(actions).await;

    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_pipeline_default_config() {
        let client = GitHubClient::new(None);
        let config = PipelineSection {
            depth: "0".to_string(),
            provider: "all".to_string(),
            deps: false,
            concurrency: None,
        };
        let pipeline = build_pipeline(&client, &config).unwrap();
        // 4 base stages: composite, workflow_expand, resolve, advisory
        assert_eq!(pipeline.stage_count(), 4);
    }

    #[test]
    fn build_pipeline_with_deps_no_token() {
        let client = GitHubClient::new(None);
        let config = PipelineSection {
            depth: "0".to_string(),
            provider: "all".to_string(),
            deps: true,
            concurrency: None,
        };
        let pipeline = build_pipeline(&client, &config).unwrap();
        // deps=true but no token: still 4 stages
        assert_eq!(pipeline.stage_count(), 4);
    }

    #[test]
    fn build_pipeline_with_deps_and_token() {
        let client = GitHubClient::new(Some("test-token".to_string()));
        let config = PipelineSection {
            depth: "0".to_string(),
            provider: "all".to_string(),
            deps: true,
            concurrency: None,
        };
        let pipeline = build_pipeline(&client, &config).unwrap();
        // 4 base + scan + dependency = 6
        assert_eq!(pipeline.stage_count(), 6);
    }
}
