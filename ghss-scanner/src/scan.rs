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

type RepoOutcome = Result<(String, Vec<AuditNode>), (String, anyhow::Error)>;

/// Result of a scan cycle, including findings and error tracking.
pub struct ScanCycleResult {
    pub results: Vec<(String, Vec<AuditNode>)>,
    pub failures: Vec<(String, anyhow::Error)>,
}

/// Run a single scan cycle over the configured repos using real GitHub API
/// calls and the `ghss` library pipeline.
pub async fn run_scan_cycle(
    repos: &[RepoEntry],
    cycle: u64,
    client: &GitHubClient,
    pipeline_config: &PipelineSection,
    max_repo_concurrency: usize,
) -> ScanCycleResult {
    tracing::info!(
        cycle,
        repos = repos.len(),
        max_repo_concurrency,
        "Starting scan cycle"
    );

    let Ok(pipeline) = build_pipeline(client, pipeline_config).inspect_err(|e| {
        tracing::error!(error = %e, "Failed to build pipeline");
    }) else {
        return ScanCycleResult {
            results: vec![],
            failures: vec![(
                "pipeline".to_string(),
                anyhow::anyhow!("Failed to build pipeline"),
            )],
        };
    };
    let pipeline = Arc::new(pipeline);

    let depth = DepthLimit::from_str(&pipeline_config.depth)
        .unwrap_or(DepthLimit::Bounded(0))
        .to_max_depth();
    let concurrency = pipeline.max_concurrency();

    let outcomes: Vec<RepoOutcome> =
        futures::stream::iter(repos.iter().map(|repo| {
            let pipeline = pipeline.clone();
            let client = client.clone();
            async move { scan_repo_task(&client, repo, &pipeline, depth, concurrency, cycle).await }
        }))
        .buffer_unordered(max_repo_concurrency)
        .collect()
        .await;

    let mut results = Vec::new();
    let mut failures = Vec::new();
    for outcome in outcomes {
        match outcome {
            Ok(success) => results.push(success),
            Err(failure) => failures.push(failure),
        }
    }

    let repos_succeeded = results.len();
    let total_errors = failures.len();
    let total_findings: usize = results.iter().map(|(_, nodes)| nodes.len()).sum();
    let total_advisories: usize = results
        .iter()
        .flat_map(|(_, nodes)| nodes.iter())
        .map(|node| node.entry.advisories.len())
        .sum();

    // DEBUG: per-repo detail
    for (repo_id, nodes) in &results {
        for node in nodes {
            let sha_display = node
                .entry
                .resolved_sha
                .as_deref()
                .map_or("none", |s| &s[..s.len().min(12)]);
            let advisory_ids: Vec<&str> = node
                .entry
                .advisories
                .iter()
                .map(|a| a.id.as_str())
                .collect();
            tracing::debug!(
                repo = %repo_id,
                action = %node.entry.action,
                resolved_sha = %sha_display,
                advisories = ?advisory_ids,
                "Scan finding detail"
            );
        }
    }

    // INFO: cycle summary
    tracing::info!(
        cycle,
        repos_attempted = repos.len(),
        repos_succeeded,
        total_findings,
        total_advisories,
        errors = total_errors,
        "Scan cycle summary"
    );

    ScanCycleResult { results, failures }
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
        .filter(|name| {
            std::path::Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
        })
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

/// Run the scan pipeline for a single repo, returning Ok on success or Err with the repo ID and error.
async fn scan_repo_task(
    client: &GitHubClient,
    repo: &RepoEntry,
    pipeline: &ghss::pipeline::Pipeline,
    depth: Option<usize>,
    concurrency: usize,
    cycle: u64,
) -> Result<(String, Vec<AuditNode>), (String, anyhow::Error)> {
    let repo_id = format!("{}/{}", repo.owner, repo.name);
    tracing::info!(cycle, repo = %repo_id, "Scanning repo");
    match scan_repo(client, repo, &repo_id, pipeline, depth, concurrency).await {
        Ok(nodes) => {
            tracing::info!(cycle, repo = %repo_id, findings = nodes.len(), "Scan complete for repo");
            Ok((repo_id, nodes))
        }
        Err(e) => {
            tracing::warn!(cycle, repo = %repo_id, error = %e, "Failed to scan repo");
            Err((repo_id, e))
        }
    }
}

/// Scan a single repo: discover workflows, fetch YAML, parse actions,
/// deduplicate, and run the walker pipeline.
async fn scan_repo(
    client: &GitHubClient,
    repo: &RepoEntry,
    repo_id: &str,
    pipeline: &ghss::pipeline::Pipeline,
    depth: Option<usize>,
    concurrency: usize,
) -> anyhow::Result<Vec<AuditNode>> {
    let workflows = discover_workflows(client, repo).await?;

    if workflows.is_empty() {
        tracing::debug!(repo = %repo_id, "No workflow files found");
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
        repo = %repo_id,
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
