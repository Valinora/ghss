use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
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
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

use crate::config::{PipelineSection, RepoEntry};

/// Path-segment percent-encoding set: preserves `/` (so multi-segment
/// branches like `release/1.0` stay readable) but encodes characters
/// that would break URL parsing (`?`, `#`, `%`, space, control chars).
const REF_PATH: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'?')
    .add(b'#')
    .add(b'%')
    .add(b'+');

/// Per-repo scan output. Carries enough context for both finding
/// persistence and SARIF upload.
///
/// The audit set is stored once (`nodes`), with `attribution` mapping
/// each workflow file to the action refs it contains. Downstream
/// consumers iterate `nodes` for repo-level work and walk
/// `attribution + nodes` together for per-workflow SARIF emission.
pub struct RepoScanOutput {
    pub repo_id: String,
    /// Deduplicated audit nodes from one Walker run — one entry per
    /// unique top-level `ActionRef` across all workflows in this repo.
    pub nodes: Vec<AuditNode>,
    /// Workflow path → action refs that workflow contained at parse
    /// time. Action refs are looked up in `nodes` by the SARIF builder.
    pub attribution: Vec<(PathBuf, Vec<ActionRef>)>,
    /// Commit SHA of the default branch HEAD at the moment scanning started.
    pub commit_sha: String,
    /// Full ref name, e.g. `refs/heads/main`.
    pub ref_name: String,
}

type RepoOutcome = Result<RepoScanOutput, (String, anyhow::Error)>;

/// Result of a scan cycle, including findings and error tracking.
pub struct ScanCycleResult {
    pub results: Vec<RepoScanOutput>,
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

    let outcomes: Vec<RepoOutcome> = futures::stream::iter(repos.iter().map(|repo| {
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
    let total_findings: usize = results.iter().map(|r| r.nodes.len()).sum();
    let total_advisories: usize = results
        .iter()
        .flat_map(|r| r.nodes.iter())
        .map(|node| node.entry.advisories.len())
        .sum();

    // DEBUG: per-repo detail
    for output in &results {
        for node in &output.nodes {
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
                repo = %output.repo_id,
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

/// Discover workflow files for a repo at a pinned ref. If
/// `repo.workflows` is set, use that list directly. Otherwise, query
/// the GitHub Contents API for `.github/workflows/` at `git_ref` so the
/// listing matches the same commit `fetch_workflow_yaml` will read
/// from — preventing TOCTOU between the listing and the fetches.
async fn discover_workflows(
    client: &GitHubClient,
    repo: &RepoEntry,
    git_ref: &str,
) -> anyhow::Result<Vec<String>> {
    if let Some(ref workflows) = repo.workflows {
        return Ok(workflows.clone());
    }

    let url = format!(
        "{}/repos/{}/{}/contents/.github/workflows?ref={}",
        client.api_base_url(),
        repo.owner,
        repo.name,
        utf8_percent_encode(git_ref, REF_PATH),
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
            std::path::Path::new(name).extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml")
            })
        })
        .collect();

    Ok(workflows)
}

/// Fetch a single workflow YAML file from a repo, pinned to the given ref.
async fn fetch_workflow_yaml(
    client: &GitHubClient,
    owner: &str,
    repo: &str,
    git_ref: &str,
    workflow: &str,
) -> anyhow::Result<String> {
    client
        .get_raw_content(
            owner,
            repo,
            git_ref,
            &format!(".github/workflows/{workflow}"),
        )
        .await
        .context(format!("failed to fetch workflow {workflow}"))
}

/// Resolve the default branch and HEAD commit SHA for a repo. Pins all
/// subsequent reads in this scan cycle to a single commit so a push
/// mid-scan can't split findings across two commits.
async fn resolve_repo_head(
    client: &GitHubClient,
    owner: &str,
    name: &str,
) -> anyhow::Result<(String, String)> {
    let repo_url = format!("{}/repos/{}/{}", client.api_base_url(), owner, name);
    let repo_meta = client
        .api_get(&repo_url)
        .await
        .context("failed to fetch repo metadata for default branch")?;

    let default_branch = repo_meta
        .get("default_branch")
        .and_then(|v| v.as_str())
        .context("repo metadata missing default_branch")?
        .to_string();

    let ref_url = format!(
        "{}/repos/{}/{}/git/ref/heads/{}",
        client.api_base_url(),
        owner,
        name,
        utf8_percent_encode(&default_branch, REF_PATH)
    );
    let ref_resp = client
        .api_get(&ref_url)
        .await
        .with_context(|| format!("failed to resolve HEAD of {default_branch}"))?;

    let sha = ref_resp
        .get("object")
        .and_then(|o| o.get("sha"))
        .and_then(|v| v.as_str())
        .context("ref response missing object.sha")?
        .to_string();

    Ok((sha, format!("refs/heads/{default_branch}")))
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
) -> RepoOutcome {
    let repo_id = format!("{}/{}", repo.owner, repo.name);
    tracing::info!(cycle, repo = %repo_id, "Scanning repo");
    match scan_repo(client, repo, &repo_id, pipeline, depth, concurrency).await {
        Ok(output) => {
            tracing::info!(
                cycle,
                repo = %repo_id,
                findings = output.nodes.len(),
                workflows = output.attribution.len(),
                commit_sha = %output.commit_sha,
                "Scan complete for repo"
            );
            Ok(output)
        }
        Err(e) => {
            tracing::warn!(cycle, repo = %repo_id, error = %e, "Failed to scan repo");
            Err((repo_id, e))
        }
    }
}

/// Scan a single repo: pin commit SHA, discover and parse workflows
/// (retaining per-workflow attribution), run the deduplicated audit
/// pipeline once, and emit the per-workflow attribution map alongside
/// the dedup'd `nodes` set.
async fn scan_repo(
    client: &GitHubClient,
    repo: &RepoEntry,
    repo_id: &str,
    pipeline: &ghss::pipeline::Pipeline,
    depth: Option<usize>,
    concurrency: usize,
) -> anyhow::Result<RepoScanOutput> {
    let (commit_sha, ref_name) = resolve_repo_head(client, &repo.owner, &repo.name).await?;

    let workflows = discover_workflows(client, repo, &commit_sha).await?;

    if workflows.is_empty() {
        tracing::debug!(repo = %repo_id, "No workflow files found");
        return Ok(RepoScanOutput {
            repo_id: repo_id.to_string(),
            nodes: vec![],
            attribution: vec![],
            commit_sha,
            ref_name,
        });
    }

    // Per-workflow attribution: each workflow file maps to its set of
    // action refs (deduplicated within that workflow).
    let mut per_workflow: BTreeMap<PathBuf, BTreeSet<ActionRef>> = BTreeMap::new();

    for workflow_name in &workflows {
        match fetch_workflow_yaml(client, &repo.owner, &repo.name, &commit_sha, workflow_name)
            .await
            .and_then(|yaml| ghss::parse_actions(&yaml))
        {
            Ok(actions) => {
                tracing::debug!(workflow = %workflow_name, actions = actions.len(), "Parsed workflow");
                let path = PathBuf::from(format!(".github/workflows/{workflow_name}"));
                per_workflow.entry(path).or_default().extend(actions);
            }
            Err(e) => {
                tracing::warn!(workflow = %workflow_name, error = %e, "Failed to process workflow");
            }
        }
    }

    // Union across workflows for the pipeline run — audit each unique
    // action only once per cycle, regardless of workflow count.
    let unique: BTreeSet<ActionRef> = per_workflow.values().flatten().cloned().collect();

    let attribution = build_attribution(&per_workflow);

    if unique.is_empty() {
        return Ok(RepoScanOutput {
            repo_id: repo_id.to_string(),
            nodes: vec![],
            attribution,
            commit_sha,
            ref_name,
        });
    }

    tracing::debug!(
        repo = %repo_id,
        actions = unique.len(),
        "Running pipeline"
    );

    let walker = Walker::new(pipeline.clone(), depth, concurrency);
    let nodes = walker.walk(unique.into_iter().collect()).await;

    Ok(RepoScanOutput {
        repo_id: repo_id.to_string(),
        nodes,
        attribution,
        commit_sha,
        ref_name,
    })
}

/// Flatten the parse-time per-workflow map into the
/// `Vec<(PathBuf, Vec<ActionRef>)>` shape consumed by the SARIF builder
/// — owned strings only, no node references, no clones of audit trees.
fn build_attribution(
    per_workflow: &BTreeMap<PathBuf, BTreeSet<ActionRef>>,
) -> Vec<(PathBuf, Vec<ActionRef>)> {
    per_workflow
        .iter()
        .map(|(path, action_set)| (path.clone(), action_set.iter().cloned().collect()))
        .collect()
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

    #[test]
    fn ref_path_encodes_unsafe_chars_but_preserves_slash() {
        // Multi-segment branches like `release/1.0` stay readable.
        let encoded = utf8_percent_encode("release/1.0", REF_PATH).to_string();
        assert_eq!(encoded, "release/1.0");

        // `?` and `#` would break URL parsing without encoding.
        let encoded = utf8_percent_encode("weird?branch", REF_PATH).to_string();
        assert_eq!(encoded, "weird%3Fbranch");

        let encoded = utf8_percent_encode("foo#bar", REF_PATH).to_string();
        assert_eq!(encoded, "foo%23bar");

        let encoded = utf8_percent_encode("foo bar", REF_PATH).to_string();
        assert_eq!(encoded, "foo%20bar");

        let encoded = utf8_percent_encode("a%b", REF_PATH).to_string();
        assert_eq!(encoded, "a%25b");
    }

    #[tokio::test]
    async fn discover_workflows_pins_contents_listing_to_git_ref() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Reject any listing request that doesn't carry our pinned ref.
        Mock::given(method("GET"))
            .and(path("/repos/o/r/contents/.github/workflows"))
            .and(query_param("ref", "deadbeef"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "ci.yml", "type": "file"}
            ])))
            .mount(&server)
            .await;

        // SAFETY: tests run sequentially within the test binary.
        unsafe {
            std::env::set_var("GHSS_API_BASE_URL", server.uri());
        }
        let client = GitHubClient::new(None);
        let repo = RepoEntry {
            owner: "o".to_string(),
            name: "r".to_string(),
            workflows: None,
            upload_sarif: None,
        };

        let workflows = discover_workflows(&client, &repo, "deadbeef")
            .await
            .expect("discover should succeed when pinned ref matches");
        assert_eq!(workflows, vec!["ci.yml".to_string()]);

        unsafe {
            std::env::remove_var("GHSS_API_BASE_URL");
        }
    }
}
