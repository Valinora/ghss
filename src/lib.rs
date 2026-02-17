#[path = "lib/action_ref.rs"]
pub mod action_ref;
#[path = "lib/advisory.rs"]
pub mod advisory;
#[path = "lib/ghsa.rs"]
pub mod ghsa;
#[path = "lib/github.rs"]
pub mod github;
#[path = "lib/osv.rs"]
pub mod osv;
#[path = "lib/output.rs"]
pub mod output;
#[path = "lib/scan.rs"]
pub mod scan;
#[path = "lib/workflow.rs"]
pub mod workflow;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::bail;
use futures::future::join_all;
use tokio::sync::Semaphore;
use tracing::warn;

pub use scan::scan_action;

use action_ref::ActionRef;
use advisory::{deduplicate_advisories, AdvisoryProvider};
use ghsa::GhsaProvider;
use github::GitHubClient;
use osv::OsvProvider;
#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub scan: bool,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self { scan: false }
    }
}

fn is_third_party(uses: &str) -> bool {
    !uses.starts_with("./") && !uses.starts_with("docker://")
}

pub fn parse_actions(path: &Path) -> anyhow::Result<Vec<ActionRef>> {
    let uses_refs = workflow::parse_workflow(path)?;

    let unique: BTreeSet<ActionRef> = uses_refs
        .into_iter()
        .filter(|u| is_third_party(u))
        .filter_map(|raw| match raw.parse::<ActionRef>() {
            Ok(ar) => Some(ar),
            Err(e) => {
                warn!(action = %raw, error = %e, "failed to parse action reference");
                None
            }
        })
        .collect();

    Ok(unique.into_iter().collect())
}

/// Build advisory providers from a provider name string.
///
/// Valid values: `"ghsa"`, `"osv"`, `"all"`.
pub fn create_providers(
    provider: &str,
    github_client: &GitHubClient,
) -> anyhow::Result<Vec<Arc<dyn AdvisoryProvider>>> {
    match provider {
        "ghsa" => Ok(vec![Arc::new(GhsaProvider::new(github_client.clone()))]),
        "osv" => Ok(vec![Arc::new(OsvProvider::new())]),
        "all" => Ok(vec![
            Arc::new(GhsaProvider::new(github_client.clone())),
            Arc::new(OsvProvider::new()),
        ]),
        other => bail!("unknown provider: {other} (valid: ghsa, osv, all)"),
    }
}

/// Run the full audit pipeline: resolve refs, query advisories, optionally scan.
pub async fn audit_actions(
    actions: Vec<ActionRef>,
    providers: &[Arc<dyn AdvisoryProvider>],
    github_client: &GitHubClient,
    options: &AuditOptions,
) -> Vec<output::ActionEntry> {
    let sem = Arc::new(Semaphore::new(10));

    let do_scan = if options.scan {
        if github_client.has_token() {
            true
        } else {
            warn!("scan enabled but no GitHub token provided; skipping scan");
            false
        }
    } else {
        false
    };

    let futures: Vec<_> = actions
        .into_iter()
        .map(|action| {
            let client = github_client.clone();
            let providers: Vec<Arc<dyn AdvisoryProvider>> = providers.to_vec();
            let sem = sem.clone();

            async move {
                let _permit = sem.acquire().await.expect("semaphore closed");

                let resolve_fut = async {
                    match client.resolve_ref(&action).await {
                        Ok(sha) => Some(sha),
                        Err(e) => {
                            warn!(action = %action.raw, error = %e, "failed to resolve ref");
                            None
                        }
                    }
                };

                let advisory_fut = async {
                    let results = join_all(providers.iter().map(|p| {
                        let p = p.clone();
                        let action = action.clone();
                        async move { (p.name().to_string(), p.query(&action).await) }
                    }))
                    .await;

                    let mut advisories = Vec::new();
                    for (provider_name, result) in results {
                        match result {
                            Ok(advs) => advisories.extend(advs),
                            Err(e) => {
                                warn!(action = %action.raw, provider = %provider_name, error = %e, "failed to query advisories");
                            }
                        }
                    }
                    deduplicate_advisories(advisories)
                };

                let scan_fut = async {
                    if do_scan {
                        match scan_action(&action, &client).await {
                            Ok(s) => Some(s),
                            Err(e) => {
                                warn!(action = %action.raw, error = %e, "failed to scan action");
                                None
                            }
                        }
                    } else {
                        None
                    }
                };

                let (resolved_sha, advisories, scan) =
                    tokio::join!(resolve_fut, advisory_fut, scan_fut);

                output::ActionEntry {
                    action,
                    resolved_sha,
                    advisories,
                    scan,
                }
            }
        })
        .collect();

    join_all(futures).await
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

    #[test]
    fn create_providers_ghsa() {
        let client = GitHubClient::new(None);
        let providers = create_providers("ghsa", &client).unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name(), "GHSA");
    }

    #[test]
    fn create_providers_osv() {
        let client = GitHubClient::new(None);
        let providers = create_providers("osv", &client).unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name(), "OSV");
    }

    #[test]
    fn create_providers_all() {
        let client = GitHubClient::new(None);
        let providers = create_providers("all", &client).unwrap();
        assert_eq!(providers.len(), 2);
    }

    #[test]
    fn create_providers_unknown_errors() {
        let client = GitHubClient::new(None);
        let result = create_providers("invalid", &client);
        let err = result.err().expect("should be an error");
        assert!(err.to_string().contains("unknown provider"));
    }

    #[test]
    fn audit_options_default_disables_scan() {
        let opts = AuditOptions::default();
        assert!(!opts.scan);
    }
}
