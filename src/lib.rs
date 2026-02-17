#[path = "lib/mod.rs"]
mod modules;

pub use modules::action_ref;
pub use modules::advisory;
pub use modules::ghsa;
pub use modules::github;
pub use modules::osv;
pub use modules::output;
pub use modules::scan;
pub use modules::workflow;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use anyhow::bail;
use futures::future::join_all;
use tokio::sync::Semaphore;
use tracing::warn;

use action_ref::ActionRef;
use advisory::{deduplicate_advisories, AdvisoryProvider};
use ghsa::GhsaProvider;
use github::GitHubClient;
use osv::OsvProvider;

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub scan: bool,
    pub resolve_refs: bool,
    pub max_concurrency: usize,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            scan: false,
            resolve_refs: true,
            max_concurrency: 10,
        }
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

fn create_providers(
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

pub struct Auditor {
    client: GitHubClient,
    providers: Vec<Arc<dyn AdvisoryProvider>>,
    options: AuditOptions,
}

impl Auditor {
    pub fn new(
        provider: &str,
        client: GitHubClient,
        options: AuditOptions,
    ) -> anyhow::Result<Self> {
        let providers = create_providers(provider, &client)?;
        Ok(Self {
            client,
            providers,
            options,
        })
    }

    pub async fn audit(&self, actions: Vec<ActionRef>) -> Vec<output::ActionEntry> {
        let sem = Arc::new(Semaphore::new(self.options.max_concurrency));
        let do_resolve = self.options.resolve_refs;

        let do_scan = if self.options.scan {
            if self.client.has_token() {
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
                let client = self.client.clone();
                let providers: Vec<Arc<dyn AdvisoryProvider>> = self.providers.clone();
                let sem = sem.clone();

                async move {
                    let _permit = sem.acquire().await.expect("semaphore closed");
                    Self::audit_one(action, client, providers, do_resolve, do_scan).await
                }
            })
            .collect();

        join_all(futures).await
    }

    async fn audit_one(
        action: ActionRef,
        client: GitHubClient,
        providers: Vec<Arc<dyn AdvisoryProvider>>,
        do_resolve: bool,
        do_scan: bool,
    ) -> output::ActionEntry {
        let resolve_fut = async {
            if !do_resolve {
                return None;
            }
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
                match scan::scan_action(&action, &client).await {
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

        let (resolved_sha, advisories, scan) = tokio::join!(resolve_fut, advisory_fut, scan_fut);

        output::ActionEntry {
            action,
            resolved_sha,
            advisories,
            scan,
        }
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

    #[test]
    fn audit_options_default_disables_scan() {
        let opts = AuditOptions::default();
        assert!(!opts.scan);
    }

    #[test]
    fn audit_options_default_enables_resolve_refs() {
        let opts = AuditOptions::default();
        assert!(opts.resolve_refs);
    }

    #[test]
    fn audit_options_default_concurrency_is_10() {
        let opts = AuditOptions::default();
        assert_eq!(opts.max_concurrency, 10);
    }

    #[test]
    fn auditor_new_ghsa() {
        let client = GitHubClient::new(None);
        let auditor = Auditor::new("ghsa", client, AuditOptions::default()).unwrap();
        assert_eq!(auditor.providers.len(), 1);
        assert_eq!(auditor.providers[0].name(), "GHSA");
    }

    #[test]
    fn auditor_new_osv() {
        let client = GitHubClient::new(None);
        let auditor = Auditor::new("osv", client, AuditOptions::default()).unwrap();
        assert_eq!(auditor.providers.len(), 1);
        assert_eq!(auditor.providers[0].name(), "OSV");
    }

    #[test]
    fn auditor_new_all() {
        let client = GitHubClient::new(None);
        let auditor = Auditor::new("all", client, AuditOptions::default()).unwrap();
        assert_eq!(auditor.providers.len(), 2);
    }

    #[test]
    fn auditor_new_unknown_errors() {
        let client = GitHubClient::new(None);
        let result = Auditor::new("invalid", client, AuditOptions::default());
        let err = result.err().expect("should be an error");
        assert!(err.to_string().contains("unknown provider"));
    }
}
