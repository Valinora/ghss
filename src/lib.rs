#[path = "lib/mod.rs"]
mod modules;

pub use modules::action_ref;
pub use modules::advisory;
pub use modules::context;
pub use modules::deps;
pub use modules::github;
pub use modules::output;
pub use modules::pipeline;
pub use modules::providers;
pub use modules::scan;
pub use modules::stage;
pub use modules::stages;
pub use modules::workflow;

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::bail;
use tracing::warn;

use action_ref::ActionRef;
use github::GitHubClient;
use pipeline::Pipeline;
use providers::ghsa::GhsaProvider;
use providers::osv::{OsvActionProvider, OsvClient, OsvPackageProvider};
use providers::{ActionAdvisoryProvider, PackageAdvisoryProvider};
use stages::{AdvisoryStage, DependencyStage, RefResolveStage, ScanStage};

/// Specifies which actions to scan, by 1-indexed position.
///
/// Valid inputs: `all`, `1-3,5`, `2`, `1,3-5,7`.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanSelection {
    None,
    All,
    /// Sorted, deduplicated 1-indexed positions.
    Indices(Vec<usize>),
}

impl ScanSelection {
    /// Returns true if the given 0-indexed position should be scanned.
    pub fn should_scan(&self, zero_index: usize) -> bool {
        match self {
            ScanSelection::None => false,
            ScanSelection::All => true,
            ScanSelection::Indices(indices) => indices.contains(&(zero_index + 1)),
        }
    }
}

impl fmt::Display for ScanSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanSelection::None => write!(f, "none"),
            ScanSelection::All => write!(f, "all"),
            ScanSelection::Indices(indices) => {
                let parts: Vec<String> = indices.iter().map(|i| i.to_string()).collect();
                write!(f, "{}", parts.join(","))
            }
        }
    }
}

impl FromStr for ScanSelection {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("all") {
            return Ok(ScanSelection::All);
        }
        if s.eq_ignore_ascii_case("none") {
            return Ok(ScanSelection::None);
        }

        let mut indices = BTreeSet::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((start_str, end_str)) = part.split_once('-') {
                let start: usize = start_str
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid range start: {start_str:?}"))?;
                let end: usize = end_str
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid range end: {end_str:?}"))?;
                if start == 0 || end == 0 {
                    bail!("scan indices are 1-based; got 0");
                }
                if start > end {
                    bail!("invalid range: {start}-{end} (start > end)");
                }
                for i in start..=end {
                    indices.insert(i);
                }
            } else {
                let idx: usize = part
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid index: {part:?}"))?;
                if idx == 0 {
                    bail!("scan indices are 1-based; got 0");
                }
                indices.insert(idx);
            }
        }

        if indices.is_empty() {
            return Ok(ScanSelection::None);
        }

        Ok(ScanSelection::Indices(indices.into_iter().collect()))
    }
}

#[derive(Debug, Clone)]
pub struct AuditOptions {
    pub scan: ScanSelection,
    pub resolve_refs: bool,
    pub max_concurrency: usize,
    pub deps: bool,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            scan: ScanSelection::None,
            resolve_refs: true,
            max_concurrency: 10,
            deps: false,
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
) -> anyhow::Result<Vec<Arc<dyn ActionAdvisoryProvider>>> {
    match provider {
        "ghsa" => Ok(vec![Arc::new(GhsaProvider::new(github_client.clone()))]),
        "osv" => Ok(vec![Arc::new(OsvActionProvider::new(OsvClient::new()))]),
        "all" => Ok(vec![
            Arc::new(GhsaProvider::new(github_client.clone())),
            Arc::new(OsvActionProvider::new(OsvClient::new())),
        ]),
        other => bail!("unknown provider: {other} (valid: ghsa, osv, all)"),
    }
}

fn create_package_providers(
    provider: &str,
) -> anyhow::Result<Vec<Arc<dyn PackageAdvisoryProvider>>> {
    match provider {
        "ghsa" => Ok(vec![]),
        "osv" | "all" => Ok(vec![Arc::new(OsvPackageProvider::new(OsvClient::new()))]),
        other => bail!("unknown provider: {other} (valid: ghsa, osv, all)"),
    }
}

pub struct Auditor {
    client: GitHubClient,
    providers: Vec<Arc<dyn ActionAdvisoryProvider>>,
    package_providers: Vec<Arc<dyn PackageAdvisoryProvider>>,
    options: AuditOptions,
}

impl Auditor {
    pub fn new(
        provider: &str,
        client: GitHubClient,
        options: AuditOptions,
    ) -> anyhow::Result<Self> {
        let providers = create_providers(provider, &client)?;
        let package_providers = create_package_providers(provider)?;
        Ok(Self {
            client,
            providers,
            package_providers,
            options,
        })
    }

    pub async fn audit(&self, actions: Vec<ActionRef>) -> Vec<output::ActionEntry> {
        let has_any_scan = !matches!(self.options.scan, ScanSelection::None);
        let has_token = self.client.has_token();
        if has_any_scan && !has_token {
            warn!("scan enabled but no GitHub token provided; skipping scan");
        }

        let mut builder = Pipeline::builder()
            .max_concurrency(self.options.max_concurrency);

        if self.options.resolve_refs {
            builder = builder.stage(RefResolveStage::new(self.client.clone()));
        }

        builder = builder.stage(AdvisoryStage::new(self.providers.clone()));

        if has_any_scan && has_token {
            builder = builder.stage(ScanStage::new(
                self.client.clone(),
                self.options.scan.clone(),
            ));
        }

        if self.options.deps {
            builder = builder.stage(DependencyStage::new(
                self.client.clone(),
                self.package_providers.clone(),
            ));
        }

        let pipeline = builder.build();
        pipeline.run(actions).await
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
        assert_eq!(opts.scan, ScanSelection::None);
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

    #[test]
    fn scan_selection_parse_all() {
        assert_eq!("all".parse::<ScanSelection>().unwrap(), ScanSelection::All);
        assert_eq!("ALL".parse::<ScanSelection>().unwrap(), ScanSelection::All);
    }

    #[test]
    fn scan_selection_parse_none() {
        assert_eq!(
            "none".parse::<ScanSelection>().unwrap(),
            ScanSelection::None
        );
    }

    #[test]
    fn scan_selection_parse_single() {
        assert_eq!(
            "3".parse::<ScanSelection>().unwrap(),
            ScanSelection::Indices(vec![3])
        );
    }

    #[test]
    fn scan_selection_parse_range() {
        assert_eq!(
            "1-3".parse::<ScanSelection>().unwrap(),
            ScanSelection::Indices(vec![1, 2, 3])
        );
    }

    #[test]
    fn scan_selection_parse_mixed() {
        assert_eq!(
            "1-3,5".parse::<ScanSelection>().unwrap(),
            ScanSelection::Indices(vec![1, 2, 3, 5])
        );
    }

    #[test]
    fn scan_selection_parse_deduplicates() {
        assert_eq!(
            "1-3,2-4".parse::<ScanSelection>().unwrap(),
            ScanSelection::Indices(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn scan_selection_parse_rejects_zero() {
        assert!("0".parse::<ScanSelection>().is_err());
        assert!("0-3".parse::<ScanSelection>().is_err());
    }

    #[test]
    fn scan_selection_parse_rejects_inverted_range() {
        assert!("5-2".parse::<ScanSelection>().is_err());
    }

    #[test]
    fn scan_selection_should_scan() {
        let sel = ScanSelection::Indices(vec![1, 3, 5]);
        assert!(sel.should_scan(0)); // position 1
        assert!(!sel.should_scan(1)); // position 2
        assert!(sel.should_scan(2)); // position 3
        assert!(!sel.should_scan(3)); // position 4
        assert!(sel.should_scan(4)); // position 5

        assert!(ScanSelection::All.should_scan(99));
        assert!(!ScanSelection::None.should_scan(0));
    }
}
