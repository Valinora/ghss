use ghss::action_ref::ActionRef;
use ghss::advisory::Advisory;
use ghss::output::{ActionEntry, AuditNode};

use crate::config::RepoEntry;

/// Run a single scan cycle over the configured repos.
///
/// For each repo, generates hardcoded fake `AuditNode` values using real
/// `ghss` library types. Returns a vec of `(repo_identifier, nodes)` tuples.
pub fn run_scan_cycle(repos: &[RepoEntry], cycle: u64) -> Vec<(String, Vec<AuditNode>)> {
    tracing::info!(cycle, repos = repos.len(), "Starting scan cycle");

    let results: Vec<(String, Vec<AuditNode>)> = repos
        .iter()
        .map(|repo| {
            let repo_id = format!("{}/{}", repo.owner, repo.name);
            tracing::info!(cycle, repo = %repo_id, "Scanning repo");

            let nodes = generate_fake_nodes(cycle);

            tracing::info!(
                cycle,
                repo = %repo_id,
                findings = nodes.len(),
                "Scan complete for repo"
            );

            (repo_id, nodes)
        })
        .collect();

    let total_findings: usize = results.iter().map(|(_, nodes)| nodes.len()).sum();
    tracing::info!(cycle, total_findings, "Scan cycle complete");

    results
}

fn generate_fake_nodes(cycle: u64) -> Vec<AuditNode> {
    let checkout: ActionRef = "actions/checkout@v4".parse().unwrap();
    let setup_node: ActionRef = "actions/setup-node@v3".parse().unwrap();

    let mut nodes = vec![
        AuditNode {
            entry: ActionEntry {
                action: checkout,
                resolved_sha: Some("b4ffde65f46336ab88eb53be808477a3936bae11".to_string()),
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![],
        },
        AuditNode {
            entry: ActionEntry {
                action: setup_node,
                resolved_sha: Some("1a4442cacd436585916779fa0482e7ad73969eb2".to_string()),
                advisories: vec![Advisory {
                    id: format!("GHSA-fake-{cycle:04}"),
                    aliases: vec![],
                    summary: "Simulated advisory for testing".to_string(),
                    severity: "medium".to_string(),
                    url: format!("https://github.com/advisories/GHSA-fake-{cycle:04}"),
                    affected_range: Some(">= 1.0, < 4.0".to_string()),
                    source: "ghsa".to_string(),
                }],
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![],
        },
    ];

    // Third node varies by cycle to enable drift detection in later tasks
    if cycle.is_multiple_of(2) {
        let codecov: ActionRef = "codecov/codecov-action@v3".parse().unwrap();
        nodes.push(AuditNode {
            entry: ActionEntry {
                action: codecov,
                resolved_sha: Some("e28ff129e5465c8c0dcc6f95a1e3aee62e3e922a".to_string()),
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![],
        });
    }

    nodes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_repos() -> Vec<RepoEntry> {
        vec![
            RepoEntry {
                owner: "my-org".to_string(),
                name: "my-app".to_string(),
                workflows: None,
            },
            RepoEntry {
                owner: "my-org".to_string(),
                name: "my-service".to_string(),
                workflows: Some(vec!["ci.yml".to_string()]),
            },
        ]
    }

    #[test]
    fn returns_results_for_each_repo() {
        let repos = sample_repos();
        let results = run_scan_cycle(&repos, 1);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "my-org/my-app");
        assert_eq!(results[1].0, "my-org/my-service");
    }

    #[test]
    fn each_repo_has_findings() {
        let repos = sample_repos();
        let results = run_scan_cycle(&repos, 1);
        for (repo_id, nodes) in &results {
            assert!(
                !nodes.is_empty(),
                "expected findings for {repo_id}, got none"
            );
        }
    }

    #[test]
    fn nodes_serialize_to_valid_json() {
        let repos = sample_repos();
        let results = run_scan_cycle(&repos, 1);
        for (_repo_id, nodes) in &results {
            let json = serde_json::to_string(nodes).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert!(parsed.is_array());
        }
    }

    #[test]
    fn cycle_counting_produces_different_advisory_ids() {
        let repos = vec![RepoEntry {
            owner: "org".to_string(),
            name: "repo".to_string(),
            workflows: None,
        }];
        let r1 = run_scan_cycle(&repos, 1);
        let r2 = run_scan_cycle(&repos, 2);

        let adv1 = &r1[0].1[1].entry.advisories[0].id;
        let adv2 = &r2[0].1[1].entry.advisories[0].id;
        assert_ne!(adv1, adv2, "advisory IDs should differ across cycles");
        assert_eq!(adv1, "GHSA-fake-0001");
        assert_eq!(adv2, "GHSA-fake-0002");
    }

    #[test]
    fn even_cycle_has_third_node() {
        let repos = vec![RepoEntry {
            owner: "org".to_string(),
            name: "repo".to_string(),
            workflows: None,
        }];
        let odd = run_scan_cycle(&repos, 1);
        let even = run_scan_cycle(&repos, 2);
        assert_eq!(odd[0].1.len(), 2, "odd cycle should have 2 nodes");
        assert_eq!(even[0].1.len(), 3, "even cycle should have 3 nodes");
    }

    #[test]
    fn empty_repos_returns_empty() {
        let results = run_scan_cycle(&[], 1);
        assert!(results.is_empty());
    }
}
