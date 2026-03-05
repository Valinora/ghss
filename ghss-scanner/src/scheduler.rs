use std::collections::HashMap;
use std::str::FromStr;

use anyhow::Context;
use chrono::Utc;
use cron::Schedule;
use ghss::github::GitHubClient;
use ghss::output::AuditNode;

use crate::config::{ScannerConfig, normalize_cron};
use crate::scan;
use crate::storage::{ScanStatus, Storage, detect_drift};

#[derive(Debug)]
pub struct Scheduler {
    schedule: Schedule,
}

impl Scheduler {
    pub fn new(cron_expr: &str) -> anyhow::Result<Self> {
        let normalized = normalize_cron(cron_expr);
        let schedule = Schedule::from_str(&normalized)
            .context(format!("invalid cron expression: {cron_expr}"))?;
        Ok(Self { schedule })
    }

    /// Returns the next upcoming occurrence after the current time.
    pub fn next_tick(&self) -> chrono::DateTime<Utc> {
        self.schedule
            .upcoming(Utc)
            .next()
            .expect("cron schedule has no upcoming occurrence")
    }
}

/// Run the scan loop. If `once` is true, run one cycle and return.
/// Otherwise, create a Scheduler and loop on the cron schedule with
/// graceful shutdown on SIGTERM/SIGINT.
///
/// Connects to the `SQLite` database, runs migrations, and persists
/// scan results after each cycle with drift detection.
pub async fn run_loop(config: &ScannerConfig, once: bool) -> anyhow::Result<()> {
    let storage = Storage::connect(&config.storage.url).await?;
    storage.migrate().await?;

    let client = GitHubClient::new(config.scanner.github_token.clone());

    let mut cycle: u64 = 0;

    if once {
        cycle += 1;
        execute_cycle(&storage, config, &client, cycle).await?;
        storage.close().await;
        return Ok(());
    }

    let scheduler = Scheduler::new(&config.scanner.schedule)?;

    // Set up signal handlers for graceful shutdown
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;

    loop {
        let next = scheduler.next_tick();
        let now = Utc::now();
        let wait = (next - now).to_std().unwrap_or(std::time::Duration::ZERO);
        tracing::info!(next = %next, wait_secs = wait.as_secs(), "Waiting for next scheduled run");

        // Race the cron sleep against shutdown signals
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received shutdown signal, shutting down...");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("Received shutdown signal, shutting down...");
                break;
            }
        }

        cycle += 1;
        execute_cycle(&storage, config, &client, cycle).await?;
    }

    storage.close().await;
    tracing::info!("Shutdown complete");
    Ok(())
}

/// Execute a single scan cycle: run the scan, determine status, and persist results.
async fn execute_cycle(
    storage: &Storage,
    config: &ScannerConfig,
    client: &GitHubClient,
    cycle: u64,
) -> anyhow::Result<()> {
    let scan_result = scan::run_scan_cycle(
        &config.repos,
        cycle,
        client,
        &config.pipeline,
        config.scanner.max_repo_concurrency.unwrap_or(1),
    )
    .await;
    let status = if scan_result.failures.is_empty() {
        ScanStatus::Completed
    } else {
        ScanStatus::Partial
    };
    persist_results(storage, &scan_result.results, cycle, status).await
}

/// Persist scan results for all repos, detecting drift against previous findings.
async fn persist_results(
    storage: &Storage,
    results: &[(String, Vec<AuditNode>)],
    cycle: u64,
    status: ScanStatus,
) -> anyhow::Result<()> {
    for (repo_id, nodes) in results {
        persist_repo_result(storage, repo_id, nodes, cycle, status).await?;
    }
    Ok(())
}

/// Persist scan results for a single repo, detecting drift against previous findings.
async fn persist_repo_result(
    storage: &Storage,
    repo_id: &str,
    nodes: &[AuditNode],
    cycle: u64,
    status: ScanStatus,
) -> anyhow::Result<()> {
    let (owner, name) = repo_id.split_once('/').unwrap_or((repo_id, "unknown"));

    let started_at = Utc::now().to_rfc3339();

    // Get previous findings for drift detection
    let previous = storage.get_latest_findings(owner, name).await?;

    // Build current findings for drift comparison
    let current_findings: Vec<_> = nodes
        .iter()
        .map(|node| crate::storage::FindingRow {
            action_ref: node.entry.action.to_string(),
            resolved_sha: node.entry.resolved_sha.clone(),
        })
        .collect();

    let drift_events = detect_drift(&previous, &current_findings);

    // Log per-finding status markers
    let prev_map: HashMap<&str, Option<&str>> = previous
        .iter()
        .map(|f| (f.action_ref.as_str(), f.resolved_sha.as_deref()))
        .collect();
    for finding in &current_findings {
        let sha_display = finding
            .resolved_sha
            .as_deref()
            .map_or("none", |s| &s[..s.len().min(7)]);
        let marker = match prev_map.get(finding.action_ref.as_str()) {
            None => "[NEW]   ",
            Some(prev_sha) if *prev_sha != finding.resolved_sha.as_deref() => "[DRIFT] ",
            Some(_) => "[CACHED]",
        };
        tracing::info!("{marker}  {}    (sha: {sha_display})", finding.action_ref);
    }

    // Insert scan run
    let completed_at = Utc::now().to_rfc3339();
    let run_id = storage
        .insert_scan_run(owner, name, &started_at, Some(&completed_at), cycle, status)
        .await?;

    insert_findings(storage, run_id, nodes).await?;

    let drift_count = drift_events.len();
    insert_drift_events(storage, run_id, &drift_events).await?;

    tracing::info!(
        repo = %repo_id,
        findings = nodes.len(),
        drift_events = drift_count,
        "Persisted {} findings, {} drift event(s) for {}",
        nodes.len(),
        drift_count,
        repo_id
    );

    Ok(())
}

/// Insert audit findings for a single scan run.
async fn insert_findings(
    storage: &Storage,
    run_id: i64,
    nodes: &[AuditNode],
) -> anyhow::Result<()> {
    for node in nodes {
        let action_ref_str = node.entry.action.to_string();
        let advisory_ids: Vec<String> =
            node.entry.advisories.iter().map(|a| a.id.clone()).collect();
        let advisory_ids_str = if advisory_ids.is_empty() {
            None
        } else {
            Some(advisory_ids.join(","))
        };
        let severity = node
            .entry
            .advisories
            .iter()
            .map(|a| a.severity.as_str())
            .next()
            .map(String::from);
        let serialized = serde_json::to_string(node).context("failed to serialize AuditNode")?;

        storage
            .insert_finding(
                run_id,
                &action_ref_str,
                node.entry.resolved_sha.as_deref(),
                advisory_ids_str.as_deref(),
                severity.as_deref(),
                &serialized,
            )
            .await?;
    }
    Ok(())
}

/// Insert drift events detected between consecutive scan runs.
async fn insert_drift_events(
    storage: &Storage,
    run_id: i64,
    drift_events: &[crate::storage::DriftEvent],
) -> anyhow::Result<()> {
    let detected_at = Utc::now().to_rfc3339();
    for event in drift_events {
        storage
            .insert_drift_event(
                run_id,
                &event.action_ref,
                &event.previous_sha,
                &event.current_sha,
                &detected_at,
            )
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn valid_cron_five_field() {
        let s = Scheduler::new("*/5 * * * *").unwrap();
        let next = s.next_tick();
        assert!(next > Utc::now());
    }

    #[test]
    fn valid_cron_six_field() {
        let s = Scheduler::new("0 */5 * * * *").unwrap();
        let next = s.next_tick();
        assert!(next > Utc::now());
    }

    #[test]
    fn invalid_expression_errors() {
        let err = Scheduler::new("not a cron").unwrap_err();
        assert!(
            err.to_string().contains("invalid cron"),
            "expected cron error, got: {err}"
        );
    }

    #[test]
    fn next_tick_is_in_the_future() {
        let s = Scheduler::new("0 * * * *").unwrap();
        let next = s.next_tick();
        assert!(next > Utc::now());
    }

    #[test]
    fn next_tick_within_expected_range() {
        // "0 * * * *" = top of every hour; next tick should be within 1 hour
        let s = Scheduler::new("0 * * * *").unwrap();
        let next = s.next_tick();
        let now = Utc::now();
        let diff = next - now;
        assert!(diff.num_seconds() > 0);
        assert!(diff.num_seconds() <= 3600);
    }

    #[test]
    fn every_minute_next_tick_within_one_minute() {
        let s = Scheduler::new("* * * * *").unwrap();
        let next = s.next_tick();
        let now = Utc::now();
        let diff = next - now;
        assert!(diff.num_seconds() > 0);
        assert!(diff.num_seconds() <= 60);
    }
}
