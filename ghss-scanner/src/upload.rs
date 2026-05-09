//! Upload SARIF analyses to GitHub Code Scanning.
//!
//! This module is fire-and-forget: a 202 from GitHub is treated as
//! success and we record the returned `sarif_id`. We do not poll the
//! processing status endpoint; alerts that fail post-processing surface
//! in the GHAS UI directly.

use anyhow::Context;
use base64::Engine;
use chrono::Utc;
use flate2::Compression;
use flate2::write::GzEncoder;
use ghss::github::{
    GitHubApiError, GitHubClient, MAX_DIAGNOSTIC_BYTES, StatusCode, truncate_for_diagnostic,
};
use ghss::output::sarif::build_repo_sarif_log;
use serde_sarif::sarif::{ResultLevel, Sarif};
use sha2::{Digest, Sha256};
use std::io::Write as _;

use crate::config::UploadSection;
use crate::scan::RepoScanOutput;
use crate::storage::Storage;

/// GitHub Code Scanning enforces these limits per upload. We pre-flight
/// before POSTing so an over-limit payload turns into a Rejected row
/// without consuming a rate-limit slot or blocking on a 4xx response.
pub const MAX_RESULTS_PER_RUN: usize = 25_000;
pub const MAX_COMPRESSED_BYTES: usize = 10 * 1024 * 1024;

/// Outcome of an upload attempt. Always recorded in `sarif_uploads` so
/// we have a paper trail even when GHAS rejects the SARIF.
#[derive(Debug, Clone)]
pub struct UploadOutcome {
    pub sarif_id: Option<String>,
    /// Opaque dedup key over `commit_sha + ref + sarif_bytes`. Stored in
    /// the `sarif_uploads.sarif_sha256` column for backward compat with
    /// the column name; the actual hash is over the full upload
    /// payload, not the SARIF body alone.
    pub payload_hash: String,
    pub status: UploadStatus,
    pub response_body: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadStatus {
    /// GitHub returned 202 with a sarif_id.
    Accepted,
    /// GitHub returned 4xx — typically GHAS-not-enabled or schema-invalid.
    Rejected,
    /// Network or 5xx error.
    Failed,
    /// `skip_unchanged` matched the prior accepted hash; no POST happened.
    Skipped,
}

impl UploadStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// Build SARIF for a repo's scan output, then upload it to GitHub Code
/// Scanning. Pre-flight checks (result-count truncation, compressed
/// size limit) and `skip_unchanged` may short-circuit the POST. Always
/// writes a row to `sarif_uploads` (status reflects the outcome).
pub async fn upload_repo_sarif(
    client: &GitHubClient,
    storage: &Storage,
    config: &UploadSection,
    scan_run_id: i64,
    output: &RepoScanOutput,
) -> anyhow::Result<UploadOutcome> {
    let (owner, name) = output
        .repo_id
        .split_once('/')
        .with_context(|| format!("malformed repo_id: {}", output.repo_id))?;

    let tool = config.tool_metadata();
    let mut sarif = build_repo_sarif_log(&output.nodes, &output.attribution, &tool);

    // Pre-flight: cap result count per GitHub's 25k-per-run limit.
    let original_results = sarif
        .runs
        .first()
        .and_then(|r| r.results.as_ref())
        .map_or(0, Vec::len);
    if original_results > MAX_RESULTS_PER_RUN {
        truncate_results_by_severity(&mut sarif, MAX_RESULTS_PER_RUN);
        tracing::warn!(
            repo = %output.repo_id,
            kept = MAX_RESULTS_PER_RUN,
            dropped = original_results - MAX_RESULTS_PER_RUN,
            "Truncated SARIF results to GitHub's 25k-per-run limit (severity-sorted)"
        );
    }

    let sarif_bytes =
        serde_json::to_vec(&sarif).context("failed to serialize SARIF for upload")?;
    let payload_hash = payload_hash(&output.commit_sha, &output.ref_name, &sarif_bytes);

    if config.skip_unchanged {
        let prior = storage.last_successful_sarif_sha(owner, name).await?;
        if prior.as_deref() == Some(payload_hash.as_str()) {
            tracing::info!(
                repo = %output.repo_id,
                "Upload payload unchanged from last successful upload; skipping POST"
            );
            return record_outcome(
                storage,
                scan_run_id,
                owner,
                name,
                output,
                UploadOutcome {
                    sarif_id: None,
                    payload_hash,
                    status: UploadStatus::Skipped,
                    response_body: None,
                },
            )
            .await;
        }
    }

    let compressed = gzip(&sarif_bytes)?;
    if compressed.len() > MAX_COMPRESSED_BYTES {
        let body = format!(
            "payload too large: {} compressed bytes (limit {})",
            compressed.len(),
            MAX_COMPRESSED_BYTES
        );
        tracing::warn!(
            repo = %output.repo_id,
            compressed_bytes = compressed.len(),
            limit = MAX_COMPRESSED_BYTES,
            "SARIF payload exceeds GitHub's 10 MiB compressed limit; recording Rejected without POST"
        );
        return record_outcome(
            storage,
            scan_run_id,
            owner,
            name,
            output,
            UploadOutcome {
                sarif_id: None,
                payload_hash,
                status: UploadStatus::Rejected,
                response_body: Some(body),
            },
        )
        .await;
    }

    let encoded = base64_standard(&compressed);
    let url = format!(
        "{}/repos/{}/{}/code-scanning/sarifs",
        client.api_base_url(),
        owner,
        name
    );
    let body = serde_json::json!({
        "commit_sha": output.commit_sha,
        "ref": output.ref_name,
        "sarif": encoded,
    });

    let outcome = match client.api_post_json(&url, body).await {
        Ok(resp) => {
            let sarif_id = resp
                .get("id")
                .and_then(|v| v.as_str())
                .map(String::from);
            UploadOutcome {
                sarif_id,
                payload_hash: payload_hash.clone(),
                status: UploadStatus::Accepted,
                response_body: None,
            }
        }
        Err(e) => classify_upload_error(&e, &output.repo_id, payload_hash.clone()),
    };

    record_outcome(storage, scan_run_id, owner, name, output, outcome).await
}

/// Examine an upload error and produce an UploadOutcome. Logs at
/// warn-level. Uses the typed `GitHubApiError` to branch on status
/// rather than parsing error strings.
fn classify_upload_error(
    err: &anyhow::Error,
    repo_id: &str,
    payload_hash: String,
) -> UploadOutcome {
    if let Some(api) = err.downcast_ref::<GitHubApiError>() {
        let status = if api.status.is_client_error() {
            UploadStatus::Rejected
        } else {
            UploadStatus::Failed
        };
        let response_body = Some(format!("{}: {}", api.status, api.body));
        if status == UploadStatus::Rejected && api_err_suggests_no_ghas(api) {
            tracing::warn!(
                repo = %repo_id,
                http_status = %api.status,
                "Code Scanning rejected upload (likely GHAS not enabled). \
                 Set `upload_sarif = false` for this repo to silence."
            );
        } else {
            tracing::warn!(
                repo = %repo_id,
                http_status = %api.status,
                body = %api.body,
                ?status,
                "Code Scanning upload did not succeed"
            );
        }
        return UploadOutcome {
            sarif_id: None,
            payload_hash,
            status,
            response_body,
        };
    }

    // Network / serialization / non-API errors.
    let formatted = format!("{err:#}");
    tracing::warn!(
        repo = %repo_id,
        error = %formatted,
        "SARIF upload failed before reaching GitHub"
    );
    UploadOutcome {
        sarif_id: None,
        payload_hash,
        status: UploadStatus::Failed,
        response_body: Some(truncate_for_diagnostic(&formatted, MAX_DIAGNOSTIC_BYTES)),
    }
}

fn api_err_suggests_no_ghas(api: &GitHubApiError) -> bool {
    if api.status != StatusCode::FORBIDDEN {
        return false;
    }
    let body_lower = api.body.to_ascii_lowercase();
    body_lower.contains("advanced security")
        || body_lower.contains("code scanning is not enabled")
        || body_lower.contains("not enabled")
}

/// Persist the outcome to `sarif_uploads` and return it. Truncates the
/// stored `response_body` to the same diagnostic cap as github.rs uses
/// for error bodies.
async fn record_outcome(
    storage: &Storage,
    scan_run_id: i64,
    owner: &str,
    name: &str,
    output: &RepoScanOutput,
    outcome: UploadOutcome,
) -> anyhow::Result<UploadOutcome> {
    let now = Utc::now().to_rfc3339();
    let stored_body = outcome
        .response_body
        .as_deref()
        .map(|s| truncate_for_diagnostic(s, MAX_DIAGNOSTIC_BYTES));
    storage
        .insert_sarif_upload(
            scan_run_id,
            owner,
            name,
            outcome.sarif_id.as_deref(),
            &outcome.payload_hash,
            &output.commit_sha,
            &output.ref_name,
            outcome.status.as_str(),
            stored_body.as_deref(),
            &now,
        )
        .await?;
    Ok(outcome)
}

/// Stable sort `sarif.runs[0].results` by severity (Error first), then
/// truncate to `keep`. Mirrors GitHub's own truncation behavior so
/// operators see the worst findings even when over-limit.
fn truncate_results_by_severity(sarif: &mut Sarif, keep: usize) {
    if let Some(run) = sarif.runs.get_mut(0)
        && let Some(results) = run.results.as_mut()
    {
        results.sort_by_key(|r| match r.level {
            Some(ResultLevel::Error) => 0,
            Some(ResultLevel::Warning) => 1,
            Some(ResultLevel::Note) => 2,
            _ => 3,
        });
        results.truncate(keep);
    }
}

/// Gzip the input bytes. Used both for size-limit pre-flight and as the
/// pre-base64 stage of the upload payload.
fn gzip(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).context("gzip write failed")?;
    encoder.finish().context("gzip finish failed")
}

fn base64_standard(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Hash the entire upload payload (commit + ref + SARIF bytes) so that
/// the same SARIF content at a different commit produces a different
/// hash — meaning `skip_unchanged` does not skip uploads at new commits.
fn payload_hash(commit_sha: &str, ref_name: &str, sarif_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(commit_sha.as_bytes());
    hasher.update(b"|");
    hasher.update(ref_name.as_bytes());
    hasher.update(b"|");
    hasher.update(sarif_bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(s, "{byte:02x}").expect("write to String never fails");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use flate2::read::GzDecoder;
    use serde_sarif::sarif::{
        Message, Result as SarifResult, Run, Tool, ToolComponent,
    };
    use std::io::Read;

    #[test]
    fn gzip_then_base64_roundtrips() {
        let input = b"the quick brown fox";
        let encoded = base64_standard(&gzip(input).unwrap());
        let compressed = STANDARD.decode(&encoded).unwrap();
        let mut out = Vec::new();
        GzDecoder::new(&compressed[..])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn payload_hash_is_deterministic() {
        let a = payload_hash("sha-1", "refs/heads/main", b"sarif");
        let b = payload_hash("sha-1", "refs/heads/main", b"sarif");
        assert_eq!(a, b);
    }

    #[test]
    fn payload_hash_changes_when_commit_advances() {
        let old = payload_hash("sha-old", "refs/heads/main", b"identical-sarif");
        let new = payload_hash("sha-new", "refs/heads/main", b"identical-sarif");
        assert_ne!(
            old, new,
            "commit advance must invalidate skip_unchanged hash"
        );
    }

    #[test]
    fn payload_hash_changes_when_ref_changes() {
        let main = payload_hash("sha", "refs/heads/main", b"x");
        let dev = payload_hash("sha", "refs/heads/develop", b"x");
        assert_ne!(main, dev);
    }

    #[test]
    fn payload_hash_changes_when_sarif_changes() {
        let a = payload_hash("sha", "refs/heads/main", b"sarif-a");
        let b = payload_hash("sha", "refs/heads/main", b"sarif-b");
        assert_ne!(a, b);
    }

    fn synthetic_sarif_with_levels(levels: &[ResultLevel]) -> Sarif {
        let driver = ToolComponent::builder()
            .name("test".to_string())
            .build();
        let tool = Tool::builder().driver(driver).build();
        let results: Vec<SarifResult> = levels
            .iter()
            .enumerate()
            .map(|(i, lvl)| {
                SarifResult::builder()
                    .rule_id(format!("r{i}"))
                    .level(*lvl)
                    .message(Message::builder().text(format!("msg {i}")).build())
                    .build()
            })
            .collect();
        let run = Run::builder().tool(tool).results(results).build();
        Sarif::builder()
            .version(serde_json::Value::String("2.1.0".to_string()))
            .runs(vec![run])
            .build()
    }

    fn run_results_levels(sarif: &Sarif) -> Vec<ResultLevel> {
        sarif
            .runs
            .first()
            .and_then(|r| r.results.as_ref())
            .map(|results| {
                results.iter().filter_map(|r| r.level).collect()
            })
            .unwrap_or_default()
    }

    fn run_results_count(sarif: &Sarif) -> usize {
        sarif
            .runs
            .first()
            .and_then(|r| r.results.as_ref())
            .map_or(0, Vec::len)
    }

    #[test]
    fn truncate_results_by_severity_keeps_errors_first() {
        let mut sarif = synthetic_sarif_with_levels(&[
            ResultLevel::Note,
            ResultLevel::Warning,
            ResultLevel::Error,
            ResultLevel::Note,
            ResultLevel::Error,
            ResultLevel::Warning,
        ]);
        truncate_results_by_severity(&mut sarif, 3);
        let levels = run_results_levels(&sarif);
        assert_eq!(levels.len(), 3);
        // Two Errors should survive (highest severity first), one Warning.
        let error_count = levels
            .iter()
            .filter(|l| matches!(**l, ResultLevel::Error))
            .count();
        assert_eq!(error_count, 2, "both Error results must survive");
        let warning_count = levels
            .iter()
            .filter(|l| matches!(**l, ResultLevel::Warning))
            .count();
        assert_eq!(warning_count, 1, "third slot is filled by next-best severity");
    }

    #[test]
    fn truncate_results_by_severity_no_op_when_under_limit() {
        let mut sarif = synthetic_sarif_with_levels(&[ResultLevel::Error, ResultLevel::Note]);
        truncate_results_by_severity(&mut sarif, 100);
        assert_eq!(run_results_count(&sarif), 2);
    }

    #[test]
    fn api_err_suggests_no_ghas_matches_advanced_security_in_403() {
        let api = GitHubApiError {
            status: StatusCode::FORBIDDEN,
            url: "x".into(),
            body: "Code scanning is not enabled for this repository".into(),
        };
        assert!(api_err_suggests_no_ghas(&api));

        let api2 = GitHubApiError {
            status: StatusCode::FORBIDDEN,
            url: "x".into(),
            body: "GitHub Advanced Security must be enabled".into(),
        };
        assert!(api_err_suggests_no_ghas(&api2));
    }

    #[test]
    fn api_err_suggests_no_ghas_does_not_match_other_403_bodies() {
        let api = GitHubApiError {
            status: StatusCode::FORBIDDEN,
            url: "x".into(),
            body: "rate limit exceeded".into(),
        };
        assert!(!api_err_suggests_no_ghas(&api));
    }

    #[test]
    fn api_err_suggests_no_ghas_ignores_non_403() {
        let api = GitHubApiError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            url: "x".into(),
            body: "Code scanning is not enabled".into(),
        };
        assert!(!api_err_suggests_no_ghas(&api));
    }

    #[test]
    fn classify_5xx_as_failed() {
        let api_err = GitHubApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            url: "x".into(),
            body: "upstream down".into(),
        };
        let err = anyhow::Error::new(api_err);
        let outcome = classify_upload_error(&err, "o/r", "hash".into());
        assert_eq!(outcome.status, UploadStatus::Failed);
        assert!(outcome.response_body.unwrap().contains("503"));
    }

    #[test]
    fn classify_4xx_as_rejected() {
        let api_err = GitHubApiError {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            url: "x".into(),
            body: "bad sarif".into(),
        };
        let err = anyhow::Error::new(api_err);
        let outcome = classify_upload_error(&err, "o/r", "hash".into());
        assert_eq!(outcome.status, UploadStatus::Rejected);
        assert!(outcome.response_body.unwrap().contains("422"));
    }

    #[test]
    fn classify_non_api_error_as_failed() {
        let err = anyhow::anyhow!("connection reset");
        let outcome = classify_upload_error(&err, "o/r", "hash".into());
        assert_eq!(outcome.status, UploadStatus::Failed);
        assert!(outcome.response_body.unwrap().contains("connection reset"));
    }
}
