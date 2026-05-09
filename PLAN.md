# SARIF Output & GitHub Code Scanning Upload — Plan

This document captures the design for adding SARIF output to `ghss` and direct
Code Scanning API uploads to `ghss-scanner`. The work is split into independent
PRs that ship in order. PR #3 (OTEL drift telemetry) is out of scope for this
document and tracked separately.

## Background and goals

`ghss` audits GitHub Actions workflows for supply-chain risk, producing a tree
of advisories per action. We want those findings to surface in GitHub's Security
tab via the SARIF v2.1.0 format that GitHub Code Scanning consumes.

Two delivery paths matter:

1. **In-workflow** — a custom GitHub Action wrapping the `ghss` CLI, composed
   with `github/codeql-action/upload-sarif@v3`. The action emits a SARIF file;
   `upload-sarif` handles the gzip/base64/POST using the workflow's
   auto-provisioned `GITHUB_TOKEN`. The CLI never calls the Code Scanning API
   itself.
2. **Out-of-band** — `ghss-scanner` running as a daemon scans repos on a cron
   schedule and POSTs SARIF directly to each target repo's Code Scanning
   endpoint. This is the path that lets findings appear without requiring the
   target repo to have a workflow run.

## Shared design decisions

These apply to both PRs.

### SARIF schema

- Target SARIF v2.1.0 (only version GitHub accepts).
- Use the `serde-sarif` crate (v0.8). Schema-derived types, full v2.1.0
  coverage, MIT, actively maintained. Add to `[workspace.dependencies]`.

### Rule taxonomy

One rule per category, not per advisory. Initial set:

| ruleId | Trigger |
|---|---|
| `ghss/vulnerable-action` | Any `Advisory` on an `ActionEntry` |
| `ghss/vulnerable-dependency` | Any `Advisory` inside `dep_vulnerabilities` |

Each rule carries `properties.tags = ["security", "supply-chain"]` so
`security-severity` is honored by GitHub's UI.

Out of scope for v1: `ghss/unpinned-action-ref` (future), `ghss/audit-error`
(stage errors deliberately excluded — not security findings), and
`ghss/action-sha-drift` (drift is operational telemetry, will land via OTEL in a
later PR).

### Severity mapping

```text
Critical  → level=error,   security-severity="9.5"
High      → level=error,   security-severity="8.0"
Medium    → level=warning, security-severity="5.5"
Low       → level=note,    security-severity="2.0"
Unknown   → level=warning, security-severity="5.0"
```

Future improvement: prefer real CVSS vectors from OSV when present. Requires
plumbing CVSS through the `Advisory` struct — punted.

### Locations

For v1, every result points at the workflow YAML file with
`startLine=1, endLine=1, startColumn=1, endColumn=1`. GitHub requires all four
region fields. Per-line accuracy requires a YAML parser that exposes spans
(`serde_yaml` does not); switching to `marked-yaml` or `saphyr` is a separate
piece of work. Findings collapse onto line 1 in the UI until then.

### Fingerprints

Each result carries:

```text
partialFingerprints.primaryLocationLineHash =
    sha256(workflow_path + "|" + action.package_name() + "|" + advisory.id)
```

Stable across reformats and re-runs so GitHub deduplicates alerts correctly.

### Out of scope for both PRs

- Per-line locations within workflow YAML.
- CVSS vector preservation through the advisory pipeline.
- `ghss/audit-error` rule for stage failures.
- `ghss/unpinned-action-ref` rule.
- Drift events in SARIF (separate OTEL-backed PR).
- CLI `--upload` flag (the custom action composes with
  `github/codeql-action/upload-sarif@v3`).

---

## PR #1 — SARIF output in the library and CLI

**Goal:** `ghss --format sarif --file workflow.yml` emits valid SARIF v2.1.0 to
stdout, ready for `github/codeql-action/upload-sarif@v3` to ingest.

This PR unblocks the custom GitHub Action and is a hard prerequisite for PR #2.

### Surface area

- New file `ghss/src/output/sarif.rs` (requires moving `output.rs` to
  `output/mod.rs`).
- New `SarifOutput` struct implementing `OutputFormatter`, parameterized on the
  workflow file path and tool version.
- Replace the `--json` boolean with `--format text|json|sarif` on the CLI. Keep
  `--json` as a hidden alias mapping to `--format json` for back-compat.
- Update the `formatter()` factory to take an enum + workflow path instead of a
  bool.
- Add `serde-sarif = "0.8"` to `[workspace.dependencies]` and to
  `ghss/Cargo.toml`.

### Builder shape

`build_sarif_log(nodes: &[AuditNode], workflow_path: &Path, tool_version: &str)
-> Sarif` walks the `AuditNode` tree and emits one result per
(action × advisory) and (action × dep × advisory). Path through the audit tree
gets encoded in the result message so reviewers can trace why a transitive
finding appears.

### Tests

- Unit test in `output/sarif.rs` constructing a small `AuditNode` with one
  advisory and snapshotting the JSON shape.
- Integration test in `ghss-cli/tests/integration.rs` running
  `ghss --format sarif -f vulnerable-workflow.yml` and round-tripping the
  output through `serde_sarif::sarif::Sarif::deserialize` to confirm the file
  parses as SARIF.
- Stretch: invoke Microsoft's `sarif-multitool` validator in CI so we catch
  GitHub-rejection-class errors before users do.

### Acceptance

- `--format sarif` produces output that parses as `Sarif`.
- All existing `--json` integration tests still pass via the hidden alias.
- Sample output uploaded manually to a test repo's Code Scanning endpoint
  surfaces alerts with correct severity and dedup behavior.

---

## PR #2 — Scanner SARIF upload to GitHub Code Scanning

**Goal:** `ghss-scanner` builds SARIF for each repo it scans and POSTs to
`/repos/{owner}/{repo}/code-scanning/sarifs` so findings land in the target
repo's Security tab without requiring any workflow run.

Depends on PR #1 for the SARIF builder.

### Config

New optional section in `ScannerConfig`:

```toml
[upload]
enabled = true            # required; nothing uploads if absent or false
tool_name = "ghss"        # appears in Security tab tool filter
skip_unchanged = true     # skip POST when SARIF hash matches last successful upload
```

New optional field on `RepoEntry`:

```toml
[[repos]]
owner = "foo"
name = "bar"
upload_sarif = false      # per-repo opt-out, only relevant when [upload].enabled = true
```

Default behavior (no `[upload]` section): no uploads, scanner behaves exactly as
today. Two-layer opt-in is intentional — the global flag is the
"yes-I-understand-this-pushes-to-GitHub" gate, the per-repo flag handles repos
without GHAS or that are deliberately excluded.

### Capturing commit SHA per scan

`POST /code-scanning/sarifs` requires `commit_sha` and `ref`. The scanner
currently fetches workflow YAML from HEAD via `get_raw_content()` without
recording which commit that was. New step at the top of `scan_repo`:

1. `GET /repos/{owner}/{name}` → grab `default_branch`.
2. `GET /repos/{owner}/{name}/git/ref/heads/{default_branch}` → record commit
   SHA.
3. Pin that SHA for all subsequent raw-content reads in the cycle so a push
   mid-scan doesn't split findings across two commits.
4. Pass `(commit_sha, ref)` into the upload step.

### New module `ghss-scanner/src/upload.rs`

- Build SARIF from `Vec<AuditNode>` using the library's builder.
- gzip + base64-encode the SARIF bytes per Code Scanning API requirements.
- POST via `GitHubClient` (requires adding an `api_post_json` method to
  `ghss/src/github.rs`).
- Return `sarif_id` for storage. Optionally poll the processing endpoint.
- Errors logged but never fail the scan cycle.

### New SQLite table

```sql
CREATE TABLE sarif_uploads (
    id INTEGER PRIMARY KEY,
    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    sarif_id TEXT,                 -- returned by GitHub on accept
    sarif_sha256 TEXT NOT NULL,    -- for skip_unchanged comparison
    commit_sha TEXT NOT NULL,
    ref TEXT NOT NULL,
    status TEXT NOT NULL,          -- pending, accepted, rejected, failed
    response_body TEXT,             -- error body for failed/rejected
    uploaded_at TEXT NOT NULL
);
```

Embedded migration. Drives idempotency (`skip_unchanged`) and gives us a paper
trail for diagnosing GHAS rejection.

### Wiring point

Called from `scheduler.rs::persist_repo_result` after the existing finding and
drift inserts. Sequence per repo:

1. Insert `scan_runs` row.
2. Insert `findings`.
3. Insert `drift_events`.
4. **(new)** If global+repo upload enabled: build SARIF, hash, compare to last
   successful `sarif_sha256`. If unchanged and `skip_unchanged=true`, log and
   skip. Otherwise POST and insert `sarif_uploads` row.

### Failure handling

- HTTP failures: insert row with `status=failed`, log, continue. Next cycle will
  retry naturally because the hash will still differ from the last successful
  upload.
- 4xx (e.g. GHAS not enabled, archived repo): insert with `status=rejected`,
  log a clear message advising per-repo opt-out, continue.
- Auth failures: same as above but with louder logging — likely a config issue,
  not transient.

### Tests

- Unit tests for the gzip+base64 wrapper and the hash-skip logic.
- Integration test using `wiremock` to stand in for the Code Scanning endpoint:
  - Successful upload path inserts an `accepted` row with the returned
    `sarif_id`.
  - 422 rejection inserts a `rejected` row and does not crash the cycle.
  - `skip_unchanged=true` plus matching prior hash skips the POST entirely.
- Integration test verifying global-disabled and per-repo-disabled both prevent
  uploads.

### Acceptance

- Scanner with `[upload] enabled = true` against a real GHAS-enabled test repo
  produces alerts in that repo's Security tab.
- Scanner without `[upload]` section behaves byte-identically to current
  behavior on the existing fixture suite.
- A 24-hour soak run with `skip_unchanged=true` shows zero redundant uploads
  when findings haven't changed.
