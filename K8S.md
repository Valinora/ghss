# Continuous Scanner (K8s)

Architectural notes for a second binary (`ghss-scanner`) that runs as a long-lived k8s workload, continuously auditing GitHub Actions workflows and emitting telemetry about findings and drift.

## Goals

- Given a set of repos, scan all workflow files on a recurring interval
- Detect when resolved SHAs change over time (drift detection)
- Emit OpenTelemetry traces and metrics about audit findings
- Keep k8s, persistence, and OTel concerns out of the `ghss` library

## Library Reuse

The existing library API covers almost everything the scanner needs. The pipeline, walker, stages, and providers are all reusable as-is. Required library changes:

- ~~**`parse_actions_from_str(yaml: &str)`**~~ — **Resolved.** `parse_actions` and `parse_workflow` now accept `&str` YAML content directly; file reading is handled by consumers.
- **`Deserialize` derives** on output types (`AuditNode`, `ActionEntry`, `ActionRef`, `Advisory`, `ScanResult`, `DependencyReport`, etc.) for snapshot round-tripping
- **`PartialEq`/`Eq` derives** on output types for diffing current vs. previous results

Consumers can implement custom `Stage`s via the public `#[async_trait] Stage` trait and plug them into `PipelineBuilder`.

## Repo Structure

Cargo workspace with three members:

- `ghss` — library (current `src/lib.rs` + `src/lib/`)
- `ghss-cli` — existing CLI binary
- `ghss-scanner` — new scanner binary

## Scanner Architecture

### Configuration

YAML config file mounted from a ConfigMap. Specifies repos to scan, intervals, pipeline options (depth, provider, deps), and OTel endpoint.

### Scan Loop

Per-repo tokio task running on a configurable interval:

1. List workflow files via GitHub Contents API
2. Fetch each workflow's YAML via `GitHubClient::get_raw_content`
3. `parse_actions_from_str` → `PipelineBuilder` → `Walker::walk`
4. Diff results against stored previous state
5. Emit OTel traces/events for findings and changes
6. Persist current state

### Persistence

Embedded SQLite on a PersistentVolume. Stores per-action resolved SHA and advisory IDs — just enough to detect drift and new/resolved advisories between runs.

### OpenTelemetry

**Traces**: Span per scan run (repo-level), child spans per workflow, events for SHA changes and advisory changes.

**Metrics**: Gauges for active advisory count per repo, counters for SHA drift events, histograms for scan duration.

### K8s Deployment

- Deployment (single replica, SQLite is single-writer)
- ConfigMap for scanner config
- Secret for GitHub token
- PersistentVolumeClaim for SQLite
- Health/readiness HTTP endpoints
- Graceful SIGTERM shutdown
