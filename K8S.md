# Continuous Scanner

Architectural notes for a second binary (`ghss-scanner`) that runs as a long-lived daemon, continuously auditing GitHub Actions workflows and emitting telemetry about findings and drift. Designed to run anywhere (bare metal, Docker, K8s) with K8s as a first-class deployment target.

## Goals

- Given a set of repos, scan all workflow files on a recurring cron schedule
- Detect when resolved SHAs change over time (drift detection)
- Emit OpenTelemetry traces and metrics about audit findings
- Support multiple storage backends (SQLite for simple deployments, PostgreSQL for production)
- Keep persistence, scheduling, and OTel concerns out of the `ghss` library

## Library Reuse

The existing library API covers almost everything the scanner needs. The pipeline, walker, stages, and providers are all reusable as-is. Required library changes:

- ~~**`parse_actions_from_str(yaml: &str)`**~~ — **Resolved.** `parse_actions` and `parse_workflow` now accept `&str` YAML content directly; file reading is handled by consumers.
- ~~**`Deserialize` derives** on output types (`AuditNode`, `ActionEntry`, `ActionRef`, `Advisory`, `ScanResult`, `DependencyReport`, etc.) for snapshot round-tripping~~ — **Resolved.** All output types now derive `Deserialize`.
- ~~**`PartialEq`/`Eq` derives** on output types for diffing current vs. previous results~~ — **Resolved.** All output types now derive or implement `PartialEq`/`Eq`.

### Library readiness status

| Type | `Serialize` | `Deserialize` | `PartialEq` | `Eq` | Notes |
|------|:-:|:-:|:-:|:-:|-------|
| `AuditNode` | Y | Y | Y | Y | |
| `ActionEntry` | Y | Y | Y | Y | |
| `ActionRef` | Y | Y | Y | Y | Manual `PartialEq`/`Eq` impls (not derives) |
| `RefType` | Y | Y | Y | Y | |
| `Advisory` | Y | Y | Y | Y | |
| `ScanResult` | Y | Y | Y | Y | |
| `Ecosystem` | Y | Y | Y | Y | |
| `DependencyReport` | Y | Y | Y | Y | |

All library types are now ready for snapshot round-tripping.

Consumers can implement custom `Stage`s via the public `#[async_trait] Stage` trait and plug them into `PipelineBuilder`.

## Repo Structure

Cargo workspace with three members — **done.**

- `ghss` — library
- `ghss-cli` — CLI binary
- `ghss-scanner` — scanner daemon (dependencies added, implementation not yet started)

## Scanner Architecture

Everything below is **not yet implemented.** `ghss-scanner` has its dependencies declared but no real code.

### Configuration

TOML config file specifying repos to scan, cron schedules, pipeline options, storage backend, and OTel endpoint. The scanner will watch the config file for changes and hot-reload without restart, making it compatible with K8s ConfigMap volume mounts (which propagate updates automatically).

Repos are specified at the repository level with optional workflow filters. Omitting the workflow list scans all workflows discovered via the GitHub Contents API.

```toml
[scanner]
github_token = "${GITHUB_TOKEN}"   # env var expansion
schedule = "*/30 * * * *"          # cron expression

[[repos]]
owner = "my-org"
name = "my-app"

[[repos]]
owner = "my-org"
name = "my-service"
workflows = ["ci.yml", "deploy.yml"]  # optional filter

[pipeline]
depth = "unlimited"
provider = "all"
deps = true

[storage]
url = "sqlite:///data/ghss.db"
# or: url = "postgresql://user:pass@host/ghss"

[telemetry]
endpoint = "http://otel-collector:4317"

[health]
bind = "0.0.0.0:8080"
```

### Scan Loop

The scanner will run as a long-lived daemon with cron-based scheduling (via the `cron` crate for expression parsing and `tokio::time::sleep_until` for execution). Per scan cycle:

1. List workflow files via GitHub Contents API for each configured repo
2. Fetch each workflow's YAML via `GitHubClient::get_raw_content`
3. `parse_actions` → `PipelineBuilder` → `Walker::walk`
4. Diff results against stored previous state (`PartialEq` on output types)
5. Emit OTel traces/events for findings and changes
6. Persist current state via `sqlx`

### Persistence

`sqlx` with the storage backend determined by the connection URL scheme (`sqlite://` or `postgresql://`). Stores serialized `AuditNode` trees per workflow (leveraging `Serialize`/`Deserialize` derives) and per-action resolved SHAs — enough to detect drift and new/resolved advisories between runs.

SQLite suits single-node and dev deployments (PVC-backed in K8s). PostgreSQL suits production environments with existing database infrastructure, HA requirements, and multi-replica potential.

### Config Hot-Reload

The `notify` + `notify-debouncer-full` crates will watch the config file for changes. On change, the scanner will re-parse the TOML config and reconcile the set of active scan jobs (add new repos, remove deleted ones, update schedules) without restarting the process. In K8s, ConfigMap volume mounts propagate updates within ~60 seconds, so this provides a seamless operator experience.

### OpenTelemetry

**Traces**: Span per scan run (repo-level), child spans per workflow, events for SHA changes and advisory changes.

**Metrics**: Gauges for active advisory count per repo, counters for SHA drift events, histograms for scan duration.

### Health Endpoints

`axum` will serve HTTP health and readiness endpoints for K8s probes. Readiness will gate on successful config parse and database connectivity. Liveness will confirm the scan loop is not stuck.

### K8s Deployment

- Deployment (single replica for SQLite; multiple replicas possible with PostgreSQL)
- ConfigMap for scanner TOML config
- Secret for GitHub token (referenced via env var in config)
- PersistentVolumeClaim for SQLite (not needed with PostgreSQL)
- Health/readiness probes pointing at axum endpoints
- Graceful SIGTERM shutdown

### Dependencies

All dependencies are declared in `ghss-scanner/Cargo.toml`:

| Category | Crates |
|----------|--------|
| Config | `toml`, `serde`, `clap`, `clap-verbosity-flag` |
| Scheduling | `cron`, `chrono` |
| File watching | `notify`, `notify-debouncer-full` |
| Persistence | `sqlx` (runtime-tokio, sqlite, postgres) |
| Health endpoints | `axum` |
| Telemetry | `opentelemetry`, `tracing-opentelemetry` |
| Core | `ghss`, `tokio`, `tracing`, `tracing-subscriber`, `anyhow` |
