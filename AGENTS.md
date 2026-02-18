# AGENTS.md

This file provides guidance to various agents (e.g. claude.ai/code) when working with code in this repository.

## Project Overview

`ghss` (GitHub Supply-chain Security) is a Rust CLI tool that audits GitHub Actions workflow files for supply-chain risk. It parses workflow YAML, extracts `uses:` references, filters out local (`./`) and Docker (`docker://`) actions, deduplicates, and audits third-party actions. Core features: advisory lookups from multiple providers (GHSA and OSV.dev), recursive expansion of composite actions and reusable workflows via BFS traversal, optional ref-to-SHA resolution via the GitHub API, repository language/ecosystem scanning, and npm dependency vulnerability detection.

## Build & Test Commands

```bash
cargo build                          # Build the project
cargo test                           # Run all tests (unit + integration)
cargo test --lib                     # Run unit tests only (in src/)
cargo test --test integration        # Run integration tests only
cargo test --test depth_integration  # Run depth integration tests (uses wiremock)
cargo test <test_name>               # Run a single test by name
```

Rust edition is 2024 — requires a recent nightly or stable Rust toolchain.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the original target architecture. The codebase has been migrated to that design. The description below reflects the **current** state.

The crate is organized as `src/lib.rs` (top-level types and orchestration) with submodules in `src/lib/` via `src/lib/mod.rs`:

### Source layout

```
src/lib.rs          — ActionSelection enum, parse_actions(), module re-exports
src/main.rs         — CLI (Clap), pipeline assembly, Walker execution
src/lib/
  mod.rs            — Module declarations and re-exports
  action_ref.rs     — ActionRef struct, RefType enum, parsing
  advisory.rs       — Advisory struct, deduplicate_advisories()
  context.rs        — AuditContext (per-action pipeline state), StageError
  depth.rs          — DepthLimit enum (Bounded/Unlimited)
  github.rs         — GitHubClient (REST + GraphQL + raw content)
  output.rs         — AuditNode tree, TextOutput, JsonOutput formatters
  pipeline.rs       — Stage trait, Pipeline, PipelineBuilder
  walker.rs         — Walker BFS traversal (cycle detection, depth, concurrency)
  workflow.rs       — YAML parsing (Workflow > Job > Step)
  providers/
    mod.rs          — ActionAdvisoryProvider + PackageAdvisoryProvider traits, factory fns
    ghsa.rs         — GhsaProvider (GitHub Advisory DB, actions only)
    osv.rs          — OsvClient, OsvActionProvider, OsvPackageProvider
  stages/
    mod.rs          — Stage re-exports
    advisory.rs     — AdvisoryStage (parallel provider queries, dedup)
    composite.rs    — CompositeExpandStage (action.yml parsing → children)
    resolve.rs      — RefResolveStage (tag/branch → SHA)
    scan.rs         — ScanStage, Ecosystem enum, ScanResult
    workflow_expand.rs — WorkflowExpandStage (reusable workflow parsing → children)
    dependency/
      mod.rs        — DependencyStage (ecosystem-aware dependency auditing)
      npm.rs        — NPM package.json fetching and parsing
```

### Module descriptions

- **`lib.rs`** — Top-level public API. Exports `ActionSelection` enum (All, or 1-indexed ranges like `"1-3,5"`), `parse_actions()` free function, and module re-exports from `src/lib/mod.rs`.
- **`main.rs`** — Clap-derived CLI struct and orchestration. Parses args, assembles the pipeline via `PipelineBuilder`, creates a `Walker`, and runs BFS traversal. See CLI flags below.
- **`context.rs`** — `AuditContext` struct: the per-action data carrier passed through all pipeline stages. Fields: `action`, `depth`, `parent`, `children`, `resolved_ref`, `advisories`, `scan`, `dependencies`, `errors`. Also defines `StageError`.
- **`depth.rs`** — `DepthLimit` enum: `Bounded(usize)` or `Unlimited`. Parsed from CLI `--depth` flag. Converts to `Option<usize>` for Walker.
- **`pipeline.rs`** — `Stage` async trait (`run` + `name`), `Pipeline` (holds `Arc<Vec<Box<dyn Stage>>>`), and `PipelineBuilder` (fluent builder with `.stage()` and `.max_concurrency()`). Stages execute sequentially; errors are captured in `ctx.errors` without halting.
- **`walker.rs`** — `Walker` struct: BFS traversal engine. Processes each depth frontier concurrently (bounded by `tokio::sync::Semaphore`), runs the pipeline on each node, discovers children from expansion stages, enforces `max_depth`, detects cycles via visited set, and builds an `AuditNode` tree.
- **`workflow.rs`** — YAML parsing via serde_yaml. Deserializes workflow into `Workflow > Job > Step` structs. `parse_workflow()` returns a `Vec<String>` of all `uses:` values, including duplicates. Malformed jobs emit warnings to stderr but don't fail the parse.
- **`action_ref.rs`** — `ActionRef` struct and parsing. Splits `uses:` strings into owner, repo, path, git_ref. Classifies refs as `Sha`, `Tag`, or `Unknown`. Provides `package_name()` and `version()` for advisory lookups.
- **`github.rs`** — `GitHubClient` HTTP wrapper using `reqwest`. Methods: `resolve_ref()` (tags/branches → SHAs), `get_raw_content()` (fetch files from repos), `api_get()` / `api_get_optional()` (REST), `graphql_post()` (GraphQL). Base URLs configurable via `GHSS_API_BASE_URL` and `GHSS_RAW_BASE_URL` env vars.
- **`advisory.rs`** — `Advisory` struct (id, aliases, summary, severity, url, affected_range, source) and `deduplicate_advisories()` function that handles cross-provider dedup via ID and alias matching.
- **`output.rs`** — `AuditNode` tree structure (`ActionEntry` + children), `OutputFormatter` trait, `TextOutput` (indented hierarchical text), `JsonOutput` (pretty-printed JSON array). Factory function `formatter(json: bool)`.

### Providers (`src/lib/providers/`)

- **`mod.rs`** — `ActionAdvisoryProvider` trait (queries by `ActionRef`) and `PackageAdvisoryProvider` trait (queries by package name + ecosystem). Factory functions `create_action_providers()` and `create_package_providers()` accept `"ghsa"`, `"osv"`, or `"all"`.
- **`ghsa.rs`** — `GhsaProvider` implementing `ActionAdvisoryProvider`. Queries GitHub Advisory API: `GET /advisories?ecosystem=actions&affects={package_name}`.
- **`osv.rs`** — `OsvClient` (shared HTTP client), `OsvActionProvider` (queries with `"GitHub Actions"` ecosystem), `OsvPackageProvider` (queries with provided ecosystem). All query `POST https://api.osv.dev/v1/query`. Base URL overridable via `GHSS_OSV_BASE_URL` env var.

### Stages (`src/lib/stages/`)

Stages implement the `Stage` trait and execute in this order within the pipeline:

1. **`CompositeExpandStage`** (`composite.rs`) — Fetches `action.yml`/`action.yaml` from repos, detects composite actions (`runs.using == "composite"`), extracts child action references, adds them to `ctx.children`.
2. **`WorkflowExpandStage`** (`workflow_expand.rs`) — Detects reusable workflows (path contains `.github/workflows/`), fetches workflow YAML, extracts step-level and job-level `uses:` refs, adds to `ctx.children`.
3. **`RefResolveStage`** (`resolve.rs`) — Resolves tag/branch refs to commit SHAs via GitHub API. SHA refs bypass the API call. Stores result in `ctx.resolved_ref`.
4. **`AdvisoryStage`** (`advisory.rs`) — Queries all configured advisory providers in parallel, merges and deduplicates results, stores in `ctx.advisories`.
5. **`ScanStage`** (`scan.rs`, conditional) — Queries GitHub GraphQL for repository languages and manifest file presence. Maps manifests to `Ecosystem` enum (Npm, Cargo, Go, Pip, Maven, Gradle, RubyGems, Composer, Docker). Stores `ScanResult` in `ctx.scan`.
6. **`DependencyStage`** (`dependency/mod.rs`, conditional) — Requires prior scan results. For npm ecosystems, fetches `package.json` via `npm.rs`, queries `PackageAdvisoryProvider`s for each dependency, stores `Vec<DependencyReport>` in `ctx.dependencies`.

### CLI flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--file` / `-f` | `PathBuf` (required) | — | Path to GitHub Actions workflow YAML file |
| `--provider` | `String` | `"all"` | Advisory provider: `ghsa`, `osv`, or `all` |
| `--json` | flag | `false` | Output results as JSON; logs to stderr as structured JSON |
| `--depth` | `DepthLimit` | `0` | Recursive expansion depth (`0` = flat, integer, or `"unlimited"`) |
| `--select` | `Option<ActionSelection>` | `None` | Select which root actions to audit (`all`, or 1-indexed ranges like `"1-3,5"`) |
| `--deps` | flag | `false` | Scan action ecosystems and npm dependencies for known vulnerabilities |
| `--github-token` | `Option<String>` | `GITHUB_TOKEN` env var | GitHub personal access token |
| `-v` / `-vv` / `-q` | verbosity | WARN | Verbosity via `clap-verbosity-flag` (`-v` = info, `-vv` = debug, `-q` = error) |

**Interaction rules:** `--deps` adds `ScanStage` + `DependencyStage` to the pipeline; requires a GitHub token (warning logged if missing). `--select` filters root actions before the Walker; unselected actions never enter the pipeline.

### Execution flow

1. Parse CLI args → validate input file exists
2. Initialize tracing (logs to stderr; JSON format if `--json`)
3. Parse workflow YAML → extract and deduplicate root `ActionRef`s → filter by `--select`
4. Create advisory providers based on `--provider`
5. Assemble pipeline: expansion stages (always) → resolve → advisory → scan (conditional) → dependency (conditional)
6. Create Walker with pipeline, `max_depth`, and concurrency limit
7. Walker BFS: process root actions, discover children from expansion stages, recurse up to depth limit
8. Format `AuditNode` tree → stdout (text or JSON)

## Testing

- **Unit tests** live in `#[cfg(test)]` blocks within most source files: `lib.rs`, `workflow.rs`, `action_ref.rs`, `github.rs`, `advisory.rs`, `output.rs`, `context.rs`, `depth.rs`, `pipeline.rs`, `walker.rs`, and files under `providers/` and `stages/`.
- **Integration tests** in `tests/integration.rs` invoke the compiled binary via `std::process::Command` and assert on stdout/stderr/exit code. Covers parsing, filtering, dedup, malformed input, JSON output, provider flags, and depth flags.
- **Depth integration tests** in `tests/depth_integration.rs` use `wiremock` to mock GitHub API responses. Tests recursive expansion, depth limiting, scan behavior, advisory display, and dependency vulnerability detection.
- **Test fixtures** in `tests/fixtures/`:
  - `sample-workflow.yml` — Valid workflow with third-party, local, Docker, and duplicate actions
  - `malformed-workflow.yml` — Broken job to test graceful degradation
  - `sha-pinned-workflow.yml` — SHA-pinned + tag-based actions
  - `vulnerable-workflow.yml` — Known-vulnerable actions for advisory testing
  - `depth-demo-workflow.yml` — Composite + reusable workflow for recursive expansion
  - `depth-test-workflow.yml` — Simple 2-root workflow for mocked depth tests
  - `local-only-workflow.yml` — Only local/Docker actions (produces empty output)
  - `reusable-workflow.yml` — Job-level reusable workflow refs

## Key Dependencies

- `clap` (derive, env) — CLI argument parsing
- `clap-verbosity-flag` — `-v`/`-q` verbosity integration with tracing
- `serde` + `serde_yaml` — YAML deserialization
- `serde_json` — JSON parsing for API responses and output
- `reqwest` 0.13 (json) — Async HTTP client for GitHub API
- `tokio` (rt-multi-thread, macros, sync) — Async runtime
- `futures` — Async combinators (`join_all`)
- `async-trait` — Async trait support
- `anyhow` — Error handling
- `tracing` + `tracing-subscriber` (fmt, env-filter, json) — Structured logging
- `wiremock` 0.6 (dev) — HTTP mocking for integration tests
