# AGENTS.md

This file provides guidance to various agents (e.g. claude.ai/code) when working with code in this repository.

## Project Overview

`ghss` (GitHub Supply-chain Security) is a Rust CLI tool that audits GitHub Actions workflow files for third-party action usage. It parses workflow YAML, extracts `uses:` references, filters out local (`./`) and Docker (`docker://`) actions, deduplicates, and prints sorted third-party actions to stdout. Advisories are always looked up from multiple providers (GHSA and OSV.dev). Optional flags resolve action refs to commit SHAs via the GitHub API, select which advisory provider to use, and scan action repositories for language/ecosystem metadata.

## Build & Test Commands

```bash
cargo build              # Build the project
cargo test               # Run all tests (unit + integration)
cargo test --lib         # Run unit tests only (in src/)
cargo test --test integration  # Run integration tests only
cargo test <test_name>   # Run a single test by name
```

Rust edition is 2024 — requires a recent nightly or stable Rust toolchain.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the target architecture. The codebase is being iteratively migrated toward that design. The description below reflects the **current** state.

The crate is organized as `src/lib.rs` (top-level types and orchestration) with submodules in `src/lib/` via `src/lib/mod.rs`:

- **`lib.rs`** — Top-level public API. Exports `ScanSelection`, `parse_actions()` free function, and module re-exports from `src/lib/mod.rs`. Pipeline orchestration is done via `PipelineBuilder` (from the `pipeline` module).
- **`main.rs`** — Clap-derived CLI struct and orchestration. Flags: `--file` / `-f` (required, path to workflow YAML), `--provider` (advisory provider: `ghsa`, `osv`, or `all`; defaults to `all`), `--json` (structured JSON output), `--scan` (scan action repos for languages/ecosystems), `--github-token` (or `GITHUB_TOKEN` env var). Assembles the pipeline directly using `PipelineBuilder` and stage types.
- **`workflow.rs`** — YAML parsing via serde_yaml. Deserializes workflow into `Workflow > Job > Step` structs. `parse_workflow()` returns a `Vec<String>` of all `uses:` values, including duplicates. Malformed jobs emit warnings to stderr but don't fail the parse.
- **`action_ref.rs`** — `ActionRef` struct and parsing. Splits `uses:` strings into owner, repo, path, git_ref. Classifies refs as `Sha`, `Tag`, or `Unknown`. Provides `package_name()` and `version()` for advisory lookups.
- **`github.rs`** — `GitHubClient` HTTP wrapper using `reqwest`. `resolve_ref()` resolves tags (lightweight and annotated) and branches to commit SHAs via the GitHub REST API. `graphql_post()` sends GraphQL queries (used by scan).
- **`advisory.rs`** — `Advisory` struct and `AdvisoryProvider` trait (object-safe). Defines the interface for advisory data sources.
- **`ghsa.rs`** — `GhsaProvider` implementing `AdvisoryProvider`. Queries `GET /advisories?ecosystem=actions&affects={package_name}` and parses GHSA JSON responses.
- **`osv.rs`** — `OsvProvider` implementing `AdvisoryProvider`. Queries `POST https://api.osv.dev/v1/query` with package name and `"GitHub Actions"` ecosystem. No authentication required.
- **`scan.rs`** — `scan_action()` detects primary language and package ecosystems for an action's repository via GitHub GraphQL API.
- **`output.rs`** — `TextOutput` and `JsonOutput` formatters. Advisories and scan results are always rendered when present.

## Testing

- **Unit tests** live in `#[cfg(test)]` blocks within `lib.rs`, `workflow.rs`, `action_ref.rs`, `github.rs`, `ghsa.rs`, `osv.rs`, `scan.rs`, and `output.rs`.
- **Integration tests** in `tests/integration.rs` invoke the compiled binary via `std::process::Command` and assert on stdout/stderr/exit code.
- **Test fixtures** in `tests/fixtures/`: `sample-workflow.yml` (valid), `malformed-workflow.yml` (has broken jobs to test graceful degradation), and `sha-pinned-workflow.yml` (SHA-pinned + tag-based actions).

## Key Dependencies

- `clap` (derive, env) — CLI argument parsing
- `serde` + `serde_yaml` — YAML deserialization
- `serde_json` — JSON parsing for API responses
- `reqwest` 0.13 (json) — Async HTTP client for GitHub API
- `tokio` (rt-multi-thread, macros, sync) — Async runtime
- `futures` — Async combinators (`join_all`)
- `async-trait` — Async trait support
- `anyhow` — Error handling
- `tracing` + `tracing-subscriber` — Structured logging
