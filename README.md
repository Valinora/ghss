# ghss

[![CI](https://github.com/Valinora/ghss/actions/workflows/ci.yml/badge.svg)](https://github.com/Valinora/ghss/actions/workflows/ci.yml)

A command-line tool for auditing GitHub Actions workflow files for supply-chain risk. Parses workflow YAML, extracts third-party action references, checks them against advisory databases (GitHub Advisory Database and OSV.dev), and optionally resolves refs to SHAs, expands composite actions and reusable workflows, and scans dependencies for known vulnerabilities.

## Requirements

- Rust 2024 edition (recent nightly or stable toolchain)
- A GitHub personal access token (required for ref resolution, recursive expansion, and dependency scanning)

## Building

The repository is a Cargo workspace with three crates:

```bash
cargo build                     # Build all workspace crates
cargo build -p ghss-cli         # Build the CLI only
cargo build -p ghss-scanner     # Build the scanner daemon only
cargo build --release           # Release build (LTO + stripped)
```

The CLI binary is named `ghss`. The scanner binary is named `ghss-scanner`.

## Testing

```bash
cargo test                                     # All tests (unit + integration)
cargo test -p ghss                             # Library unit tests
cargo test -p ghss-cli --test integration      # CLI integration tests
cargo test -p ghss-cli --test depth_integration # Depth integration tests (wiremock)
cargo test -p ghss-scanner                     # Scanner tests
cargo test <test_name>                         # Single test by name
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub personal access token. Used as the default when `--github-token` is not provided. |
| `GHSS_API_BASE_URL` | Override the GitHub REST/GraphQL API base URL. Default: `https://api.github.com` |
| `GHSS_RAW_BASE_URL` | Override the GitHub raw content base URL. Default: `https://raw.githubusercontent.com` |
| `GHSS_OSV_BASE_URL` | Override the OSV.dev API base URL. Default: `https://api.osv.dev/v1/query` |
| `GHSS_SCANNER_CONFIG` | Path to the scanner config file. Used when `--config` is not provided and the default `/opt/ghss/config.toml` is not desired. |

## CLI Reference (`ghss`)

```
ghss -f <workflow.yml> [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-f`, `--file` | path | (required) | Path to a GitHub Actions workflow YAML file. |
| `--provider` | string | `all` | Advisory provider: `ghsa`, `osv`, or `all`. |
| `--json` | flag | off | Output results as JSON. Logs are emitted to stderr as structured JSON. |
| `--depth` | integer or `unlimited` | `0` | Recursive expansion depth for composite actions and reusable workflows. `0` disables expansion. |
| `--select` | string | all | Select which root actions to audit. Accepts `all` or 1-indexed ranges like `1-3,5`. |
| `--deps` | flag | off | Scan action repositories for ecosystems and audit npm dependencies for known vulnerabilities. Requires a GitHub token. |
| `--fail-on-severity` | `critical`, `high`, `medium`, `low` | off | Exit with code 2 if any advisory meets or exceeds the given severity. |
| `--github-token` | string | `$GITHUB_TOKEN` | GitHub personal access token. |
| `-v` / `-vv` | flag | warn | Increase log verbosity (info, debug). |
| `-q` | flag | warn | Decrease log verbosity (error only). |

### Examples

Basic audit:
```bash
ghss -f .github/workflows/ci.yml
```

Full recursive audit with dependency scanning and JSON output:
```bash
ghss -f .github/workflows/ci.yml --depth unlimited --deps --json --github-token ghp_...
```

Audit specific actions and fail on high-severity advisories:
```bash
ghss -f .github/workflows/ci.yml --select 1-3 --fail-on-severity high
```

## Scanner Reference (`ghss-scanner`)

A scheduled daemon that continuously audits configured repositories. Stores results in SQLite for drift detection.

```
ghss-scanner [OPTIONS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-c`, `--config` | path | see below | Path to TOML config file. |
| `--once` | flag | off | Run one scan cycle and exit instead of running as a daemon. |
| `-v` / `-vv` / `-q` | flag | warn | Log verbosity. |

Config file resolution order:
1. `--config` CLI flag
2. `GHSS_SCANNER_CONFIG` environment variable
3. `/opt/ghss/config.toml`

### Config File Format

TOML. All sections except `[telemetry]` and `[health]` are required.

```toml
[scanner]
github_token = "ghp_..."           # or "${ENV_VAR_NAME}" for expansion
schedule = "*/30 * * * *"          # cron expression (5 or 6 fields)
max_repo_concurrency = 4           # optional, default 1

[[repos]]
owner = "my-org"
name = "my-app"

[[repos]]
owner = "my-org"
name = "my-service"
workflows = ["ci.yml", "deploy.yml"]  # optional, scans all if omitted

[pipeline]
depth = "unlimited"                # "0", integer, or "unlimited"
provider = "all"                   # "ghsa", "osv", or "all"
deps = true                        # enable dependency scanning
concurrency = 20                   # optional, default 10

[storage]
url = "sqlite:///var/lib/ghss/data.db"

[telemetry]                        # optional
endpoint = "http://otel-collector:4317"

[health]                           # optional
bind = "0.0.0.0:8080"
```

## Challenges

Everything started in `main`. Advisory lookups, ref resolution, composite expansion, dependency scanning, all in one place. It stopped scaling around the time I added the fourth concern.

The fix was a `Stage` trait and a `Pipeline` that holds `Box<dyn Stage>` objects. Each audit concern lives in its own stage, the pipeline runs them in sequence, and adding a new one doesn't mean touching anything else.

I went with dynamic dispatch over generics. Making the pipeline generic over async stages meant trait bounds and lifetime annotations on every function they touched. The signatures got bad enough that I stopped trying. Vtable overhead is irrelevant when every stage is bottlenecked on HTTP requests, so the trade was straightforward: confirmed readability over theoretical performance.

## Roadmap

- **More ecosystems.** Dependency scanning only covers npm right now. Cargo, Go modules, pip, Maven, and the rest of what OSV.dev tracks are on the list.
- **GitHub App auth.** PATs work fine for individual use, but whether they're sufficient org-wide is an open question. Installation tokens with fine-grained permissions may be the answer.
- **Scanner OTel traces.** Basic tracing is in place. Better span attributes, metrics, and context propagation would go a long way for long-running deployments.

## License

MIT
