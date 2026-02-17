# Architecture

This document describes the target architecture for `ghss`. It is forward-looking and prescriptive — it defines what we are building toward, not the current state of the codebase.

## Goals

1. **Audit the GitHub Actions supply chain.** Given a workflow file, produce a comprehensive security report covering direct and transitive action dependencies.
2. **Recursive analysis.** Walk the action dependency graph — composite actions and reusable workflows can themselves reference other actions. The tool follows these references to arbitrary depth.
3. **Extensible enrichment.** New analysis capabilities (advisory lookup, static analysis, license checking, etc.) can be added without modifying core orchestration.
4. **Configurable pipelines.** Users control which analyses run via CLI flags. The pipeline is assembled at startup, not hardcoded.
5. **Library-first design.** Core logic lives in the library crate. The CLI is one consumer. Other tools (a "deep audit" binary, CI integrations) can compose their own pipelines using the same library.

## Scope

The tool's graph traversal concerns itself exclusively with the **action/workflow dependency graph**:

- Actions referenced via `uses:` in workflow files
- Composite actions (whose `action.yml` may reference further actions)
- Reusable workflows (which contain jobs that reference actions and other reusable workflows)

Software package dependencies (npm, pip, etc.) are **not nodes in the graph**. They are metadata attached to action nodes via enrichment stages. Deep package-tree walking is delegated to ecosystem-specific tools.

## Core Patterns

### Context Object — `AuditContext`

Each node in the action graph is represented by an `AuditContext` that accumulates data as it flows through the pipeline. Stages read from and write to this shared context.

```rust
struct AuditContext {
    action: ActionRef,
    depth: usize,
    parent: Option<String>,          // "owner/repo@ref" of parent node
    index: Option<usize>,            // 0-based position in the current frontier (for selective scan)

    // Populated by expansion stages (discovered children to traverse)
    children: Vec<ActionRef>,

    // Populated by enrichment stages
    resolved_ref: Option<String>,
    advisories: Vec<Advisory>,
    scan: Option<ScanResult>,
    dependencies: Vec<DependencyReport>,
    // Future: license_info, static_analysis_findings, etc.
}
```

### Strategy Pattern — Providers

Providers are interchangeable data sources behind trait interfaces. Each trait defines a focused query contract. Concrete implementations can hit different backends (GitHub API, OSV.dev, local cache, etc.).

```rust
#[async_trait]
trait ActionAdvisoryProvider: Send + Sync {
    async fn query(&self, action: &ActionRef) -> Result<Vec<Advisory>>;
    fn name(&self) -> &str;
}

#[async_trait]
trait PackageAdvisoryProvider: Send + Sync {
    async fn query(&self, package: &str, ecosystem: &str) -> Result<Vec<Advisory>>;
    fn name(&self) -> &str;
}
```

Multiple providers can serve the same trait. For example, `GhsaProvider` and `OsvActionProvider` both implement `ActionAdvisoryProvider`. Stages that consume providers hold a `Vec<Arc<dyn ActionAdvisoryProvider>>` and query all of them, deduplicating results.

#### Shared Clients

Where a single upstream API serves multiple provider traits, the HTTP and parsing logic lives in a shared client struct. Thin provider wrappers adapt the shared client to the appropriate trait.

OSV is the primary example. Its API (`POST /v1/query`) accepts any package name and ecosystem string, so the same request/response logic serves both action-level and package-level advisory queries:

```rust
// Shared client — owns HTTP logic and response parsing
struct OsvClient {
    http: reqwest::Client,
}

impl OsvClient {
    async fn query(&self, package: &str, ecosystem: &str) -> Result<Vec<Advisory>> {
        // POST to https://api.osv.dev/v1/query — one implementation
    }
}

// Thin wrappers implementing the appropriate trait
struct OsvActionProvider { client: OsvClient }
struct OsvPackageProvider { client: OsvClient }

impl ActionAdvisoryProvider for OsvActionProvider {
    async fn query(&self, action: &ActionRef) -> Result<Vec<Advisory>> {
        self.client.query(&action.package_name(), "GitHub Actions").await
    }
}

impl PackageAdvisoryProvider for OsvPackageProvider {
    async fn query(&self, package: &str, ecosystem: &str) -> Result<Vec<Advisory>> {
        self.client.query(package, ecosystem).await
    }
}
```

This pattern applies to any future API that spans multiple provider traits. The shared client is not a provider itself — it is an implementation detail of the providers that use it.

Provider implementations live in `src/lib/providers/`. The module is organized as:

```
src/lib/providers/
  mod.rs       — trait definitions, re-exports
  ghsa.rs      — GhsaProvider (ActionAdvisoryProvider)
  osv.rs       — OsvClient (shared), OsvActionProvider, OsvPackageProvider
```

### Pipeline Pattern — Stages

A **Stage** is a unit of work that processes a single node. Stages are composed into an ordered pipeline. Each stage receives a mutable `AuditContext` and enriches it.

```rust
#[async_trait]
trait Stage: Send + Sync {
    async fn run(&self, ctx: &mut AuditContext) -> Result<()>;
    fn name(&self) -> &str;
}
```

There is no type-level distinction between enrichment stages and expansion stages. Both implement the same `Stage` trait. The difference is behavioral:

- **Enrichment stages** add data to the context (advisories, scan results, resolved refs). They do not modify `ctx.children`.
- **Expansion stages** fetch an action's `action.yml` or a reusable workflow's YAML, parse it, and populate `ctx.children` with discovered `ActionRef`s.

Stages run sequentially within a single node. Ordering is determined by insertion order in the pipeline. Stages that depend on prior results (e.g., a dependency stage that needs scan results) are placed after their prerequisites. If a prerequisite result is absent (e.g., scan was not enabled), the stage skips gracefully — it does not error.

Concrete stages:

| Stage                  | Type        | Depends On | Description                                                   |
|------------------------|-------------|------------|---------------------------------------------------------------|
| `RefResolveStage`      | Enrichment  | —          | Resolves tag/branch refs to commit SHAs via GitHub API        |
| `CompositeExpandStage` | Expansion   | —          | Fetches `action.yml`, parses `uses:`, populates `children`    |
| `WorkflowExpandStage`  | Expansion   | —          | Fetches reusable workflow YAML, parses `uses:`, populates `children` |
| `AdvisoryStage`        | Enrichment  | —          | Queries action-level advisory providers                       |
| `ScanStage`            | Enrichment  | —          | Detects primary language and ecosystems via GitHub API         |
| `DependencyStage`      | Enrichment  | `ScanStage`| Queries package-level advisory providers for detected ecosystems |

### Builder Pattern — Pipeline Construction

The `Pipeline` is constructed using a builder. The builder provides a fluent API for adding stages and validates the pipeline at build time.

```rust
let pipeline = PipelineBuilder::new()
    .stage(RefResolveStage::new(github.clone()))
    .stage(CompositeExpandStage::new(github.clone()))
    .stage(WorkflowExpandStage::new(github.clone()))
    .stage(AdvisoryStage::new(advisory_providers))
    .stage(ScanStage::new(github.clone()))
    .stage(DependencyStage::new(package_providers))
    .build();
```

The CLI maps flags to builder calls:

- `--no-resolve-refs` → omits `RefResolveStage` (ref resolution is on by default)
- `--scan` → adds `ScanStage` and `DependencyStage`
- `--provider <name>` → controls which providers are injected into `AdvisoryStage`
- Expansion stages are always included (graph walking is a core feature, not optional)

A no-flag invocation produces a minimal pipeline: expansion stages + advisory stage only.

### Crawler Pattern — Walker

The `Walker` performs breadth-first traversal of the action dependency graph. It drives the pipeline and manages traversal state.

```rust
struct Walker {
    pipeline: Pipeline,
    visited: HashSet<String>,
    max_depth: Option<usize>,
}
```

Algorithm:

1. Parse the input workflow to extract root `ActionRef`s.
2. Enqueue root actions at depth 0.
3. Dequeue an action. If already visited (by `"owner/repo@ref"` key), skip.
4. Create an `AuditContext` for the action. Run the pipeline.
5. Mark the action as visited.
6. Enqueue any `ctx.children` at `depth + 1` (subject to `max_depth`).
7. Repeat until the queue is empty.
8. Return the result tree.

Cycle detection is handled by the visited set — composite actions or reusable workflows that form cycles are visited once and not re-expanded.

### Result Tree — `AuditNode`

The walker produces a tree of `AuditNode`s, preserving the dependency structure for output:

```rust
struct AuditNode {
    context: AuditContext,
    children: Vec<AuditNode>,
}
```

Output formatters (text, JSON) receive the tree and render it with depth information, so users can see provenance: "your workflow uses X, which uses Y, which has advisory Z."

## Concurrency Model

- **Cross-node**: Multiple independent nodes at the same depth level can be processed concurrently. The walker can process the current frontier in parallel (bounded by `max_concurrency`).
- **Within-node**: Stages run sequentially for a given node (they may depend on each other's output).
- **Within-stage**: A stage may internally parallelize work (e.g., `AdvisoryStage` queries multiple providers concurrently via `join_all`).

## Error Handling

Stages use `anyhow::Result`. A stage failure for one node does not halt traversal — the walker logs the error, attaches it to the `AuditContext`, and continues processing other nodes. This matches the current behavior where malformed jobs produce warnings but don't fail the parse.

The `AuditContext` carries an errors field:

```rust
struct AuditContext {
    // ...
    errors: Vec<StageError>,
}

struct StageError {
    stage: String,
    message: String,
}
```

## Iterative Migration Path

This architecture will be implemented incrementally. Each step should leave the tool functional:

1. **Reorganize providers.** Move `ghsa.rs` and `osv.rs` into `providers/` module. Extract `AdvisoryProvider` trait into `providers/mod.rs`. Split into `ActionAdvisoryProvider` and `PackageAdvisoryProvider`.
2. **Introduce `AuditContext`.** Replace the ad-hoc enrichment in `Auditor::audit_one()` with a context object that accumulates results.
3. **Introduce the `Stage` trait and built-in stages.** Extract each block of logic in `audit_one()` into its own `Stage` implementation.
4. **Introduce `Pipeline` with builder.** Replace `Auditor` with `Pipeline` constructed via builder. CLI maps flags to builder calls.
5. **Introduce the `Walker`.** Add expansion stages and BFS traversal. Output becomes a tree.
6. **Update output formatters.** Adapt text and JSON output to render the tree structure with depth and provenance.
