# TODO

Deferred work items from the pipeline migration (Steps 1–4 of ARCHITECTURE.md).

## CLI

- [ ] `--no-resolve-refs` flag — ref resolution is on by default; add an opt-out flag

## Pipeline Stages

- [x] `CompositeExpandStage` — fetch `action.yml`, parse `uses:`, populate `ctx.children`
- [x] `WorkflowExpandStage` — fetch reusable workflow YAML, parse `uses:`, populate `ctx.children`

## Walker

- [x] Introduce `Walker` for BFS traversal of the action dependency graph (Step 5)
- [x] Cycle detection via visited set
- [x] `max_depth` support

## Output

- [x] `AuditNode` result tree structure
- [x] Update text and JSON formatters to render tree with depth and provenance

## Refactoring

- [ ] Replace `#[async_trait]` on `Stage` trait with native `async fn in trait` (edition 2024 supports this) — removes `async-trait` dependency and simplifies external `Stage` implementations
