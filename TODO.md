# TODO

Deferred work items from the pipeline migration (Steps 1–4 of ARCHITECTURE.md).

## CLI

- [ ] `--no-resolve-refs` flag — ref resolution is on by default; add an opt-out flag

## Pipeline Stages

- [ ] `CompositeExpandStage` — fetch `action.yml`, parse `uses:`, populate `ctx.children`
- [ ] `WorkflowExpandStage` — fetch reusable workflow YAML, parse `uses:`, populate `ctx.children`

## Walker

- [ ] Introduce `Walker` for BFS traversal of the action dependency graph (Step 5)
- [ ] Cycle detection via visited set
- [ ] `max_depth` support

## Output

- [ ] `AuditNode` result tree structure
- [ ] Update text and JSON formatters to render tree with depth and provenance
