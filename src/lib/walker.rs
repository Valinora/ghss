use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use tokio::sync::Semaphore;
use tracing::{debug, instrument};

use crate::action_ref::ActionRef;
use crate::context::AuditContext;
use crate::output::AuditNode;
use crate::pipeline::Pipeline;

/// Drives breadth-first traversal of the action dependency graph.
///
/// The Walker takes a `Pipeline` and processes each BFS frontier concurrently
/// (bounded by `max_concurrency`), tracks visited nodes to prevent cycles,
/// and produces a `Vec<AuditNode>` tree.
pub struct Walker {
    pipeline: Pipeline,
    max_depth: Option<usize>,
    max_concurrency: usize,
}

/// Internal record for a node that has been processed by the pipeline.
struct ProcessedNode {
    key: String,
    context: AuditContext,
}

impl Walker {
    pub fn new(pipeline: Pipeline, max_depth: Option<usize>, max_concurrency: usize) -> Self {
        Self {
            pipeline,
            max_depth,
            max_concurrency,
        }
    }

    /// Perform a breadth-first walk of the action dependency graph starting
    /// from `root_actions`. Returns a tree of `AuditNode` values.
    #[instrument(skip(self, root_actions), fields(root_count = root_actions.len(), max_depth = ?self.max_depth))]
    pub async fn walk(&self, root_actions: Vec<ActionRef>) -> Vec<AuditNode> {
        let mut visited: HashSet<String> = HashSet::new();
        let semaphore = Arc::new(Semaphore::new(self.max_concurrency));

        // Queue entries: (action, depth, parent_key)
        let mut frontier: VecDeque<(ActionRef, usize, Option<String>)> = VecDeque::new();
        for action in root_actions {
            frontier.push_back((action, 0, None));
        }

        // All processed nodes, keyed by their visited key
        let mut all_nodes: HashMap<String, ProcessedNode> = HashMap::new();
        // Track insertion order of root keys for final output ordering
        let mut root_keys: Vec<String> = Vec::new();
        // Track child ordering per parent
        let mut children_order: HashMap<String, Vec<String>> = HashMap::new();

        while !frontier.is_empty() {
            // Drain the current frontier (all nodes at the same depth level)
            let current_level: Vec<(ActionRef, usize, Option<String>)> =
                frontier.drain(..).collect();

            // Filter out already-visited actions, mark new ones as visited
            let mut to_process: Vec<(ActionRef, usize, Option<String>, String)> = Vec::new();
            for (action, depth, parent_key) in current_level {
                let key = action.raw.clone();
                if visited.contains(&key) {
                    debug!(action = %key, "skipping already-visited action");
                    continue;
                }
                visited.insert(key.clone());
                to_process.push((action, depth, parent_key, key));
            }

            if to_process.is_empty() {
                continue;
            }

            // Track which keys are roots vs children
            for (_, depth, parent_key, key) in &to_process {
                if *depth == 0 {
                    root_keys.push(key.clone());
                }
                if let Some(pk) = parent_key {
                    children_order
                        .entry(pk.clone())
                        .or_default()
                        .push(key.clone());
                }
            }

            // Process all nodes in this frontier concurrently, bounded by semaphore.
            // We clone the pipeline (cheap — stages are Arc'd) and use tokio::spawn
            // so each task owns its data and satisfies 'static.
            let mut handles = Vec::new();
            for (i, (action, depth, parent_key, key)) in
                to_process.into_iter().enumerate()
            {
                let sem = Arc::clone(&semaphore);
                let pipeline = self.pipeline.clone();
                handles.push(tokio::spawn(async move {
                    let _permit =
                        sem.acquire().await.expect("semaphore closed unexpectedly");

                    let mut ctx = AuditContext {
                        action,
                        depth,
                        parent: parent_key,
                        children: vec![],
                        index: Some(i),
                        resolved_ref: None,
                        advisories: vec![],
                        scan: None,
                        dependencies: vec![],
                        errors: vec![],
                    };

                    pipeline.run_one(&mut ctx).await;

                    debug!(
                        action = %ctx.action.raw,
                        depth,
                        child_count = ctx.children.len(),
                        "node processed"
                    );

                    ProcessedNode { key, context: ctx }
                }));
            }

            let results: Vec<ProcessedNode> = futures::future::join_all(handles)
                .await
                .into_iter()
                .map(|r| r.expect("walker task panicked"))
                .collect();
            for processed in results {
                let depth = processed.context.depth;
                let children_actions: Vec<ActionRef> = processed.context.children.clone();
                let node_key = processed.key.clone();

                all_nodes.insert(processed.key.clone(), processed);

                // Enqueue children for the next frontier if depth allows
                let should_expand = match self.max_depth {
                    Some(max) => depth < max,
                    None => true,
                };

                if should_expand {
                    for child_action in children_actions {
                        frontier.push_back((
                            child_action,
                            depth + 1,
                            Some(node_key.clone()),
                        ));
                    }
                }
            }
        }

        // Build the tree: convert all contexts to AuditNodes, then
        // attach children to parents using a recursive traversal.
        build_tree(&mut all_nodes, &root_keys, &children_order)
    }
}

/// Recursively build `AuditNode` trees from the flat processed node map.
fn build_tree(
    nodes: &mut HashMap<String, ProcessedNode>,
    keys: &[String],
    children_order: &HashMap<String, Vec<String>>,
) -> Vec<AuditNode> {
    let mut result = Vec::new();
    for key in keys {
        if let Some(processed) = nodes.remove(key) {
            let child_keys = children_order.get(key).cloned().unwrap_or_default();
            let children = build_tree(nodes, &child_keys, children_order);

            let mut node = AuditNode::from(processed.context);
            node.children = children;
            result.push(node);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::PipelineBuilder;
    use crate::stages::Stage;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// A mock stage that populates `ctx.children` based on a predefined mapping.
    /// Also records the order in which actions are visited.
    struct MockChildStage {
        /// Maps action raw string -> list of child raw strings
        child_map: HashMap<String, Vec<String>>,
        /// Records (action_raw, depth) in the order visited
        visit_log: Arc<StdMutex<Vec<(String, usize, Option<String>)>>>,
    }

    #[async_trait]
    impl Stage for MockChildStage {
        async fn run(&self, ctx: &mut AuditContext) -> anyhow::Result<()> {
            // Record this visit
            self.visit_log.lock().unwrap().push((
                ctx.action.raw.clone(),
                ctx.depth,
                ctx.parent.clone(),
            ));

            // Populate children from the map
            if let Some(children) = self.child_map.get(&ctx.action.raw) {
                for child_raw in children {
                    let child: ActionRef = child_raw.parse().unwrap();
                    ctx.children.push(child);
                }
            }

            Ok(())
        }

        fn name(&self) -> &'static str {
            "mock-child"
        }
    }

    fn make_walker(
        child_map: HashMap<String, Vec<String>>,
        visit_log: Arc<StdMutex<Vec<(String, usize, Option<String>)>>>,
        max_depth: Option<usize>,
    ) -> Walker {
        let pipeline = PipelineBuilder::new()
            .stage(MockChildStage {
                child_map,
                visit_log,
            })
            .max_concurrency(1) // sequential for deterministic ordering in tests
            .build();

        Walker::new(pipeline, max_depth, 1)
    }

    // Helper: parse an ActionRef from a raw string
    fn action(raw: &str) -> ActionRef {
        raw.parse().unwrap()
    }

    /// (a) BFS order: Root [A], A->[B,C], B->[D].
    /// Verify nodes are visited in BFS order: A, B, C, D.
    #[tokio::test]
    async fn bfs_order() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/A@v1".to_string(),
            vec!["owner/B@v1".to_string(), "owner/C@v1".to_string()],
        );
        child_map.insert(
            "owner/B@v1".to_string(),
            vec!["owner/D@v1".to_string()],
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), None);

        let roots = vec![action("owner/A@v1")];
        let _result = walker.walk(roots).await;

        let visited: Vec<String> = log.lock().unwrap().iter().map(|(a, _, _)| a.clone()).collect();
        assert_eq!(
            visited,
            vec!["owner/A@v1", "owner/B@v1", "owner/C@v1", "owner/D@v1"],
            "expected BFS order: A, B, C, D"
        );
    }

    /// (b) Depth tracking: depth is 0 for roots, 1 for their children, 2 for grandchildren.
    #[tokio::test]
    async fn depth_tracking() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/A@v1".to_string(),
            vec!["owner/B@v1".to_string()],
        );
        child_map.insert(
            "owner/B@v1".to_string(),
            vec!["owner/C@v1".to_string()],
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), None);

        let roots = vec![action("owner/A@v1")];
        walker.walk(roots).await;

        let visits = log.lock().unwrap().clone();
        assert_eq!(visits[0], ("owner/A@v1".to_string(), 0, None));
        assert_eq!(
            visits[1],
            ("owner/B@v1".to_string(), 1, Some("owner/A@v1".to_string()))
        );
        assert_eq!(
            visits[2],
            ("owner/C@v1".to_string(), 2, Some("owner/B@v1".to_string()))
        );
    }

    /// (c) Parent tracking: roots have None, children have Some(parent_key).
    #[tokio::test]
    async fn parent_tracking() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/root@v1".to_string(),
            vec!["owner/child@v1".to_string()],
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), None);

        let roots = vec![action("owner/root@v1")];
        walker.walk(roots).await;

        let visits = log.lock().unwrap().clone();
        // Root has no parent
        assert_eq!(visits[0].2, None);
        // Child's parent is the root
        assert_eq!(visits[1].2, Some("owner/root@v1".to_string()));
    }

    /// (d) Cycle detection: A->[B], B->[A]. Each visited exactly once.
    #[tokio::test]
    async fn cycle_detection() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/A@v1".to_string(),
            vec!["owner/B@v1".to_string()],
        );
        child_map.insert(
            "owner/B@v1".to_string(),
            vec!["owner/A@v1".to_string()],
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), None);

        let roots = vec![action("owner/A@v1")];
        walker.walk(roots).await;

        let visited: Vec<String> = log.lock().unwrap().iter().map(|(a, _, _)| a.clone()).collect();
        assert_eq!(visited.len(), 2, "each action should be visited exactly once");
        assert!(visited.contains(&"owner/A@v1".to_string()));
        assert!(visited.contains(&"owner/B@v1".to_string()));
    }

    /// (e) max_depth enforcement: With max_depth Some(1), grandchildren are not expanded.
    #[tokio::test]
    async fn max_depth_enforcement() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/A@v1".to_string(),
            vec!["owner/B@v1".to_string()],
        );
        child_map.insert(
            "owner/B@v1".to_string(),
            vec!["owner/C@v1".to_string()], // should NOT be visited
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), Some(1));

        let roots = vec![action("owner/A@v1")];
        walker.walk(roots).await;

        let visited: Vec<String> = log.lock().unwrap().iter().map(|(a, _, _)| a.clone()).collect();
        assert_eq!(
            visited,
            vec!["owner/A@v1", "owner/B@v1"],
            "max_depth=1 should only visit root (depth 0) and its children (depth 1)"
        );
    }

    /// (f) max_depth 0: No expansion at all (children are ignored).
    #[tokio::test]
    async fn max_depth_zero() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/A@v1".to_string(),
            vec!["owner/B@v1".to_string()], // should NOT be visited
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), Some(0));

        let roots = vec![action("owner/A@v1")];
        walker.walk(roots).await;

        let visited: Vec<String> = log.lock().unwrap().iter().map(|(a, _, _)| a.clone()).collect();
        assert_eq!(
            visited,
            vec!["owner/A@v1"],
            "max_depth=0 should only visit root, no children"
        );
    }

    /// (g) Unlimited depth: Full traversal with max_depth None.
    #[tokio::test]
    async fn unlimited_depth() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/A@v1".to_string(),
            vec!["owner/B@v1".to_string()],
        );
        child_map.insert(
            "owner/B@v1".to_string(),
            vec!["owner/C@v1".to_string()],
        );
        child_map.insert(
            "owner/C@v1".to_string(),
            vec!["owner/D@v1".to_string()],
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), None);

        let roots = vec![action("owner/A@v1")];
        walker.walk(roots).await;

        let visited: Vec<String> = log.lock().unwrap().iter().map(|(a, _, _)| a.clone()).collect();
        assert_eq!(
            visited,
            vec!["owner/A@v1", "owner/B@v1", "owner/C@v1", "owner/D@v1"],
            "unlimited depth should traverse all reachable nodes"
        );
    }

    /// Verify the tree structure: A->[B, C], B->[D] produces correct nesting.
    #[tokio::test]
    async fn tree_structure() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/A@v1".to_string(),
            vec!["owner/B@v1".to_string(), "owner/C@v1".to_string()],
        );
        child_map.insert(
            "owner/B@v1".to_string(),
            vec!["owner/D@v1".to_string()],
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), None);

        let roots = vec![action("owner/A@v1")];
        let result = walker.walk(roots).await;

        // One root node
        assert_eq!(result.len(), 1);
        let a = &result[0];
        assert_eq!(a.entry.action.raw, "owner/A@v1");

        // A has two children: B and C
        assert_eq!(a.children.len(), 2);
        let b = &a.children[0];
        let c = &a.children[1];
        assert_eq!(b.entry.action.raw, "owner/B@v1");
        assert_eq!(c.entry.action.raw, "owner/C@v1");

        // B has one child: D
        assert_eq!(b.children.len(), 1);
        assert_eq!(b.children[0].entry.action.raw, "owner/D@v1");

        // C and D have no children
        assert!(c.children.is_empty());
        assert!(b.children[0].children.is_empty());
    }

    /// Multiple roots are each traversed independently.
    #[tokio::test]
    async fn multiple_roots() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/A@v1".to_string(),
            vec!["owner/C@v1".to_string()],
        );
        child_map.insert(
            "owner/B@v1".to_string(),
            vec!["owner/D@v1".to_string()],
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), None);

        let roots = vec![action("owner/A@v1"), action("owner/B@v1")];
        let result = walker.walk(roots).await;

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].entry.action.raw, "owner/A@v1");
        assert_eq!(result[1].entry.action.raw, "owner/B@v1");
        assert_eq!(result[0].children.len(), 1);
        assert_eq!(result[1].children.len(), 1);
    }

    /// Shared children across different parents: A->[C], B->[C].
    /// C is only visited once (by whichever parent enqueues it first).
    #[tokio::test]
    async fn shared_child_deduplication() {
        let mut child_map = HashMap::new();
        child_map.insert(
            "owner/A@v1".to_string(),
            vec!["owner/C@v1".to_string()],
        );
        child_map.insert(
            "owner/B@v1".to_string(),
            vec!["owner/C@v1".to_string()],
        );

        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), None);

        let roots = vec![action("owner/A@v1"), action("owner/B@v1")];
        walker.walk(roots).await;

        let visited: Vec<String> = log.lock().unwrap().iter().map(|(a, _, _)| a.clone()).collect();
        // A, B are roots (depth 0). C is only visited once.
        assert_eq!(visited.len(), 3);

        let c_visits: Vec<_> = visited.iter().filter(|v| *v == "owner/C@v1").collect();
        assert_eq!(c_visits.len(), 1, "shared child should only be visited once");
    }

    /// Empty roots produces an empty result.
    #[tokio::test]
    async fn empty_roots() {
        let child_map = HashMap::new();
        let log = Arc::new(StdMutex::new(Vec::new()));
        let walker = make_walker(child_map, Arc::clone(&log), None);

        let result = walker.walk(vec![]).await;
        assert!(result.is_empty());
        assert!(log.lock().unwrap().is_empty());
    }
}
