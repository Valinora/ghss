use std::sync::Arc;

use futures::future::join_all;
use tokio::sync::Semaphore;

use crate::action_ref::ActionRef;
use crate::context::AuditContext;
use crate::output::ActionEntry;
use crate::stage::Stage;

pub struct Pipeline {
    stages: Arc<Vec<Box<dyn Stage>>>,
    max_concurrency: usize,
}

impl Pipeline {
    pub fn builder() -> PipelineBuilder {
        PipelineBuilder {
            stages: vec![],
            max_concurrency: 10,
        }
    }

    pub async fn run(&self, actions: Vec<ActionRef>) -> Vec<ActionEntry> {
        let sem = Arc::new(Semaphore::new(self.max_concurrency));
        let stages = self.stages.clone();

        let futures: Vec<_> = actions
            .into_iter()
            .enumerate()
            .map(|(idx, action)| {
                let sem = sem.clone();
                let stages = stages.clone();
                async move {
                    let _permit = sem.acquire().await.expect("semaphore closed");

                    let mut ctx = AuditContext {
                        action,
                        depth: 0,
                        parent: None,
                        children: vec![],
                        index: Some(idx),
                        resolved_ref: None,
                        advisories: vec![],
                        scan: None,
                        dependencies: vec![],
                        errors: vec![],
                    };

                    for stage in stages.iter() {
                        if let Err(e) = stage.run(&mut ctx).await {
                            tracing::warn!(
                                stage = stage.name(),
                                action = %ctx.action.raw,
                                error = %e,
                                "stage failed"
                            );
                            ctx.errors.push(crate::context::StageError {
                                stage: stage.name().to_string(),
                                message: e.to_string(),
                            });
                        }
                    }

                    ActionEntry::from(ctx)
                }
            })
            .collect();

        join_all(futures).await
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

pub struct PipelineBuilder {
    stages: Vec<Box<dyn Stage>>,
    max_concurrency: usize,
}

impl PipelineBuilder {
    pub fn stage(mut self, stage: impl Stage + 'static) -> Self {
        self.stages.push(Box::new(stage));
        self
    }

    pub fn max_concurrency(mut self, n: usize) -> Self {
        self.max_concurrency = n;
        self
    }

    pub fn build(self) -> Pipeline {
        Pipeline {
            stages: Arc::new(self.stages),
            max_concurrency: self.max_concurrency,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct NoOpStage(&'static str);

    #[async_trait]
    impl Stage for NoOpStage {
        async fn run(&self, _ctx: &mut AuditContext) -> anyhow::Result<()> {
            Ok(())
        }
        fn name(&self) -> &str {
            self.0
        }
    }

    #[test]
    fn builder_defaults() {
        let pipeline = Pipeline::builder().build();
        assert_eq!(pipeline.stage_count(), 0);
        assert_eq!(pipeline.max_concurrency, 10);
    }

    #[test]
    fn builder_stage_count() {
        let pipeline = Pipeline::builder()
            .stage(NoOpStage("a"))
            .stage(NoOpStage("b"))
            .stage(NoOpStage("c"))
            .build();
        assert_eq!(pipeline.stage_count(), 3);
    }

    #[test]
    fn builder_max_concurrency() {
        let pipeline = Pipeline::builder().max_concurrency(5).build();
        assert_eq!(pipeline.max_concurrency, 5);
    }

    #[test]
    fn builder_stage_ordering() {
        let pipeline = Pipeline::builder()
            .stage(NoOpStage("first"))
            .stage(NoOpStage("second"))
            .stage(NoOpStage("third"))
            .build();

        let names: Vec<&str> = pipeline.stages.iter().map(|s| s.name()).collect();
        assert_eq!(names, vec!["first", "second", "third"]);
    }

    #[tokio::test]
    async fn run_empty_actions() {
        let pipeline = Pipeline::builder()
            .stage(NoOpStage("test"))
            .build();
        let results = pipeline.run(vec![]).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn run_processes_all_actions() {
        let pipeline = Pipeline::builder().build();
        let actions = vec![
            "actions/checkout@v4".parse().unwrap(),
            "actions/setup-node@v3".parse().unwrap(),
        ];
        let results = pipeline.run(actions).await;
        assert_eq!(results.len(), 2);
    }
}
