use std::sync::Arc;

use tracing::{debug, instrument};

use crate::context::AuditContext;
use crate::stages::Stage;

#[derive(Clone)]
pub struct Pipeline {
    stages: Arc<Vec<Box<dyn Stage>>>,
    max_concurrency: usize,
}

impl Pipeline {
    #[instrument(skip(self, ctx), fields(action = %ctx.action, stage_count = self.stages.len()))]
    pub async fn run_one(&self, ctx: &mut AuditContext) {
        for stage in self.stages.iter() {
            if let Err(e) = stage.run(ctx).await {
                tracing::warn!(
                    stage = stage.name(),
                    action = %ctx.action,
                    error = %e,
                    "stage failed"
                );
                ctx.record_error(stage.name(), &e);
            } else {
                debug!(stage = stage.name(), action = %ctx.action, "stage complete");
            }
        }
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    pub fn max_concurrency(&self) -> usize {
        self.max_concurrency
    }
}

pub struct PipelineBuilder {
    stages: Vec<Box<dyn Stage>>,
    max_concurrency: usize,
}

impl PipelineBuilder {
    pub fn new() -> Self {
        Self {
            stages: vec![],
            max_concurrency: 10,
        }
    }

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

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use async_trait::async_trait;

    fn test_ctx() -> AuditContext {
        AuditContext {
            action: "actions/checkout@v4".parse().unwrap(),
            depth: 0,
            parent: None,
            children: vec![],
            resolved_ref: None,
            advisories: vec![],
            scan: None,
            dependencies: vec![],
            errors: vec![],
        }
    }

    struct TrackingStage {
        name: &'static str,
        log: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl Stage for TrackingStage {
        async fn run(&self, _ctx: &mut AuditContext) -> anyhow::Result<()> {
            self.log.lock().unwrap().push(self.name.to_string());
            Ok(())
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    struct FailingStage {
        name: &'static str,
        log: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl Stage for FailingStage {
        async fn run(&self, _ctx: &mut AuditContext) -> anyhow::Result<()> {
            self.log.lock().unwrap().push(self.name.to_string());
            Err(anyhow::anyhow!("boom"))
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    #[test]
    fn builder_defaults() {
        let pipeline = PipelineBuilder::new().build();
        assert_eq!(pipeline.stage_count(), 0);
        assert_eq!(pipeline.max_concurrency, 10);
    }

    #[test]
    fn builder_stage_count() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let pipeline = PipelineBuilder::new()
            .stage(TrackingStage { name: "a", log: log.clone() })
            .stage(TrackingStage { name: "b", log: log.clone() })
            .stage(TrackingStage { name: "c", log: log.clone() })
            .build();
        assert_eq!(pipeline.stage_count(), 3);
    }

    #[test]
    fn builder_max_concurrency() {
        let pipeline = PipelineBuilder::new().max_concurrency(5).build();
        assert_eq!(pipeline.max_concurrency, 5);
    }

    #[test]
    fn builder_stage_ordering() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let pipeline = PipelineBuilder::new()
            .stage(TrackingStage { name: "first", log: log.clone() })
            .stage(TrackingStage { name: "second", log: log.clone() })
            .stage(TrackingStage { name: "third", log: log.clone() })
            .build();

        let names: Vec<&str> = pipeline.stages.iter().map(|s| s.name()).collect();
        assert_eq!(names, vec!["first", "second", "third"]);
    }

    #[tokio::test]
    async fn run_one_with_no_stages() {
        let pipeline = PipelineBuilder::new().build();
        let mut ctx = test_ctx();
        pipeline.run_one(&mut ctx).await;
        assert!(ctx.errors.is_empty());
    }

    #[tokio::test]
    async fn run_one_processes_context() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let pipeline = PipelineBuilder::new()
            .stage(TrackingStage { name: "test", log: log.clone() })
            .build();
        let mut ctx = test_ctx();
        pipeline.run_one(&mut ctx).await;
        assert!(ctx.errors.is_empty());
    }

    #[tokio::test]
    async fn run_one_stages_execute_in_order() {
        let log = Arc::new(Mutex::new(Vec::new()));

        let pipeline = PipelineBuilder::new()
            .stage(TrackingStage { name: "first", log: log.clone() })
            .stage(TrackingStage { name: "second", log: log.clone() })
            .stage(TrackingStage { name: "third", log: log.clone() })
            .build();

        let mut ctx = test_ctx();
        pipeline.run_one(&mut ctx).await;

        let executed = log.lock().unwrap();
        assert_eq!(*executed, vec!["first", "second", "third"]);
        assert!(ctx.errors.is_empty());
    }

    #[tokio::test]
    async fn run_one_captures_error_and_continues() {
        let log = Arc::new(Mutex::new(Vec::new()));

        let pipeline = PipelineBuilder::new()
            .stage(TrackingStage { name: "before", log: log.clone() })
            .stage(FailingStage { name: "bad", log: log.clone() })
            .stage(TrackingStage { name: "after", log: log.clone() })
            .build();

        let mut ctx = test_ctx();
        pipeline.run_one(&mut ctx).await;

        // All three stages executed despite the middle one failing
        let executed = log.lock().unwrap();
        assert_eq!(*executed, vec!["before", "bad", "after"]);

        // Exactly one error captured with correct stage name and message
        assert_eq!(ctx.errors.len(), 1);
        assert_eq!(ctx.errors[0].stage, "bad");
        assert_eq!(ctx.errors[0].message, "boom");
    }
}
