use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Workflow {
    #[serde(default)]
    pub jobs: HashMap<String, serde_yaml::Value>,
}

#[derive(Deserialize)]
pub struct Job {
    #[serde(default)]
    pub steps: Option<Vec<Step>>,
}

#[derive(Deserialize)]
pub struct Step {
    pub uses: Option<String>,
    #[serde(flatten)]
    pub _extra: serde_yaml::Value,
}

pub fn parse_workflow(path: &Path) -> anyhow::Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)?;
    let workflow: Workflow = serde_yaml::from_str(&contents)?;

    let mut uses_refs = Vec::new();

    for (job_name, job_value) in &workflow.jobs {
        match serde_yaml::from_value::<Job>(job_value.clone()) {
            Ok(job) => {
                if let Some(steps) = job.steps {
                    for step in steps {
                        if let Some(uses) = step.uses {
                            uses_refs.push(uses);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("warning: failed to parse job '{}': {}", job_name, e);
            }
        }
    }

    Ok(uses_refs)
}
