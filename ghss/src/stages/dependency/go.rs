use anyhow::{Context, Result};

use crate::action_ref::ActionRef;
use crate::github::GitHubClient;
use crate::stages::Ecosystem;

/// Fetch and parse Go module dependencies from an action's go.mod.
///
/// Returns an empty Vec if the action's ecosystems don't include Go.
pub(super) async fn fetch_go_packages(
    action: &ActionRef,
    ecosystems: &[Ecosystem],
    client: &GitHubClient,
) -> Result<Vec<(String, String)>> {
    if !ecosystems.contains(&Ecosystem::Go) {
        return Ok(vec![]);
    }

    let content = client
        .get_raw_content(&action.owner, &action.repo, &action.git_ref, "go.mod")
        .await
        .with_context(|| {
            format!(
                "failed to fetch go.mod for {}/{}",
                action.owner, action.repo
            )
        })?;

    let deps = parse_go_mod(&content)?;
    tracing::debug!(count = deps.len(), "found go module dependencies");
    Ok(deps)
}

fn parse_go_mod(content: &str) -> Result<Vec<(String, String)>> {
    let mut deps = Vec::new();
    let mut in_require_block = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        if trimmed.starts_with("require") && trimmed.contains('(') {
            in_require_block = true;
            continue;
        }

        if trimmed == ")" {
            in_require_block = false;
            continue;
        }

        if in_require_block {
            if let Some(dep) = parse_require_line(trimmed) {
                deps.push(dep);
            }
        } else if let Some(rest) = trimmed.strip_prefix("require") {
            let rest = rest.trim();
            if let Some(dep) = parse_require_line(rest) {
                deps.push(dep);
            }
        }
    }

    Ok(deps)
}

/// Parse a single require entry: "module/path v1.2.3 // indirect"
/// Returns (module_path, version_without_v_prefix).
fn parse_require_line(line: &str) -> Option<(String, String)> {
    let line = line.split("//").next()?.trim();
    let mut parts = line.split_whitespace();
    let module = parts.next()?;
    let version_raw = parts.next()?;

    let version = version_raw.strip_prefix('v').unwrap_or(version_raw);

    Some((module.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_go_mod_block_require() {
        let content = r#"
module example.com/myaction

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/net v0.17.0
)
"#;
        let deps = parse_go_mod(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&("github.com/gin-gonic/gin".to_string(), "1.9.1".to_string())));
        assert!(deps.contains(&("golang.org/x/net".to_string(), "0.17.0".to_string())));
    }

    #[test]
    fn parse_go_mod_single_line_require() {
        let content = r#"
module example.com/myaction

go 1.21

require github.com/gin-gonic/gin v1.9.1
require golang.org/x/net v0.17.0
"#;
        let deps = parse_go_mod(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&("github.com/gin-gonic/gin".to_string(), "1.9.1".to_string())));
        assert!(deps.contains(&("golang.org/x/net".to_string(), "0.17.0".to_string())));
    }

    #[test]
    fn parse_go_mod_multiple_blocks() {
        let content = r#"
module example.com/myaction

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
)

require (
    golang.org/x/net v0.17.0
)
"#;
        let deps = parse_go_mod(content).unwrap();
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn parse_go_mod_indirect_included() {
        let content = r#"
module example.com/myaction

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/net v0.17.0 // indirect
)
"#;
        let deps = parse_go_mod(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.contains(&("golang.org/x/net".to_string(), "0.17.0".to_string())));
    }

    #[test]
    fn parse_go_mod_empty() {
        let content = r#"
module example.com/myaction

go 1.21
"#;
        let deps = parse_go_mod(content).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn parse_go_mod_strips_v_prefix() {
        let content = "require github.com/foo/bar v1.9.1\n";
        let deps = parse_go_mod(content).unwrap();
        assert_eq!(deps[0].1, "1.9.1");
    }

    #[test]
    fn parse_go_mod_incompatible_suffix() {
        let content = "require github.com/foo/bar v2.0.0+incompatible\n";
        let deps = parse_go_mod(content).unwrap();
        assert_eq!(deps[0].1, "2.0.0+incompatible");
    }

    #[test]
    fn parse_go_mod_with_replace() {
        let content = r#"
module example.com/myaction

go 1.21

require github.com/gin-gonic/gin v1.9.1

replace github.com/gin-gonic/gin => github.com/fork/gin v1.9.2

exclude github.com/old/dep v1.0.0
"#;
        let deps = parse_go_mod(content).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].0, "github.com/gin-gonic/gin");
    }

    #[test]
    fn fetch_go_packages_skips_non_go() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let action: ActionRef = "actions/checkout@v4".parse().unwrap();
            let client = GitHubClient::new(None);
            let result =
                fetch_go_packages(&action, &[Ecosystem::Npm, Ecosystem::Cargo], &client).await;
            assert!(result.unwrap().is_empty());
        });
    }
}
