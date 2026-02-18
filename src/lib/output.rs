use serde::Serialize;

use crate::action_ref::ActionRef;
use crate::advisory::Advisory;
use crate::context::AuditContext;
use crate::stages::dependency::DependencyReport;
use crate::stages::ScanResult;

#[derive(Serialize)]
pub struct ActionEntry {
    #[serde(flatten)]
    pub action: ActionRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_sha: Option<String>,
    pub advisories: Vec<Advisory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<ScanResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dep_vulnerabilities: Vec<DependencyReport>,
}

impl From<AuditContext> for ActionEntry {
    fn from(ctx: AuditContext) -> Self {
        Self {
            action: ctx.action,
            resolved_sha: ctx.resolved_ref,
            advisories: ctx.advisories,
            scan: ctx.scan,
            dep_vulnerabilities: ctx.dependencies,
        }
    }
}

#[derive(Serialize)]
pub struct AuditNode {
    #[serde(flatten)]
    pub entry: ActionEntry,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<AuditNode>,
}

impl From<AuditContext> for AuditNode {
    fn from(ctx: AuditContext) -> Self {
        Self {
            entry: ActionEntry::from(ctx),
            children: vec![],
        }
    }
}

pub trait OutputFormatter {
    fn write_results(
        &self,
        nodes: &[AuditNode],
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<()>;
}

pub struct TextOutput;

fn write_node(
    node: &AuditNode,
    depth: usize,
    writer: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let indent = "  ".repeat(depth);
    let entry = &node.entry;

    writeln!(writer, "{indent}{}", entry.action)?;

    if let Some(sha) = &entry.resolved_sha {
        writeln!(writer, "{indent}  sha: {sha}")?;
    }

    if let Some(scan) = &entry.scan {
        if let Some(lang) = &scan.primary_language {
            writeln!(writer, "{indent}  language: {lang}")?;
        }
        if !scan.ecosystems.is_empty() {
            let eco_list: Vec<String> =
                scan.ecosystems.iter().map(ToString::to_string).collect();
            writeln!(writer, "{indent}  ecosystems: {}", eco_list.join(", "))?;
        }
    }

    if entry.advisories.is_empty() {
        writeln!(writer, "{indent}  advisories: none")?;
    } else {
        for adv in &entry.advisories {
            writeln!(writer, "{indent}  {adv}")?;
        }
    }

    if !entry.dep_vulnerabilities.is_empty() {
        writeln!(writer, "{indent}  dependency vulnerabilities:")?;
        for dep in &entry.dep_vulnerabilities {
            writeln!(
                writer,
                "{indent}    {}@{} ({}):",
                dep.package, dep.version, dep.ecosystem
            )?;
            for adv in &dep.advisories {
                writeln!(writer, "{indent}      {adv}")?;
            }
        }
    }

    for child in &node.children {
        write_node(child, depth + 1, writer)?;
    }

    Ok(())
}

impl OutputFormatter for TextOutput {
    fn write_results(
        &self,
        nodes: &[AuditNode],
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        for node in nodes {
            write_node(node, 0, writer)?;
        }
        Ok(())
    }
}

pub struct JsonOutput;

impl OutputFormatter for JsonOutput {
    fn write_results(
        &self,
        nodes: &[AuditNode],
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        serde_json::to_writer_pretty(&mut *writer, nodes)?;
        writeln!(writer)?;
        Ok(())
    }
}

pub fn formatter(json: bool) -> Box<dyn OutputFormatter> {
    if json {
        Box::new(JsonOutput)
    } else {
        Box::new(TextOutput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_ref::ActionRef;

    fn sample_action() -> ActionRef {
        "actions/checkout@v4".parse::<ActionRef>().unwrap()
    }

    fn leaf_node(entry: ActionEntry) -> AuditNode {
        AuditNode {
            entry,
            children: vec![],
        }
    }

    fn sample_entry() -> ActionEntry {
        ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        }
    }

    #[test]
    fn text_output_basic() {
        let nodes = vec![leaf_node(sample_entry())];
        let mut buf = Vec::new();
        let fmt = TextOutput;
        fmt.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("actions/checkout@v4"));
        assert!(output.contains("advisories: none"));
    }

    #[test]
    fn text_output_with_sha() {
        let nodes = vec![leaf_node(ActionEntry {
            action: sample_action(),
            resolved_sha: Some("abc123".to_string()),
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        })];
        let mut buf = Vec::new();
        let fmt = TextOutput;
        fmt.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("actions/checkout@v4"));
        assert!(output.contains("  sha: abc123"));
    }

    #[test]
    fn text_output_with_no_advisories() {
        let nodes = vec![leaf_node(sample_entry())];
        let mut buf = Vec::new();
        let fmt = TextOutput;
        fmt.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("advisories: none"));
    }

    #[test]
    fn text_output_with_advisories() {
        let nodes = vec![leaf_node(ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![Advisory {
                id: "GHSA-1234".to_string(),
                aliases: vec![],
                summary: "Bad thing".to_string(),
                severity: "high".to_string(),
                url: "https://ghsa.example.com/1234".to_string(),
                affected_range: Some(">= 1.0, < 2.0".to_string()),
                source: "ghsa".to_string(),
            }],
            scan: None,
            dep_vulnerabilities: vec![],
        })];
        let mut buf = Vec::new();
        let fmt = TextOutput;
        fmt.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("GHSA-1234 (high): Bad thing"));
        assert!(output.contains("https://ghsa.example.com/1234"));
        assert!(output.contains("affected: >= 1.0, < 2.0"));
    }

    #[test]
    fn json_output_basic() {
        let nodes = vec![leaf_node(sample_entry())];
        let mut buf = Vec::new();
        let fmt = JsonOutput;
        fmt.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["raw"], "actions/checkout@v4");
        assert_eq!(arr[0]["owner"], "actions");
        assert_eq!(arr[0]["repo"], "checkout");
        assert_eq!(arr[0]["ref_type"], "tag");
        // resolved_sha should be absent when None
        assert!(arr[0].get("resolved_sha").is_none());
        // advisories is always present (now a Vec, not Option)
        assert!(arr[0].get("advisories").is_some());
        // children should be absent when empty
        assert!(
            arr[0].get("children").is_none(),
            "children key should be omitted when empty"
        );
    }

    #[test]
    fn json_output_with_all_fields() {
        let nodes = vec![leaf_node(ActionEntry {
            action: sample_action(),
            resolved_sha: Some("deadbeef".to_string()),
            advisories: vec![Advisory {
                id: "GHSA-1234".to_string(),
                aliases: vec![],
                summary: "Bad thing".to_string(),
                severity: "high".to_string(),
                url: "https://ghsa.example.com/1234".to_string(),
                affected_range: Some(">= 1.0".to_string()),
                source: "ghsa".to_string(),
            }],
            scan: None,
            dep_vulnerabilities: vec![],
        })];
        let mut buf = Vec::new();
        let fmt = JsonOutput;
        fmt.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr[0]["resolved_sha"], "deadbeef");
        assert_eq!(arr[0]["advisories"][0]["id"], "GHSA-1234");
    }

    #[test]
    fn factory_returns_json() {
        let f = formatter(true);
        let nodes = vec![leaf_node(sample_entry())];
        let mut buf = Vec::new();
        f.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Should be valid JSON
        serde_json::from_str::<serde_json::Value>(&output).unwrap();
    }

    #[test]
    fn factory_returns_text() {
        let f = formatter(false);
        let nodes = vec![leaf_node(sample_entry())];
        let mut buf = Vec::new();
        f.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("actions/checkout@v4"));
        assert!(output.contains("advisories: none"));
    }

    #[test]
    fn json_output_omits_scan_when_none() {
        let nodes = vec![leaf_node(sample_entry())];
        let mut buf = Vec::new();
        JsonOutput.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert!(arr[0].get("scan").is_none());
    }

    #[test]
    fn json_output_includes_scan_when_present() {
        use crate::stages::{Ecosystem, ScanResult};
        let nodes = vec![leaf_node(ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![],
            scan: Some(ScanResult {
                primary_language: Some("TypeScript".to_string()),
                ecosystems: vec![Ecosystem::Npm, Ecosystem::Docker],
            }),
            dep_vulnerabilities: vec![],
        })];
        let mut buf = Vec::new();
        JsonOutput.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        let scan = &arr[0]["scan"];
        assert_eq!(scan["primary_language"], "TypeScript");
        let ecos = scan["ecosystems"].as_array().unwrap();
        assert_eq!(ecos.len(), 2);
        assert_eq!(ecos[0], "npm");
        assert_eq!(ecos[1], "docker");
    }

    #[test]
    fn audit_context_converts_to_action_entry() {
        use crate::context::AuditContext;
        use crate::stages::{Ecosystem, ScanResult};

        let ctx = AuditContext {
            action: sample_action(),
            depth: 0,
            parent: None,
            children: vec![],
            resolved_ref: Some("abc123".to_string()),
            advisories: vec![Advisory {
                id: "GHSA-1234".to_string(),
                aliases: vec![],
                summary: "Bad thing".to_string(),
                severity: "high".to_string(),
                url: "https://example.com".to_string(),
                affected_range: None,
                source: "ghsa".to_string(),
            }],
            scan: Some(ScanResult {
                primary_language: Some("TypeScript".to_string()),
                ecosystems: vec![Ecosystem::Npm],
            }),
            dependencies: vec![],
            errors: vec![],
        };

        let entry: ActionEntry = ctx.into();
        assert_eq!(entry.action, sample_action());
        assert_eq!(entry.resolved_sha, Some("abc123".to_string()));
        assert_eq!(entry.advisories.len(), 1);
        assert_eq!(entry.advisories[0].id, "GHSA-1234");
        assert!(entry.scan.is_some());
        assert!(entry.dep_vulnerabilities.is_empty());
    }

    #[test]
    fn text_output_with_scan_data() {
        use crate::stages::{Ecosystem, ScanResult};
        let nodes = vec![leaf_node(ActionEntry {
            action: sample_action(),
            resolved_sha: Some("abc123".to_string()),
            advisories: vec![],
            scan: Some(ScanResult {
                primary_language: Some("TypeScript".to_string()),
                ecosystems: vec![Ecosystem::Npm, Ecosystem::Docker],
            }),
            dep_vulnerabilities: vec![],
        })];
        let mut buf = Vec::new();
        TextOutput.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("language: TypeScript"));
        assert!(output.contains("ecosystems: npm, docker"));
        assert!(output.contains("sha: abc123"));
        assert!(output.contains("advisories: none"));
    }

    #[test]
    fn audit_node_from_context() {
        use crate::context::AuditContext;

        let ctx = AuditContext {
            action: sample_action(),
            depth: 0,
            parent: None,
            children: vec![],
            resolved_ref: Some("abc123".to_string()),
            advisories: vec![Advisory {
                id: "GHSA-5678".to_string(),
                aliases: vec![],
                summary: "Test advisory".to_string(),
                severity: "medium".to_string(),
                url: "https://example.com/5678".to_string(),
                affected_range: None,
                source: "ghsa".to_string(),
            }],
            scan: None,
            dependencies: vec![],
            errors: vec![],
        };

        let node: AuditNode = ctx.into();
        assert_eq!(node.entry.action, sample_action());
        assert_eq!(node.entry.resolved_sha, Some("abc123".to_string()));
        assert_eq!(node.entry.advisories.len(), 1);
        assert_eq!(node.entry.advisories[0].id, "GHSA-5678");
        assert!(node.entry.scan.is_none());
        assert!(node.entry.dep_vulnerabilities.is_empty());
        assert!(node.children.is_empty());
    }

    #[test]
    fn audit_node_serialization_omits_empty_children() {
        let node = leaf_node(sample_entry());

        let json = serde_json::to_string(&node).unwrap();
        assert!(
            !json.contains("\"children\""),
            "expected 'children' key to be absent in JSON, got: {json}"
        );
    }

    #[test]
    fn audit_node_serialization_includes_children() {
        let child = leaf_node(ActionEntry {
            action: "actions/setup-node@v4".parse::<ActionRef>().unwrap(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        });

        let parent = AuditNode {
            entry: ActionEntry {
                action: sample_action(),
                resolved_sha: None,
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![child],
        };

        let json = serde_json::to_string_pretty(&parent).unwrap();
        assert!(
            json.contains("\"children\""),
            "expected 'children' key in JSON, got: {json}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let children = parsed["children"].as_array().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0]["raw"], "actions/setup-node@v4");
    }

    // --- Regression tests: depth-0 (flat) output matches legacy format ---

    #[test]
    fn text_regression_flat_nodes_match_legacy_format() {
        // Flat AuditNodes (no children) must produce identical output to old ActionEntry format
        let nodes = vec![
            leaf_node(ActionEntry {
                action: sample_action(),
                resolved_sha: Some("abc123".to_string()),
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            }),
            leaf_node(ActionEntry {
                action: "actions/setup-node@v4".parse::<ActionRef>().unwrap(),
                resolved_sha: None,
                advisories: vec![Advisory {
                    id: "GHSA-9999".to_string(),
                    aliases: vec![],
                    summary: "Something bad".to_string(),
                    severity: "critical".to_string(),
                    url: "https://example.com/9999".to_string(),
                    affected_range: None,
                    source: "osv".to_string(),
                }],
                scan: None,
                dep_vulnerabilities: vec![],
            }),
        ];
        let mut buf = Vec::new();
        TextOutput.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // First entry: action line starts at column 0, enrichment indented by 2 spaces
        assert!(output.starts_with("actions/checkout@v4\n"));
        assert!(output.contains("  sha: abc123\n"));
        assert!(output.contains("  advisories: none\n"));
        // Second entry: action line starts at column 0
        assert!(output.contains("actions/setup-node@v4\n"));
        // No leading spaces on action lines
        for line in output.lines() {
            if !line.starts_with(' ') {
                // action lines: no leading whitespace
                assert!(
                    line == "actions/checkout@v4" || line == "actions/setup-node@v4",
                    "unexpected non-indented line: {line}"
                );
            }
        }
    }

    #[test]
    fn json_regression_flat_nodes_omit_children_key() {
        let nodes = vec![
            leaf_node(sample_entry()),
            leaf_node(ActionEntry {
                action: "actions/setup-node@v4".parse::<ActionRef>().unwrap(),
                resolved_sha: None,
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            }),
        ];
        let mut buf = Vec::new();
        JsonOutput.write_results(&nodes, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        for entry in arr {
            assert!(
                entry.get("children").is_none(),
                "children key should be absent for flat nodes, got: {entry}"
            );
        }
    }

    // --- Tree-specific tests ---

    #[test]
    fn text_output_two_level_tree_indentation() {
        let child = leaf_node(ActionEntry {
            action: "actions/setup-node@v4".parse::<ActionRef>().unwrap(),
            resolved_sha: Some("child-sha".to_string()),
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        });
        let parent = AuditNode {
            entry: ActionEntry {
                action: sample_action(),
                resolved_sha: Some("parent-sha".to_string()),
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![child],
        };

        let mut buf = Vec::new();
        TextOutput.write_results(&[parent], &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();

        // Depth 0: parent action at column 0
        assert_eq!(lines[0], "actions/checkout@v4");
        assert_eq!(lines[1], "  sha: parent-sha");
        assert_eq!(lines[2], "  advisories: none");
        // Depth 1: child action indented by 2 spaces
        assert_eq!(lines[3], "  actions/setup-node@v4");
        assert_eq!(lines[4], "    sha: child-sha");
        assert_eq!(lines[5], "    advisories: none");
    }

    #[test]
    fn text_output_three_level_tree_indentation() {
        let grandchild = leaf_node(ActionEntry {
            action: "codecov/codecov-action@v3".parse::<ActionRef>().unwrap(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        });
        let child = AuditNode {
            entry: ActionEntry {
                action: "actions/setup-node@v4".parse::<ActionRef>().unwrap(),
                resolved_sha: None,
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![grandchild],
        };
        let root = AuditNode {
            entry: ActionEntry {
                action: sample_action(),
                resolved_sha: None,
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![child],
        };

        let mut buf = Vec::new();
        TextOutput.write_results(&[root], &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = output.lines().collect();

        // Depth 0
        assert_eq!(lines[0], "actions/checkout@v4");
        assert_eq!(lines[1], "  advisories: none");
        // Depth 1
        assert_eq!(lines[2], "  actions/setup-node@v4");
        assert_eq!(lines[3], "    advisories: none");
        // Depth 2
        assert_eq!(lines[4], "    codecov/codecov-action@v3");
        assert_eq!(lines[5], "      advisories: none");
    }

    #[test]
    fn json_output_nested_children() {
        let child = leaf_node(ActionEntry {
            action: "actions/setup-node@v4".parse::<ActionRef>().unwrap(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        });
        let parent = AuditNode {
            entry: ActionEntry {
                action: sample_action(),
                resolved_sha: None,
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![child],
        };

        let mut buf = Vec::new();
        JsonOutput.write_results(&[parent], &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["raw"], "actions/checkout@v4");

        let children = arr[0]["children"].as_array().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0]["raw"], "actions/setup-node@v4");
        // Grandchildren should be absent (empty)
        assert!(children[0].get("children").is_none());
    }

    #[test]
    fn text_output_dep_vulnerabilities_with_depth() {
        use crate::stages::dependency::DependencyReport;
        use crate::stages::Ecosystem;

        let child = leaf_node(ActionEntry {
            action: "actions/setup-node@v4".parse::<ActionRef>().unwrap(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![DependencyReport {
                package: "lodash".to_string(),
                version: "4.17.20".to_string(),
                ecosystem: Ecosystem::Npm,
                advisories: vec![Advisory {
                    id: "GHSA-dep1".to_string(),
                    aliases: vec![],
                    summary: "Prototype pollution".to_string(),
                    severity: "high".to_string(),
                    url: "https://example.com/dep1".to_string(),
                    affected_range: None,
                    source: "osv".to_string(),
                }],
            }],
        });
        let root = AuditNode {
            entry: sample_entry(),
            children: vec![child],
        };

        let mut buf = Vec::new();
        TextOutput.write_results(&[root], &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Child dep vuln lines should be indented at depth 1 (2 spaces base)
        assert!(output.contains("    dependency vulnerabilities:"));
        assert!(output.contains("      lodash@4.17.20 (npm):"));
        assert!(output.contains("        GHSA-dep1"));
    }
}
