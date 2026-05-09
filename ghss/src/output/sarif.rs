//! SARIF v2.1.0 output for GitHub Code Scanning ingestion.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_sarif::sarif::{
    ArtifactLocation, Location, Message, MultiformatMessageString, PhysicalLocation, PropertyBag,
    Region, ReportingDescriptor, Result as SarifResult, ResultLevel, Run, Sarif, Tool,
    ToolComponent,
};
use sha2::{Digest, Sha256};

use crate::action_ref::ActionRef;
use crate::advisory::{Advisory, Severity};
use crate::output::{AuditNode, OutputFormatter};

const RULE_VULNERABLE_ACTION: &str = "ghss/vulnerable-action";
const RULE_VULNERABLE_DEPENDENCY: &str = "ghss/vulnerable-dependency";

const SARIF_SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const TOOL_INFORMATION_URI: &str = "https://github.com/Valinora/ghss";

/// Tool identity and homepage metadata advertised in the SARIF driver.
/// Operators (e.g. the scanner with a configured `[upload]` section)
/// can substitute custom values without forking the library.
#[derive(Debug, Clone, Copy)]
pub struct ToolMetadata<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub information_uri: &'a str,
}

impl ToolMetadata<'static> {
    /// Default identity: `ghss`, the crate version, and the canonical
    /// project URL.
    pub const fn default_const() -> Self {
        Self {
            name: "ghss",
            version: env!("CARGO_PKG_VERSION"),
            information_uri: TOOL_INFORMATION_URI,
        }
    }
}

impl Default for ToolMetadata<'static> {
    fn default() -> Self {
        Self::default_const()
    }
}

pub struct SarifOutput {
    pub workflow_path: PathBuf,
    pub tool_version: &'static str,
}

impl SarifOutput {
    pub fn new(workflow_path: PathBuf) -> Self {
        Self {
            workflow_path,
            tool_version: env!("CARGO_PKG_VERSION"),
        }
    }
}

impl OutputFormatter for SarifOutput {
    fn write_results(
        &self,
        nodes: &[AuditNode],
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        let sarif = build_sarif_log(nodes, &self.workflow_path, self.tool_version);
        serde_json::to_writer_pretty(&mut *writer, &sarif)?;
        writeln!(writer)?;
        Ok(())
    }
}

/// Single-workflow convenience wrapper used by the CLI. Treats `nodes` as
/// the audit set for a single workflow file. Prefer
/// `build_repo_sarif_log` when emitting findings across multiple
/// workflows in one repo.
pub fn build_sarif_log(nodes: &[AuditNode], workflow_path: &Path, tool_version: &str) -> Sarif {
    let actions: Vec<ActionRef> = nodes.iter().map(|n| n.entry.action.clone()).collect();
    let attribution = vec![(workflow_path.to_path_buf(), actions)];
    let tool = ToolMetadata {
        version: tool_version,
        ..ToolMetadata::default_const()
    };
    build_repo_sarif_log(nodes, &attribution, &tool)
}

/// Build a SARIF log spanning multiple workflow files in one repo.
///
/// `nodes` is the deduplicated set of audit nodes for the repo (one per
/// unique top-level action ref). `attribution` is metadata mapping each
/// workflow file path to the action refs that workflow contains; the
/// builder indexes `nodes` by `entry.action` and emits one set of
/// results per attribution entry. Children of a node inherit the
/// parent's workflow path.
pub fn build_repo_sarif_log(
    nodes: &[AuditNode],
    attribution: &[(PathBuf, Vec<ActionRef>)],
    tool: &ToolMetadata<'_>,
) -> Sarif {
    let index: BTreeMap<&ActionRef, &AuditNode> =
        nodes.iter().map(|n| (&n.entry.action, n)).collect();

    let mut results = Vec::new();
    for (path, actions) in attribution {
        let workflow_uri = path.to_string_lossy().into_owned();
        for action in actions {
            if let Some(node) = index.get(action) {
                collect_results(node, &workflow_uri, &mut results, &[]);
            }
        }
    }

    let driver = ToolComponent::builder()
        .name(tool.name.to_string())
        .semantic_version(tool.version.to_string())
        .information_uri(tool.information_uri.to_string())
        .rules(rules())
        .build();

    let sarif_tool = Tool::builder().driver(driver).build();

    let run = Run::builder().tool(sarif_tool).results(results).build();

    Sarif::builder()
        .schema(SARIF_SCHEMA_URL.to_string())
        .version(serde_json::Value::String("2.1.0".to_string()))
        .runs(vec![run])
        .build()
}

fn collect_results(
    node: &AuditNode,
    workflow_uri: &str,
    out: &mut Vec<SarifResult>,
    ancestors: &[String],
) {
    let action_str = node.entry.action.to_string();
    let path_descriptor = if ancestors.is_empty() {
        action_str.clone()
    } else {
        format!(
            "{} (via {} → {action_str})",
            action_str,
            ancestors.join(" → ")
        )
    };

    for advisory in &node.entry.advisories {
        out.push(make_result(
            workflow_uri,
            RULE_VULNERABLE_ACTION,
            &node.entry.action,
            &advisory.id,
            advisory,
            &format!(
                "{} — {}: {}",
                advisory.id, path_descriptor, advisory.summary
            ),
        ));
    }

    for dep in &node.entry.dep_vulnerabilities {
        for advisory in &dep.advisories {
            let dep_subject = format!("{}@{}", dep.package, dep.version);
            let message = format!(
                "{} — {}@{} ({} dep of {}): {}",
                advisory.id,
                dep.package,
                dep.version,
                dep.ecosystem,
                path_descriptor,
                advisory.summary
            );
            out.push(make_dep_result(
                workflow_uri,
                &dep_subject,
                &advisory.id,
                advisory,
                &message,
            ));
        }
    }

    if !node.children.is_empty() {
        let mut next_ancestors: Vec<String> = ancestors.to_vec();
        next_ancestors.push(action_str);
        for child in &node.children {
            collect_results(child, workflow_uri, out, &next_ancestors);
        }
    }
}

fn make_result(
    workflow_uri: &str,
    rule_id: &str,
    action: &ActionRef,
    advisory_id: &str,
    advisory: &Advisory,
    message_text: &str,
) -> SarifResult {
    let fingerprint_subject = action.package_name();
    finish_result(
        workflow_uri,
        rule_id,
        &fingerprint_subject,
        advisory_id,
        advisory,
        message_text,
    )
}

fn make_dep_result(
    workflow_uri: &str,
    dep_subject: &str,
    advisory_id: &str,
    advisory: &Advisory,
    message_text: &str,
) -> SarifResult {
    finish_result(
        workflow_uri,
        RULE_VULNERABLE_DEPENDENCY,
        dep_subject,
        advisory_id,
        advisory,
        message_text,
    )
}

fn finish_result(
    workflow_uri: &str,
    rule_id: &str,
    fingerprint_subject: &str,
    advisory_id: &str,
    advisory: &Advisory,
    message_text: &str,
) -> SarifResult {
    let (level, security_severity) = map_severity(advisory);

    let region = Region::builder()
        .start_line(1i64)
        .end_line(1i64)
        .start_column(1i64)
        .end_column(1i64)
        .build();

    let artifact = ArtifactLocation::builder()
        .uri(workflow_uri.to_string())
        .build();

    let physical = PhysicalLocation::builder()
        .artifact_location(artifact)
        .region(region)
        .build();

    let location = Location::builder().physical_location(physical).build();

    let mut additional = BTreeMap::new();
    additional.insert(
        "security-severity".to_string(),
        serde_json::Value::String(security_severity.to_string()),
    );
    let result_props = PropertyBag::builder()
        .additional_properties(additional)
        .build();

    let mut fps: BTreeMap<String, String> = BTreeMap::new();
    fps.insert(
        "primaryLocationLineHash".to_string(),
        fingerprint(workflow_uri, fingerprint_subject, advisory_id),
    );

    SarifResult::builder()
        .rule_id(rule_id.to_string())
        .level(level)
        .message(Message::builder().text(message_text.to_string()).build())
        .locations(vec![location])
        .properties(result_props)
        .partial_fingerprints(fps)
        .build()
}

fn map_severity(advisory: &Advisory) -> (ResultLevel, &'static str) {
    match advisory.parsed_severity() {
        Some(Severity::Critical) => (ResultLevel::Error, "9.5"),
        Some(Severity::High) => (ResultLevel::Error, "8.0"),
        Some(Severity::Medium) => (ResultLevel::Warning, "5.5"),
        Some(Severity::Low) => (ResultLevel::Note, "2.0"),
        None => (ResultLevel::Warning, "5.0"),
    }
}

fn fingerprint(workflow_path: &str, package_name: &str, advisory_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(workflow_path.as_bytes());
    hasher.update(b"|");
    hasher.update(package_name.as_bytes());
    hasher.update(b"|");
    hasher.update(advisory_id.as_bytes());
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(s, "{byte:02x}").expect("writing to String never fails");
    }
    s
}

fn rules() -> Vec<ReportingDescriptor> {
    vec![rule_vulnerable_action(), rule_vulnerable_dependency()]
}

fn security_tags() -> Vec<String> {
    vec!["security".to_string(), "supply-chain".to_string()]
}

fn rule_vulnerable_action() -> ReportingDescriptor {
    let props = PropertyBag::builder().tags(security_tags()).build();

    ReportingDescriptor::builder()
        .id(RULE_VULNERABLE_ACTION.to_string())
        .name("VulnerableAction".to_string())
        .short_description(
            MultiformatMessageString::builder()
                .text("A referenced GitHub Action has a known security advisory.".to_string())
                .build(),
        )
        .full_description(
            MultiformatMessageString::builder()
                .text(
                    "ghss matched the action's package coordinates against advisory providers \
                     (GHSA, OSV) and found one or more advisories applicable to the resolved \
                     version. Update the action reference to a fixed version or remove the action."
                        .to_string(),
                )
                .build(),
        )
        .help(
            MultiformatMessageString::builder()
                .text(
                    "Update the action reference to a non-vulnerable version. See the linked \
                     advisory in the result message for details."
                        .to_string(),
                )
                .build(),
        )
        .properties(props)
        .build()
}

fn rule_vulnerable_dependency() -> ReportingDescriptor {
    let props = PropertyBag::builder().tags(security_tags()).build();

    ReportingDescriptor::builder()
        .id(RULE_VULNERABLE_DEPENDENCY.to_string())
        .name("VulnerableDependency".to_string())
        .short_description(
            MultiformatMessageString::builder()
                .text(
                    "A package dependency declared by a referenced GitHub Action has a known \
                     security advisory."
                        .to_string(),
                )
                .build(),
        )
        .full_description(
            MultiformatMessageString::builder()
                .text(
                    "ghss inspected the action's repository for ecosystem manifests (e.g. \
                     package.json) and matched the declared dependencies against advisory \
                     providers. The flagged dependency version is affected by a known advisory."
                        .to_string(),
                )
                .build(),
        )
        .help(
            MultiformatMessageString::builder()
                .text(
                    "Upgrade the affected dependency to a non-vulnerable version, or replace the \
                     action with one that does not pull in the affected package."
                        .to_string(),
                )
                .build(),
        )
        .properties(props)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_ref::ActionRef;
    use crate::output::{ActionEntry, AuditNode};
    use crate::stages::Ecosystem;
    use crate::stages::dependency::DependencyReport;

    fn advisory(id: &str, severity: &str) -> Advisory {
        Advisory {
            id: id.to_string(),
            aliases: vec![],
            summary: format!("Issue {id}"),
            severity: severity.to_string(),
            url: format!("https://example.com/{id}"),
            affected_range: None,
            source: "ghsa".to_string(),
        }
    }

    fn leaf_with_advisories(uses: &str, advs: Vec<Advisory>) -> AuditNode {
        AuditNode {
            entry: ActionEntry {
                action: uses.parse::<ActionRef>().unwrap(),
                resolved_sha: None,
                advisories: advs,
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![],
        }
    }

    #[test]
    fn build_sarif_log_minimal_shape() {
        let nodes = vec![leaf_with_advisories(
            "actions/checkout@v1",
            vec![advisory("GHSA-aaaa", "high")],
        )];

        let sarif = build_sarif_log(&nodes, Path::new(".github/workflows/ci.yml"), "0.0.0-test");
        let json = serde_json::to_value(&sarif).unwrap();

        assert_eq!(json["version"], "2.1.0");
        assert!(json["$schema"].is_string());
        assert_eq!(json["runs"].as_array().unwrap().len(), 1);

        let driver = &json["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "ghss");
        assert_eq!(driver["semanticVersion"], "0.0.0-test");
        let rules = driver["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], RULE_VULNERABLE_ACTION);
        assert_eq!(rules[1]["id"], RULE_VULNERABLE_DEPENDENCY);
        // Security tags must be present so security-severity is honored.
        let action_tags = rules[0]["properties"]["tags"].as_array().unwrap();
        assert!(action_tags.iter().any(|t| t == "security"));
    }

    #[test]
    fn build_sarif_log_emits_one_result_per_advisory() {
        let nodes = vec![leaf_with_advisories(
            "actions/checkout@v1",
            vec![
                advisory("GHSA-aaaa", "high"),
                advisory("GHSA-bbbb", "critical"),
            ],
        )];

        let sarif = build_sarif_log(&nodes, Path::new(".github/workflows/ci.yml"), "test");
        let json = serde_json::to_value(&sarif).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);

        // Severity → level mapping: high → error, critical → error
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "error");
        // security-severity strings present
        assert_eq!(results[0]["properties"]["security-severity"], "8.0");
        assert_eq!(results[1]["properties"]["security-severity"], "9.5");
    }

    #[test]
    fn build_sarif_log_severity_mapping_covers_all_levels() {
        let nodes = vec![leaf_with_advisories(
            "actions/checkout@v1",
            vec![
                advisory("GHSA-low", "low"),
                advisory("GHSA-med", "medium"),
                advisory("GHSA-high", "high"),
                advisory("GHSA-crit", "critical"),
                advisory("GHSA-unk", "moderate"),
            ],
        )];

        let sarif = build_sarif_log(&nodes, Path::new("workflow.yml"), "test");
        let json = serde_json::to_value(&sarif).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 5);

        let levels: Vec<&str> = results
            .iter()
            .map(|r| r["level"].as_str().unwrap())
            .collect();
        let scores: Vec<&str> = results
            .iter()
            .map(|r| r["properties"]["security-severity"].as_str().unwrap())
            .collect();
        assert_eq!(levels, ["note", "warning", "error", "error", "warning"]);
        assert_eq!(scores, ["2.0", "5.5", "8.0", "9.5", "5.0"]);
    }

    #[test]
    fn build_sarif_log_emits_dependency_results() {
        let entry = ActionEntry {
            action: "actions/checkout@v1".parse::<ActionRef>().unwrap(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![DependencyReport {
                package: "lodash".to_string(),
                version: "4.17.20".to_string(),
                ecosystem: Ecosystem::Npm,
                advisories: vec![advisory("GHSA-dep", "critical")],
            }],
        };
        let nodes = vec![AuditNode {
            entry,
            children: vec![],
        }];

        let sarif = build_sarif_log(&nodes, Path::new("workflow.yml"), "test");
        let json = serde_json::to_value(&sarif).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], RULE_VULNERABLE_DEPENDENCY);
        assert!(
            results[0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains("lodash@4.17.20")
        );
    }

    #[test]
    fn build_sarif_log_locations_point_at_workflow() {
        let nodes = vec![leaf_with_advisories(
            "actions/checkout@v1",
            vec![advisory("GHSA-aaaa", "high")],
        )];

        let sarif = build_sarif_log(&nodes, Path::new(".github/workflows/ci.yml"), "test");
        let json = serde_json::to_value(&sarif).unwrap();
        let loc = &json["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], ".github/workflows/ci.yml");
        // GitHub requires all four region fields.
        assert_eq!(loc["region"]["startLine"], 1);
        assert_eq!(loc["region"]["endLine"], 1);
        assert_eq!(loc["region"]["startColumn"], 1);
        assert_eq!(loc["region"]["endColumn"], 1);
    }

    #[test]
    fn build_sarif_log_sets_fingerprints() {
        let nodes = vec![leaf_with_advisories(
            "actions/checkout@v1",
            vec![advisory("GHSA-aaaa", "high")],
        )];

        let sarif = build_sarif_log(&nodes, Path::new(".github/workflows/ci.yml"), "test");
        let json = serde_json::to_value(&sarif).unwrap();
        let fp = &json["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"];
        let fp_str = fp.as_str().unwrap();
        // SHA-256 hex == 64 chars
        assert_eq!(fp_str.len(), 64);
        assert!(fp_str.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_stable_for_same_inputs() {
        let a = fingerprint("workflow.yml", "actions/checkout", "GHSA-1");
        let b = fingerprint("workflow.yml", "actions/checkout", "GHSA-1");
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprint_differs_for_different_advisories() {
        let a = fingerprint("workflow.yml", "actions/checkout", "GHSA-1");
        let b = fingerprint("workflow.yml", "actions/checkout", "GHSA-2");
        assert_ne!(a, b);
    }

    #[test]
    fn build_sarif_log_recurses_into_children_with_path_descriptor() {
        let child = leaf_with_advisories(
            "actions/setup-node@v1",
            vec![advisory("GHSA-child", "high")],
        );
        let parent = AuditNode {
            entry: ActionEntry {
                action: "actions/checkout@v1".parse::<ActionRef>().unwrap(),
                resolved_sha: None,
                advisories: vec![],
                scan: None,
                dep_vulnerabilities: vec![],
            },
            children: vec![child],
        };

        let sarif = build_sarif_log(&[parent], Path::new("workflow.yml"), "test");
        let json = serde_json::to_value(&sarif).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        let msg = results[0]["message"]["text"].as_str().unwrap();
        assert!(msg.contains("actions/setup-node@v1"));
        assert!(msg.contains("via actions/checkout@v1"));
    }

    #[test]
    fn build_repo_sarif_log_indexes_nodes_by_action_ref() {
        // One deduplicated audit node, referenced by two workflows.
        let action: ActionRef = "actions/checkout@v1".parse().unwrap();
        let nodes = vec![leaf_with_advisories(
            "actions/checkout@v1",
            vec![advisory("GHSA-shared", "high")],
        )];

        let attribution = vec![
            (
                PathBuf::from(".github/workflows/ci.yml"),
                vec![action.clone()],
            ),
            (
                PathBuf::from(".github/workflows/deploy.yml"),
                vec![action.clone()],
            ),
        ];

        let tool = ToolMetadata {
            version: "test",
            ..ToolMetadata::default_const()
        };
        let sarif = build_repo_sarif_log(&nodes, &attribution, &tool);
        let json = serde_json::to_value(&sarif).unwrap();

        let results = json["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results.len(),
            2,
            "one result per (workflow × advisory) — single dedup'd node referenced twice"
        );

        let uris: Vec<&str> = results
            .iter()
            .map(|r| {
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    .as_str()
                    .unwrap()
            })
            .collect();
        assert!(uris.contains(&".github/workflows/ci.yml"));
        assert!(uris.contains(&".github/workflows/deploy.yml"));

        let fps: Vec<&str> = results
            .iter()
            .map(|r| {
                r["partialFingerprints"]["primaryLocationLineHash"]
                    .as_str()
                    .unwrap()
            })
            .collect();
        assert_ne!(
            fps[0], fps[1],
            "same advisory in different workflows must produce distinct fingerprints"
        );
    }

    #[test]
    fn build_repo_sarif_log_uses_tool_metadata() {
        let nodes = vec![leaf_with_advisories(
            "actions/checkout@v1",
            vec![advisory("GHSA-x", "high")],
        )];
        let action: ActionRef = "actions/checkout@v1".parse().unwrap();
        let attribution = vec![(PathBuf::from("ci.yml"), vec![action])];

        let tool = ToolMetadata {
            name: "acme-scanner",
            version: "9.9.9",
            information_uri: "https://example.com/acme",
        };
        let sarif = build_repo_sarif_log(&nodes, &attribution, &tool);
        let json = serde_json::to_value(&sarif).unwrap();
        let driver = &json["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "acme-scanner");
        assert_eq!(driver["semanticVersion"], "9.9.9");
        assert_eq!(driver["informationUri"], "https://example.com/acme");
    }

    #[test]
    fn build_repo_sarif_log_skips_attribution_entries_with_unknown_actions() {
        // Defensive: if attribution references an action not present in
        // nodes (shouldn't happen in normal flow), skip silently rather
        // than panic.
        let nodes: Vec<AuditNode> = vec![];
        let bogus: ActionRef = "actions/checkout@v1".parse().unwrap();
        let attribution = vec![(PathBuf::from("ci.yml"), vec![bogus])];
        let tool = ToolMetadata::default_const();
        let sarif = build_repo_sarif_log(&nodes, &attribution, &tool);
        let json = serde_json::to_value(&sarif).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn build_repo_sarif_log_empty_input_produces_zero_results() {
        let tool = ToolMetadata::default_const();
        let sarif = build_repo_sarif_log(&[], &[], &tool);
        let json = serde_json::to_value(&sarif).unwrap();
        let results = json["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn sarif_output_writer_produces_valid_json() {
        let nodes = vec![leaf_with_advisories(
            "actions/checkout@v1",
            vec![advisory("GHSA-aaaa", "high")],
        )];
        let out = SarifOutput {
            workflow_path: PathBuf::from(".github/workflows/ci.yml"),
            tool_version: "test",
        };
        let mut buf = Vec::new();
        out.write_results(&nodes, &mut buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
    }
}
