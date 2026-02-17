use serde::Serialize;

use crate::action_ref::ActionRef;
use crate::advisory::Advisory;
use crate::deps::DependencyReport;
use crate::scan::ActionScan;

#[derive(Serialize)]
pub struct ActionEntry {
    #[serde(flatten)]
    pub action: ActionRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_sha: Option<String>,
    pub advisories: Vec<Advisory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<ActionScan>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dep_vulnerabilities: Vec<DependencyReport>,
}

pub trait OutputFormatter {
    fn write_results(
        &self,
        entries: &[ActionEntry],
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<()>;
}

pub struct TextOutput;

impl OutputFormatter for TextOutput {
    fn write_results(
        &self,
        entries: &[ActionEntry],
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        for entry in entries {
            writeln!(writer, "{}", entry.action.raw)?;

            if let Some(sha) = &entry.resolved_sha {
                writeln!(writer, "  sha: {sha}")?;
            }

            if let Some(scan) = &entry.scan {
                if let Some(lang) = &scan.primary_language {
                    writeln!(writer, "  language: {lang}")?;
                }
                if !scan.ecosystems.is_empty() {
                    let eco_list: Vec<String> =
                        scan.ecosystems.iter().map(|e| e.to_string()).collect();
                    writeln!(writer, "  ecosystems: {}", eco_list.join(", "))?;
                }
            }

            if entry.advisories.is_empty() {
                writeln!(writer, "  advisories: none")?;
            } else {
                for adv in &entry.advisories {
                    writeln!(writer, "  {adv}")?;
                }
            }

            if !entry.dep_vulnerabilities.is_empty() {
                writeln!(writer, "  dependency vulnerabilities:")?;
                for dep in &entry.dep_vulnerabilities {
                    writeln!(writer, "    {}@{} ({}):", dep.package, dep.version, dep.ecosystem)?;
                    for adv in &dep.advisories {
                        writeln!(writer, "      {adv}")?;
                    }
                }
            }
        }
        Ok(())
    }
}

pub struct JsonOutput;

impl OutputFormatter for JsonOutput {
    fn write_results(
        &self,
        entries: &[ActionEntry],
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        serde_json::to_writer_pretty(&mut *writer, entries)?;
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

    #[test]
    fn text_output_basic() {
        let entries = vec![ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        }];
        let mut buf = Vec::new();
        let fmt = TextOutput;
        fmt.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("actions/checkout@v4"));
        assert!(output.contains("advisories: none"));
    }

    #[test]
    fn text_output_with_sha() {
        let entries = vec![ActionEntry {
            action: sample_action(),
            resolved_sha: Some("abc123".to_string()),
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        }];
        let mut buf = Vec::new();
        let fmt = TextOutput;
        fmt.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("actions/checkout@v4"));
        assert!(output.contains("  sha: abc123"));
    }

    #[test]
    fn text_output_with_no_advisories() {
        let entries = vec![ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        }];
        let mut buf = Vec::new();
        let fmt = TextOutput;
        fmt.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("advisories: none"));
    }

    #[test]
    fn text_output_with_advisories() {
        let entries = vec![ActionEntry {
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
        }];
        let mut buf = Vec::new();
        let fmt = TextOutput;
        fmt.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("GHSA-1234 (high): Bad thing"));
        assert!(output.contains("https://ghsa.example.com/1234"));
        assert!(output.contains("affected: >= 1.0, < 2.0"));
    }

    #[test]
    fn json_output_basic() {
        let entries = vec![ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        }];
        let mut buf = Vec::new();
        let fmt = JsonOutput;
        fmt.write_results(&entries, &mut buf).unwrap();
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
    }

    #[test]
    fn json_output_with_all_fields() {
        let entries = vec![ActionEntry {
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
        }];
        let mut buf = Vec::new();
        let fmt = JsonOutput;
        fmt.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr[0]["resolved_sha"], "deadbeef");
        assert_eq!(arr[0]["advisories"][0]["id"], "GHSA-1234");
    }

    #[test]
    fn factory_returns_json() {
        let f = formatter(true);
        let entries = vec![ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        }];
        let mut buf = Vec::new();
        f.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Should be valid JSON
        serde_json::from_str::<serde_json::Value>(&output).unwrap();
    }

    #[test]
    fn factory_returns_text() {
        let f = formatter(false);
        let entries = vec![ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        }];
        let mut buf = Vec::new();
        f.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("actions/checkout@v4"));
        assert!(output.contains("advisories: none"));
    }

    #[test]
    fn json_output_omits_scan_when_none() {
        let entries = vec![ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![],
            scan: None,
            dep_vulnerabilities: vec![],
        }];
        let mut buf = Vec::new();
        JsonOutput.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert!(arr[0].get("scan").is_none());
    }

    #[test]
    fn json_output_includes_scan_when_present() {
        use crate::scan::{ActionScan, Ecosystem};
        let entries = vec![ActionEntry {
            action: sample_action(),
            resolved_sha: None,
            advisories: vec![],
            scan: Some(ActionScan {
                primary_language: Some("TypeScript".to_string()),
                ecosystems: vec![Ecosystem::Npm, Ecosystem::Docker],
            }),
            dep_vulnerabilities: vec![],
        }];
        let mut buf = Vec::new();
        JsonOutput.write_results(&entries, &mut buf).unwrap();
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
    fn text_output_with_scan_data() {
        use crate::scan::{ActionScan, Ecosystem};
        let entries = vec![ActionEntry {
            action: sample_action(),
            resolved_sha: Some("abc123".to_string()),
            advisories: vec![],
            scan: Some(ActionScan {
                primary_language: Some("TypeScript".to_string()),
                ecosystems: vec![Ecosystem::Npm, Ecosystem::Docker],
            }),
            dep_vulnerabilities: vec![],
        }];
        let mut buf = Vec::new();
        TextOutput.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("language: TypeScript"));
        assert!(output.contains("ecosystems: npm, docker"));
        assert!(output.contains("sha: abc123"));
        assert!(output.contains("advisories: none"));
    }
}
