use serde::Serialize;

use crate::action_ref::ActionRef;
use crate::advisory::Advisory;

#[derive(Serialize)]
pub struct ActionEntry<'a> {
    #[serde(flatten)]
    pub action: &'a ActionRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_sha: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisories: Option<&'a [Advisory]>,
}

pub trait OutputFormatter {
    fn write_results(
        &self,
        entries: &[ActionEntry],
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<()>;
}

pub struct TextOutput {
    pub show_advisories: bool,
}

impl OutputFormatter for TextOutput {
    fn write_results(
        &self,
        entries: &[ActionEntry],
        writer: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        for entry in entries {
            writeln!(writer, "{}", entry.action.raw)?;

            if let Some(sha) = entry.resolved_sha {
                writeln!(writer, "  sha: {sha}")?;
            }

            if self.show_advisories {
                if let Some(advs) = entry.advisories {
                    if advs.is_empty() {
                        writeln!(writer, "  advisories: none")?;
                    } else {
                        for adv in advs {
                            writeln!(
                                writer,
                                "  {} ({}): {}",
                                adv.id, adv.severity, adv.summary
                            )?;
                            writeln!(writer, "    {}", adv.url)?;
                            if let Some(range) = &adv.affected_range {
                                writeln!(writer, "    affected: {range}")?;
                            }
                        }
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

pub fn formatter(json: bool, show_advisories: bool) -> Box<dyn OutputFormatter> {
    if json {
        Box::new(JsonOutput)
    } else {
        Box::new(TextOutput { show_advisories })
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
        let action = sample_action();
        let entries = vec![ActionEntry {
            action: &action,
            resolved_sha: None,
            advisories: None,
        }];
        let mut buf = Vec::new();
        let fmt = TextOutput {
            show_advisories: false,
        };
        fmt.write_results(&entries, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "actions/checkout@v4\n");
    }

    #[test]
    fn text_output_with_sha() {
        let action = sample_action();
        let entries = vec![ActionEntry {
            action: &action,
            resolved_sha: Some("abc123"),
            advisories: None,
        }];
        let mut buf = Vec::new();
        let fmt = TextOutput {
            show_advisories: false,
        };
        fmt.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("actions/checkout@v4"));
        assert!(output.contains("  sha: abc123"));
    }

    #[test]
    fn text_output_with_no_advisories() {
        let action = sample_action();
        let entries = vec![ActionEntry {
            action: &action,
            resolved_sha: None,
            advisories: Some(&[]),
        }];
        let mut buf = Vec::new();
        let fmt = TextOutput {
            show_advisories: true,
        };
        fmt.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("advisories: none"));
    }

    #[test]
    fn text_output_with_advisories() {
        let action = sample_action();
        let advs = vec![Advisory {
            id: "GHSA-1234".to_string(),
            summary: "Bad thing".to_string(),
            severity: "high".to_string(),
            url: "https://ghsa.example.com/1234".to_string(),
            affected_range: Some(">= 1.0, < 2.0".to_string()),
            source: "ghsa".to_string(),
        }];
        let entries = vec![ActionEntry {
            action: &action,
            resolved_sha: None,
            advisories: Some(&advs),
        }];
        let mut buf = Vec::new();
        let fmt = TextOutput {
            show_advisories: true,
        };
        fmt.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("GHSA-1234 (high): Bad thing"));
        assert!(output.contains("https://ghsa.example.com/1234"));
        assert!(output.contains("affected: >= 1.0, < 2.0"));
    }

    #[test]
    fn json_output_basic() {
        let action = sample_action();
        let entries = vec![ActionEntry {
            action: &action,
            resolved_sha: None,
            advisories: None,
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
        // Optional fields should be absent
        assert!(arr[0].get("resolved_sha").is_none());
        assert!(arr[0].get("advisories").is_none());
    }

    #[test]
    fn json_output_with_all_fields() {
        let action = sample_action();
        let advs = vec![Advisory {
            id: "GHSA-1234".to_string(),
            summary: "Bad thing".to_string(),
            severity: "high".to_string(),
            url: "https://ghsa.example.com/1234".to_string(),
            affected_range: Some(">= 1.0".to_string()),
            source: "ghsa".to_string(),
        }];
        let entries = vec![ActionEntry {
            action: &action,
            resolved_sha: Some("deadbeef"),
            advisories: Some(&advs),
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
        let f = formatter(true, false);
        let action = sample_action();
        let entries = vec![ActionEntry {
            action: &action,
            resolved_sha: None,
            advisories: None,
        }];
        let mut buf = Vec::new();
        f.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        // Should be valid JSON
        serde_json::from_str::<serde_json::Value>(&output).unwrap();
    }

    #[test]
    fn factory_returns_text() {
        let f = formatter(false, false);
        let action = sample_action();
        let entries = vec![ActionEntry {
            action: &action,
            resolved_sha: None,
            advisories: None,
        }];
        let mut buf = Vec::new();
        f.write_results(&entries, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(output, "actions/checkout@v4\n");
    }
}
