use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: String,
    pub url: String,
    pub affected_range: Option<String>,
    pub source: String,
}

impl fmt::Display for Advisory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} ({}): {}", self.id, self.severity, self.summary)?;
        write!(f, "    {}", self.url)?;
        if let Some(range) = &self.affected_range {
            write!(f, "\n    affected: {range}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl FromStr for Severity {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(anyhow::anyhow!("unknown severity: {s:?}")),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl Advisory {
    /// Parse the free-form `severity` string into a typed `Severity`.
    /// Returns `None` for unrecognized values.
    pub fn parsed_severity(&self) -> Option<Severity> {
        self.severity.parse().ok()
    }
}

/// Deduplicate advisories by ID and aliases.
///
/// If an advisory's ID or any of its aliases have already been seen,
/// it is dropped. This handles cross-provider duplicates where e.g.
/// GHSA and OSV report the same vulnerability under different IDs
/// linked by aliases.
pub fn deduplicate_advisories(mut advisories: Vec<Advisory>) -> Vec<Advisory> {
    let mut seen_ids: HashSet<String> = HashSet::new();
    advisories.retain(|adv| {
        if seen_ids.contains(&adv.id) {
            return false;
        }
        if adv.aliases.iter().any(|a| seen_ids.contains(a)) {
            return false;
        }
        seen_ids.insert(adv.id.clone());
        seen_ids.extend(adv.aliases.iter().cloned());
        true
    });
    advisories
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_advisory(id: &str, aliases: Vec<&str>, source: &str) -> Advisory {
        Advisory {
            id: id.to_string(),
            aliases: aliases.into_iter().map(String::from).collect(),
            summary: format!("Advisory {id}"),
            severity: "high".to_string(),
            url: format!("https://example.com/{id}"),
            affected_range: None,
            source: source.to_string(),
        }
    }

    #[test]
    fn dedup_removes_exact_duplicate_ids() {
        let advisories = vec![
            make_advisory("GHSA-1234", vec![], "GHSA"),
            make_advisory("GHSA-1234", vec![], "GHSA"),
        ];
        let result = deduplicate_advisories(advisories);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-1234");
    }

    #[test]
    fn dedup_removes_by_alias() {
        let advisories = vec![
            make_advisory("GHSA-mcph-m25j-8j63", vec!["CVE-2025-30066"], "GHSA"),
            make_advisory("CVE-2025-30066", vec!["GHSA-mcph-m25j-8j63"], "OSV"),
        ];
        let result = deduplicate_advisories(advisories);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-mcph-m25j-8j63");
    }

    #[test]
    fn dedup_keeps_unrelated_advisories() {
        let advisories = vec![
            make_advisory("GHSA-1111", vec![], "GHSA"),
            make_advisory("GHSA-2222", vec![], "GHSA"),
            make_advisory("OSV-3333", vec![], "OSV"),
        ];
        let result = deduplicate_advisories(advisories);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn dedup_mixed_providers_with_shared_alias() {
        let advisories = vec![
            make_advisory("GHSA-aaaa", vec!["CVE-2025-0001"], "GHSA"),
            make_advisory("OSV-bbbb", vec!["CVE-2025-0001"], "OSV"),
            make_advisory("GHSA-cccc", vec![], "GHSA"),
        ];
        let result = deduplicate_advisories(advisories);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].id, "GHSA-aaaa");
        assert_eq!(result[1].id, "GHSA-cccc");
    }

    #[test]
    fn dedup_empty_input() {
        let result = deduplicate_advisories(vec![]);
        assert!(result.is_empty());
    }

    // --- Severity tests ---

    #[test]
    fn severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_case_insensitive_parse() {
        assert_eq!("CRITICAL".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("Critical".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("critical".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("low".parse::<Severity>().unwrap(), Severity::Low);
        assert_eq!("HIGH".parse::<Severity>().unwrap(), Severity::High);
    }

    #[test]
    fn severity_rejects_unknown() {
        assert!("moderate".parse::<Severity>().is_err());
        assert!("".parse::<Severity>().is_err());
        assert!("unknown".parse::<Severity>().is_err());
    }

    #[test]
    fn severity_display_roundtrips() {
        for sev in [Severity::Low, Severity::Medium, Severity::High, Severity::Critical] {
            let s = sev.to_string();
            assert_eq!(s.parse::<Severity>().unwrap(), sev);
        }
    }

    #[test]
    fn advisory_parsed_severity_known() {
        let adv = make_advisory("GHSA-1234", vec![], "GHSA");
        assert_eq!(adv.parsed_severity(), Some(Severity::High)); // default severity is "high"
    }

    #[test]
    fn advisory_parsed_severity_unknown() {
        let mut adv = make_advisory("GHSA-1234", vec![], "GHSA");
        adv.severity = "moderate".to_string();
        assert_eq!(adv.parsed_severity(), None);
    }
}
