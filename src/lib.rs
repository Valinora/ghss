#[path = "lib/mod.rs"]
mod modules;

pub use modules::action_ref;
pub use modules::advisory;
pub use modules::context;
pub use modules::depth;
pub use modules::github;
pub use modules::output;
pub use modules::pipeline;
pub use modules::providers;
pub use modules::stages;
pub use modules::workflow;

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use anyhow::bail;
use tracing::{debug, warn};

use action_ref::ActionRef;

/// Specifies which actions to scan, by 1-indexed position.
///
/// Valid inputs: `all`, `1-3,5`, `2`, `1,3-5,7`.
#[derive(Debug, Clone, PartialEq)]
pub enum ScanSelection {
    None,
    All,
    /// Sorted, deduplicated 1-indexed positions.
    Indices(Vec<usize>),
}

impl ScanSelection {
    /// Returns true if the given 0-indexed position should be scanned.
    pub fn should_scan(&self, zero_index: usize) -> bool {
        match self {
            ScanSelection::None => false,
            ScanSelection::All => true,
            ScanSelection::Indices(indices) => indices.contains(&(zero_index + 1)),
        }
    }
}

impl fmt::Display for ScanSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanSelection::None => write!(f, "none"),
            ScanSelection::All => write!(f, "all"),
            ScanSelection::Indices(indices) => {
                let parts: Vec<String> = indices.iter().map(|i| i.to_string()).collect();
                write!(f, "{}", parts.join(","))
            }
        }
    }
}

impl FromStr for ScanSelection {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("all") {
            return Ok(ScanSelection::All);
        }
        if s.eq_ignore_ascii_case("none") {
            return Ok(ScanSelection::None);
        }

        let mut indices = BTreeSet::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((start_str, end_str)) = part.split_once('-') {
                let start: usize = start_str
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid range start: {start_str:?}"))?;
                let end: usize = end_str
                    .trim()
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid range end: {end_str:?}"))?;
                if start == 0 || end == 0 {
                    bail!("scan indices are 1-based; got 0");
                }
                if start > end {
                    bail!("invalid range: {start}-{end} (start > end)");
                }
                for i in start..=end {
                    indices.insert(i);
                }
            } else {
                let idx: usize = part
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid index: {part:?}"))?;
                if idx == 0 {
                    bail!("scan indices are 1-based; got 0");
                }
                indices.insert(idx);
            }
        }

        if indices.is_empty() {
            return Ok(ScanSelection::None);
        }

        Ok(ScanSelection::Indices(indices.into_iter().collect()))
    }
}

fn is_third_party(uses: &str) -> bool {
    !uses.starts_with("./") && !uses.starts_with("docker://")
}

pub fn parse_actions(path: &Path) -> anyhow::Result<Vec<ActionRef>> {
    let uses_refs = workflow::parse_workflow(path)?;

    let unique: BTreeSet<ActionRef> = uses_refs
        .into_iter()
        .filter(|u| is_third_party(u))
        .filter_map(|raw| match raw.parse::<ActionRef>() {
            Ok(ar) => Some(ar),
            Err(e) => {
                warn!(action = %raw, error = %e, "failed to parse action reference");
                None
            }
        })
        .collect();

    debug!(count = unique.len(), "parsed unique third-party actions");
    Ok(unique.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn third_party_actions_are_detected() {
        assert!(is_third_party("actions/checkout@v4"));
        assert!(is_third_party("codecov/codecov-action@v3"));
    }

    #[test]
    fn local_actions_are_not_third_party() {
        assert!(!is_third_party("./local-action"));
        assert!(!is_third_party("./path/to/action"));
    }

    #[test]
    fn docker_actions_are_not_third_party() {
        assert!(!is_third_party("docker://node:18"));
        assert!(!is_third_party("docker://alpine:3.18"));
    }

    #[test]
    fn scan_selection_parse_all() {
        assert_eq!("all".parse::<ScanSelection>().unwrap(), ScanSelection::All);
        assert_eq!("ALL".parse::<ScanSelection>().unwrap(), ScanSelection::All);
    }

    #[test]
    fn scan_selection_parse_none() {
        assert_eq!(
            "none".parse::<ScanSelection>().unwrap(),
            ScanSelection::None
        );
    }

    #[test]
    fn scan_selection_parse_single() {
        assert_eq!(
            "3".parse::<ScanSelection>().unwrap(),
            ScanSelection::Indices(vec![3])
        );
    }

    #[test]
    fn scan_selection_parse_range() {
        assert_eq!(
            "1-3".parse::<ScanSelection>().unwrap(),
            ScanSelection::Indices(vec![1, 2, 3])
        );
    }

    #[test]
    fn scan_selection_parse_mixed() {
        assert_eq!(
            "1-3,5".parse::<ScanSelection>().unwrap(),
            ScanSelection::Indices(vec![1, 2, 3, 5])
        );
    }

    #[test]
    fn scan_selection_parse_deduplicates() {
        assert_eq!(
            "1-3,2-4".parse::<ScanSelection>().unwrap(),
            ScanSelection::Indices(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn scan_selection_parse_rejects_zero() {
        assert!("0".parse::<ScanSelection>().is_err());
        assert!("0-3".parse::<ScanSelection>().is_err());
    }

    #[test]
    fn scan_selection_parse_rejects_inverted_range() {
        assert!("5-2".parse::<ScanSelection>().is_err());
    }

    #[test]
    fn scan_selection_should_scan() {
        let sel = ScanSelection::Indices(vec![1, 3, 5]);
        assert!(sel.should_scan(0)); // position 1
        assert!(!sel.should_scan(1)); // position 2
        assert!(sel.should_scan(2)); // position 3
        assert!(!sel.should_scan(3)); // position 4
        assert!(sel.should_scan(4)); // position 5

        assert!(ScanSelection::All.should_scan(99));
        assert!(!ScanSelection::None.should_scan(0));
    }
}
