use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use anyhow::{bail, Result};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RefType {
    Sha,
    Tag,
    Unknown,
}

impl fmt::Display for RefType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefType::Sha => write!(f, "sha"),
            RefType::Tag => write!(f, "tag"),
            RefType::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionRef {
    pub raw: String,
    pub owner: String,
    pub repo: String,
    pub path: Option<String>,
    pub git_ref: String,
    pub ref_type: RefType,
}

impl FromStr for ActionRef {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        let Some((name_part, git_ref)) = raw.split_once('@') else {
            bail!("missing '@' in action reference: {raw}");
        };

        let segments: Vec<&str> = name_part.split('/').collect();
        if segments.len() < 2 {
            bail!("expected owner/repo in action reference: {raw}");
        }

        let owner = segments[0].to_string();
        let repo = segments[1].to_string();
        let path = if segments.len() > 2 {
            Some(segments[2..].join("/"))
        } else {
            None
        };

        let ref_type = classify_ref(git_ref);

        Ok(Self {
            raw: raw.to_string(),
            owner,
            repo,
            path,
            git_ref: git_ref.to_string(),
            ref_type,
        })
    }
}

impl fmt::Display for ActionRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl PartialEq for ActionRef {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.repo == other.repo
            && self.path == other.path
            && self.git_ref == other.git_ref
    }
}

impl Eq for ActionRef {}

impl PartialOrd for ActionRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ActionRef {
    fn cmp(&self, other: &Self) -> Ordering {
        self.owner
            .cmp(&other.owner)
            .then_with(|| self.repo.cmp(&other.repo))
            .then_with(|| self.path.cmp(&other.path))
            .then_with(|| self.git_ref.cmp(&other.git_ref))
    }
}

impl Hash for ActionRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.owner.hash(state);
        self.repo.hash(state);
        self.path.hash(state);
        self.git_ref.hash(state);
    }
}

impl ActionRef {
    pub fn package_name(&self) -> String {
        match &self.path {
            Some(p) => format!("{}/{}/{}", self.owner, self.repo, p),
            None => format!("{}/{}", self.owner, self.repo),
        }
    }

    pub fn version(&self) -> Option<&str> {
        if self.ref_type != RefType::Tag {
            return None;
        }
        Some(self.git_ref.strip_prefix('v').unwrap_or(&self.git_ref))
    }
}

fn classify_ref(git_ref: &str) -> RefType {
    if git_ref.len() == 40 && git_ref.chars().all(|c| c.is_ascii_hexdigit()) {
        return RefType::Sha;
    }

    // Match v?\d+ (optional v prefix followed by at least one digit, then anything)
    let without_v = git_ref.strip_prefix('v').unwrap_or(git_ref);
    if without_v.starts_with(|c: char| c.is_ascii_digit()) {
        return RefType::Tag;
    }

    RefType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_action() {
        let ar: ActionRef = "actions/checkout@v4".parse().unwrap();
        assert_eq!(ar.owner, "actions");
        assert_eq!(ar.repo, "checkout");
        assert!(ar.path.is_none());
        assert_eq!(ar.git_ref, "v4");
        assert_eq!(ar.ref_type, RefType::Tag);
    }

    #[test]
    fn parse_action_with_subpath() {
        let ar: ActionRef = "google-github-actions/auth/slim@v2".parse().unwrap();
        assert_eq!(ar.owner, "google-github-actions");
        assert_eq!(ar.repo, "auth");
        assert_eq!(ar.path, Some("slim".to_string()));
        assert_eq!(ar.git_ref, "v2");
        assert_eq!(ar.package_name(), "google-github-actions/auth/slim");
    }

    #[test]
    fn parse_sha_ref() {
        let sha = "b4ffde65f46336ab88eb53be808477a3936bae11";
        let raw = format!("actions/checkout@{sha}");
        let ar: ActionRef = raw.parse().unwrap();
        assert_eq!(ar.ref_type, RefType::Sha);
        assert_eq!(ar.git_ref, sha);
    }

    #[test]
    fn parse_tag_ref() {
        let ar: ActionRef = "codecov/codecov-action@v3.1.0".parse().unwrap();
        assert_eq!(ar.ref_type, RefType::Tag);
        assert_eq!(ar.version(), Some("3.1.0"));
    }

    #[test]
    fn parse_tag_without_v_prefix() {
        let ar: ActionRef = "some/action@2.0".parse().unwrap();
        assert_eq!(ar.ref_type, RefType::Tag);
        assert_eq!(ar.version(), Some("2.0"));
    }

    #[test]
    fn parse_unknown_ref() {
        let ar: ActionRef = "actions/checkout@main".parse().unwrap();
        assert_eq!(ar.ref_type, RefType::Unknown);
        assert_eq!(ar.version(), None);
    }

    #[test]
    fn missing_at_sign_is_error() {
        assert!("actions/checkout".parse::<ActionRef>().is_err());
    }

    #[test]
    fn missing_repo_is_error() {
        assert!("actions@v4".parse::<ActionRef>().is_err());
    }

    #[test]
    fn package_name_simple() {
        let ar: ActionRef = "actions/checkout@v4".parse().unwrap();
        assert_eq!(ar.package_name(), "actions/checkout");
    }

    #[test]
    fn version_returns_none_for_non_tag() {
        let ar: ActionRef = "actions/checkout@main".parse().unwrap();
        assert_eq!(ar.version(), None);
    }

    #[test]
    fn ref_type_display() {
        assert_eq!(RefType::Sha.to_string(), "sha");
        assert_eq!(RefType::Tag.to_string(), "tag");
        assert_eq!(RefType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn display_matches_raw() {
        let ar: ActionRef = "actions/checkout@v4".parse().unwrap();
        assert_eq!(format!("{ar}"), "actions/checkout@v4");
        assert_eq!(ar.to_string(), ar.raw);
    }

    #[test]
    fn equal_actions_are_equal() {
        let a: ActionRef = "actions/checkout@v4".parse().unwrap();
        let b: ActionRef = "actions/checkout@v4".parse().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_actions_are_not_equal() {
        let a: ActionRef = "actions/checkout@v4".parse().unwrap();
        let b: ActionRef = "actions/checkout@v3".parse().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn ordering_by_owner_then_repo() {
        let a: ActionRef = "actions/checkout@v4".parse().unwrap();
        let b: ActionRef = "codecov/codecov-action@v3".parse().unwrap();
        assert!(a < b);
    }

    #[test]
    fn ordering_by_ref_within_same_repo() {
        let a: ActionRef = "actions/checkout@v3".parse().unwrap();
        let b: ActionRef = "actions/checkout@v4".parse().unwrap();
        assert!(a < b);
    }
}
