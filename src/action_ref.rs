use anyhow::{bail, Result};

#[derive(Debug, PartialEq)]
pub enum RefType {
    Sha,
    Tag,
    Unknown,
}

#[derive(Debug)]
pub struct ActionRef {
    pub raw: String,
    pub owner: String,
    pub repo: String,
    pub path: Option<String>,
    pub git_ref: String,
    pub ref_type: RefType,
}

impl ActionRef {
    pub fn parse(raw: &str) -> Result<Self> {
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
        let ar = ActionRef::parse("actions/checkout@v4").unwrap();
        assert_eq!(ar.owner, "actions");
        assert_eq!(ar.repo, "checkout");
        assert!(ar.path.is_none());
        assert_eq!(ar.git_ref, "v4");
        assert_eq!(ar.ref_type, RefType::Tag);
    }

    #[test]
    fn parse_action_with_subpath() {
        let ar = ActionRef::parse("google-github-actions/auth/slim@v2").unwrap();
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
        let ar = ActionRef::parse(&raw).unwrap();
        assert_eq!(ar.ref_type, RefType::Sha);
        assert_eq!(ar.git_ref, sha);
    }

    #[test]
    fn parse_tag_ref() {
        let ar = ActionRef::parse("codecov/codecov-action@v3.1.0").unwrap();
        assert_eq!(ar.ref_type, RefType::Tag);
        assert_eq!(ar.version(), Some("3.1.0"));
    }

    #[test]
    fn parse_tag_without_v_prefix() {
        let ar = ActionRef::parse("some/action@2.0").unwrap();
        assert_eq!(ar.ref_type, RefType::Tag);
        assert_eq!(ar.version(), Some("2.0"));
    }

    #[test]
    fn parse_unknown_ref() {
        let ar = ActionRef::parse("actions/checkout@main").unwrap();
        assert_eq!(ar.ref_type, RefType::Unknown);
        assert_eq!(ar.version(), None);
    }

    #[test]
    fn missing_at_sign_is_error() {
        assert!(ActionRef::parse("actions/checkout").is_err());
    }

    #[test]
    fn missing_repo_is_error() {
        assert!(ActionRef::parse("actions@v4").is_err());
    }

    #[test]
    fn package_name_simple() {
        let ar = ActionRef::parse("actions/checkout@v4").unwrap();
        assert_eq!(ar.package_name(), "actions/checkout");
    }

    #[test]
    fn version_returns_none_for_non_tag() {
        let ar = ActionRef::parse("actions/checkout@main").unwrap();
        assert_eq!(ar.version(), None);
    }
}
