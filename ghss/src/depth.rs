use std::fmt;
use std::str::FromStr;

use anyhow::bail;

/// Controls how deeply recursive workflow scanning descends.
///
/// Valid inputs: any non-negative integer (e.g. `"0"`, `"5"`) for a bounded
/// depth, or `"unlimited"` (case-insensitive) for no limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepthLimit {
    Bounded(usize),
    Unlimited,
}

impl DepthLimit {
    /// Converts to an `Option<usize>` for use as a max-depth guard.
    ///
    /// `Bounded(n)` returns `Some(n)`; `Unlimited` returns `None`.
    pub fn to_max_depth(&self) -> Option<usize> {
        match self {
            DepthLimit::Bounded(n) => Some(*n),
            DepthLimit::Unlimited => None,
        }
    }
}

impl fmt::Display for DepthLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DepthLimit::Bounded(n) => write!(f, "{n}"),
            DepthLimit::Unlimited => write!(f, "unlimited"),
        }
    }
}

impl FromStr for DepthLimit {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("unlimited") {
            return Ok(DepthLimit::Unlimited);
        }
        match s.parse::<usize>() {
            Ok(n) => Ok(DepthLimit::Bounded(n)),
            Err(_) => bail!("invalid depth limit: {s:?} (expected a non-negative integer or \"unlimited\")"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zero() {
        assert_eq!("0".parse::<DepthLimit>().unwrap(), DepthLimit::Bounded(0));
    }

    #[test]
    fn parse_positive_integer() {
        assert_eq!("5".parse::<DepthLimit>().unwrap(), DepthLimit::Bounded(5));
    }

    #[test]
    fn parse_large_integer() {
        assert_eq!(
            "100".parse::<DepthLimit>().unwrap(),
            DepthLimit::Bounded(100)
        );
    }

    #[test]
    fn parse_unlimited_lowercase() {
        assert_eq!(
            "unlimited".parse::<DepthLimit>().unwrap(),
            DepthLimit::Unlimited
        );
    }

    #[test]
    fn parse_unlimited_mixed_case() {
        assert_eq!(
            "Unlimited".parse::<DepthLimit>().unwrap(),
            DepthLimit::Unlimited
        );
        assert_eq!(
            "UNLIMITED".parse::<DepthLimit>().unwrap(),
            DepthLimit::Unlimited
        );
    }

    #[test]
    fn parse_unlimited_with_whitespace() {
        assert_eq!(
            "  unlimited  ".parse::<DepthLimit>().unwrap(),
            DepthLimit::Unlimited
        );
    }

    #[test]
    fn parse_rejects_negative() {
        assert!("-1".parse::<DepthLimit>().is_err());
    }

    #[test]
    fn parse_rejects_non_numeric() {
        assert!("abc".parse::<DepthLimit>().is_err());
    }

    #[test]
    fn parse_rejects_empty() {
        assert!("".parse::<DepthLimit>().is_err());
    }

    #[test]
    fn parse_rejects_float() {
        assert!("3.5".parse::<DepthLimit>().is_err());
    }

    #[test]
    fn to_max_depth_bounded() {
        assert_eq!(DepthLimit::Bounded(0).to_max_depth(), Some(0));
        assert_eq!(DepthLimit::Bounded(5).to_max_depth(), Some(5));
    }

    #[test]
    fn to_max_depth_unlimited() {
        assert_eq!(DepthLimit::Unlimited.to_max_depth(), None);
    }

    #[test]
    fn display_bounded() {
        assert_eq!(DepthLimit::Bounded(3).to_string(), "3");
    }

    #[test]
    fn display_unlimited() {
        assert_eq!(DepthLimit::Unlimited.to_string(), "unlimited");
    }

    #[test]
    fn display_roundtrips() {
        let cases = [DepthLimit::Bounded(0), DepthLimit::Bounded(42), DepthLimit::Unlimited];
        for case in &cases {
            let s = case.to_string();
            let parsed: DepthLimit = s.parse().unwrap();
            assert_eq!(&parsed, case);
        }
    }
}
