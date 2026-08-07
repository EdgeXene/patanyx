//! Semantic versions, compared numerically — never as strings.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serde::Deserialize;

use crate::error::UpdateError;

/// Longest version string accepted. Three u64s need at most 62 characters;
/// anything longer is not a version, it is a payload.
const MAX_VERSION_LEN: usize = 64;

/// A `major.minor.patch` version.
///
/// The derived `Ord` compares major, then minor, then patch — field
/// declaration order — which is exactly semantic-version order for numeric
/// triplets, and NOT string order ("2.10.0" is newer than "2.9.0" here;
/// lexicographic comparison gets that backwards, and that backwards is a
/// rollback channel).
///
/// Pre-release and build-metadata suffixes are deliberately unsupported:
/// anything that is not three dot-separated unsigned integers fails to
/// parse, and a version that fails to parse fails the whole manifest.
/// Channels (beta/nightly) are a policy layer above this crate, not a
/// suffix, because "is 1.0.0-rc.2 before 1.0.0?" is exactly the kind of
/// rule an updater must not get subtly wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Version {
    type Err = UpdateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || UpdateError::Malformed(format!("not a semantic version: {s:?}"));
        if s.len() > MAX_VERSION_LEN {
            return Err(bad());
        }
        let mut parts = s.split('.');
        let mut number = |parts: &mut std::str::Split<'_, char>| -> Result<u64, UpdateError> {
            let part = parts.next().ok_or_else(bad)?;
            // Non-empty, ASCII digits only. u64::from_str rejects overflow,
            // so an absurd component is refused rather than wrapped.
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            part.parse::<u64>().map_err(|_| bad())
        };
        let version = Version {
            major: number(&mut parts)?,
            minor: number(&mut parts)?,
            patch: number(&mut parts)?,
        };
        // Three components, not two and not four.
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(version)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = Cow::<str>::deserialize(deserializer)?;
        Version::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::Version;

    #[test]
    fn parses_plain_triplets() {
        assert_eq!("0.0.0".parse::<Version>().unwrap(), Version::new(0, 0, 0));
        assert_eq!(
            "2.10.0".parse::<Version>().unwrap(),
            Version::new(2, 10, 0)
        );
        assert_eq!(
            "18446744073709551615.0.1".parse::<Version>().unwrap(),
            Version::new(u64::MAX, 0, 1)
        );
    }

    #[test]
    fn orders_numerically_not_lexicographically() {
        assert!("2.10.0".parse::<Version>().unwrap() > "2.9.0".parse::<Version>().unwrap());
        assert!("10.0.0".parse::<Version>().unwrap() > "9.9.9".parse::<Version>().unwrap());
        assert!("1.0.0".parse::<Version>().unwrap() < "1.0.1".parse::<Version>().unwrap());
        assert!("1.2.0".parse::<Version>().unwrap() < "1.10.0".parse::<Version>().unwrap());
    }

    #[test]
    fn rejects_anything_but_three_numbers() {
        for bad in [
            "",
            "2",
            "2.9",
            "2.9.0.1",
            "2..0",
            ".2.9.0",
            "2.9.0.",
            "v2.9.0",
            "2.9.0-rc1",
            "2.9.0+build",
            "a.b.c",
            " 2.9.0",
            "2.9.0 ",
            "2. 9.0",
            "-2.9.0",
            "+2.9.0",
            "2.9.x",
            "٢.٩.٠", // non-ASCII digits are not digits here
        ] {
            assert!(bad.parse::<Version>().is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn rejects_component_overflow_without_panicking() {
        assert!("99999999999999999999999.0.0".parse::<Version>().is_err());
    }

    #[test]
    fn rejects_overlong_strings_without_panicking() {
        let long = format!("{}.0.0", "1".repeat(100));
        assert!(long.parse::<Version>().is_err());
    }

    #[test]
    fn displays_as_it_parses() {
        let version = Version::new(2, 10, 0);
        assert_eq!(version.to_string(), "2.10.0");
        assert_eq!(version.to_string().parse::<Version>().unwrap(), version);
    }
}
