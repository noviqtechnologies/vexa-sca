use semver::Version;
use serde_json::Value;
use std::collections::BTreeSet;

pub fn clean_or_coerce_version(v: &str) -> Option<Version> {
    let clean = v.trim().trim_start_matches('v').trim_start_matches('^').trim_start_matches('~');
    if let Ok(ver) = Version::parse(clean) {
        return Some(ver);
    }
    // Loose parsing fallback: x.y -> x.y.0
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() == 2 {
        let reconstructed = format!("{}.{}.0", parts[0], parts[1]);
        if let Ok(ver) = Version::parse(&reconstructed) {
            return Some(ver);
        }
    }
    if parts.len() == 1 {
        let reconstructed = format!("{}.0.0", parts[0]);
        if let Ok(ver) = Version::parse(&reconstructed) {
            return Some(ver);
        }
    }
    None
}

pub fn extract_fixed_versions(vuln: &Value) -> Vec<String> {
    let mut fixes = BTreeSet::new();

    if let Some(affected_arr) = vuln.get("affected").and_then(|v| v.as_array()) {
        for aff in affected_arr {
            if let Some(ranges) = aff.get("ranges").and_then(|v| v.as_array()) {
                for range in ranges {
                    if let Some(events) = range.get("events").and_then(|v| v.as_array()) {
                        for ev in events {
                            if let Some(fixed_str) = ev.get("fixed").and_then(|v| v.as_str()) {
                                if let Some(v) = clean_or_coerce_version(fixed_str) {
                                    fixes.insert(v.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut result: Vec<String> = fixes.into_iter().collect();
    result.sort_by(|a, b| {
        let va = clean_or_coerce_version(a);
        let vb = clean_or_coerce_version(b);
        match (va, vb) {
            (Some(x), Some(y)) => x.cmp(&y),
            _ => a.cmp(b),
        }
    });
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SemverChange {
    Major,
    Minor,
    Patch,
    Unknown,
}

impl SemverChange {
    pub fn as_str(&self) -> &'static str {
        match self {
            SemverChange::Major => "MAJOR",
            SemverChange::Minor => "MINOR",
            SemverChange::Patch => "PATCH",
            SemverChange::Unknown => "UNKNOWN",
        }
    }
}

/// Classifies the SemVer difference from `from` version to `to` version.
/// Returns (SemverChange, is_breaking).
/// In Cargo & npm SemVer:
/// - Any major bump (e.g. 9 -> 10) is breaking.
/// - In 0.x.y, a minor bump (0.23 -> 0.24) is breaking.
/// - In 0.0.z, a patch bump (0.0.1 -> 0.0.2) is breaking.
pub fn classify_semver_change(from: &str, to: &str) -> (SemverChange, bool) {
    if let (Some(cur), Some(target)) = (clean_or_coerce_version(from), clean_or_coerce_version(to)) {
        if target.major > cur.major {
            (SemverChange::Major, true)
        } else if cur.major == 0 && target.minor > cur.minor {
            (SemverChange::Major, true)
        } else if cur.major == 0 && cur.minor == 0 && target.patch > cur.patch {
            (SemverChange::Major, true)
        } else if target.minor > cur.minor {
            (SemverChange::Minor, false)
        } else if target.patch > cur.patch {
            (SemverChange::Patch, false)
        } else {
            (SemverChange::Patch, false)
        }
    } else {
        (SemverChange::Unknown, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_fixed_versions() {
        let vuln = serde_json::json!({
            "affected": [
                {
                    "ranges": [
                        {
                            "events": [
                                { "introduced": "0" },
                                { "fixed": "4.17.21" }
                            ]
                        }
                    ]
                }
            ]
        });

        let fixes = extract_fixed_versions(&vuln);
        assert_eq!(fixes, vec!["4.17.21"]);
    }

    #[test]
    fn test_classify_semver_change() {
        // Major bump
        assert_eq!(classify_semver_change("9", "10.3.0"), (SemverChange::Major, true));
        assert_eq!(classify_semver_change("1.2.3", "2.0.0"), (SemverChange::Major, true));

        // 0.x minor is breaking in Cargo/npm
        assert_eq!(classify_semver_change("0.23.0", "0.24.0"), (SemverChange::Major, true));

        // 0.x patch is non-breaking
        assert_eq!(classify_semver_change("0.23", "0.23.46"), (SemverChange::Patch, false));

        // Regular minor/patch
        assert_eq!(classify_semver_change("1.0.70", "1.1.0"), (SemverChange::Minor, false));
        assert_eq!(classify_semver_change("1.0.70", "1.0.103"), (SemverChange::Patch, false));
    }
}
