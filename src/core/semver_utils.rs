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
}
