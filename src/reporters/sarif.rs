use crate::scanner::vuln_scanner::ScanResult;
use crate::types::{ReachabilityStatus, RemediationAction, SeverityLevel};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;

/// Formats a scan result into standard OASIS SARIF v2.1.0 JSON format.
/// Adheres strictly to GitHub Code Scanning & GitLab SAST SARIF ingestion standards.
pub fn format_sarif_report(
    scan_result: &ScanResult,
    remediations: &[RemediationAction],
    manifest_file: Option<&Path>,
) -> String {
    let manifest_uri = manifest_file
        .map(|p| {
            // Normalize path to forward slashes for cross-platform SARIF URI compliance
            p.file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| p.to_string_lossy().replace('\\', "/"))
        })
        .unwrap_or_else(|| "package-lock.json".to_string());

    let mut rules = Vec::new();
    let mut rule_id_to_index: HashMap<String, usize> = HashMap::new();
    let mut results = Vec::new();

    // Map remediation advice by package for quick lookup
    let rem_map: HashMap<&str, &RemediationAction> = remediations
        .iter()
        .map(|r| (r.package.as_str(), r))
        .collect();

    for vuln in &scan_result.vulnerabilities {
        let rule_id = vuln.cve.as_deref().unwrap_or(&vuln.id).to_string();

        let rule_index = if let Some(&idx) = rule_id_to_index.get(&rule_id) {
            idx
        } else {
            let idx = rules.len();
            rule_id_to_index.insert(rule_id.clone(), idx);

            let sarif_level = match vuln.severity.level {
                SeverityLevel::Critical | SeverityLevel::High => "error",
                SeverityLevel::Medium => "warning",
                SeverityLevel::Low | SeverityLevel::Unknown => "note",
            };

            let help_text = if let Some(target) = vuln.fixed_in.first() {
                format!("Upgrade {} to version {} or higher.", vuln.package, target)
            } else if let Some(rem) = rem_map.get(vuln.package.as_str()) {
                rem.advice.clone()
            } else {
                format!("No fixed version currently published for {}.", vuln.package)
            };

            let help_md = format!(
                "### Remediation\n\n{}\n\n**Package**: `{}` ({})\n**Severity Score**: {:.1}\n**References**:\n{}",
                help_text,
                vuln.pkg_id,
                vuln.ecosystem,
                vuln.severity.score,
                vuln.references
                    .iter()
                    .map(|r| format!("- [{}]({})", r, r))
                    .collect::<Vec<_>>()
                    .join("\n")
            );

            let mut tags = vec!["security".to_string(), "sca".to_string(), vuln.ecosystem.clone()];
            for cwe in &vuln.cwes {
                tags.push(cwe.clone());
            }

            let rule_obj = json!({
                "id": rule_id,
                "name": format!("{}_{}", vuln.package.replace('/', "_").replace('@', ""), vuln.id.replace('-', "_")),
                "shortDescription": {
                    "text": vuln.title
                },
                "fullDescription": {
                    "text": vuln.details.as_deref().unwrap_or(&vuln.title)
                },
                "help": {
                    "text": help_text,
                    "markdown": help_md
                },
                "defaultConfiguration": {
                    "level": sarif_level
                },
                "properties": {
                    "security-severity": format!("{:.1}", vuln.severity.score),
                    "tags": tags,
                    "precision": "high"
                }
            });

            rules.push(rule_obj);
            idx
        };

        let sarif_level = match vuln.severity.level {
            SeverityLevel::Critical | SeverityLevel::High => "error",
            SeverityLevel::Medium => "warning",
            SeverityLevel::Low | SeverityLevel::Unknown => "note",
        };

        // Determine location: if AST reachability pinpointed a call site, use that; else manifest file
        let (location_uri, line_number, snippet) = if let Some(reach) = &vuln.reachability {
            if reach.status == ReachabilityStatus::Reachable && !reach.call_sites.is_empty() {
                let site = &reach.call_sites[0];
                let norm_file = site.file.replace('\\', "/");
                (norm_file, site.line, Some(site.code.clone()))
            } else {
                (manifest_uri.clone(), 1, None)
            }
        } else {
            (manifest_uri.clone(), 1, None)
        };

        let fix_advice = if !vuln.fixed_in.is_empty() {
            format!("Upgrade to {}", vuln.fixed_in.join(", "))
        } else {
            "No fix available".to_string()
        };

        let message_text = format!(
            "Vulnerability {} in {}@{}: {}. {}",
            vuln.id, vuln.package, vuln.version, vuln.title, fix_advice
        );

        let mut location_region = json!({
            "startLine": line_number
        });
        if let Some(snip) = snippet {
            location_region["snippet"] = json!({ "text": snip });
        }

        let reach_str = vuln
            .reachability
            .as_ref()
            .map(|r| match r.status {
                ReachabilityStatus::Reachable => "REACHABLE",
                ReachabilityStatus::Unreachable => "UNREACHABLE",
                ReachabilityStatus::Unknown => "UNKNOWN",
            })
            .unwrap_or("NOT_EVALUATED");

        let dep_path = vuln
            .paths
            .first()
            .map(|p| p.join(" > "))
            .unwrap_or_else(|| vuln.pkg_id.clone());

        let result_obj = json!({
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": sarif_level,
            "message": {
                "text": message_text
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location_uri,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": location_region
                    }
                }
            ],
            "properties": {
                "package": vuln.package,
                "version": vuln.version,
                "ecosystem": vuln.ecosystem,
                "isTransitive": vuln.is_transitive,
                "reachability": reach_str,
                "dependencyPath": dep_path
            }
        });

        results.push(result_obj);
    }

    let sarif_data = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vexa-sca",
                        "semanticVersion": "1.0.0",
                        "informationUri": "https://github.com/vexa-sca/vexa-sca",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    });

    serde_json::to_string_pretty(&sarif_data).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SeverityInfo;
    use crate::types::VulnerabilityFinding;
    use serde_json::Value;

    #[test]
    fn test_format_sarif_report_valid_schema() {
        let mut scan_result = ScanResult::default();
        scan_result.scanned_packages_count = 5;

        scan_result.vulnerabilities.push(VulnerabilityFinding {
            id: "GHSA-35jh-r3h4-6jhm".to_string(),
            title: "Command Injection in lodash".to_string(),
            package: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "lodash@4.17.15".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::High,
                score: 7.4,
                vector: None,
            },
            cve: Some("CVE-2021-23337".to_string()),
            cwes: vec!["CWE-78".to_string()],
            fixed_in: vec!["4.17.21".to_string()],
            is_transitive: false,
            paths: vec![vec!["my-app@1.0.0".to_string(), "lodash@4.17.15".to_string()]],
            details: Some("A command injection flaw exists in lodash template.".to_string()),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-23337".to_string()],
            reachability: None,
            ..Default::default()
        });

        let sarif_str = format_sarif_report(&scan_result, &[], Some(Path::new("package-lock.json")));
        let parsed: Value = serde_json::from_str(&sarif_str).expect("Valid JSON");

        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "vexa-sca");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 1);

        let res = &parsed["runs"][0]["results"][0];
        assert_eq!(res["ruleId"], "CVE-2021-23337");
        assert_eq!(res["level"], "error");
        assert_eq!(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "package-lock.json");
    }
}
