use crate::licenses::license_scanner::LicenseAudit;
use crate::policy::policy_engine::SuppressedFinding;
pub use crate::reporters::html::format_html_report;
pub use crate::reporters::sarif::format_sarif_report;
pub use crate::reporters::sbom::{format_cyclonedx_sbom, format_spdx_sbom, SbomFormat};
use crate::scanner::vuln_scanner::ScanResult;
use crate::types::{ReachabilityStatus, RemediationAction, UsageSignal};
use chrono::Utc;
use std::path::Path;

pub fn format_json_report(
    scan_result: &ScanResult,
    suppressed: &[SuppressedFinding],
    remediations: &[RemediationAction],
    license_audit: Option<&LicenseAudit>,
    policy_file: Option<&Path>,
) -> String {
    let reachable_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Reachable)
                .unwrap_or(false)
        })
        .count();
    let unreachable_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Unreachable)
                .unwrap_or(false)
        })
        .count();

    let signal_matched_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.usage_signal == UsageSignal::ImportedSource
                || v.usage_signal == UsageSignal::ReferencedConfigOrScript
                || v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Reachable)
                    .unwrap_or(false)
        })
        .count();
    let no_signal_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.usage_signal == UsageSignal::NoReferenceFoundWithinScope
                || v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Unreachable)
                    .unwrap_or(false)
        })
        .count();
    let unknown_signal_count = scan_result
        .vulnerabilities
        .len()
        .saturating_sub(signal_matched_count + no_signal_count);

    let data = serde_json::json!({
        "meta": {
            "scanner": "vexa-sca-rust",
            "version": env!("CARGO_PKG_VERSION"),
            "schemaVersion": "1.0.0",
            "timestamp": Utc::now().to_rfc3339(),
            "policyFile": policy_file.map(|p| p.display().to_string()),
        },
        "summary": {
            "totalDependencies": scan_result.scanned_packages_count,
            "activeVulnerabilitiesCount": scan_result.vulnerabilities.len(),
            "reachabilitySummary": {
                "reachable": reachable_count,
                "unreachable": unreachable_count,
            },
            "usageSignalsSummary": {
                "signalMatched": signal_matched_count,
                "noSignalObserved": no_signal_count,
                "unknown": unknown_signal_count,
            },
            "suppressedCount": suppressed.len(),
            "hasCycles": scan_result.has_cycles,
            "status": scan_result.scan_status.as_str(),
            "advisoryStatus": scan_result.advisory_status.as_str(),
            "packagesChecked": scan_result.packages_checked,
            "packagesUnavailable": scan_result.packages_unavailable,
            "newVulnerabilitiesCount": scan_result.new_vulnerabilities_count,
            "baselineVulnerabilitiesCount": scan_result.baseline_vulnerabilities_count,
            "completeness": &scan_result.completeness,
        },
        "vulnerabilities": scan_result.vulnerabilities,
        "suppressed": suppressed,
        "remediations": remediations,
        "licenses": license_audit.map(|a| &a.results),
    });

    serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".to_string())
}

pub fn format_markdown_report(
    scan_result: &ScanResult,
    suppressed: &[SuppressedFinding],
    remediations: &[RemediationAction],
    license_audit: Option<&LicenseAudit>,
    policy_file: Option<&Path>,
) -> String {
    let mut md = String::from("# Vexa SCA - Software Composition Analysis Report (Rust Core)\n\n");
    md.push_str(&format!("- **Date**: {}\n", Utc::now().to_rfc2822()));
    md.push_str(&format!(
        "- **Scanned Dependencies**: {}\n",
        scan_result.scanned_packages_count
    ));
    md.push_str(&format!(
        "- **Active Vulnerabilities**: {}\n",
        scan_result.vulnerabilities.len()
    ));

    let signal_matched_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.usage_signal == UsageSignal::ImportedSource
                || v.usage_signal == UsageSignal::ReferencedConfigOrScript
                || v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Reachable)
                    .unwrap_or(false)
        })
        .count();
    let no_signal_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.usage_signal == UsageSignal::NoReferenceFoundWithinScope
                || v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Unreachable)
                    .unwrap_or(false)
        })
        .count();
    let unknown_signal_count = scan_result
        .vulnerabilities
        .len()
        .saturating_sub(signal_matched_count + no_signal_count);

    md.push_str(&format!(
        "- **Repository Usage Signals (heuristic)**: {} signal matched | {} no signal observed | {} unknown/unresolved\n",
        signal_matched_count, no_signal_count, unknown_signal_count
    ));
    md.push_str("- A matched signal is not proof of runtime reachability; no observed signal is not evidence of safety.\n");

    if !suppressed.is_empty() {
        md.push_str(&format!(
            "- **Suppressed Vulnerabilities (Policy)**: {}\n",
            suppressed.len()
        ));
    }
    if let Some(pf) = policy_file {
        md.push_str(&format!("- **Policy File**: `{}`\n", pf.display()));
    }
    md.push('\n');

    if let Some(audit) = license_audit {
        md.push_str("## License Compliance Summary\n\n");
        md.push_str(&format!(
            "- **Permissive (Low Risk)**: {}\n",
            audit.summary.permissive
        ));
        md.push_str(&format!(
            "- **Weak Copyleft (Medium Risk)**: {}\n",
            audit.summary.weak_copyleft
        ));
        md.push_str(&format!(
            "- **Strong Copyleft (High Risk)**: {}\n",
            audit.summary.strong_copyleft
        ));
        md.push_str(&format!(
            "- **Unknown / Unset**: {}\n\n",
            audit.summary.unknown
        ));
    }

    if scan_result.vulnerabilities.is_empty() {
        md.push_str("## Vulnerabilities\n\nNo active vulnerabilities detected!\n\n");
    } else {
        md.push_str("## Active Vulnerabilities\n\n");
        md.push_str("| Severity | Usage Signal | Package | Vulnerability ID | CVE | Fixed In |\n");
        md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");

        for v in &scan_result.vulnerabilities {
            let cve = v.cve.as_deref().unwrap_or("N/A");
            let fixes = if !v.fixed_in.is_empty() {
                v.fixed_in.join(", ")
            } else {
                "No fix".to_string()
            };
            let usage_signal = match v.reachability.as_ref() {
                Some(r) if r.status == ReachabilityStatus::Reachable => {
                    "Signal matched (heuristic)"
                }
                Some(r) if r.status == ReachabilityStatus::Unreachable => {
                    "No signal observed (not safety evidence)"
                }
                _ => "Unknown",
            };

            let ref_link = v
                .references
                .first()
                .cloned()
                .unwrap_or_else(|| "#".to_string());
            md.push_str(&format!(
                "| **{}** ({:.1}) | {} | `{}` | [{}]({}) | {} | {} |\n",
                v.severity.level.as_str(),
                v.severity.score,
                usage_signal,
                v.pkg_id,
                v.id,
                ref_link,
                cve,
                fixes
            ));
        }
        md.push('\n');
    }

    if !suppressed.is_empty() {
        md.push_str("## Suppressed Vulnerabilities (Vexa SCA Policy)\n\n");
        md.push_str("| Package | Vulnerability ID | Reason | Expiration |\n");
        md.push_str("| :--- | :--- | :--- | :--- |\n");
        for s in suppressed {
            let v = &s.vulnerability;
            md.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                v.pkg_id, v.id, s.suppression.reason, s.suppression.expires
            ));
        }
        md.push('\n');
    }

    if !remediations.is_empty() {
        md.push_str("## Remediation Actions\n\n");
        for rem in remediations {
            md.push_str(&format!(
                "### `{}` ({})\n- **Advice**: {}\n- **Current Version**: `{}`\n",
                rem.package,
                if rem.is_transitive {
                    "Transitive"
                } else {
                    "Direct"
                },
                rem.advice,
                rem.current_version
            ));
            if let Some(target) = &rem.target_version {
                md.push_str(&format!("- **Recommended Version**: `{}`\n", target));
            }
            md.push_str(&format!(
                "- **Resolves**: {} vulnerabilities\n\n",
                rem.resolved_vulnerability_count
            ));
        }
    }

    md
}

/// Formats the GitHub Actions job summary per PRD v2.2 FR-017a.
pub fn format_github_step_summary(
    scan_result: &ScanResult,
    remediations: &[RemediationAction],
) -> String {
    let mut out = String::new();
    out.push_str("## 🛡️ Vexa SCA Security Report\n\n");
    let status_badge = match scan_result.scan_status {
        crate::types::ScanStatus::Pass => "🟢 **PASS**",
        crate::types::ScanStatus::Fail => "🔴 **FAIL**",
        crate::types::ScanStatus::Incomplete => "🟡 **INCOMPLETE**",
    };
    out.push_str(&format!(
        "**Status:** {} | **Dependencies:** {} | **Active Vulnerabilities:** {}\n\n",
        status_badge,
        scan_result.scanned_packages_count,
        scan_result.vulnerabilities.len()
    ));

    if scan_result.baseline_vulnerabilities_count > 0 {
        out.push_str(&format!(
            "- **New Findings (PR):** {}\n- **Baseline Findings:** {}\n\n",
            scan_result.new_vulnerabilities_count, scan_result.baseline_vulnerabilities_count
        ));
    }

    if !scan_result.vulnerabilities.is_empty() {
        out.push_str("### ⚡ Top Priority Findings\n\n");
        out.push_str("| Package | Severity | Priority | Usage Signal | Safest Fix |\n");
        out.push_str("| :--- | :--- | :--- | :--- | :--- |\n");

        let mut prioritized = scan_result.vulnerabilities.clone();
        prioritized.sort_by(|a, b| {
            b.priority_score
                .partial_cmp(&a.priority_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for v in prioritized.iter().take(3) {
            let fix = v
                .fixed_in
                .first()
                .cloned()
                .unwrap_or_else(|| "No fix published".to_string());
            out.push_str(&format!(
                "| `{}` | `{}` | `{:.1}` | `{}` | `{}` |\n",
                v.package,
                v.severity.level.as_str(),
                v.priority_score,
                v.usage_signal.as_str(),
                fix
            ));
        }
        out.push('\n');
    }

    if !remediations.is_empty() {
        out.push_str("### 🛠️ Recommended Remediation Actions\n\n");
        for rem in remediations.iter().take(5) {
            out.push_str(&format!("- **{}**: {}\n", rem.package, rem.advice));
        }
        out.push('\n');
    }

    out
}

/// Emits workflow annotations to stdout/stderr in GitHub Actions per PRD v2.2 FR-017a.
pub fn emit_github_annotations(vulns: &[crate::types::VulnerabilityFinding]) {
    for v in vulns {
        let (file, line) = if let Some(reach) = &v.reachability {
            if let Some(site) = reach.call_sites.first() {
                (site.file.clone(), site.line)
            } else {
                ("package.json".to_string(), 1)
            }
        } else {
            ("package.json".to_string(), 1)
        };
        let level = match v.severity.level {
            crate::types::SeverityLevel::Critical | crate::types::SeverityLevel::High => "error",
            crate::types::SeverityLevel::Medium => "warning",
            _ => "notice",
        };
        let fix = if let Some(target) = v.fixed_in.first() {
            format!(" Upgrade to {}.", target)
        } else {
            String::new()
        };
        println!(
            "::{} file={},line={},title=Vulnerability in {} ({})::{} in {}@{}.{}",
            level, file, line, v.package, v.id, v.title, v.package, v.version, fix
        );
    }
}

#[cfg(test)]
mod tests {
    use super::format_markdown_report;
    use crate::scanner::vuln_scanner::ScanResult;
    use crate::types::VulnerabilityFinding;

    #[test]
    fn markdown_uses_usage_signal_terminology_and_keeps_unknown_explicit() {
        let mut scan_result = ScanResult::default();
        scan_result.vulnerabilities.push(VulnerabilityFinding {
            id: "TEST-UNKNOWN".to_string(),
            package: "example".to_string(),
            ..Default::default()
        });

        let report = format_markdown_report(&scan_result, &[], &[], None, None);

        assert!(report.contains("Repository Usage Signals (heuristic)"));
        assert!(report.contains("| Severity | Usage Signal |"));
        assert!(report.contains("Unknown"));
        assert!(!report.contains("Unreachable (Low Risk)"));
    }
}
