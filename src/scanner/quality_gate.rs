use crate::licenses::license_scanner::LicenseAudit;
use crate::scanner::vuln_scanner::ScanResult;
use crate::types::{AdvisoryCategory, ReachabilityStatus, SeverityLevel};
use colored::*;

#[derive(Debug, Clone, Default)]
pub struct QualityGateOptions {
    pub fail_on_severity: Option<SeverityLevel>,
    pub fail_on_reachable: bool,
    pub fail_on_licenses: Option<String>,
    pub fail_on_unmaintained: bool,
    pub no_fail: bool,
    pub baseline_mode: bool,
}

#[derive(Debug, Clone)]
pub struct QualityGateResult {
    pub passed: bool,
    pub failure_reasons: Vec<String>,
    pub reachable_violations: usize,
    pub deferred_unreachable_count: usize,
    pub no_fail: bool,
}

pub struct QualityGate;

impl QualityGate {
    pub fn evaluate(
        scan_result: &ScanResult,
        license_audit: Option<&LicenseAudit>,
        options: &QualityGateOptions,
    ) -> QualityGateResult {
        let mut failure_reasons = Vec::new();

        let vulns_to_eval: Vec<&crate::types::VulnerabilityFinding> = if options.baseline_mode {
            scan_result
                .vulnerabilities
                .iter()
                .filter(|v| v.is_new)
                .collect()
        } else {
            scan_result.vulnerabilities.iter().collect()
        };

        let reachable_count = vulns_to_eval
            .iter()
            .filter(|v| {
                v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Reachable)
                    .unwrap_or(false)
            })
            .count();

        let unreachable_count = vulns_to_eval
            .iter()
            .filter(|v| {
                v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Unreachable)
                    .unwrap_or(false)
            })
            .count();

        let sec_vulns: Vec<_> = vulns_to_eval
            .iter()
            .filter(|v| v.advisory_category == AdvisoryCategory::Vulnerability)
            .copied()
            .collect();

        let unmaintained_count = vulns_to_eval
            .iter()
            .filter(|v| v.advisory_category == AdvisoryCategory::Unmaintained)
            .count();

        // 1. Severity Gate (with reachability-awareness)
        if let Some(threshold) = options.fail_on_severity {
            let violating_count = sec_vulns
                .iter()
                .filter(|v| {
                    let meets_sev = v.severity.level.weight() >= threshold.weight();
                    if options.fail_on_reachable {
                        meets_sev
                            && v.reachability
                                .as_ref()
                                .map(|r| r.status == ReachabilityStatus::Reachable)
                                .unwrap_or(false)
                    } else {
                        meets_sev
                    }
                })
                .count();

            if violating_count > 0 {
                let scope = if options.fail_on_reachable {
                    "reachable "
                } else {
                    ""
                };
                let new_tag = if options.baseline_mode { "new " } else { "" };
                failure_reasons.push(format!(
                    "Found {} {}{}vulnerabilities at or above '{}' threshold",
                    violating_count,
                    new_tag,
                    scope,
                    threshold.as_str()
                ));
            }
        } else if options.fail_on_reachable {
            // 2. Reachable-only Gate without explicit severity threshold
            if reachable_count > 0 {
                let new_tag = if options.baseline_mode { "new " } else { "" };
                failure_reasons.push(format!(
                    "Found {} {}vulnerabilities with confirmed runtime reachability (🚨 REACHABLE)",
                    reachable_count, new_tag
                ));
            }
        } else if !sec_vulns.is_empty() && options.fail_on_licenses.is_none() {
            // 3. Default behavior: fail on any active security vulnerability
            let new_tag = if options.baseline_mode { "new " } else { "" };
            if reachable_count == 0 && unreachable_count > 0 {
                failure_reasons.push(format!(
                    "Found {} {}active security vulnerabilities (0 reachable, {} unreachable). Tip: use '--fail-on reachable' to block only on confirmed runtime call paths.",
                    sec_vulns.len(),
                    new_tag,
                    unreachable_count
                ));
            } else {
                failure_reasons.push(format!(
                    "Found {} {}active security vulnerabilities",
                    sec_vulns.len(),
                    new_tag
                ));
            }
        }

        // 4. Unmaintained Gate (opt-in)
        if options.fail_on_unmaintained && unmaintained_count > 0 {
            failure_reasons.push(format!(
                "Found {} unmaintained package advisories violating policy",
                unmaintained_count
            ));
        }

        // 5. License Compliance Gate
        if let Some(lic_policy) = &options.fail_on_licenses {
            if let Some(audit) = license_audit {
                let policy_lower = lic_policy.trim().to_lowercase();
                if (policy_lower.contains("strong") || policy_lower == "copyleft")
                    && audit.summary.strong_copyleft > 0
                {
                    failure_reasons.push(format!(
                        "Found {} Strong Copyleft (GPL/AGPL) licensed packages violating policy",
                        audit.summary.strong_copyleft
                    ));
                } else if policy_lower.contains("weak")
                    && (audit.summary.weak_copyleft > 0 || audit.summary.strong_copyleft > 0)
                {
                    failure_reasons.push(format!(
                        "Found {} Copyleft (Weak/Strong) licensed packages violating policy",
                        audit.summary.weak_copyleft + audit.summary.strong_copyleft
                    ));
                }
            }
        }

        let passed = if options.no_fail {
            true
        } else {
            failure_reasons.is_empty()
        };
        QualityGateResult {
            passed,
            failure_reasons,
            reachable_violations: reachable_count,
            deferred_unreachable_count: unreachable_count,
            no_fail: options.no_fail,
        }
    }

    pub fn print_terminal_summary(res: &QualityGateResult) {
        println!("\n{}", "─".repeat(70));
        if res.no_fail && !res.failure_reasons.is_empty() {
            println!(
                "{}",
                "ℹ CI/CD QUALITY GATE: Findings detected, exiting 0 (--no-fail / --report-only active)."
                    .yellow()
                    .bold()
            );
            for reason in &res.failure_reasons {
                println!("  ↳ {}", reason.dimmed());
            }
        } else if res.passed {
            println!(
                "{}",
                "✔ CI/CD QUALITY GATE PASSED: All security & policy checks satisfied."
                    .green()
                    .bold()
            );
            if res.deferred_unreachable_count > 0 {
                println!(
                    "  ↳ {} unreachable vulnerabilities deferred to backlog (0 active runtime risks)",
                    res.deferred_unreachable_count
                );
            }
        } else {
            println!(
                "{}",
                "✖ CI/CD QUALITY GATE FAILED: Policy violation(s) detected:"
                    .red()
                    .bold()
            );
            for reason in &res.failure_reasons {
                println!("  ↳ {}", reason.yellow());
            }
        }
        println!("{}", "─".repeat(70));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SeverityInfo, VulnerabilityFinding};

    #[test]
    fn test_quality_gate_severity_threshold() {
        let mut scan_result = ScanResult::default();
        scan_result.vulnerabilities.push(VulnerabilityFinding {
            id: "VULN-1".to_string(),
            title: "Test Low".to_string(),
            package: "pkg-a".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "pkg-a@1.0.0".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::Low,
                score: 3.0,
                vector: None,
            },
            ..Default::default()
        });
        scan_result.vulnerabilities_count = 1;

        // Fail only on HIGH: should PASS because finding is LOW
        let opts = QualityGateOptions {
            fail_on_severity: Some(SeverityLevel::High),
            ..Default::default()
        };
        let res = QualityGate::evaluate(&scan_result, None, &opts);
        assert!(res.passed);

        // Fail on reachable: finding has no reachability -> PASS
        let opts_reach = QualityGateOptions {
            fail_on_reachable: true,
            ..Default::default()
        };
        let res_reach = QualityGate::evaluate(&scan_result, None, &opts_reach);
        assert!(res_reach.passed);

        // Fail on LOW: should FAIL
        let opts_low = QualityGateOptions {
            fail_on_severity: Some(SeverityLevel::Low),
            ..Default::default()
        };
        let res_low = QualityGate::evaluate(&scan_result, None, &opts_low);
        assert!(!res_low.passed);

        // Default gate (no flags): fails on any active security vulnerability
        let opts_default = QualityGateOptions {
            ..Default::default()
        };
        let res_default = QualityGate::evaluate(&scan_result, None, &opts_default);
        assert!(!res_default.passed);
        assert_eq!(res_default.failure_reasons.len(), 1);

        // --no-fail / --report-only: passes even if findings exist
        let opts_no_fail = QualityGateOptions {
            no_fail: true,
            ..Default::default()
        };
        let res_no_fail = QualityGate::evaluate(&scan_result, None, &opts_no_fail);
        assert!(res_no_fail.passed);
        assert!(res_no_fail.no_fail);
        assert!(!res_no_fail.failure_reasons.is_empty());
    }
}
