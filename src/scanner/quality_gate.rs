use crate::licenses::license_scanner::LicenseAudit;
use crate::scanner::vuln_scanner::ScanResult;
use crate::types::{AdvisoryCategory, ReachabilityStatus, SeverityLevel};
use colored::*;

#[derive(Debug, Clone, Default)]
pub struct QualityGateOptions {
    pub fail_on_severity: Option<SeverityLevel>,
    pub fail_on_reachable: bool,
    pub fail_on_unknown_reachability: bool,
    pub allow_unknown_reachability: bool,
    pub fail_on_licenses: Option<String>,
    pub fail_on_unmaintained: bool,
    pub no_fail: bool,
    pub baseline_mode: bool,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGateResult {
    pub passed: bool,
    pub failure_reasons: Vec<String>,
    pub reachable_violations: usize,
    pub unknown_reachability_violations: usize,
    pub deferred_unreachable_count: usize,
    pub no_fail: bool,
}

impl QualityGateResult {
    pub fn has_severity_failure(&self) -> bool {
        self.failure_reasons.iter().any(|r| {
            r.contains("threshold")
                || r.contains("active security vulnerabilities")
                || r.contains("confirmed usage signals")
                || r.contains("UNKNOWN reachability")
        })
    }
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

        let unknown_count = vulns_to_eval
            .iter()
            .filter(|v| {
                v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Unknown)
                    .unwrap_or(true)
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

        // 1. Severity Gate (over ALL unsuppressed vulnerabilities by default!)
        if let Some(threshold) = options.fail_on_severity {
            let violating_count = sec_vulns
                .iter()
                .filter(|v| {
                    let meets_sev = v.severity.level.weight() >= threshold.weight();
                    if options.fail_on_reachable {
                        // Fail-safe: when reachable gate is combined with severity,
                        // reachable findings fail. Unknown reachability ALSO fails unless explicitly opted out.
                        let is_reachable = v
                            .reachability
                            .as_ref()
                            .map(|r| r.status == ReachabilityStatus::Reachable)
                            .unwrap_or(false);
                        let is_unknown = v
                            .reachability
                            .as_ref()
                            .map(|r| r.status == ReachabilityStatus::Unknown)
                            .unwrap_or(true);
                        let counts =
                            is_reachable || (is_unknown && !options.allow_unknown_reachability);
                        meets_sev && counts
                    } else {
                        // Unmodified severity gate evaluates over all findings
                        meets_sev
                    }
                })
                .count();

            if violating_count > 0 {
                let scope = if options.fail_on_reachable {
                    if options.allow_unknown_reachability {
                        "confirmed-reachable "
                    } else {
                        "reachable/unverified "
                    }
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
            let new_tag = if options.baseline_mode { "new " } else { "" };
            if reachable_count > 0 {
                failure_reasons.push(format!(
                    "Found {} {}vulnerabilities with confirmed usage signals (REACHABLE)",
                    reachable_count, new_tag
                ));
            }
            if unknown_count > 0 && !options.allow_unknown_reachability {
                failure_reasons.push(format!(
                    "Found {} {}vulnerabilities with UNKNOWN reachability under reachable gate policy (fail-safe: use '--allow-unknown-reachability' to opt out)",
                    unknown_count, new_tag
                ));
            }
        } else if !sec_vulns.is_empty() && options.fail_on_licenses.is_none() {
            // 3. Default behavior: fail on any active security vulnerability
            let new_tag = if options.baseline_mode { "new " } else { "" };
            failure_reasons.push(format!(
                "Found {} {}active security vulnerabilities",
                sec_vulns.len(),
                new_tag
            ));
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
            unknown_reachability_violations: unknown_count,
            deferred_unreachable_count: unreachable_count,
            no_fail: options.no_fail,
        }
    }

    pub fn print_terminal_summary(result: &QualityGateResult) {
        if result.passed {
            if result.no_fail && !result.failure_reasons.is_empty() {
                println!(
                    "\n{} (report-only mode enabled: exit code 0)",
                    "✔ Quality Gate: PASSED".green().bold()
                );
                for reason in &result.failure_reasons {
                    println!("  {} {}", "ℹ [Ignored by --no-fail]:".yellow(), reason);
                }
            } else {
                println!("\n{}", "✔ Quality Gate: PASSED".green().bold());
                if result.deferred_unreachable_count > 0 {
                    println!(
                        "  {} {} unreachable vulnerabilities deferred from blocking CI",
                        "ℹ".blue(),
                        result.deferred_unreachable_count
                    );
                }
            }
        } else {
            println!("\n{}", "✖ Quality Gate: FAILED".red().bold());
            for reason in &result.failure_reasons {
                println!("  {} {}", "✖".red(), reason);
            }
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ReachabilityResult, SeverityInfo, VulnerabilityFinding};

    fn make_finding(
        id: &str,
        level: SeverityLevel,
        reach: ReachabilityStatus,
    ) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: id.to_string(),
            package: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            severity: SeverityInfo {
                level,
                score: level.weight() as f64 * 2.5,
                vector: None,
            },
            reachability: Some(ReachabilityResult {
                status: reach,
                is_direct_call: true,
                call_sites: vec![],
                target_functions: vec!["*".to_string()],
                reason_code: None,
                analyzer_version: "1.0.0".to_string(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_unknown_reachability_fails_reachable_gate_by_default() {
        let scan_result = ScanResult {
            vulnerabilities: vec![make_finding(
                "VULN-1",
                SeverityLevel::High,
                ReachabilityStatus::Unknown,
            )],
            ..Default::default()
        };

        let opts = QualityGateOptions {
            fail_on_reachable: true,
            allow_unknown_reachability: false,
            ..Default::default()
        };

        let res = QualityGate::evaluate(&scan_result, None, &opts);
        assert!(
            !res.passed,
            "Unknown reachability must fail reachable gate by default"
        );
        assert!(res.failure_reasons[0].contains("UNKNOWN reachability"));
    }

    #[test]
    fn test_allow_unknown_reachability_opt_out_passes_unknown() {
        let scan_result = ScanResult {
            vulnerabilities: vec![make_finding(
                "VULN-1",
                SeverityLevel::High,
                ReachabilityStatus::Unknown,
            )],
            ..Default::default()
        };

        let opts = QualityGateOptions {
            fail_on_reachable: true,
            allow_unknown_reachability: true,
            ..Default::default()
        };

        let res = QualityGate::evaluate(&scan_result, None, &opts);
        assert!(
            res.passed,
            "Explicit allow_unknown_reachability must allow unknown finding to pass"
        );
    }

    #[test]
    fn test_ordinary_severity_gate_evaluates_all_findings_regardless_of_reachability() {
        let scan_result = ScanResult {
            vulnerabilities: vec![
                make_finding(
                    "VULN-1",
                    SeverityLevel::High,
                    ReachabilityStatus::Unreachable,
                ),
                make_finding("VULN-2", SeverityLevel::High, ReachabilityStatus::Unknown),
            ],
            ..Default::default()
        };

        let opts = QualityGateOptions {
            fail_on_severity: Some(SeverityLevel::High),
            fail_on_reachable: false,
            ..Default::default()
        };

        let res = QualityGate::evaluate(&scan_result, None, &opts);
        assert!(
            !res.passed,
            "Ordinary fail_on high must evaluate all high findings"
        );
        assert!(res.failure_reasons[0].contains("2 vulnerabilities at or above 'HIGH' threshold"));
    }
}
