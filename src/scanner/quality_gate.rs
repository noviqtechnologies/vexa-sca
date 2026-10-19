use crate::licenses::license_scanner::LicenseAudit;
use crate::scanner::vuln_scanner::ScanResult;
use crate::types::{ReachabilityStatus, SeverityLevel};
use colored::*;

#[derive(Debug, Clone, Default)]
pub struct QualityGateOptions {
    pub fail_on_severity: Option<SeverityLevel>,
    pub fail_on_reachable: bool,
    pub fail_on_licenses: Option<String>,
}

#[derive(Debug, Clone)]
pub struct QualityGateResult {
    pub passed: bool,
    pub failure_reasons: Vec<String>,
}

pub struct QualityGate;

impl QualityGate {
    pub fn evaluate(
        scan_result: &ScanResult,
        license_audit: Option<&LicenseAudit>,
        options: &QualityGateOptions,
    ) -> QualityGateResult {
        let mut failure_reasons = Vec::new();

        // 1. Severity Gate
        if let Some(threshold) = options.fail_on_severity {
            let violating_count = scan_result
                .vulnerabilities
                .iter()
                .filter(|v| v.severity.level.weight() >= threshold.weight())
                .count();

            if violating_count > 0 {
                failure_reasons.push(format!(
                    "Found {} vulnerabilities at or above '{}' threshold",
                    violating_count,
                    threshold.as_str()
                ));
            }
        } else if scan_result.vulnerabilities_count > 0 && !options.fail_on_reachable && options.fail_on_licenses.is_none() {
            // Default behavior if no gates specified: fail on any vulnerability
            failure_reasons.push(format!(
                "Found {} active security vulnerabilities",
                scan_result.vulnerabilities_count
            ));
        }

        // 2. Reachable-only Gate
        if options.fail_on_reachable {
            let reachable_count = scan_result
                .vulnerabilities
                .iter()
                .filter(|v| v.reachability.as_ref().map(|r| r.status == ReachabilityStatus::Reachable).unwrap_or(false))
                .count();

            if reachable_count > 0 {
                failure_reasons.push(format!(
                    "Found {} vulnerabilities with confirmed runtime reachability (🚨 REACHABLE)",
                    reachable_count
                ));
            }
        }

        // 3. License Compliance Gate
        if let Some(lic_policy) = &options.fail_on_licenses {
            if let Some(audit) = license_audit {
                let policy_lower = lic_policy.trim().to_lowercase();
                if policy_lower.contains("strong") || policy_lower == "copyleft" {
                    if audit.summary.strong_copyleft > 0 {
                        failure_reasons.push(format!(
                            "Found {} Strong Copyleft (GPL/AGPL) licensed packages violating policy",
                            audit.summary.strong_copyleft
                        ));
                    }
                } else if policy_lower.contains("weak") {
                    if audit.summary.weak_copyleft > 0 || audit.summary.strong_copyleft > 0 {
                        failure_reasons.push(format!(
                            "Found {} Copyleft (Weak/Strong) licensed packages violating policy",
                            audit.summary.weak_copyleft + audit.summary.strong_copyleft
                        ));
                    }
                }
            }
        }

        let passed = failure_reasons.is_empty();
        QualityGateResult {
            passed,
            failure_reasons,
        }
    }

    pub fn print_terminal_summary(res: &QualityGateResult) {
        println!("\n{}", "─".repeat(70));
        if res.passed {
            println!("{}", "✔ CI/CD QUALITY GATE PASSED: All security & policy checks satisfied.".green().bold());
        } else {
            println!("{}", "✖ CI/CD QUALITY GATE FAILED: Policy violation(s) detected:".red().bold());
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
            cve: None,
            cwes: vec![],
            fixed_in: vec![],
            is_transitive: false,
            paths: vec![],
            details: None,
            references: vec![],
            reachability: None,
        });
        scan_result.vulnerabilities_count = 1;

        // Fail only on HIGH: should PASS because finding is LOW
        let opts = QualityGateOptions {
            fail_on_severity: Some(SeverityLevel::High),
            fail_on_reachable: false,
            fail_on_licenses: None,
        };
        let res = QualityGate::evaluate(&scan_result, None, &opts);
        assert!(res.passed);

        // Fail on LOW: should FAIL
        let opts_low = QualityGateOptions {
            fail_on_severity: Some(SeverityLevel::Low),
            fail_on_reachable: false,
            fail_on_licenses: None,
        };
        let res_low = QualityGate::evaluate(&scan_result, None, &opts_low);
        assert!(!res_low.passed);
    }
}
