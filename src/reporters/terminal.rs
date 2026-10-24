use crate::licenses::license_scanner::{LicenseAudit, LicenseCategory};
use crate::policy::policy_engine::SuppressedFinding;
use crate::scanner::vuln_scanner::ScanResult;
use crate::types::{
    AdvisoryCategory, ReachabilityResult, ReachabilityStatus, RemediationAction, SeverityLevel,
};
use colored::*;
use std::path::Path;

pub fn format_severity_badge(level: SeverityLevel) -> ColoredString {
    match level {
        SeverityLevel::Critical => " CRITICAL ".on_red().white().bold(),
        SeverityLevel::High => "[HIGH]".red().bold(),
        SeverityLevel::Medium => "[MEDIUM]".yellow().bold(),
        SeverityLevel::Low => "[LOW]".blue().bold(),
        SeverityLevel::Unknown => "[UNKNOWN]".normal(),
    }
}

pub fn format_reachability_badge(reachability: Option<&ReachabilityResult>) -> String {
    match reachability {
        Some(r) => match r.status {
            ReachabilityStatus::Reachable => {
                format!("{}", " 🚨 REACHABLE ".on_red().white().bold())
            }
            ReachabilityStatus::Unreachable => format!("{}", "[🛡️ UNREACHABLE]".green().bold()),
            ReachabilityStatus::Unknown => "".to_string(),
        },
        None => "".to_string(),
    }
}

pub fn render_terminal_report(
    scan_result: &ScanResult,
    suppressed: &[SuppressedFinding],
    remediations: &[RemediationAction],
    license_audit: Option<&LicenseAudit>,
    policy_file: Option<&Path>,
) {
    let vulns = &scan_result.vulnerabilities;

    println!("\n{}", "=".repeat(78));
    println!(
        " {}",
        "Vexa SCA Security & Reachability Scan Results (Rust Core)"
            .cyan()
            .bold()
    );
    println!("{}", "=".repeat(78));

    println!(
        "Scan Status          : {}",
        match scan_result.scan_status {
            crate::types::ScanStatus::Pass => " PASS ".on_green().white().bold(),
            crate::types::ScanStatus::Fail => " FAIL ".on_red().white().bold(),
            crate::types::ScanStatus::Incomplete => " INCOMPLETE ".on_yellow().black().bold(),
        }
    );
    println!(
        "Scanned Dependencies : {}",
        scan_result.scanned_packages_count.to_string().bold()
    );
    if scan_result.baseline_vulnerabilities_count > 0 {
        println!(
            "New Findings (PR)    : {}",
            scan_result
                .new_vulnerabilities_count
                .to_string()
                .red()
                .bold()
        );
        println!(
            "Baseline Findings    : {}",
            scan_result
                .baseline_vulnerabilities_count
                .to_string()
                .dimmed()
        );
    }
    println!(
        "Dependency Cycles    : {}",
        if scan_result.has_cycles {
            "Detected".yellow().to_string()
        } else {
            "None".green().to_string()
        }
    );

    let reachable_count = vulns
        .iter()
        .filter(|v| {
            v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Reachable)
                .unwrap_or(false)
        })
        .count();

    if reachable_count > 0 {
        println!(
            "Reachability Evidence: 🚨 {}",
            format!("{} Active Call-sites Found", reachable_count)
                .red()
                .bold()
        );
    } else if vulns.is_empty() {
        println!(
            "Reachability Evidence: {}",
            "Clean (No Vulnerabilities)".green()
        );
    } else {
        println!(
            "Reachability Evidence: {}",
            "0 Direct Call-sites (Conservative triage: no symbols confirmed)".dimmed()
        );
    }

    if let Some(pf) = policy_file {
        println!(
            "Policy File          : {}",
            pf.display().to_string().dimmed()
        );
    }
    if !suppressed.is_empty() {
        println!(
            "Suppressed (Ignored) : {}",
            suppressed.len().to_string().yellow().bold()
        );
    }
    let unm_vulns: Vec<_> = vulns
        .iter()
        .filter(|v| v.advisory_category == AdvisoryCategory::Unmaintained)
        .collect();

    let crit_count = vulns
        .iter()
        .filter(|v| v.severity.level == SeverityLevel::Critical)
        .count();
    let high_count = vulns
        .iter()
        .filter(|v| v.severity.level == SeverityLevel::High)
        .count();
    let med_count = vulns
        .iter()
        .filter(|v| v.severity.level == SeverityLevel::Medium)
        .count();
    let low_count = vulns
        .iter()
        .filter(|v| v.severity.level == SeverityLevel::Low)
        .count();

    let mut breakdown = Vec::new();
    if crit_count > 0 {
        breakdown.push(format!("CRITICAL: {}", crit_count).red().bold().to_string());
    }
    if high_count > 0 {
        breakdown.push(format!("HIGH: {}", high_count).red().to_string());
    }
    if med_count > 0 {
        breakdown.push(format!("MEDIUM: {}", med_count).yellow().to_string());
    }
    if low_count > 0 {
        breakdown.push(format!("LOW: {}", low_count).blue().to_string());
    }
    if !unm_vulns.is_empty() {
        breakdown.push(
            format!("UNMAINTAINED: {}", unm_vulns.len())
                .magenta()
                .to_string(),
        );
    }

    let breakdown_str = if !breakdown.is_empty() {
        format!(" ({})", breakdown.join(" | "))
    } else {
        String::new()
    };

    println!(
        "Active Vulns Found   : {}{}",
        if !vulns.is_empty() {
            vulns.len().to_string().red().bold().to_string()
        } else {
            "0 (Clean)".green().to_string()
        },
        breakdown_str
    );

    // 1. License Compliance Summary
    if let Some(audit) = license_audit {
        let sum = &audit.summary;
        println!("\n{}", "-".repeat(78));
        println!(" {}", "License Compliance Audit:".bold());
        println!("{}", "-".repeat(78));
        println!(" Total Evaluated     : {}", sum.total);
        println!(
            " Permissive (Low)    : {}",
            sum.permissive.to_string().green()
        );
        println!(
            " Weak Copyleft (Med) : {}",
            if sum.weak_copyleft > 0 {
                sum.weak_copyleft.to_string().yellow().to_string()
            } else {
                "0".to_string()
            }
        );
        println!(
            " Strong Copyleft     : {}",
            if sum.strong_copyleft > 0 {
                format!("{} (High Risk / GPL!)", sum.strong_copyleft)
                    .red()
                    .bold()
                    .to_string()
            } else {
                "0 (None)".green().to_string()
            }
        );
        if sum.unknown > 0 {
            println!(
                " Unknown / Unset     : {}",
                sum.unknown.to_string().dimmed()
            );
        }

        if sum.strong_copyleft > 0 {
            println!(
                "\n {} Strong copyleft licenses detected:",
                " WARNING ".on_red().white()
            );
            for r in audit
                .results
                .iter()
                .filter(|r| r.category == LicenseCategory::StrongCopyleft)
            {
                println!(
                    "   • {}@{}: {}",
                    r.package.bold(),
                    r.version,
                    r.license.red()
                );
            }
        }
    }

    // 2. Suppressed
    if !suppressed.is_empty() {
        println!("\n{}", "-".repeat(78));
        println!(
            " {}",
            "Suppressed Vulnerabilities (via Vexa SCA Policy):"
                .yellow()
                .bold()
        );
        println!("{}", "-".repeat(78));
        for s in suppressed {
            let v = &s.vulnerability;
            println!(
                " [IGNORED] {}@{} - {} ({})",
                v.package.dimmed(),
                v.version.dimmed(),
                v.id.bold(),
                v.cve.as_deref().unwrap_or("No CVE")
            );
            println!("   ↳ Reason : {}", s.suppression.reason.yellow());
            if let Some(exp) = &s.suppression.expires {
                println!("   ↳ Expires: {}", exp);
            }
        }
    }

    // 3. Top Priority Recommendations (FR-008a)
    if !vulns.is_empty() {
        println!("\n{}", "-".repeat(78));
        println!(
            " {}",
            "Top Priority Recommendations (Action within 30s):".bold()
        );
        println!("{}", "-".repeat(78));

        let mut prioritized = vulns.clone();
        prioritized.sort_by(|a, b| {
            b.priority_score
                .partial_cmp(&a.priority_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for (idx, v) in prioritized.iter().take(3).enumerate() {
            let reason = match v.usage_signal {
                crate::types::UsageSignal::ImportedSource => {
                    "Imported directly in first-party source code"
                }
                crate::types::UsageSignal::ReferencedConfigOrScript => {
                    "Referenced in build/dev scripts or configuration"
                }
                crate::types::UsageSignal::NoReferenceFoundWithinScope => {
                    "No active reference found in analyzed scope"
                }
                crate::types::UsageSignal::Unknown => "Usage analysis inconclusive",
            };
            let fix = if let Some(first_fix) = v.fixed_in.first() {
                format!("Upgrade to {}", first_fix)
            } else {
                "No patch currently published".to_string()
            };
            println!(
                " {}. {}@{} [{}] - Priority: {:.1}",
                idx + 1,
                v.package.bold(),
                v.version,
                v.severity.level.as_str().red(),
                v.priority_score
            );
            println!("    ↳ Reason : {}", reason.yellow());
            println!("    ↳ Fix    : {}", fix.green().bold());
        }
    }

    // 4. All Detected Vulnerabilities
    if !vulns.is_empty() {
        println!("\n{}", "-".repeat(78));
        println!(" {}", "All Detected Vulnerabilities:".bold());
        println!("{}", "-".repeat(78));

        for v in vulns {
            let sev_badge = if v.advisory_category == AdvisoryCategory::Unmaintained {
                "[UNMAINTAINED]".magenta().bold()
            } else {
                format_severity_badge(v.severity.level)
            };
            let reach_badge = format_reachability_badge(v.reachability.as_ref());
            let cve_str = v
                .cve
                .as_ref()
                .map(|c| format!("({})", c))
                .unwrap_or_default()
                .dimmed();
            let score_str = if v.advisory_category == AdvisoryCategory::Unmaintained {
                "Advisory".to_string()
            } else if let Some(ref epss) = v.epss {
                match epss.source {
                    crate::types::EpssSource::FirstOrg | crate::types::EpssSource::Cache => {
                        let epss_pct = epss.score * 100.0;
                        format!("CVSS {:.1} | EPSS {:.1}%", v.severity.score, epss_pct)
                    }
                    crate::types::EpssSource::Heuristic => {
                        let epss_pct = epss.score * 100.0;
                        format!(
                            "CVSS {:.1} | Est. Exploit {:.1}% (heuristic)",
                            v.severity.score, epss_pct
                        )
                    }
                    crate::types::EpssSource::Unavailable => {
                        format!("CVSS {:.1} | EPSS unavailable", v.severity.score)
                    }
                }
            } else {
                format!("CVSS {:.1}", v.severity.score)
            };

            let id_display = if !v.aliases.is_empty() {
                let alias_filter: Vec<_> = v
                    .aliases
                    .iter()
                    .filter(|a| a.as_str() != v.id.as_str() && Some(a.as_str()) != v.cve.as_deref())
                    .take(3)
                    .cloned()
                    .collect();
                if !alias_filter.is_empty() {
                    format!("{} ({})", v.id.cyan(), alias_filter.join(" | ").dimmed())
                } else {
                    v.id.cyan().to_string()
                }
            } else {
                v.id.cyan().to_string()
            };

            println!(
                "\n {} {} {} {}",
                sev_badge,
                reach_badge,
                v.title.bold(),
                cve_str
            );
            println!("   ID          : {} [{}]", id_display, score_str);
            println!(
                "   Package     : {}@{} ({})",
                v.package.magenta(),
                v.version,
                if v.is_transitive {
                    "Transitive"
                } else {
                    "Direct"
                }
            );

            if !v.fixed_in.is_empty() {
                println!("   Fixed in    : {}", v.fixed_in.join(", ").green().bold());
            } else {
                println!(
                    "   Fixed in    : {}",
                    "No fix available (Vendor backlog / unfixed)".dimmed()
                );
            }

            if let Some(reach) = &v.reachability {
                if reach.status == ReachabilityStatus::Reachable && !reach.call_sites.is_empty() {
                    println!("   {}", "Call-site Execution Path:".red().bold());
                    for cs in reach.call_sites.iter().take(2) {
                        println!(
                            "     🚨 {} ➔ `{}` (invokes {})",
                            format!("{}:{}", cs.file, cs.line).bold(),
                            cs.code.yellow(),
                            cs.matched_function.red()
                        );
                    }
                } else if reach.status == ReachabilityStatus::Unreachable {
                    println!(
                        "   Execution   : {}",
                        "Unreachable in application source code (vulnerable functions not called)"
                            .green()
                    );
                }
            }

            if !v.paths.is_empty() {
                println!("   Dep Path    :");
                for p in v.paths.iter().take(2) {
                    println!("     ↳ {}", p.join(" ➔ ").dimmed());
                }
                if v.paths.len() > 2 {
                    println!("     ↳ ... and {} more path(s)", v.paths.len() - 2);
                }
            }
        }
    } else {
        println!(
            "\n{}",
            "✔ No active vulnerabilities found in project dependencies!"
                .green()
                .bold()
        );
    }

    // 4. Remediations
    if !remediations.is_empty() {
        println!("\n{}", "=".repeat(78));
        println!(
            " {}",
            "Recommended Remediations & Upgrade Paths:".green().bold()
        );
        println!("{}", "=".repeat(78));

        for (idx, rem) in remediations.iter().enumerate() {
            println!(
                "\n [{}] {}@{} ({})",
                idx + 1,
                rem.package.bold(),
                rem.current_version,
                if rem.is_transitive {
                    "transitive"
                } else {
                    "direct"
                }
            );
            println!("     Action : {}", rem.advice.yellow());
            println!(
                "     Impact : Resolves {} vulnerability/advisories",
                rem.resolved_vulnerability_count
            );
        }

        println!(
            "\n {} Run {} to automatically patch manifest/overrides!",
            " TIP ".on_green().white().bold(),
            "vexa fix".bold()
        );
    }

    println!("\n{}\n", "=".repeat(78));
}
