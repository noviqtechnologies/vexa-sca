use crate::licenses::license_scanner::{LicenseAudit, LicenseCategory};
use crate::policy::policy_engine::SuppressedFinding;
use crate::scanner::vuln_scanner::ScanResult;
use crate::types::{ReachabilityResult, ReachabilityStatus, RemediationAction, SeverityLevel};
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
            ReachabilityStatus::Reachable => format!("{}", " 🚨 REACHABLE ".on_red().white().bold()),
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
    println!(" {}", "Vexa SCA Security & Reachability Scan Results (Rust Core)".cyan().bold());
    println!("{}", "=".repeat(78));

    println!("Scanned Dependencies : {}", scan_result.scanned_packages_count.to_string().bold());
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
        .filter(|v| v.reachability.as_ref().map(|r| r.status == ReachabilityStatus::Reachable).unwrap_or(false))
        .count();
    let unreachable_count = vulns
        .iter()
        .filter(|v| v.reachability.as_ref().map(|r| r.status == ReachabilityStatus::Unreachable).unwrap_or(false))
        .count();

    println!(
        "Reachability (Deep)  : 🚨 {} | 🛡️ {}",
        if reachable_count > 0 {
            format!("{} Active Call-sites", reachable_count).red().bold().to_string()
        } else {
            "0".green().to_string()
        },
        if unreachable_count > 0 {
            format!("{} Not Called (Low Risk)", unreachable_count).green().to_string()
        } else {
            "0".to_string()
        }
    );

    if let Some(pf) = policy_file {
        println!("Policy File          : {}", pf.display().to_string().dimmed());
    }
    if !suppressed.is_empty() {
        println!("Suppressed (Ignored) : {}", suppressed.len().to_string().yellow().bold());
    }
    println!(
        "Active Vulns Found   : {}",
        if !vulns.is_empty() {
            vulns.len().to_string().red().bold().to_string()
        } else {
            "0 (Clean)".green().to_string()
        }
    );

    // 1. License Compliance Summary
    if let Some(audit) = license_audit {
        let sum = &audit.summary;
        println!("\n{}", "-".repeat(78));
        println!(" {}", "License Compliance Audit:".bold());
        println!("{}", "-".repeat(78));
        println!(" Total Evaluated     : {}", sum.total);
        println!(" Permissive (Low)    : {}", sum.permissive.to_string().green());
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
                format!("{} (High Risk / GPL!)", sum.strong_copyleft).red().bold().to_string()
            } else {
                "0 (None)".green().to_string()
            }
        );
        if sum.unknown > 0 {
            println!(" Unknown / Unset     : {}", sum.unknown.to_string().dimmed());
        }

        if sum.strong_copyleft > 0 {
            println!("\n {} Strong copyleft licenses detected:", " WARNING ".on_red().white());
            for r in audit.results.iter().filter(|r| r.category == LicenseCategory::StrongCopyleft) {
                println!("   • {}@{}: {}", r.package.bold(), r.version, r.license.red());
            }
        }
    }

    // 2. Suppressed
    if !suppressed.is_empty() {
        println!("\n{}", "-".repeat(78));
        println!(" {}", "Suppressed Vulnerabilities (via Vexa SCA Policy):".yellow().bold());
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

    // 3. Active Vulnerabilities
    if !vulns.is_empty() {
        println!("\n{}", "-".repeat(78));
        println!(" {}", "Detected Vulnerabilities:".bold());
        println!("{}", "-".repeat(78));

        for v in vulns {
            let sev_badge = format_severity_badge(v.severity.level);
            let reach_badge = format_reachability_badge(v.reachability.as_ref());
            let cve_str = v.cve.as_ref().map(|c| format!("({})", c)).unwrap_or_default().dimmed();
            let score_str = format!("CVSS {:.1}", v.severity.score);

            println!("\n {} {} {} {}", sev_badge, reach_badge, v.title.bold(), cve_str);
            println!("   ID          : {} [{}]", v.id.cyan(), score_str);
            println!(
                "   Package     : {}@{} ({})",
                v.package.magenta(),
                v.version,
                if v.is_transitive { "Transitive" } else { "Direct" }
            );

            if !v.fixed_in.is_empty() {
                println!("   Fixed in    : {}", v.fixed_in.join(", ").green());
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
                        "Unreachable in application source code (vulnerable functions not called)".green()
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
        println!("\n{}", "✔ No active vulnerabilities found in project dependencies!".green().bold());
    }

    // 4. Remediations
    if !remediations.is_empty() {
        println!("\n{}", "=".repeat(78));
        println!(" {}", "Recommended Remediations & Upgrade Paths:".green().bold());
        println!("{}", "=".repeat(78));

        for (idx, rem) in remediations.iter().enumerate() {
            println!(
                "\n [{}] {} ({})",
                idx + 1,
                rem.package.bold(),
                if rem.is_transitive { "transitive" } else { "direct" }
            );
            println!("     Action : {}", rem.advice.yellow());
            println!("     Impact : Resolves {} vulnerability/advisories", rem.resolved_vulnerability_count);
        }

        println!(
            "\n {} Run {} to automatically patch manifest/overrides!",
            " TIP ".on_green().white().bold(),
            "vexa fix".bold()
        );
    }

    println!("\n{}\n", "=".repeat(78));
}
