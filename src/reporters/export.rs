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
    quality_gate: Option<&crate::scanner::quality_gate::QualityGateResult>,
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
    let unknown_reachability_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Unknown)
                .unwrap_or(true)
        })
        .count();

    let mut signal_matched_count = 0usize;
    let mut no_signal_count = 0usize;
    let mut unknown_signal_count = 0usize;
    for v in &scan_result.vulnerabilities {
        let is_matched = v.usage_signal == UsageSignal::ImportedSource
            || v.usage_signal == UsageSignal::ReferencedConfigOrScript
            || v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Reachable)
                .unwrap_or(false);
        if is_matched {
            signal_matched_count += 1;
        } else if v.usage_signal == UsageSignal::NoReferenceFoundWithinScope
            || v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Unreachable)
                .unwrap_or(false)
        {
            no_signal_count += 1;
        } else {
            unknown_signal_count += 1;
        }
    }

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
                "unknown": unknown_reachability_count,
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
            "qualityGate": quality_gate.map(|g| {
                serde_json::json!({
                    "passed": g.passed,
                    "severityGateFailed": !g.passed && g.has_severity_failure(),
                    "failureReasons": &g.failure_reasons,
                    "noFailSuppressed": g.no_fail && !g.failure_reasons.is_empty(),
                })
            }),
        },
        "vulnerabilities": scan_result.vulnerabilities,
        "supplyChainFindings": scan_result.supply_chain_findings,
        "codeFindings": scan_result.code_findings,
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

    if !scan_result.code_findings.is_empty() {
        let sast_findings: Vec<_> = scan_result
            .code_findings
            .iter()
            .filter(|f| !f.category.eq_ignore_ascii_case("SECRET"))
            .collect();
        let secret_findings: Vec<_> = scan_result
            .code_findings
            .iter()
            .filter(|f| f.category.eq_ignore_ascii_case("SECRET"))
            .collect();

        if !sast_findings.is_empty() {
            md.push_str("## Code Security Findings (SAST)\n\n");
            md.push_str("| Severity | Rule | CWE | Location | Sink |\n");
            md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
            for f in &sast_findings {
                let cwe = f.cwe.as_deref().unwrap_or("—");
                let sink = f.matched_sink.as_deref().unwrap_or("—");
                md.push_str(&format!(
                    "| **{}** | `{}` | {} | `{}:{}` | `{}` |\n",
                    escape_md_cell(&f.severity),
                    escape_md_cell(&f.rule_id),
                    escape_md_cell(cwe),
                    escape_md_cell(&f.file_path),
                    f.line,
                    escape_md_cell(sink),
                ));
            }
            md.push('\n');
        }

        if !secret_findings.is_empty() {
            md.push_str("## Secret Detection Findings\n\n");
            md.push_str("| Severity | Rule | Location | Sanitized Match |\n");
            md.push_str("| :--- | :--- | :--- | :--- |\n");
            for f in &secret_findings {
                let sink = f.matched_sink.as_deref().unwrap_or("redacted");
                md.push_str(&format!(
                    "| **{}** | `{}` | `{}:{}` | `{}` |\n",
                    escape_md_cell(&f.severity),
                    escape_md_cell(&f.rule_id),
                    escape_md_cell(&f.file_path),
                    f.line,
                    escape_md_cell(sink),
                ));
            }
            md.push('\n');
        }
    }

    md
}

pub const PR_COMMENT_MARKER: &str = "<!-- vexa-sca-pr-report -->";

#[derive(Debug, Clone, Default)]
pub struct PrReportOptions<'a> {
    pub license_audit: Option<&'a LicenseAudit>,
    pub quality_gate: Option<&'a crate::scanner::quality_gate::QualityGateResult>,
    pub sast_enabled: bool,
    pub secrets_enabled: bool,
    pub dashboard_url: Option<&'a str>,
}

fn escape_md_cell(raw: &str) -> String {
    raw.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('`', "'")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace(['\r', '\n'], " ")
}

#[derive(Debug, Clone, Copy, Default)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

impl SeverityCounts {
    fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low
    }

    fn add_str_severity(&mut self, sev: &str) {
        match sev.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => self.critical += 1,
            "HIGH" => self.high += 1,
            "MEDIUM" => self.medium += 1,
            _ => self.low += 1,
        }
    }
}

fn format_engine_row(
    status: &str,
    engine: &str,
    counts: Option<SeverityCounts>,
    total_cell: String,
) -> String {
    match counts {
        Some(c) => format!(
            "| {} | **{}** | {} | {} | {} | {} | {} |\n",
            status, engine, c.critical, c.high, c.medium, c.low, total_cell
        ),
        None => format!(
            "| {} | **{}** | — | — | — | — | {} |\n",
            status, engine, total_cell
        ),
    }
}

/// Formats a deduplicated, Snyk-style Pull Request security matrix comment (Zero-Code-Retention).
pub fn format_pr_comment_report(
    scan_result: &ScanResult,
    remediations: &[RemediationAction],
    opts: &PrReportOptions<'_>,
) -> String {
    let mut out = String::new();
    out.push_str(PR_COMMENT_MARKER);
    out.push('\n');

    // 1. Aggregate Open Source Security (SCA) counts
    let mut sca_counts = SeverityCounts::default();
    let mut reachable_count = 0usize;
    for v in &scan_result.vulnerabilities {
        match v.severity.level {
            crate::types::SeverityLevel::Critical => sca_counts.critical += 1,
            crate::types::SeverityLevel::High => sca_counts.high += 1,
            crate::types::SeverityLevel::Medium => sca_counts.medium += 1,
            crate::types::SeverityLevel::Low | crate::types::SeverityLevel::Unknown => {
                sca_counts.low += 1
            }
        }
        if v.reachability
            .as_ref()
            .map(|r| r.status == ReachabilityStatus::Reachable)
            .unwrap_or(false)
        {
            reachable_count += 1;
        }
    }

    // 2. Aggregate License counts (non-permissive items only; permissive licenses are not issues)
    let license_counts = opts.license_audit.map(|audit| SeverityCounts {
        critical: 0,
        high: audit.summary.strong_copyleft,
        medium: audit.summary.weak_copyleft,
        low: audit.summary.unknown,
    });

    // 3. Aggregate SAST and Secret counts from code_findings
    let sast_findings: Vec<_> = scan_result
        .code_findings
        .iter()
        .filter(|f| !f.category.eq_ignore_ascii_case("SECRET"))
        .collect();
    let secret_findings: Vec<_> = scan_result
        .code_findings
        .iter()
        .filter(|f| f.category.eq_ignore_ascii_case("SECRET"))
        .collect();

    let mut sast_counts = SeverityCounts::default();
    for f in &sast_findings {
        sast_counts.add_str_severity(&f.severity);
    }
    let mut secret_counts = SeverityCounts::default();
    for f in &secret_findings {
        secret_counts.add_str_severity(&f.severity);
    }

    let show_sast = opts.sast_enabled || !sast_findings.is_empty();
    let show_secrets = opts.secrets_enabled || !secret_findings.is_empty();

    let total_all_issues = sca_counts.total()
        + license_counts.map(|c| c.total()).unwrap_or(0)
        + if show_sast { sast_counts.total() } else { 0 }
        + if show_secrets {
            secret_counts.total()
        } else {
            0
        };

    let no_fail = opts.quality_gate.map(|g| g.no_fail).unwrap_or(false);
    let gate_passed = opts
        .quality_gate
        .map(|g| g.passed)
        .unwrap_or(scan_result.scan_status == crate::types::ScanStatus::Pass);
    let is_incomplete = scan_result.scan_status == crate::types::ScanStatus::Incomplete;

    // Headline
    if is_incomplete {
        out.push_str("### ⚠️ Vexa SCA checks are incomplete. Review scan diagnostics.\n\n");
    } else if gate_passed && total_all_issues == 0 {
        out.push_str("### ✅ Vexa SCA checks have passed. No issues have been found so far.\n\n");
    } else if gate_passed {
        let mode_note = if no_fail {
            "report-only (`--no-fail`)"
        } else {
            "below fail threshold or advisory"
        };
        out.push_str(&format!(
            "### ✅ Vexa SCA checks have passed ({total_all_issues} issue(s) {mode_note}).\n\n"
        ));
    } else {
        out.push_str(&format!(
            "### ❌ Vexa SCA checks failed ({total_all_issues} total issue(s) found).\n\n"
        ));
    }

    // 7-column severity matrix
    out.push_str(&format!(
        "| Status | Scan Engine | Critical | High | Medium | Low | Total ({total_all_issues}) |\n"
    ));
    out.push_str("| :---: | :--- | :---: | :---: | :---: | :---: | :---: |\n");

    let sca_failed = opts
        .quality_gate
        .map(|g| !g.passed && g.has_severity_failure())
        .unwrap_or(sca_counts.total() > 0 && !no_fail);
    let sca_status = if sca_failed {
        "❌"
    } else if sca_counts.total() > 0 {
        "⚠️"
    } else {
        "✅"
    };
    let sca_total_cell = if sca_counts.total() > 0 && reachable_count > 0 {
        format!(
            "{} issues ({} reachable)",
            sca_counts.total(),
            reachable_count
        )
    } else {
        format!("{} issues", sca_counts.total())
    };
    out.push_str(&format_engine_row(
        sca_status,
        "Open Source Security (SCA)",
        Some(sca_counts),
        sca_total_cell,
    ));

    let license_failed = opts
        .quality_gate
        .map(|g| {
            !g.passed
                && g.failure_reasons
                    .iter()
                    .any(|r| r.to_ascii_lowercase().contains("license"))
        })
        .unwrap_or(false);
    if let Some(lc) = license_counts {
        let lic_status = if license_failed {
            "❌"
        } else if lc.total() > 0 {
            "⚠️"
        } else {
            "✅"
        };
        out.push_str(&format_engine_row(
            lic_status,
            "Licenses",
            Some(lc),
            format!("{} issues", lc.total()),
        ));
    } else {
        out.push_str(&format_engine_row(
            "⏭️",
            "Licenses",
            None,
            "skipped".to_string(),
        ));
    }

    if show_sast {
        let sast_status = if sast_counts.total() > 0 && !no_fail {
            "❌"
        } else if sast_counts.total() > 0 {
            "⚠️"
        } else {
            "✅"
        };
        out.push_str(&format_engine_row(
            sast_status,
            "Code Security (SAST)",
            Some(sast_counts),
            format!("{} issues", sast_counts.total()),
        ));
    } else {
        out.push_str(&format_engine_row(
            "⏭️",
            "Code Security (SAST)",
            None,
            "skipped".to_string(),
        ));
    }

    if show_secrets {
        let sec_status = if secret_counts.total() > 0 && !no_fail {
            "❌"
        } else if secret_counts.total() > 0 {
            "⚠️"
        } else {
            "✅"
        };
        out.push_str(&format_engine_row(
            sec_status,
            "Secrets",
            Some(secret_counts),
            format!("{} issues", secret_counts.total()),
        ));
    } else {
        out.push_str(&format_engine_row(
            "⏭️",
            "Secrets",
            None,
            "skipped".to_string(),
        ));
    }

    out.push('\n');

    if scan_result.baseline_vulnerabilities_count > 0 {
        out.push_str(&format!(
            "**PR Diff Baseline:** {} new finding(s) | {} baseline finding(s)\n\n",
            scan_result.new_vulnerabilities_count, scan_result.baseline_vulnerabilities_count
        ));
    }

    if let Some(gate) = opts.quality_gate {
        if !gate.failure_reasons.is_empty() {
            let heading = if gate.no_fail {
                "#### 🚦 Quality Gate Findings (Report-Only)\n\n"
            } else {
                "#### 🚦 Quality Gate Failures\n\n"
            };
            out.push_str(heading);
            for reason in &gate.failure_reasons {
                out.push_str(&format!("- {}\n", escape_md_cell(reason)));
            }
            out.push('\n');
        }
    }

    // Collapsible details: Open Source Security
    if !scan_result.vulnerabilities.is_empty() {
        let mut prioritized = scan_result.vulnerabilities.clone();
        prioritized.sort_by(|a, b| {
            b.priority_score
                .partial_cmp(&a.priority_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out.push_str(&format!(
            "<details>\n<summary>📦 <b>Open Source Security Details ({} finding(s))</b></summary>\n\n",
            prioritized.len()
        ));
        out.push_str("| Package | Severity | Threat Signal | Reachability | Fixed In |\n");
        out.push_str("| :--- | :---: | :---: | :---: | :--- |\n");
        for v in prioritized.iter().take(20) {
            let fix = v
                .fixed_in
                .first()
                .cloned()
                .unwrap_or_else(|| "No fix".to_string());
            let reach = match &v.reachability {
                Some(r) if r.status == ReachabilityStatus::Reachable => "**REACHABLE**",
                Some(r) if r.status == ReachabilityStatus::Unreachable => "NOT_REACHABLE",
                _ => "UNKNOWN",
            };
            let threat = match v.exploit_maturity {
                crate::types::ExploitMaturity::ActiveKev => "🚨 Active KEV",
                crate::types::ExploitMaturity::PublicPoc => "🔥 Public PoC",
                crate::types::ExploitMaturity::HighProbability => "⚠️ High EPSS",
                crate::types::ExploitMaturity::Theoretical => "—",
            };
            out.push_str(&format!(
                "| `{}` | `{}` | {} | {} | `{}` |\n",
                escape_md_cell(&v.package),
                escape_md_cell(v.severity.level.as_str()),
                threat,
                reach,
                escape_md_cell(&fix),
            ));
        }
        if prioritized.len() > 20 {
            out.push_str(&format!(
                "\n*...and {} more vulnerability finding(s).*\n",
                prioritized.len() - 20
            ));
        }
        out.push_str("\n</details>\n\n");
    }

    // Collapsible details: Licenses
    if let Some(audit) = opts.license_audit {
        let flagged: Vec<_> = audit
            .results
            .iter()
            .filter(|r| r.category != crate::licenses::license_scanner::LicenseCategory::Permissive)
            .collect();
        if !flagged.is_empty() {
            out.push_str(&format!(
                "<details>\n<summary>⚖️ <b>License Compliance Details ({} non-permissive package(s))</b></summary>\n\n",
                flagged.len()
            ));
            out.push_str("| Package | Version | License | Category | Risk |\n");
            out.push_str("| :--- | :--- | :--- | :---: | :---: |\n");
            for r in flagged.iter().take(20) {
                out.push_str(&format!(
                    "| `{}` | `{}` | `{}` | {} | `{}` |\n",
                    escape_md_cell(&r.package),
                    escape_md_cell(&r.version),
                    escape_md_cell(&r.license),
                    escape_md_cell(r.category.as_str()),
                    escape_md_cell(&r.risk.level),
                ));
            }
            if flagged.len() > 20 {
                out.push_str(&format!(
                    "\n*...and {} more package(s).*\n",
                    flagged.len() - 20
                ));
            }
            out.push_str("\n</details>\n\n");
        }
    }

    // Collapsible details: Code Security (SAST)
    if !sast_findings.is_empty() {
        out.push_str(&format!(
            "<details>\n<summary>🔎 <b>Code Security (SAST) Details ({} finding(s))</b></summary>\n\n",
            sast_findings.len()
        ));
        out.push_str("| Severity | Rule | CWE | Location | Sink |\n");
        out.push_str("| :---: | :--- | :---: | :--- | :--- |\n");
        for f in sast_findings.iter().take(20) {
            let cwe = f.cwe.as_deref().unwrap_or("—");
            let sink = f.matched_sink.as_deref().unwrap_or("—");
            out.push_str(&format!(
                "| `{}` | `{}` | {} | `{}:{}` | `{}` |\n",
                escape_md_cell(&f.severity),
                escape_md_cell(&f.rule_id),
                escape_md_cell(cwe),
                escape_md_cell(&f.file_path),
                f.line,
                escape_md_cell(sink),
            ));
        }
        if sast_findings.len() > 20 {
            out.push_str(&format!(
                "\n*...and {} more SAST finding(s).*\n",
                sast_findings.len() - 20
            ));
        }
        out.push_str("\n</details>\n\n");
    }

    // Collapsible details: Secrets (Zero-Code-Retention: never prints raw secret values)
    if !secret_findings.is_empty() {
        out.push_str(&format!(
            "<details>\n<summary>🔑 <b>Secret Detection Details ({} finding(s))</b></summary>\n\n",
            secret_findings.len()
        ));
        out.push_str("| Severity | Rule | Location | Sanitized Match |\n");
        out.push_str("| :---: | :--- | :--- | :--- |\n");
        for f in secret_findings.iter().take(20) {
            let sink = f.matched_sink.as_deref().unwrap_or("redacted");
            out.push_str(&format!(
                "| `{}` | `{}` | `{}:{}` | `{}` |\n",
                escape_md_cell(&f.severity),
                escape_md_cell(&f.rule_id),
                escape_md_cell(&f.file_path),
                f.line,
                escape_md_cell(sink),
            ));
        }
        if secret_findings.len() > 20 {
            out.push_str(&format!(
                "\n*...and {} more secret finding(s).*\n",
                secret_findings.len() - 20
            ));
        }
        out.push_str("\n</details>\n\n");
    }

    if !remediations.is_empty() {
        out.push_str("<details>\n<summary>🛠️ <b>Recommended Remediations</b></summary>\n\n");
        for rem in remediations.iter().take(10) {
            out.push_str(&format!(
                "- **`{}`**: {}\n",
                escape_md_cell(&rem.package),
                escape_md_cell(&rem.advice)
            ));
        }
        out.push_str("\n</details>\n\n");
    }

    if let Some(url) = opts.dashboard_url.filter(|u| !u.trim().is_empty()) {
        out.push_str(&format!(
            "🔗 [View full scan report in Vexa Cloud]({url})\n\n"
        ));
    }

    out.push_str("💻 Catch issues earlier locally with `vexa-sca scan . --sast --secrets` or via MCP (`vexa-sca mcp`).\n");
    out
}

/// Formats the GitHub Actions job summary per PRD v2.2 FR-017a with full multi-engine matrix.
pub fn format_github_step_summary_with_options(
    scan_result: &ScanResult,
    remediations: &[RemediationAction],
    opts: &PrReportOptions<'_>,
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
    out.push_str(&format_pr_comment_report(scan_result, remediations, opts));
    out.push_str("\n<details>\n<summary>🔍 <b>Vulnerability Intelligence & Exploit Threat Provenance</b></summary>\n\n");
    out.push_str("- **Google OSV & GHSA:** Canonical identifiers, fixed release versions, and CWE classifications.\n");
    out.push_str("- **NVD / CVSS v3.1:** Industry baseline severity metrics and vector strings.\n");
    out.push_str(
        "- **FIRST.org EPSS:** Empirical 30-day statistical exploit prediction likelihood.\n",
    );
    out.push_str("- **CISA KEV & Exploit Repositories:** Real-world in-the-wild weaponized threats and public PoC code.\n\n");
    out.push_str("</details>\n");
    out
}

/// Formats the GitHub Actions job summary per PRD v2.2 FR-017a.
pub fn format_github_step_summary(
    scan_result: &ScanResult,
    remediations: &[RemediationAction],
    quality_gate: Option<&crate::scanner::quality_gate::QualityGateResult>,
) -> String {
    format_github_step_summary_with_options(
        scan_result,
        remediations,
        &PrReportOptions {
            license_audit: None,
            quality_gate,
            sast_enabled: false,
            secrets_enabled: false,
            dashboard_url: None,
        },
    )
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

pub fn generate_workspace_facts(
    project_dir: &Path,
    detection: &crate::parsers::detector::DetectionResult,
    reach_engine: Option<&crate::reachability::reachability_engine::ReachabilityEngine>,
) -> crate::types::WorkspaceScanFacts {
    let repo_name = project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("project")
        .to_string();

    let mut git_repo = repo_name;
    let mut commit_sha = None;
    let mut branch = None;

    let git_dir = project_dir.join(".git");
    if git_dir.exists() {
        if let Ok(head) = std::fs::read_to_string(git_dir.join("HEAD")) {
            let trimmed = head.trim();
            if let Some(b) = trimmed.strip_prefix("ref: refs/heads/") {
                branch = Some(b.to_string());
                let ref_path = git_dir.join("refs").join("heads").join(b);
                if let Ok(c) = std::fs::read_to_string(ref_path) {
                    commit_sha = Some(c.trim().to_string());
                }
            } else if trimmed.len() == 40 {
                commit_sha = Some(trimmed.to_string());
            }
        }
        if let Ok(config) = std::fs::read_to_string(git_dir.join("config")) {
            for line in config.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("url = ") {
                    git_repo = trimmed.trim_start_matches("url = ").to_string();
                    break;
                }
            }
        }
    }

    let mut manifests = Vec::new();
    let mut dep_facts = Vec::new();

    for (node_id, node) in &detection.graph.nodes {
        if node_id == &detection.graph.root_node_id {
            continue;
        }
        let pkg_info = detection.graph.pkgs.get(&node.pkg_id);
        let purl = pkg_info
            .map(|p| p.purl.clone())
            .unwrap_or_else(|| format!("pkg:generic/{}", node_id));

        let is_direct = detection
            .graph
            .nodes
            .get(&detection.graph.root_node_id)
            .map(|r| r.deps.contains(node_id))
            .unwrap_or(false);

        let parents: Vec<String> = detection
            .graph
            .parents
            .get(node_id)
            .map(|p_set| {
                p_set
                    .iter()
                    .filter_map(|p_id| {
                        detection
                            .graph
                            .nodes
                            .get(p_id)
                            .and_then(|pn| detection.graph.pkgs.get(&pn.pkg_id))
                            .map(|p| p.purl.clone())
                    })
                    .collect()
            })
            .unwrap_or_default();

        dep_facts.push(crate::types::FactDependency {
            purl,
            is_direct,
            scope: node.info.scope.clone(),
            parents,
        });
    }

    let manifest_path_rel = detection
        .manifest_file
        .strip_prefix(project_dir)
        .unwrap_or(&detection.manifest_file)
        .to_string_lossy()
        .replace('\\', "/");

    let lockfile_sha = std::fs::read(&detection.manifest_file).ok().map(|bytes| {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hex::encode(hasher.finalize())
    });

    manifests.push(crate::types::ManifestFact {
        path: manifest_path_rel,
        ecosystem: detection.manifest_type.as_str().to_string(),
        lockfile_blob_sha256: lockfile_sha,
        dependencies: dep_facts,
    });

    let (coverage_complete, files_analyzed, imported_packages) = if let Some(re) = reach_engine {
        let mut pkgs_map = std::collections::HashMap::new();

        for (pkg_name, files) in &re.ast_index.package_importers {
            let mut symbols = std::collections::HashSet::new();
            let mut call_locs = Vec::new();

            for fpath in files {
                if let Some(facts) = re.ast_index.files.get(fpath) {
                    if let Some(syms) = facts.external_imports.get(pkg_name) {
                        for s in syms {
                            symbols.insert(s.clone());
                        }
                    }
                }
            }

            for ((p, sym), sites) in &re.ast_index.symbol_calls {
                if p == pkg_name {
                    for s in sites {
                        call_locs.push(crate::types::FactCallLocation {
                            file: s.file.clone(),
                            line: s.line,
                            symbol: sym.clone(),
                        });
                    }
                }
            }

            let mut sorted_symbols: Vec<String> = symbols.into_iter().collect();
            sorted_symbols.sort();

            let purl_prefix = match detection.graph.pkg_manager.name.to_lowercase().as_str() {
                "npm" | "yarn" | "pnpm" => "pkg:npm/",
                "crates.io" | "cargo" => "pkg:cargo/",
                "pypi" | "pip" | "poetry" | "pipenv" => "pkg:pypi/",
                "go" | "golang" => "pkg:golang/",
                "maven" | "gradle" => "pkg:maven/",
                _ => match detection.manifest_type.as_str().to_lowercase().as_str() {
                    "cargo.lock" | "cargo.toml" => "pkg:cargo/",
                    "requirements.txt" | "pipfile.lock" | "poetry.lock" | "pyproject.toml" => {
                        "pkg:pypi/"
                    }
                    "go.mod" | "go.sum" => "pkg:golang/",
                    "pom.xml" | "build.gradle" => "pkg:maven/",
                    _ => "pkg:npm/",
                },
            };
            let purl = format!("{}{}", purl_prefix, pkg_name);
            pkgs_map.insert(
                purl,
                crate::types::ImportedPackageFact {
                    imported_symbols: sorted_symbols,
                    call_locations: call_locs,
                },
            );
        }

        (
            re.ast_index.parse_complete,
            re.ast_index.files_analyzed,
            pkgs_map,
        )
    } else {
        (true, 0, std::collections::HashMap::new())
    };

    crate::types::WorkspaceScanFacts {
        schema_version: "2.0".to_string(),
        repository: git_repo,
        commit_sha,
        branch,
        manifests,
        ast_facts: crate::types::AstFacts {
            coverage_complete,
            files_analyzed,
            imported_packages,
        },
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

    #[test]
    fn test_generate_workspace_facts_zero_code_retention() {
        let fixture_dir = std::path::Path::new("test/fixtures/npm-app");
        let detection = crate::parsers::detector::detect_and_parse(fixture_dir, true)
            .expect("should detect and parse npm-app");
        let facts = super::generate_workspace_facts(fixture_dir, &detection, None);

        assert_eq!(facts.schema_version, "2.0");
        assert_eq!(facts.manifests.len(), 1);
        assert!(!facts.manifests[0].dependencies.is_empty());
        let json_str = serde_json::to_string_pretty(&facts).unwrap();
        // Zero-code-retention: ensure no source code lines are leaked
        assert!(!json_str.contains("console.log"));
        assert!(!json_str.contains("function "));
    }

    #[test]
    fn pr_comment_report_renders_clean_pass_and_skipped_engines() {
        let scan_result = ScanResult::default();
        let report = super::format_pr_comment_report(
            &scan_result,
            &[],
            &super::PrReportOptions {
                license_audit: None,
                quality_gate: None,
                sast_enabled: false,
                secrets_enabled: false,
                dashboard_url: None,
            },
        );
        assert!(report.contains(super::PR_COMMENT_MARKER));
        assert!(report.contains("Vexa SCA checks have passed. No issues have been found so far."));
        assert!(report
            .contains("| Status | Scan Engine | Critical | High | Medium | Low | Total (0) |"));
        assert!(
            report.contains("| ✅ | **Open Source Security (SCA)** | 0 | 0 | 0 | 0 | 0 issues |")
        );
        assert!(report.contains("| ⏭️ | **Licenses** | — | — | — | — | skipped |"));
        assert!(report.contains("| ⏭️ | **Code Security (SAST)** | — | — | — | — | skipped |"));
        assert!(report.contains("| ⏭️ | **Secrets** | — | — | — | — | skipped |"));
    }

    #[test]
    fn pr_comment_report_renders_all_four_engines_and_escapes_markdown() {
        let mut scan_result = ScanResult {
            scan_status: crate::types::ScanStatus::Fail,
            ..Default::default()
        };
        scan_result.vulnerabilities.push(VulnerabilityFinding {
            id: "CVE-2026-0001".to_string(),
            package: "lodash".to_string(),
            severity: crate::types::SeverityInfo {
                level: crate::types::SeverityLevel::High,
                score: 7.5,
                vector: None,
            },
            ..Default::default()
        });
        scan_result
            .code_findings
            .push(crate::scanner::sast::CodeFinding {
                rule_id: "VEXA-SAST-001".to_string(),
                category: "SAST".to_string(),
                severity: "CRITICAL".to_string(),
                title: "OS Command Injection".to_string(),
                cwe: Some("CWE-78".to_string()),
                file_path: "src/<evil>|file.js".to_string(),
                line: 12,
                matched_sink: Some("exec(cmd)".to_string()),
                remediation: None,
            });
        scan_result
            .code_findings
            .push(crate::scanner::sast::CodeFinding {
                rule_id: "VEXA-SEC-001".to_string(),
                category: "SECRET".to_string(),
                severity: "CRITICAL".to_string(),
                title: "AWS Key".to_string(),
                cwe: Some("CWE-798".to_string()),
                file_path: ".env".to_string(),
                line: 1,
                matched_sink: Some("AKIA...XXXX".to_string()),
                remediation: None,
            });

        let license_audit = crate::licenses::license_scanner::LicenseAudit {
            summary: crate::licenses::license_scanner::LicenseSummary {
                total: 2,
                permissive: 1,
                weak_copyleft: 1,
                strong_copyleft: 0,
                unknown: 0,
            },
            results: vec![crate::licenses::license_scanner::PackageLicenseResult {
                package: "lgpl-lib".to_string(),
                version: "1.0.0".to_string(),
                ecosystem: "npm".to_string(),
                license: "LGPL-2.1".to_string(),
                category: crate::licenses::license_scanner::LicenseCategory::WeakCopyleft,
                risk: crate::licenses::license_scanner::LicenseRisk {
                    level: "MEDIUM".to_string(),
                    score: 2,
                },
                dep_path: None,
                resolution_note: None,
            }],
        };

        let report = super::format_pr_comment_report(
            &scan_result,
            &[],
            &super::PrReportOptions {
                license_audit: Some(&license_audit),
                quality_gate: None,
                sast_enabled: true,
                secrets_enabled: true,
                dashboard_url: Some("https://cloud.vexasec.io/scans/123"),
            },
        );

        assert!(report.contains("Total (4)"));
        assert!(
            report.contains("| ❌ | **Open Source Security (SCA)** | 0 | 1 | 0 | 0 | 1 issues |")
        );
        assert!(report.contains("| ⚠️ | **Licenses** | 0 | 0 | 1 | 0 | 1 issues |"));
        assert!(report.contains("| ❌ | **Code Security (SAST)** | 1 | 0 | 0 | 0 | 1 issues |"));
        assert!(report.contains("| ❌ | **Secrets** | 1 | 0 | 0 | 0 | 1 issues |"));
        assert!(report.contains("src/&lt;evil&gt;\\|file.js:12"));
        assert!(report.contains("https://cloud.vexasec.io/scans/123"));
    }

    #[test]
    fn json_report_reachability_summary_preserves_unknown_count() {
        use crate::types::{ReachabilityResult, ReachabilityStatus};

        let mk = |id: &str, status: Option<ReachabilityStatus>| VulnerabilityFinding {
            id: id.to_string(),
            package: "pkg".to_string(),
            reachability: status.map(|s| ReachabilityResult {
                status: s,
                is_direct_call: matches!(s, ReachabilityStatus::Reachable),
                call_sites: vec![],
                target_functions: vec![],
                reason_code: None,
                analyzer_version: "1.8.0".to_string(),
            }),
            ..Default::default()
        };

        let scan_result = ScanResult {
            scanned_packages_count: 10,
            vulnerabilities_count: 4,
            vulnerabilities: vec![
                mk("CVE-1", Some(ReachabilityStatus::Reachable)),
                mk("CVE-2", Some(ReachabilityStatus::Unreachable)),
                mk("CVE-3", Some(ReachabilityStatus::Unknown)),
                mk("CVE-4", None),
            ],
            ..Default::default()
        };

        let json_str = super::format_json_report(&scan_result, &[], &[], None, None, None);
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("json report must parse");

        assert_eq!(parsed["summary"]["reachabilitySummary"]["reachable"], 1);
        assert_eq!(parsed["summary"]["reachabilitySummary"]["unreachable"], 1);
        assert_eq!(parsed["summary"]["reachabilitySummary"]["unknown"], 2);
        assert_eq!(
            parsed["summary"]["usageSignalsSummary"]["signalMatched"]
                .as_u64()
                .unwrap()
                + parsed["summary"]["usageSignalsSummary"]["noSignalObserved"]
                    .as_u64()
                    .unwrap()
                + parsed["summary"]["usageSignalsSummary"]["unknown"]
                    .as_u64()
                    .unwrap(),
            4
        );
    }
}
