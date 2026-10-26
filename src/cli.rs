use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;
use std::process::exit;

use crate::container::container_scanner::ContainerScanner;
use crate::core::dep_graph::DepGraph;
use crate::licenses::license_scanner::LicenseScanner;
use crate::parsers::detector::detect_and_parse;
use crate::patcher;
use crate::patcher::pr_creator::PrCreator;
use crate::reporters::export::{
    emit_github_annotations, format_cyclonedx_sbom, format_github_step_summary, format_html_report,
    format_json_report, format_markdown_report, format_sarif_report, format_spdx_sbom, SbomFormat,
};
use crate::reporters::terminal::render_terminal_report;
use crate::scanner::quality_gate::{QualityGate, QualityGateOptions};
use crate::scanner::vuln_scanner::{ScanResult, VulnScanner};
use crate::types::{PkgInfo, ScanStatus, SeverityLevel};
use crate::{scan_project, ScanOptions};

fn incomplete_scan_requires_exit3(result: &ScanResult, allow_unavailable: bool) -> bool {
    let completeness = &result.completeness;
    let is_incomplete = result.scan_status == ScanStatus::Incomplete
        || completeness.advisory_status.has_unreliable_data()
        || completeness.manifests_skipped > 0
        || completeness.source_files_skipped > 0
        || completeness.source_files_failed > 0
        || !completeness.limits_hit.is_empty()
        || result.packages_unavailable > 0;

    if !is_incomplete {
        return false;
    }

    let advisory_only = (completeness.advisory_status.has_unreliable_data()
        || result.packages_unavailable > 0)
        && completeness.manifests_skipped == 0
        && completeness.source_files_skipped == 0
        && completeness.source_files_failed == 0
        && completeness.limits_hit.is_empty();

    !(allow_unavailable && advisory_only)
}

#[cfg(test)]
mod incomplete_scan_exit_tests {
    use super::*;
    use crate::types::AdvisoryStatus;

    #[test]
    fn report_only_does_not_hide_an_incomplete_scan() {
        let mut result = ScanResult {
            scan_status: ScanStatus::Incomplete,
            ..Default::default()
        };
        result.completeness.advisory_status = AdvisoryStatus::Unavailable;
        assert!(incomplete_scan_requires_exit3(&result, false));
        assert!(!incomplete_scan_requires_exit3(&result, true));
    }

    #[test]
    fn advisory_override_does_not_hide_source_or_manifest_gaps() {
        let mut result = ScanResult {
            scan_status: ScanStatus::Incomplete,
            ..Default::default()
        };
        result.completeness.advisory_status = AdvisoryStatus::PartialFailure;
        result.completeness.source_files_skipped = 1;
        assert!(incomplete_scan_requires_exit3(&result, true));

        result.completeness.source_files_skipped = 0;
        result.completeness.manifests_skipped = 1;
        assert!(incomplete_scan_requires_exit3(&result, true));
    }
}

fn parse_epss_threshold(s: &str) -> Result<f64, String> {
    let val: f64 = s
        .parse::<f64>()
        .map_err(|_| format!("invalid float value '{}' for EPSS threshold", s))?;
    if val.is_nan() || !(0.0..=1.0).contains(&val) {
        return Err(format!(
            "EPSS threshold must be a number between 0.0 and 1.0, got '{}'",
            s
        ));
    }
    Ok(val)
}

fn parse_severity_threshold(s: &str) -> Result<SeverityLevel, String> {
    match s.trim().to_lowercase().as_str() {
        "critical" | "crit" => Ok(SeverityLevel::Critical),
        "high" => Ok(SeverityLevel::High),
        "medium" | "med" | "moderate" => Ok(SeverityLevel::Medium),
        "low" => Ok(SeverityLevel::Low),
        _ => Err(format!(
            "invalid severity threshold '{}'. Expected one of: low, medium, high, critical",
            s
        )),
    }
}

fn parse_fail_on_scan(s: &str) -> Result<String, String> {
    let lower = s.trim().to_lowercase();
    if lower == "reachable" {
        return Ok(lower);
    }
    if let Some(rest) = lower
        .strip_prefix("reachable-")
        .or_else(|| lower.strip_prefix("reachable_"))
    {
        match rest {
            "critical" | "crit" | "high" | "medium" | "med" | "moderate" | "low" => Ok(lower),
            _ => Err(format!(
                "invalid fail-on severity in '{}'. Expected one of: critical, high, medium, low",
                s
            )),
        }
    } else {
        match lower.as_str() {
            "critical" | "crit" | "high" | "medium" | "med" | "moderate" | "low" => Ok(lower),
            _ => Err(format!(
                "invalid fail-on value '{}'. Expected one of: low, medium, high, critical, reachable, reachable-critical, reachable-high, reachable-medium, reachable-low",
                s
            )),
        }
    }
}

fn parse_fail_on_severity(s: &str) -> Result<String, String> {
    let lower = s.trim().to_lowercase();
    match lower.as_str() {
        "critical" | "crit" | "high" | "medium" | "med" | "moderate" | "low" => Ok(lower),
        _ => Err(format!(
            "invalid fail-on severity '{}'. Expected one of: low, medium, high, critical",
            s
        )),
    }
}

fn parse_fail_on_licenses(s: &str) -> Result<String, String> {
    let lower = s.trim().to_lowercase();
    if lower.contains("strong")
        || lower.contains("weak")
        || lower == "copyleft"
        || lower.contains("unknown")
    {
        Ok(lower)
    } else {
        Err(format!(
            "invalid license risk category '{}'. Expected one of: strong-copyleft, weak-copyleft, copyleft, unknown",
            s
        ))
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "vexa-sca",
    bin_name = "vexa-sca",
    about = "Vexa SCA - Commercial-Grade Software Composition Analysis & Security Engine",
    version = env!("CARGO_PKG_VERSION")
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan project dependencies for vulnerabilities
    Scan {
        /// Target path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Only show vulnerabilities with confirmed AST execution paths
        #[arg(long)]
        reachable_only: bool,

        /// Exclude devDependencies
        #[arg(long)]
        prod_only: bool,

        /// Path to custom policy file (.vexa-sca)
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Filter by minimum severity (low, medium, high, critical)
        #[arg(long, value_parser = parse_severity_threshold)]
        severity_threshold: Option<SeverityLevel>,

        /// Ignore vulnerabilities without a known fixed version (only show actionable fixes)
        #[arg(long, visible_alias = "only-fixed")]
        ignore_unfixed: bool,

        /// Output report in JSON format
        #[arg(long)]
        json: bool,

        /// Output report in Markdown format
        #[arg(long)]
        markdown: bool,

        /// Output report in standard OASIS SARIF v2.1.0 format
        #[arg(long)]
        sarif: bool,

        /// Save SARIF report to a file path (e.g. results.sarif)
        #[arg(long)]
        sarif_file: Option<PathBuf>,

        /// Output standalone interactive HTML dashboard
        #[arg(long)]
        html: bool,

        /// Save interactive HTML report to a file path
        #[arg(long)]
        html_file: Option<PathBuf>,

        /// Output Software Bill of Materials (cyclonedx or spdx)
        #[arg(
            long,
            value_enum,
            default_missing_value = "cyclonedx",
            num_args = 0..=1
        )]
        sbom: Option<SbomFormat>,

        /// Save SBOM report to a file path
        #[arg(long)]
        sbom_file: Option<PathBuf>,

        /// CI/CD Quality Gate: fail on or above severity threshold (low, medium, high, critical)
        #[arg(long, value_parser = parse_fail_on_scan)]
        fail_on: Option<String>,

        /// CI/CD Quality Gate: fail only if at least one vulnerability has confirmed AST reachability
        #[arg(long)]
        fail_on_reachable: bool,

        /// CI/CD Quality Gate: fail when reachability analysis result is UNKNOWN (conservative default for reachable-only gates)
        #[arg(long)]
        fail_on_unknown_reachability: bool,

        /// CI/CD Quality Gate: allow UNKNOWN reachability without failing gate (permissive mode, may cause false negatives)
        #[arg(long)]
        allow_unknown_reachability: bool,

        /// CI/CD Quality Gate: fail on license risk category (e.g. strong-copyleft, weak-copyleft)
        #[arg(long, value_parser = parse_fail_on_licenses)]
        fail_on_licenses: Option<String>,

        /// CI/CD Quality Gate: fail on unmaintained or deprecated dependencies
        #[arg(long)]
        fail_on_unmaintained: bool,

        /// Filter by minimum EPSS exploit prediction probability (0.0 to 1.0, e.g. 0.2 for 20%)
        #[arg(long, value_parser = parse_epss_threshold)]
        epss_threshold: Option<f64>,

        /// Allow local heuristic estimates to satisfy --epss-threshold when FIRST.org is unreachable
        #[arg(long)]
        epss_allow_heuristic: bool,

        /// Strict EPSS enforcement: require authoritative FIRST.org EPSS data for all evaluated vulnerabilities
        #[arg(long)]
        strict_epss: bool,

        /// Display scan volume quota and plan usage details
        #[arg(long)]
        usage: bool,

        /// Baseline report file (JSON or SARIF) for PR-diff gating
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Do not fail scan with exit code 1 when vulnerabilities are found (report-only mode)
        #[arg(long, visible_alias = "report-only")]
        no_fail: bool,

        /// Allow scan to succeed (exit 0) even when the OSV advisory database is unreachable.
        /// Without this flag, an advisory service outage exits with code 3 to prevent
        /// silent false-negative reports.
        #[arg(long)]
        allow_unavailable: bool,

        /// Maximum number of source files to analyze for AST reachability (default: 10000, 0 for unlimited)
        #[arg(long, visible_alias = "max-files")]
        max_source_files: Option<usize>,

        /// Overall scan timeout in seconds (default: 300)
        #[arg(long, default_value = "300")]
        timeout_secs: u64,
    },

    /// Automated scan profile for CI/CD pipelines (fails closed on incomplete data/advisory outage)
    Ci {
        /// Target path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Baseline report file (JSON or SARIF) for PR-diff gating
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Path to write GitHub Actions Step Summary markdown (or writes to $GITHUB_STEP_SUMMARY)
        #[arg(long, visible_alias = "github-step-summary")]
        job_summary_file: Option<PathBuf>,

        /// Emit GitHub workflow annotations (notice/warning/error) to stdout
        #[arg(long, default_value_t = true)]
        emit_annotations: bool,

        /// Only show vulnerabilities with confirmed AST execution paths
        #[arg(long)]
        reachable_only: bool,

        /// Exclude devDependencies
        #[arg(long)]
        prod_only: bool,

        /// Path to custom policy file (.vexa-sca)
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Filter by minimum severity (low, medium, high, critical)
        #[arg(long, value_parser = parse_severity_threshold)]
        severity_threshold: Option<SeverityLevel>,

        /// Ignore vulnerabilities without a known fixed version
        #[arg(long, visible_alias = "only-fixed")]
        ignore_unfixed: bool,

        /// Output report in JSON format
        #[arg(long)]
        json: bool,

        /// Output report in Markdown format
        #[arg(long)]
        markdown: bool,

        /// Output report in standard OASIS SARIF v2.1.0 format
        #[arg(long)]
        sarif: bool,

        /// Save SARIF report to a file path
        #[arg(long)]
        sarif_file: Option<PathBuf>,

        /// Output Software Bill of Materials (cyclonedx or spdx)
        #[arg(
            long,
            value_enum,
            default_missing_value = "cyclonedx",
            num_args = 0..=1
        )]
        sbom: Option<SbomFormat>,

        /// Save SBOM report to a file path
        #[arg(long)]
        sbom_file: Option<PathBuf>,

        /// CI/CD Quality Gate: fail on or above severity threshold (low, medium, high, critical)
        #[arg(long, value_parser = parse_fail_on_scan)]
        fail_on: Option<String>,

        /// CI/CD Quality Gate: fail only if at least one vulnerability has confirmed AST reachability
        #[arg(long)]
        fail_on_reachable: bool,

        /// CI/CD Quality Gate: fail when reachability analysis result is UNKNOWN (conservative default for reachable-only gates)
        #[arg(long)]
        fail_on_unknown_reachability: bool,

        /// CI/CD Quality Gate: allow UNKNOWN reachability without failing gate (permissive mode, may cause false negatives)
        #[arg(long)]
        allow_unknown_reachability: bool,

        /// CI/CD Quality Gate: fail on license risk category (e.g. strong-copyleft, weak-copyleft)
        #[arg(long, value_parser = parse_fail_on_licenses)]
        fail_on_licenses: Option<String>,

        /// CI/CD Quality Gate: fail on unmaintained or deprecated dependencies
        #[arg(long)]
        fail_on_unmaintained: bool,

        /// Filter by minimum EPSS exploit prediction probability (0.0 to 1.0)
        #[arg(long, value_parser = parse_epss_threshold)]
        epss_threshold: Option<f64>,

        /// Allow local heuristic estimates to satisfy --epss-threshold when FIRST.org is unreachable
        #[arg(long)]
        epss_allow_heuristic: bool,

        /// Strict EPSS enforcement: require authoritative FIRST.org EPSS data for all evaluated vulnerabilities
        #[arg(long)]
        strict_epss: bool,

        /// Do not fail scan with exit code 1 when vulnerabilities are found (report-only mode)
        #[arg(long, visible_alias = "report-only")]
        no_fail: bool,

        /// Allow scan to succeed (exit 0) even when the OSV advisory database is unreachable
        #[arg(long)]
        allow_unavailable: bool,

        /// Maximum number of source files to analyze for AST reachability (default: 10000, 0 for unlimited)
        #[arg(long, visible_alias = "max-files")]
        max_source_files: Option<usize>,

        /// Overall scan timeout in seconds (default: 300)
        #[arg(long, default_value = "300")]
        timeout_secs: u64,
    },

    /// Initialize pinned GitHub Actions workflow for Vexa SCA in .github/workflows/vexa-sca.yml
    Init {
        /// Target path (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Enforce quality gate (fail CI on high or critical vulnerabilities)
        #[arg(long)]
        enforce: bool,
    },

    /// Automatically patch dependencies and overrides
    Fix {
        /// Target path (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Automatically create git branch, commit changes, and open a GitHub PR
        #[arg(long)]
        create_pr: bool,

        /// Target GitHub repository (owner/repo)
        #[arg(long)]
        repo: Option<String>,

        /// GitHub token (defaults to GITHUB_TOKEN or GH_TOKEN env var)
        #[arg(long)]
        token: Option<String>,

        /// Branch name for security fix PR (defaults to vexa-sca/fix-vulnerabilities-<timestamp>)
        #[arg(long)]
        branch: Option<String>,

        /// Base branch to target for PR (defaults to repo default branch e.g. main)
        #[arg(long)]
        base: Option<String>,

        /// Preview changes and PR details without modifying files or opening PR
        #[arg(long)]
        dry_run: bool,
    },

    /// Audit open source licenses and copyleft risks
    Licenses {
        /// Target path (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Display all individual packages including compliant permissive ones
        #[arg(long, short)]
        all: bool,

        /// Output report in JSON format
        #[arg(long)]
        json: bool,

        /// CI/CD Quality Gate: fail on license risk category (e.g. strong-copyleft, weak-copyleft)
        #[arg(long, value_parser = parse_fail_on_licenses)]
        fail_on: Option<String>,
    },

    /// Visualize dependency graph
    Graph {
        /// Target path (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output graph in standard JSON schema format
        #[arg(long)]
        json: bool,

        /// Maximum tree depth to render (defaults to 6)
        #[arg(long)]
        max_depth: Option<usize>,
    },

    /// Test a single package version (e.g. lodash@4.17.15)
    Test {
        /// Package and version (e.g. lodash@4.17.15)
        target: String,

        /// Ecosystem (npm, PyPI, Go, crates.io, Maven)
        #[arg(short, long, visible_alias = "eco")]
        ecosystem: Option<String>,

        /// Positional ecosystem (optional, e.g. npm)
        #[arg(value_name = "ECOSYSTEM_POSITIONAL")]
        ecosystem_pos: Option<String>,

        /// Output report in JSON format
        #[arg(long)]
        json: bool,

        /// Minimum severity threshold (low, medium, high, critical)
        #[arg(long, value_parser = parse_severity_threshold)]
        severity_threshold: Option<SeverityLevel>,
    },

    /// Scan container image archive (.tar/.tar.gz), rootfs directory, or Dockerfile for OS package vulnerabilities
    Container {
        /// Target image archive (.tar/.tar.gz), rootfs directory, or Dockerfile (defaults to current directory)
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Minimum severity threshold (low, medium, high, critical)
        #[arg(long, value_parser = parse_severity_threshold)]
        severity_threshold: Option<SeverityLevel>,

        /// Ignore vulnerabilities without a known fixed version (only show actionable fixes)
        #[arg(long, visible_alias = "only-fixed")]
        ignore_unfixed: bool,

        /// Output report in JSON format
        #[arg(long)]
        json: bool,

        /// Output report in Markdown format
        #[arg(long)]
        markdown: bool,

        /// Output report in standard OASIS SARIF v2.1.0 format
        #[arg(long)]
        sarif: bool,

        /// Save SARIF report to a file path
        #[arg(long)]
        sarif_file: Option<PathBuf>,

        /// Output standalone interactive HTML dashboard
        #[arg(long)]
        html: bool,

        /// Save interactive HTML report to a file path
        #[arg(long)]
        html_file: Option<PathBuf>,

        /// Output Software Bill of Materials (cyclonedx or spdx)
        #[arg(
            long,
            value_enum,
            default_missing_value = "cyclonedx",
            num_args = 0..=1
        )]
        sbom: Option<SbomFormat>,

        /// Save SBOM report to a file path
        #[arg(long)]
        sbom_file: Option<PathBuf>,

        /// CI/CD Quality Gate: fail on or above severity (low, medium, high, critical)
        #[arg(long, value_parser = parse_fail_on_severity)]
        fail_on: Option<String>,

        /// CI/CD Quality Gate: fail on license risk category (e.g. strong-copyleft)
        #[arg(long, value_parser = parse_fail_on_licenses)]
        fail_on_licenses: Option<String>,

        /// Do not fail scan with exit code 1 when vulnerabilities are found (report-only mode)
        #[arg(long, visible_alias = "report-only")]
        no_fail: bool,
    },

    /// Display scan volume quota and plan usage details
    Usage {
        /// Output report in JSON format
        #[arg(long)]
        json: bool,
    },
}

pub async fn run() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Licenses {
            path,
            all,
            json,
            fail_on,
        } => {
            let detection = match detect_and_parse(&path, true) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    if e.contains("Failed to parse manifest")
                        || e.contains("Invalid JSON in")
                        || e.contains("Invalid YAML in")
                    {
                        exit(3);
                    } else {
                        exit(2);
                    }
                }
            };

            let audit = LicenseScanner::scan_graph_licenses(&detection.graph, &path);

            // Group by license name to show distribution table
            let mut lic_counts: std::collections::HashMap<
                String,
                (usize, crate::licenses::license_scanner::LicenseCategory),
            > = std::collections::HashMap::new();
            for r in &audit.results {
                let entry = lic_counts
                    .entry(r.license.clone())
                    .or_insert((0, r.category));
                entry.0 += 1;
            }
            let mut sorted_lics: Vec<(
                String,
                usize,
                crate::licenses::license_scanner::LicenseCategory,
            )> = lic_counts
                .into_iter()
                .map(|(lic, (cnt, cat))| (lic, cnt, cat))
                .collect();
            sorted_lics.sort_by_key(|b| std::cmp::Reverse(b.1));

            // Actionable Flagged Items (Copyleft & Unknown)
            let flagged: Vec<_> = audit
                .results
                .iter()
                .filter(|r| {
                    r.category == crate::licenses::license_scanner::LicenseCategory::StrongCopyleft
                        || r.category
                            == crate::licenses::license_scanner::LicenseCategory::WeakCopyleft
                        || r.category == crate::licenses::license_scanner::LicenseCategory::Unknown
                })
                .collect();

            if json {
                let dist_json: Vec<serde_json::Value> = sorted_lics
                    .iter()
                    .map(|(lic, cnt, cat)| {
                        serde_json::json!({
                            "license": lic,
                            "category": cat.as_str(),
                            "count": cnt,
                        })
                    })
                    .collect();

                let flagged_json: Vec<serde_json::Value> = flagged
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "package": r.package,
                            "version": r.version,
                            "license": r.license,
                            "category": r.category.as_str(),
                            "depPath": r.dep_path,
                            "resolutionNote": r.resolution_note,
                        })
                    })
                    .collect();

                let all_deps_json: Option<Vec<serde_json::Value>> = if all {
                    Some(
                        audit
                            .results
                            .iter()
                            .map(|r| {
                                serde_json::json!({
                                    "package": r.package,
                                    "version": r.version,
                                    "license": r.license,
                                    "category": r.category.as_str(),
                                    "depPath": r.dep_path,
                                    "resolutionNote": r.resolution_note,
                                })
                            })
                            .collect(),
                    )
                } else {
                    None
                };

                let out = serde_json::json!({
                    "target": path.display().to_string(),
                    "summary": {
                        "total": audit.summary.total,
                        "permissive": audit.summary.permissive,
                        "weakCopyleft": audit.summary.weak_copyleft,
                        "strongCopyleft": audit.summary.strong_copyleft,
                        "unknown": audit.summary.unknown,
                    },
                    "distribution": dist_json,
                    "flagged": flagged_json,
                    "dependencies": all_deps_json,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                let path_display = path.display().to_string();
                let clean_path = path_display.strip_prefix(r"\\?\").unwrap_or(&path_display);
                println!("\nLicense Compliance Report: {}", clean_path.bold());
                println!(
                    "Total: {} | Permissive: {} | Weak Copyleft: {} | Strong Copyleft: {} | Unknown: {}",
                    audit.summary.total,
                    audit.summary.permissive.to_string().green(),
                    if audit.summary.weak_copyleft > 0 {
                        audit.summary.weak_copyleft.to_string().yellow().to_string()
                    } else {
                        "0".green().to_string()
                    },
                    if audit.summary.strong_copyleft > 0 {
                        audit.summary.strong_copyleft.to_string().red().bold().to_string()
                    } else {
                        "0".green().to_string()
                    },
                    if audit.summary.unknown > 0 {
                        audit.summary.unknown.to_string().dimmed().to_string()
                    } else {
                        "0".to_string()
                    }
                );
                println!("{}", "-".repeat(78));

                let max_lic_len = sorted_lics
                    .iter()
                    .map(|(lic, _, _)| lic.len())
                    .max()
                    .unwrap_or(7)
                    .max("License".len());
                let lic_col_width = max_lic_len.max(45);
                let table_width = lic_col_width + 18 + 8 + 4;

                println!("\n{}", "License Distribution:".bold());
                println!(
                    "  {:<width$} {:<18} {:>6}",
                    "License",
                    "Category",
                    "Count",
                    width = lic_col_width
                );
                println!("  {}", "-".repeat(table_width));
                for (lic, count, cat) in &sorted_lics {
                    let cat_colored = match cat {
                        crate::licenses::license_scanner::LicenseCategory::Permissive => {
                            cat.as_str().green()
                        }
                        crate::licenses::license_scanner::LicenseCategory::WeakCopyleft => {
                            cat.as_str().yellow()
                        }
                        crate::licenses::license_scanner::LicenseCategory::StrongCopyleft => {
                            cat.as_str().red().bold()
                        }
                        crate::licenses::license_scanner::LicenseCategory::Unknown => {
                            cat.as_str().dimmed()
                        }
                    };
                    println!(
                        "  {:<width$} {:<18} {:>6}",
                        lic,
                        cat_colored,
                        count,
                        width = lic_col_width
                    );
                }

                if !flagged.is_empty() {
                    println!(
                        "\n{}",
                        "Flagged Dependencies (Action Recommended):".yellow().bold()
                    );
                    println!("  {}", "-".repeat(table_width.min(78)));
                    for r in &flagged {
                        let risk_colored = match r.category {
                            crate::licenses::license_scanner::LicenseCategory::StrongCopyleft => {
                                format!("[{}]", r.category.as_str()).red().bold()
                            }
                            crate::licenses::license_scanner::LicenseCategory::WeakCopyleft => {
                                format!("[{}]", r.category.as_str()).yellow()
                            }
                            _ => format!("[{}]", r.category.as_str()).dimmed(),
                        };
                        println!(
                            "  • {}@{}: {} {}",
                            r.package.bold(),
                            r.version,
                            r.license.cyan(),
                            risk_colored
                        );
                        if let Some(path) = &r.dep_path {
                            println!("    {} {}", "Path:".dimmed(), path);
                        }
                        if let Some(note) = &r.resolution_note {
                            println!("    {} {}", "Policy:".dimmed(), note.italic());
                        }
                    }
                } else {
                    println!(
                        "\n{}",
                        "✔ All evaluated dependencies comply with permissive license policies."
                            .green()
                            .bold()
                    );
                }

                if all {
                    println!("\n{}", "All Dependencies:".bold());
                    println!("  {}", "-".repeat(table_width.min(78)));
                    for r in &audit.results {
                        println!(
                            "  - {}@{}: {} [{}]",
                            r.package,
                            r.version,
                            r.license,
                            r.category.as_str()
                        );
                        if let Some(path) = &r.dep_path {
                            println!("    {} {}", "Path:".dimmed(), path.dimmed());
                        }
                    }
                } else if flagged.len() < audit.results.len() {
                    println!("\n  {}", format!("💡 Showing flagged/breakdown only. Pass '--all' to display all {} individual dependencies.", audit.summary.total).dimmed());
                }
            }

            if let Some(target_risk) = &fail_on {
                let risk_lower = target_risk.to_lowercase();
                let has_violation = if risk_lower.contains("strong") {
                    audit.summary.strong_copyleft > 0
                } else if risk_lower.contains("weak") {
                    audit.summary.strong_copyleft > 0 || audit.summary.weak_copyleft > 0
                } else if risk_lower.contains("unknown") {
                    audit.summary.unknown > 0
                } else {
                    false
                };

                if has_violation {
                    if !json {
                        eprintln!(
                            "\n{}",
                            format!(
                                "✖ CI/CD QUALITY GATE FAILED: License risk policy violated ({})",
                                target_risk
                            )
                            .red()
                            .bold()
                        );
                    }
                    exit(1);
                } else if !json {
                    println!(
                        "\n{}",
                        "✔ CI/CD QUALITY GATE PASSED: License policies satisfied."
                            .green()
                            .bold()
                    );
                }
            }
        }

        Commands::Fix {
            path,
            create_pr,
            repo,
            token,
            branch,
            base,
            dry_run,
        } => {
            println!(
                "Analyzing project at {} for fixable vulnerabilities...",
                path.display()
            );
            let output = match scan_project(&path, ScanOptions::default()).await {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    exit(1);
                }
            };

            if output.remediations.is_empty() {
                println!("No fixable vulnerabilities found.");
                return;
            }

            let manifest_type = &output.manifest_type;
            let target_dir = output.manifest_file.parent().unwrap_or(&path);
            let lockfile_state = if !dry_run
                && matches!(
                    manifest_type,
                    crate::parsers::detector::ManifestType::NpmPackageLock
                        | crate::parsers::detector::ManifestType::NpmShrinkwrap
                        | crate::parsers::detector::ManifestType::YarnLock
                        | crate::parsers::detector::ManifestType::PnpmLock
                ) {
                match crate::patcher::LockfilePatcher::snapshot_project_state(target_dir) {
                    Ok(state) => Some(state),
                    Err(error) => {
                        eprintln!(
                            "{} {}",
                            "Error snapshotting project state:".red().bold(),
                            error
                        );
                        exit(1);
                    }
                }
            } else {
                None
            };
            match patcher::apply_fixes(target_dir, manifest_type, &output.remediations, dry_run) {
                Ok(patch_res) => {
                    let target_desc = match manifest_type {
                        crate::parsers::detector::ManifestType::RustCargoLock => {
                            "Cargo.toml / Cargo.lock"
                        }
                        crate::parsers::detector::ManifestType::PythonRequirements => {
                            "requirements.txt"
                        }
                        _ => "package.json",
                    };

                    if patch_res.modified || dry_run {
                        if dry_run {
                            println!(
                                "\n{}",
                                format!("🔍 [Dry Run] Proposed patches for {}:", target_desc)
                                    .cyan()
                                    .bold()
                            );
                        } else {
                            println!(
                                "\n{}",
                                format!("✔ Successfully applied patches to {}!", target_desc)
                                    .green()
                                    .bold()
                            );
                            if let Some(bak) = &patch_res.backup_file {
                                println!("  Backup created: {}", bak.display());
                            }
                        }

                        let mut total_vulns = 0;
                        let mut breaking_count = 0;
                        let mut sev_counts: std::collections::HashMap<String, usize> =
                            std::collections::HashMap::new();

                        if !patch_res.changes.direct_upgrades.is_empty() {
                            let dir_header = match manifest_type {
                                crate::parsers::detector::ManifestType::RustCargoLock => {
                                    "Direct Manifest Upgrades (Cargo.toml):"
                                }
                                crate::parsers::detector::ManifestType::PythonRequirements => {
                                    "Direct Manifest Upgrades (requirements.txt):"
                                }
                                _ => "Direct Manifest Upgrades (package.json):",
                            };
                            println!("\n  {}", dir_header.bold());
                            for u in &patch_res.changes.direct_upgrades {
                                if u.is_breaking {
                                    breaking_count += 1;
                                }
                                total_vulns += u.vulnerability_ids.len();
                                if let Some(s) = u.highest_severity {
                                    *sev_counts.entry(s.as_str().to_string()).or_default() +=
                                        u.vulnerability_ids.len();
                                }

                                let badge = if u.is_breaking {
                                    "⚠️  [MAJOR]".yellow().bold()
                                } else if !u.semver_change.is_empty() {
                                    format!("✔  [{}]", u.semver_change).green().bold()
                                } else {
                                    "✔  [SAFE]".green().bold()
                                };

                                println!(
                                    "   {} {}: {} ➔ {} ({})",
                                    badge,
                                    u.package.bold(),
                                    u.from,
                                    u.to.cyan().bold(),
                                    u.section
                                );
                                if !u.vulnerability_ids.is_empty() {
                                    let ids_formatted = u.vulnerability_ids.join(", ");
                                    let sev_badge = match u.highest_severity {
                                        Some(crate::types::SeverityLevel::Critical) => {
                                            " [CRITICAL]".red().bold().to_string()
                                        }
                                        Some(crate::types::SeverityLevel::High) => {
                                            " [HIGH]".bright_red().bold().to_string()
                                        }
                                        Some(crate::types::SeverityLevel::Medium) => {
                                            " [MEDIUM]".yellow().bold().to_string()
                                        }
                                        Some(crate::types::SeverityLevel::Low) => {
                                            " [LOW]".blue().to_string()
                                        }
                                        _ => String::new(),
                                    };
                                    println!("      ↳ Resolves: {}{}", ids_formatted, sev_badge);
                                }
                                if u.is_breaking {
                                    println!("      ↳ {}", "Warning: Major version bump may introduce breaking API changes.".yellow());
                                }
                            }
                        }

                        if !patch_res.changes.transitive_overrides.is_empty() {
                            let trans_header = match manifest_type {
                                crate::parsers::detector::ManifestType::RustCargoLock => {
                                    "Transitive Dependency Updates (Cargo.lock):"
                                }
                                crate::parsers::detector::ManifestType::PythonRequirements => {
                                    "Transitive Dependency Pins (requirements.txt):"
                                }
                                _ => "Transitive Overrides:",
                            };
                            println!("\n  {}", trans_header.bold());
                            for o in &patch_res.changes.transitive_overrides {
                                if o.is_breaking {
                                    breaking_count += 1;
                                }
                                total_vulns += o.vulnerability_ids.len();
                                if let Some(s) = o.highest_severity {
                                    *sev_counts.entry(s.as_str().to_string()).or_default() +=
                                        o.vulnerability_ids.len();
                                }

                                let from_str = o
                                    .current_version
                                    .as_deref()
                                    .map(|v| format!("{} ➔ ", v))
                                    .unwrap_or_default();
                                let mut line = match manifest_type {
                                    crate::parsers::detector::ManifestType::RustCargoLock
                                    | crate::parsers::detector::ManifestType::PythonRequirements => {
                                        format!(
                                            "   ↳ {}: {}{}",
                                            o.package.bold(),
                                            from_str,
                                            o.pinned_to.cyan().bold()
                                        )
                                    }
                                    _ => {
                                        format!(
                                            "   ↳ {} pinned to {}",
                                            o.package.bold(),
                                            o.pinned_to.cyan().bold()
                                        )
                                    }
                                };

                                if !o.vulnerability_ids.is_empty() {
                                    let ids_formatted = o.vulnerability_ids.join(", ");
                                    let sev_badge = match o.highest_severity {
                                        Some(crate::types::SeverityLevel::Critical) => {
                                            " [CRITICAL]".red().bold().to_string()
                                        }
                                        Some(crate::types::SeverityLevel::High) => {
                                            " [HIGH]".bright_red().bold().to_string()
                                        }
                                        Some(crate::types::SeverityLevel::Medium) => {
                                            " [MEDIUM]".yellow().bold().to_string()
                                        }
                                        Some(crate::types::SeverityLevel::Low) => {
                                            " [LOW]".blue().to_string()
                                        }
                                        _ => String::new(),
                                    };
                                    line.push_str(&format!(
                                        " (fixes: {}{})",
                                        ids_formatted, sev_badge
                                    ));
                                }
                                println!("{}", line);
                                if o.is_breaking {
                                    println!("      ↳ {}", "Warning: Transitive major bump may require upstream parent update.".yellow());
                                }
                            }
                        }

                        if !patch_res.warnings.is_empty() {
                            println!("\n  {}", "Warnings during update:".yellow().bold());
                            for w in &patch_res.warnings {
                                println!("   ⚠️  {}", w.yellow());
                            }
                        }

                        // Summary Section
                        let direct_count = patch_res.changes.direct_upgrades.len();
                        let trans_count = patch_res.changes.transitive_overrides.len();
                        let total_pkgs = direct_count + trans_count;

                        println!("\n{}", "Summary:".bold());
                        println!(
                            "  • {} package{} to update ({} manifest, {} lockfile)",
                            total_pkgs,
                            if total_pkgs == 1 { "" } else { "s" },
                            direct_count,
                            trans_count
                        );
                        if total_vulns > 0 {
                            let mut sev_parts = Vec::new();
                            for sev in &["CRITICAL", "HIGH", "MEDIUM", "LOW"] {
                                if let Some(&c) = sev_counts.get(*sev) {
                                    sev_parts.push(format!("{} {}", c, sev));
                                }
                            }
                            let sev_detail = if sev_parts.is_empty() {
                                String::new()
                            } else {
                                format!(" ({})", sev_parts.join(", "))
                            };
                            println!(
                                "  • {} vulnerabilit{} remediated{}",
                                total_vulns,
                                if total_vulns == 1 { "y" } else { "ies" },
                                sev_detail
                            );
                        }
                        if breaking_count > 0 {
                            println!(
                                "  • {}",
                                format!(
                                    "{} potentially breaking upgrade{} detected",
                                    breaking_count,
                                    if breaking_count == 1 { "" } else { "s" }
                                )
                                .yellow()
                                .bold()
                            );
                        }

                        if dry_run {
                            println!("\n{}", "Next Steps:".bold());
                            println!("  • Run without --dry-run to apply changes:");
                            println!(
                                "      {}",
                                format!("vexa-sca fix \"{}\"", path.display()).cyan()
                            );
                            println!("  • Or open an automated GitHub Pull Request:");
                            println!(
                                "      {}",
                                format!("vexa-sca fix \"{}\" --create-pr", path.display()).cyan()
                            );
                        }

                        if !dry_run && patch_res.modified && lockfile_state.is_some() {
                            println!("\nRegenerating lockfile in {}…", target_dir.display());
                            match crate::patcher::LockfilePatcher::regenerate_lockfile(target_dir) {
                                Ok(cmd) => println!(
                                    "  {} `{}` succeeded — lockfile is up to date.",
                                    "✔".green(),
                                    cmd.cyan()
                                ),
                                Err(error) => {
                                    eprintln!(
                                        "\n{} Lockfile regeneration failed:\n{}",
                                        "✘".red().bold(),
                                        error
                                    );
                                    match lockfile_state.as_ref() {
                                        Some(snapshot) => {
                                            match crate::patcher::LockfilePatcher::restore_project_state(snapshot) {
                                                Ok(()) => eprintln!(
                                                    "{} package.json and captured lockfiles were restored.",
                                                    "Rollback complete:".yellow().bold()
                                                ),
                                                Err(rollback_error) => eprintln!(
                                                    "{} {}. Preserve the repository state and restore manually; package.json.bak may contain the prior manifest.",
                                                    "ROLLBACK FAILED:".red().bold(),
                                                    rollback_error
                                                ),
                                            }
                                        }
                                        None => eprintln!(
                                            "{} No pre-change snapshot was available; restore package.json and the lockfile manually.",
                                            "ROLLBACK FAILED:".red().bold()
                                        ),
                                    }
                                    exit(1);
                                }
                            }
                        }

                        if create_pr {
                            println!("\nPreparing automated GitHub Pull Request...");
                            match PrCreator::create_and_open_pr(
                                &path, &patch_res, repo, branch, base, token, dry_run,
                            )
                            .await
                            {
                                Ok(pr_res) => {
                                    println!(
                                        "\n{}",
                                        format!("✔ {}", pr_res.message).green().bold()
                                    );
                                    if let Some(url) = pr_res.pr_url {
                                        println!("  🔗 Pull Request: {}", url.cyan().bold());
                                    }
                                }
                                Err(e) => {
                                    eprintln!("\n{} {}", "PR creation warning:".yellow().bold(), e);
                                }
                            }
                        } else if !dry_run {
                            match manifest_type {
                                crate::parsers::detector::ManifestType::RustCargoLock => {
                                    println!("\nRun \"cargo check\" or \"cargo test\" to verify the updated dependencies.");
                                }
                                crate::parsers::detector::ManifestType::PythonRequirements => {
                                    println!("\nRun \"pip install -r requirements.txt\" to install the updated dependencies.");
                                }
                                crate::parsers::detector::ManifestType::NpmPackageLock
                                | crate::parsers::detector::ManifestType::NpmShrinkwrap
                                | crate::parsers::detector::ManifestType::YarnLock
                                | crate::parsers::detector::ManifestType::PnpmLock => {}
                                _ => {}
                            }
                        }
                    } else {
                        println!("No modifications were made.");
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "Error applying fixes:".red().bold(), e);
                    exit(1);
                }
            }
        }

        Commands::Graph {
            path,
            json,
            max_depth,
        } => {
            let detection = match detect_and_parse(&path, true) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    if e.contains("Failed to parse manifest")
                        || e.contains("Invalid JSON in")
                        || e.contains("Invalid YAML in")
                    {
                        exit(3);
                    } else {
                        exit(2);
                    }
                }
            };

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&detection.graph.to_json()).unwrap()
                );
            } else {
                let manifest_display = detection.manifest_file.display().to_string();
                let clean_manifest = manifest_display
                    .strip_prefix(r"\\?\")
                    .unwrap_or(&manifest_display);
                println!("Dependency Graph for {}:", clean_manifest.bold());
                println!(
                    "  Root Package : {}@{} ({})",
                    detection.graph.root_pkg.name.bold(),
                    detection.graph.root_pkg.version,
                    detection.graph.root_pkg.ecosystem
                );
                println!(
                    "  Total Unique : {} packages",
                    detection.graph.get_all_pkgs().len()
                );
                println!(
                    "  Total Nodes  : {} dependency nodes",
                    detection.graph.get_all_nodes().len()
                );
                println!(
                    "  Cycles       : {}",
                    if detection.graph.has_cycles() {
                        "Yes".yellow().bold()
                    } else {
                        "No".green()
                    }
                );
                println!("\nDependency Tree:");
                print!("{}", detection.graph.render_ascii_tree(max_depth));
            }
        }

        Commands::Test {
            target,
            ecosystem,
            ecosystem_pos,
            json,
            severity_threshold,
        } => {
            let ecosystem = ecosystem
                .or(ecosystem_pos)
                .unwrap_or_else(|| "npm".to_string());
            let parts: Vec<&str> = target.split('@').collect();
            if parts.len() < 2 {
                eprintln!(
                    "Error: specify package and version, e.g. \"vexa-sca test lodash@4.17.15\""
                );
                exit(1);
            }
            let name = parts[0];
            let version = parts[1];

            if !json {
                println!("Testing {}@{} ({})...", name, version, ecosystem);
            }

            let root_pkg = PkgInfo::new("adhoc-test", "1.0.0", &ecosystem);
            let mut graph = DepGraph::new(
                root_pkg,
                crate::core::dep_graph::PkgManagerInfo {
                    name: ecosystem.clone(),
                    version: "1.0.0".to_string(),
                },
            );

            let test_pkg = PkgInfo::new(name, version, &ecosystem);
            graph.add_pkg(test_pkg.clone());
            let node_id = format!("{}:{}", ecosystem, test_pkg.id);
            graph.add_node(
                node_id.clone(),
                test_pkg.id.clone(),
                crate::core::dep_graph::NodeInfo {
                    scope: "prod".to_string(),
                    path: None,
                    integrity: None,
                },
            );
            let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);

            let scanner = VulnScanner::default();
            match scanner.scan_graph(&graph).await {
                Ok(mut res) => {
                    if let Some(min_level) = severity_threshold {
                        res.vulnerabilities
                            .retain(|v| v.severity.level.weight() >= min_level.weight());
                        res.vulnerabilities_count = res.vulnerabilities.len();
                    }

                    if json {
                        println!("{}", format_json_report(&res, &[], &[], None, None));
                    } else {
                        render_terminal_report(&res, &[], &[], None, None);
                    }

                    if res.vulnerabilities_count > 0 {
                        if !json {
                            eprintln!("\n{}", format!("✖ Security Test Failed: Found {} active vulnerabilities in {}@{}", res.vulnerabilities_count, name, version).red().bold());
                        }
                        exit(1);
                    } else if !json {
                        println!(
                            "\n{}",
                            format!(
                                "✔ Security Test Passed: No vulnerabilities found in {}@{}",
                                name, version
                            )
                            .green()
                            .bold()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Scan error: {}", e);
                    exit(2);
                }
            }
        }

        Commands::Scan {
            path,
            reachable_only,
            prod_only,
            policy,
            severity_threshold,
            ignore_unfixed,
            json,
            markdown,
            sarif,
            sarif_file,
            html,
            html_file,
            sbom,
            sbom_file,
            fail_on,
            fail_on_reachable,
            fail_on_unknown_reachability,
            allow_unknown_reachability,
            fail_on_licenses,
            fail_on_unmaintained,
            epss_threshold,
            epss_allow_heuristic,
            strict_epss,
            usage,
            baseline,
            no_fail,
            allow_unavailable,
            max_source_files,
            timeout_secs,
        } => {
            if fail_on_unknown_reachability && allow_unknown_reachability {
                eprintln!(
                    "{} Cannot specify both --fail-on-unknown-reachability and --allow-unknown-reachability.",
                    "Error:".red().bold()
                );
                exit(2);
            }

            let options = ScanOptions {
                dev: !prod_only,
                reachable_only,
                severity_threshold,
                ignore_unfixed,
                policy_file: policy,
                timeout_secs,
                licenses: true,
                allow_unavailable,
                baseline_file: baseline.clone(),
                is_ci_profile: false,
                max_source_files,
            };

            match scan_project(&path, options).await {
                Ok(mut output) => {
                    if let Some(thresh) = epss_threshold {
                        let mut retained = Vec::new();
                        let mut heuristic_or_unavailable_count = 0;
                        let mut strict_failure = false;

                        for v in output.scan_result.vulnerabilities {
                            let (matches, is_heuristic_or_unavail) = match &v.epss {
                                Some(epss) => match epss.source {
                                    crate::types::EpssSource::FirstOrg
                                    | crate::types::EpssSource::Cache => {
                                        (epss.score >= thresh, false)
                                    }
                                    crate::types::EpssSource::Heuristic => {
                                        if epss_allow_heuristic {
                                            (epss.score >= thresh, false)
                                        } else {
                                            (true, true) // fail-closed: retain findings without authoritative EPSS
                                        }
                                    }
                                    crate::types::EpssSource::Unavailable => (true, true), // fail-closed: retain
                                },
                                None => (true, true),
                            };

                            if is_heuristic_or_unavail {
                                heuristic_or_unavailable_count += 1;
                                if strict_epss {
                                    eprintln!(
                                        "{} EPSS data is unavailable or heuristic for vulnerability {} affecting {} (authoritative EPSS required by --strict-epss).",
                                        "Error:".red().bold(),
                                        v.id,
                                        v.package
                                    );
                                    strict_failure = true;
                                }
                            }

                            if matches {
                                retained.push(v);
                            }
                        }

                        if strict_failure {
                            exit(2);
                        }

                        if heuristic_or_unavailable_count > 0
                            && !json
                            && !sarif
                            && !html
                            && sbom.is_none()
                        {
                            println!(
                                "{}",
                                format!(
                                    "ℹ Notice: {} vulnerabilit{} retained under fail-closed EPSS policy (EPSS unavailable/heuristic from FIRST.org).",
                                    heuristic_or_unavailable_count,
                                    if heuristic_or_unavailable_count == 1 { "y" } else { "ies" }
                                )
                                .yellow()
                            );
                        }

                        output.scan_result.vulnerabilities = retained;
                        output.scan_result.vulnerabilities_count =
                            output.scan_result.vulnerabilities.len();
                    }

                    if usage && !json && !sarif && !html && sbom.is_none() {
                        println!("\n{}", "Vexa SCA Scan Volume & Quota Status:".bold());
                        println!("  Edition:      {}", "Open Source Engine".cyan().bold());
                        println!(
                            "  Scan Quota:   {}",
                            "Unlimited (Local CLI & Repositories)".green().bold()
                        );
                        println!("  Status:       {}", "Active".green());
                        println!(
                            "  Policy:       {}\n",
                            "No cloud telemetry or scan quotas enforced.".dimmed()
                        );
                    }
                    let project_name = output
                        .manifest_file
                        .parent()
                        .and_then(|p| p.file_name())
                        .and_then(|n| n.to_str())
                        .unwrap_or("project");

                    // 1. SARIF Report
                    let sarif_output = if sarif || sarif_file.is_some() {
                        Some(format_sarif_report(
                            &output.scan_result,
                            &output.remediations,
                            Some(&output.manifest_file),
                        ))
                    } else {
                        None
                    };

                    if let (Some(file_path), Some(content)) = (&sarif_file, &sarif_output) {
                        if let Err(e) = std::fs::write(file_path, content) {
                            eprintln!(
                                "{} Failed to write SARIF report to {}: {}",
                                "Error:".red(),
                                file_path.display(),
                                e
                            );
                            output.scan_result.completeness.limits_hit.push(format!(
                                "REPORT_WRITE_FAILED (SARIF: {}: {})",
                                file_path.display(),
                                e
                            ));
                            output.scan_result.scan_status = ScanStatus::Incomplete;
                        } else {
                            println!("✔ SARIF v2.1.0 report saved to {}", file_path.display());
                        }
                    }

                    // 2. HTML Report
                    let html_output = if html || html_file.is_some() {
                        Some(format_html_report(
                            &output.scan_result,
                            &output.suppressed,
                            &output.remediations,
                            output.license_audit.as_ref(),
                            project_name,
                            Some(&output.manifest_file),
                        ))
                    } else {
                        None
                    };

                    if let (Some(file_path), Some(content)) = (&html_file, &html_output) {
                        if let Err(e) = std::fs::write(file_path, content) {
                            eprintln!(
                                "{} Failed to write HTML report to {}: {}",
                                "Error:".red(),
                                file_path.display(),
                                e
                            );
                            output.scan_result.completeness.limits_hit.push(format!(
                                "REPORT_WRITE_FAILED (HTML: {}: {})",
                                file_path.display(),
                                e
                            ));
                            output.scan_result.scan_status = ScanStatus::Incomplete;
                        } else {
                            println!(
                                "✔ Interactive HTML dashboard saved to {}",
                                file_path.display()
                            );
                        }
                    }

                    // 3. SBOM Report
                    let sbom_output = if sbom.is_some() || sbom_file.is_some() {
                        let fmt = sbom
                            .or_else(|| {
                                sbom_file
                                    .as_ref()
                                    .and_then(|p| p.extension())
                                    .and_then(|e| e.to_str())
                                    .and_then(SbomFormat::from_str_loose)
                            })
                            .unwrap_or(SbomFormat::CycloneDx);
                        Some(match fmt {
                            SbomFormat::CycloneDx => format_cyclonedx_sbom(
                                &output.dep_graph,
                                Some(&output.scan_result),
                                output.license_audit.as_ref(),
                            ),
                            SbomFormat::Spdx => format_spdx_sbom(
                                &output.dep_graph,
                                Some(&output.scan_result),
                                output.license_audit.as_ref(),
                            ),
                        })
                    } else {
                        None
                    };

                    if let (Some(file_path), Some(content)) = (&sbom_file, &sbom_output) {
                        if let Err(e) = std::fs::write(file_path, content) {
                            eprintln!(
                                "{} Failed to write SBOM report to {}: {}",
                                "Error:".red(),
                                file_path.display(),
                                e
                            );
                            output.scan_result.completeness.limits_hit.push(format!(
                                "REPORT_WRITE_FAILED (SBOM: {}: {})",
                                file_path.display(),
                                e
                            ));
                            output.scan_result.scan_status = ScanStatus::Incomplete;
                        } else {
                            println!("✔ SBOM report saved to {}", file_path.display());
                        }
                    }

                    // 4. Output routing
                    if html && html_file.is_none() {
                        if let Some(content) = &html_output {
                            println!("{}", content);
                        }
                    } else if sbom.is_some() && sbom_file.is_none() {
                        if let Some(content) = &sbom_output {
                            println!("{}", content);
                        }
                    } else if sarif && sarif_file.is_none() {
                        if let Some(content) = &sarif_output {
                            println!("{}", content);
                        }
                    } else if json {
                        println!(
                            "{}",
                            format_json_report(
                                &output.scan_result,
                                &output.suppressed,
                                &output.remediations,
                                output.license_audit.as_ref(),
                                output.policy_file.as_deref()
                            )
                        );
                    } else if markdown {
                        println!(
                            "{}",
                            format_markdown_report(
                                &output.scan_result,
                                &output.suppressed,
                                &output.remediations,
                                output.license_audit.as_ref(),
                                output.policy_file.as_deref()
                            )
                        );
                    } else {
                        render_terminal_report(
                            &output.scan_result,
                            &output.suppressed,
                            &output.remediations,
                            output.license_audit.as_ref(),
                            output.policy_file.as_deref(),
                        );
                    }

                    // Write GitHub Step Summary if env var is set
                    if let Some(summary_env) = std::env::var_os("GITHUB_STEP_SUMMARY") {
                        let summary_md =
                            format_github_step_summary(&output.scan_result, &output.remediations);
                        use std::io::Write;
                        if let Ok(mut f) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(PathBuf::from(summary_env))
                        {
                            let _ = writeln!(f, "{}", summary_md);
                        }
                    }

                    // 5. CI/CD Quality Gate Evaluation
                    let mut effective_fail_on_reachable = fail_on_reachable;
                    let mut effective_severity = None;

                    if let Some(fo) = &fail_on {
                        let lower = fo.trim().to_lowercase();
                        if lower == "reachable" {
                            effective_fail_on_reachable = true;
                        } else if lower.starts_with("reachable-") || lower.starts_with("reachable_")
                        {
                            effective_fail_on_reachable = true;
                            let sev_str = &lower[10..];
                            effective_severity = Some(SeverityLevel::from_str_loose(sev_str));
                        } else {
                            effective_severity = Some(SeverityLevel::from_str_loose(&lower));
                        }
                    }

                    if effective_fail_on_reachable {
                        eprintln!(
                            "{} --fail-on-reachable evaluates repository syntactic import/require usage, not runtime control-flow exploitability. Vulnerabilities with UNKNOWN reachability fail the gate unless --allow-unknown-reachability is set.",
                            "Notice:".yellow().bold()
                        );
                    }

                    let mut gate_scan_result = output.scan_result.clone();
                    if !output.all_vulnerabilities.is_empty() {
                        gate_scan_result.vulnerabilities = output.all_vulnerabilities.clone();
                    }

                    let gate_opts = QualityGateOptions {
                        fail_on_severity: effective_severity,
                        fail_on_reachable: effective_fail_on_reachable,
                        fail_on_unknown_reachability,
                        allow_unknown_reachability,
                        fail_on_licenses,
                        fail_on_unmaintained,
                        no_fail,
                        baseline_mode: baseline.is_some(),
                    };
                    let gate_res = QualityGate::evaluate(
                        &gate_scan_result,
                        output.license_audit.as_ref(),
                        &gate_opts,
                    );

                    if !json && !sarif && !html && sbom.is_none() {
                        QualityGate::print_terminal_summary(&gate_res);
                    }

                    if !gate_res.passed {
                        exit(1);
                    }
                    if incomplete_scan_requires_exit3(&output.scan_result, allow_unavailable) {
                        eprintln!(
                            "{} Scan data is incomplete; refusing a successful exit. Review the completeness report or explicitly allow an advisory-only outage with --allow-unavailable.",
                            "Error:".red().bold()
                        );
                        exit(3);
                    }
                }
                Err(e) => {
                    eprintln!("Scan error: {}", e);
                    if e.contains("Failed to parse manifest")
                        || e.contains("Invalid JSON in")
                        || e.contains("Invalid YAML in")
                    {
                        exit(3);
                    } else {
                        exit(2);
                    }
                }
            }
        }

        Commands::Ci {
            path,
            baseline,
            job_summary_file,
            emit_annotations,
            reachable_only,
            prod_only,
            policy,
            severity_threshold,
            ignore_unfixed,
            json,
            markdown,
            sarif,
            sarif_file,
            sbom,
            sbom_file,
            fail_on,
            fail_on_reachable,
            fail_on_unknown_reachability,
            allow_unknown_reachability,
            fail_on_licenses,
            fail_on_unmaintained,
            epss_threshold,
            epss_allow_heuristic,
            strict_epss,
            no_fail,
            allow_unavailable,
            max_source_files,
            timeout_secs,
        } => {
            if fail_on_unknown_reachability && allow_unknown_reachability {
                eprintln!(
                    "{} Cannot specify both --fail-on-unknown-reachability and --allow-unknown-reachability.",
                    "Error:".red().bold()
                );
                exit(2);
            }

            let options = ScanOptions {
                dev: !prod_only,
                reachable_only,
                severity_threshold,
                ignore_unfixed,
                policy_file: policy,
                timeout_secs,
                licenses: true,
                allow_unavailable,
                baseline_file: baseline.clone(),
                is_ci_profile: true,
                max_source_files,
            };

            match scan_project(&path, options).await {
                Ok(mut output) => {
                    if let Some(thresh) = epss_threshold {
                        let mut retained = Vec::new();
                        let mut heuristic_or_unavailable_count = 0;
                        let mut strict_failure = false;

                        for v in output.scan_result.vulnerabilities {
                            let (matches, is_heuristic_or_unavail) = match &v.epss {
                                Some(epss) => match epss.source {
                                    crate::types::EpssSource::FirstOrg
                                    | crate::types::EpssSource::Cache => {
                                        (epss.score >= thresh, false)
                                    }
                                    crate::types::EpssSource::Heuristic => {
                                        if epss_allow_heuristic {
                                            (epss.score >= thresh, false)
                                        } else {
                                            (true, true)
                                        }
                                    }
                                    crate::types::EpssSource::Unavailable => (true, true),
                                },
                                None => (true, true),
                            };

                            if is_heuristic_or_unavail {
                                heuristic_or_unavailable_count += 1;
                                if strict_epss {
                                    eprintln!(
                                        "{} EPSS data is unavailable or heuristic for vulnerability {} affecting {} (authoritative EPSS required by --strict-epss).",
                                        "Error:".red().bold(),
                                        v.id,
                                        v.package
                                    );
                                    strict_failure = true;
                                }
                            }

                            if matches {
                                retained.push(v);
                            }
                        }

                        if strict_failure {
                            exit(2);
                        }

                        if heuristic_or_unavailable_count > 0 && !json && !sarif && sbom.is_none() {
                            println!(
                                "{}",
                                format!(
                                    "ℹ Notice: {} vulnerabilit{} retained under fail-closed EPSS policy (EPSS unavailable/heuristic from FIRST.org).",
                                    heuristic_or_unavailable_count,
                                    if heuristic_or_unavailable_count == 1 { "y" } else { "ies" }
                                )
                                .yellow()
                            );
                        }

                        output.scan_result.vulnerabilities = retained;
                        output.scan_result.vulnerabilities_count =
                            output.scan_result.vulnerabilities.len();
                    }

                    // SARIF Report
                    let sarif_output = if sarif || sarif_file.is_some() {
                        Some(format_sarif_report(
                            &output.scan_result,
                            &output.remediations,
                            Some(&output.manifest_file),
                        ))
                    } else {
                        None
                    };

                    if let (Some(file_path), Some(content)) = (&sarif_file, &sarif_output) {
                        if let Err(e) = std::fs::write(file_path, content) {
                            eprintln!(
                                "{} Failed to write SARIF report to {}: {}",
                                "Error:".red(),
                                file_path.display(),
                                e
                            );
                            output.scan_result.completeness.limits_hit.push(format!(
                                "REPORT_WRITE_FAILED (SARIF: {}: {})",
                                file_path.display(),
                                e
                            ));
                            output.scan_result.scan_status = ScanStatus::Incomplete;
                        } else {
                            println!("✔ SARIF v2.1.0 report saved to {}", file_path.display());
                        }
                    }

                    // SBOM Report
                    let sbom_output = if sbom.is_some() || sbom_file.is_some() {
                        let fmt = sbom.unwrap_or(SbomFormat::CycloneDx);
                        Some(match fmt {
                            SbomFormat::CycloneDx => format_cyclonedx_sbom(
                                &output.dep_graph,
                                Some(&output.scan_result),
                                output.license_audit.as_ref(),
                            ),
                            SbomFormat::Spdx => format_spdx_sbom(
                                &output.dep_graph,
                                Some(&output.scan_result),
                                output.license_audit.as_ref(),
                            ),
                        })
                    } else {
                        None
                    };

                    if let (Some(file_path), Some(content)) = (&sbom_file, &sbom_output) {
                        if let Err(e) = std::fs::write(file_path, content) {
                            eprintln!(
                                "{} Failed to write SBOM report to {}: {}",
                                "Error:".red(),
                                file_path.display(),
                                e
                            );
                            output.scan_result.completeness.limits_hit.push(format!(
                                "REPORT_WRITE_FAILED (SBOM: {}: {})",
                                file_path.display(),
                                e
                            ));
                            output.scan_result.scan_status = ScanStatus::Incomplete;
                        } else {
                            println!("✔ SBOM report saved to {}", file_path.display());
                        }
                    }

                    // Write GitHub Step Summary ($GITHUB_STEP_SUMMARY or custom file)
                    let summary_md =
                        format_github_step_summary(&output.scan_result, &output.remediations);

                    let summary_target = job_summary_file
                        .or_else(|| std::env::var_os("GITHUB_STEP_SUMMARY").map(PathBuf::from));

                    if let Some(summary_path) = summary_target {
                        use std::io::Write;
                        let write_res = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&summary_path)
                            .and_then(|mut f| writeln!(f, "{}", summary_md));
                        if let Err(e) = write_res {
                            eprintln!(
                                "{} Failed to write job summary to {}: {}",
                                "Error:".red(),
                                summary_path.display(),
                                e
                            );
                            output.scan_result.completeness.limits_hit.push(format!(
                                "REPORT_WRITE_FAILED (JobSummary: {}: {})",
                                summary_path.display(),
                                e
                            ));
                            output.scan_result.scan_status = ScanStatus::Incomplete;
                        }
                    }

                    // Emit GitHub Actions Annotations (warning/error notice)
                    if emit_annotations {
                        emit_github_annotations(&output.scan_result.vulnerabilities);
                    }

                    // Output routing
                    if sbom.is_some() && sbom_file.is_none() {
                        if let Some(content) = &sbom_output {
                            println!("{}", content);
                        }
                    } else if sarif && sarif_file.is_none() {
                        if let Some(content) = &sarif_output {
                            println!("{}", content);
                        }
                    } else if json {
                        println!(
                            "{}",
                            format_json_report(
                                &output.scan_result,
                                &output.suppressed,
                                &output.remediations,
                                output.license_audit.as_ref(),
                                output.policy_file.as_deref()
                            )
                        );
                    } else if markdown {
                        println!(
                            "{}",
                            format_markdown_report(
                                &output.scan_result,
                                &output.suppressed,
                                &output.remediations,
                                output.license_audit.as_ref(),
                                output.policy_file.as_deref()
                            )
                        );
                    } else {
                        render_terminal_report(
                            &output.scan_result,
                            &output.suppressed,
                            &output.remediations,
                            output.license_audit.as_ref(),
                            output.policy_file.as_deref(),
                        );
                    }

                    // CI Quality Gate Evaluation
                    let mut effective_fail_on_reachable = fail_on_reachable;
                    let mut effective_severity = None;

                    if let Some(fo) = &fail_on {
                        let lower = fo.trim().to_lowercase();
                        if lower == "reachable" {
                            effective_fail_on_reachable = true;
                        } else if lower.starts_with("reachable-") || lower.starts_with("reachable_")
                        {
                            effective_fail_on_reachable = true;
                            let sev_str = &lower[10..];
                            effective_severity = Some(SeverityLevel::from_str_loose(sev_str));
                        } else {
                            effective_severity = Some(SeverityLevel::from_str_loose(&lower));
                        }
                    }

                    if effective_fail_on_reachable {
                        eprintln!(
                            "{} --fail-on-reachable evaluates repository syntactic import/require usage, not runtime control-flow exploitability. Vulnerabilities with UNKNOWN reachability fail the gate unless --allow-unknown-reachability is set.",
                            "Notice:".yellow().bold()
                        );
                    }

                    let mut gate_scan_result = output.scan_result.clone();
                    if !output.all_vulnerabilities.is_empty() {
                        gate_scan_result.vulnerabilities = output.all_vulnerabilities.clone();
                    }

                    let gate_opts = QualityGateOptions {
                        fail_on_severity: effective_severity,
                        fail_on_reachable: effective_fail_on_reachable,
                        fail_on_unknown_reachability,
                        allow_unknown_reachability,
                        fail_on_licenses,
                        fail_on_unmaintained,
                        no_fail,
                        baseline_mode: baseline.is_some(),
                    };

                    let gate_res = QualityGate::evaluate(
                        &gate_scan_result,
                        output.license_audit.as_ref(),
                        &gate_opts,
                    );

                    if !json && !sarif && sbom.is_none() {
                        QualityGate::print_terminal_summary(&gate_res);
                    }

                    if !gate_res.passed {
                        exit(1);
                    }
                    if incomplete_scan_requires_exit3(&output.scan_result, allow_unavailable) {
                        eprintln!(
                            "{} Scan data is incomplete; refusing a successful exit. Review the completeness report or explicitly allow an advisory-only outage with --allow-unavailable.",
                            "Error:".red().bold()
                        );
                        exit(3);
                    }
                }
                Err(e) => {
                    eprintln!("CI Scan error: {}", e);
                    if e.contains("Failed to parse manifest")
                        || e.contains("Invalid JSON in")
                        || e.contains("Invalid YAML in")
                    {
                        exit(3);
                    } else {
                        exit(2);
                    }
                }
            }
        }

        Commands::Init { path, enforce } => {
            let workflows_dir = path.join(".github").join("workflows");
            if let Err(e) = std::fs::create_dir_all(&workflows_dir) {
                eprintln!(
                    "{} Failed to create {}: {}",
                    "Error:".red(),
                    workflows_dir.display(),
                    e
                );
                exit(2);
            }
            let workflow_file = workflows_dir.join("vexa-sca.yml");
            let gate_flag = if enforce {
                "--fail-on high"
            } else {
                "--no-fail"
            };
            let workflow_content = format!(
                r#"name: Vexa SCA Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  contents: read

jobs:
  vexa-scan:
    name: Vexa SCA Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Install Vexa SCA
        run: |
          curl -fsSL https://github.com/noviqtechnologies/vexa-sca/releases/latest/download/vexa-sca-linux-x86_64.tar.gz | tar -xz
          sudo mv vexa-sca /usr/local/bin/

      - name: Run Vexa SCA CI Scan
        run: vexa-sca ci {}
"#,
                gate_flag
            );

            if let Err(e) = std::fs::write(&workflow_file, workflow_content) {
                eprintln!(
                    "{} Failed to write {}: {}",
                    "Error:".red(),
                    workflow_file.display(),
                    e
                );
                exit(2);
            }

            println!(
                "✔ Pinned GitHub Actions workflow initialized at {}",
                workflow_file.display().to_string().green().bold()
            );

            // Also create default .vexa-sca policy file if not present (FR-015)
            let policy_file = path.join(".vexa-sca");
            if !policy_file.exists() {
                let default_policy = r#"# Vexa SCA Policy Configuration (.vexa-sca)
version: "v1.0.0"

# Vulnerability ignore / suppression rules
# Each suppression should have a documented reason and expiration date
ignore:
  # Example:
  # GHSA-xxxx-xxxx-xxxx:
  #   reason: "Compensating control in WAF; mitigation in review"
  #   expires: "2026-12-31"
"#;
                if let Ok(()) = std::fs::write(&policy_file, default_policy) {
                    println!(
                        "✔ Security policy template initialized at {}",
                        policy_file.display().to_string().green().bold()
                    );
                }
            }

            println!(
                "  Policy enforcement: {}",
                if enforce {
                    "Strict (fails on high/critical)".yellow()
                } else {
                    "Report-only (non-blocking)".green()
                }
            );
            println!("  Authoritative surfaces: GitHub Step Summary ($GITHUB_STEP_SUMMARY) and Workflow Annotations.");
        }

        Commands::Container {
            target,
            severity_threshold,
            ignore_unfixed,
            json,
            markdown,
            sarif,
            sarif_file,
            html,
            html_file,
            sbom,
            sbom_file,
            fail_on,
            fail_on_licenses,
            no_fail,
        } => {
            println!("Scanning container target at {}...", target.display());
            match ContainerScanner::scan_target(&target).await {
                Ok(mut output) => {
                    if let Some(min_level) = severity_threshold {
                        output
                            .scan_result
                            .vulnerabilities
                            .retain(|v| v.severity.level.weight() >= min_level.weight());
                        output.scan_result.vulnerabilities_count =
                            output.scan_result.vulnerabilities.len();
                    }

                    if ignore_unfixed {
                        output
                            .scan_result
                            .vulnerabilities
                            .retain(|v| !v.fixed_in.is_empty());
                        output.scan_result.vulnerabilities_count =
                            output.scan_result.vulnerabilities.len();
                    }

                    let sarif_output = if sarif || sarif_file.is_some() {
                        Some(format_sarif_report(&output.scan_result, &[], Some(&target)))
                    } else {
                        None
                    };

                    if let (Some(file_path), Some(content)) = (&sarif_file, &sarif_output) {
                        let _ = std::fs::write(file_path, content);
                        println!("✔ SARIF report saved to {}", file_path.display());
                    }

                    let html_output = if html || html_file.is_some() {
                        Some(format_html_report(
                            &output.scan_result,
                            &[],
                            &[],
                            output.license_audit.as_ref(),
                            &output.os_info.name,
                            Some(&target),
                        ))
                    } else {
                        None
                    };

                    if let (Some(file_path), Some(content)) = (&html_file, &html_output) {
                        let _ = std::fs::write(file_path, content);
                        println!("✔ HTML dashboard saved to {}", file_path.display());
                    }

                    let sbom_output = if sbom.is_some() || sbom_file.is_some() {
                        let fmt = sbom
                            .or_else(|| {
                                sbom_file
                                    .as_ref()
                                    .and_then(|p| p.extension())
                                    .and_then(|e| e.to_str())
                                    .and_then(SbomFormat::from_str_loose)
                            })
                            .unwrap_or(SbomFormat::CycloneDx);
                        Some(match fmt {
                            SbomFormat::CycloneDx => format_cyclonedx_sbom(
                                &output.dep_graph,
                                Some(&output.scan_result),
                                output.license_audit.as_ref(),
                            ),
                            SbomFormat::Spdx => format_spdx_sbom(
                                &output.dep_graph,
                                Some(&output.scan_result),
                                output.license_audit.as_ref(),
                            ),
                        })
                    } else {
                        None
                    };

                    if let (Some(file_path), Some(content)) = (&sbom_file, &sbom_output) {
                        let _ = std::fs::write(file_path, content);
                        println!("✔ SBOM saved to {}", file_path.display());
                    }

                    if html && html_file.is_none() {
                        if let Some(content) = &html_output {
                            println!("{}", content);
                        }
                    } else if sbom.is_some() && sbom_file.is_none() {
                        if let Some(content) = &sbom_output {
                            println!("{}", content);
                        }
                    } else if sarif && sarif_file.is_none() {
                        if let Some(content) = &sarif_output {
                            println!("{}", content);
                        }
                    } else if json {
                        println!(
                            "{}",
                            format_json_report(
                                &output.scan_result,
                                &[],
                                &[],
                                output.license_audit.as_ref(),
                                None
                            )
                        );
                    } else if markdown {
                        println!(
                            "{}",
                            format_markdown_report(
                                &output.scan_result,
                                &[],
                                &[],
                                output.license_audit.as_ref(),
                                None
                            )
                        );
                    } else {
                        render_terminal_report(
                            &output.scan_result,
                            &[],
                            &[],
                            output.license_audit.as_ref(),
                            None,
                        );
                    }

                    let gate_opts = QualityGateOptions {
                        fail_on_severity: fail_on.as_deref().map(SeverityLevel::from_str_loose),
                        fail_on_reachable: false,
                        fail_on_unknown_reachability: false,
                        allow_unknown_reachability: false,
                        fail_on_licenses,
                        fail_on_unmaintained: false,
                        no_fail,
                        baseline_mode: false,
                    };
                    let gate_res = QualityGate::evaluate(
                        &output.scan_result,
                        output.license_audit.as_ref(),
                        &gate_opts,
                    );

                    if !json && !sarif && !html && sbom.is_none() {
                        QualityGate::print_terminal_summary(&gate_res);
                    }

                    if !gate_res.passed {
                        exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Container scan error: {}", e);
                    exit(2);
                }
            }
        }

        Commands::Usage { json } => {
            if json {
                let report = serde_json::json!({
                    "plan_tier": "Open Source Engine",
                    "scan_quota": "unlimited",
                    "status": "active",
                    "telemetry": "disabled"
                });
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!("\n{}", "Vexa SCA Usage & Engine Status".bold().underline());
                println!("──────────────────────────────────────────────────");
                println!(
                    "  {}   {}",
                    "Edition:     ".bold(),
                    "Open Source Engine".cyan().bold()
                );
                println!(
                    "  {}   {}",
                    "Scan Quota:  ".bold(),
                    "Unlimited (Local CLI & Repositories)".green().bold()
                );
                println!("  {}   {}", "Status:      ".bold(), "Active".green());
                println!(
                    "  {}   {}",
                    "Policy:      ".dimmed(),
                    "No cloud telemetry or scan quotas enforced.".dimmed()
                );
                println!("──────────────────────────────────────────────────\n");
            }
        }
    }
}
