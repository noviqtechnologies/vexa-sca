use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;
use std::process::exit;

use crate::core::dep_graph::DepGraph;
use crate::licenses::license_scanner::LicenseScanner;
use crate::parsers::detector::detect_and_parse;
use crate::container::container_scanner::ContainerScanner;
use crate::patcher::lockfile_patcher::LockfilePatcher;
use crate::patcher::pr_creator::PrCreator;
use crate::reporters::export::{
    format_cyclonedx_sbom, format_html_report, format_json_report, format_markdown_report,
    format_sarif_report, format_spdx_sbom, SbomFormat,
};
use crate::reporters::terminal::render_terminal_report;
use crate::scanner::quality_gate::{QualityGate, QualityGateOptions};
use crate::scanner::vuln_scanner::VulnScanner;
use crate::types::{PkgInfo, SeverityLevel};
use crate::{scan_project, ScanOptions};

#[derive(Parser, Debug)]
#[command(name = "vexa", about = "Vexa - Commercial-Grade Software Composition Analysis & Security Engine", version = "1.0.0")]
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
        #[arg(long)]
        severity_threshold: Option<String>,

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
        #[arg(long)]
        sbom: Option<String>,

        /// Save SBOM report to a file path
        #[arg(long)]
        sbom_file: Option<PathBuf>,

        /// CI/CD Quality Gate: fail on or above severity threshold (low, medium, high, critical)
        #[arg(long)]
        fail_on: Option<String>,

        /// CI/CD Quality Gate: fail only if at least one vulnerability has confirmed AST reachability
        #[arg(long)]
        fail_on_reachable: bool,

        /// CI/CD Quality Gate: fail on license risk category (e.g. strong-copyleft, weak-copyleft)
        #[arg(long)]
        fail_on_licenses: Option<String>,
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
    },

    /// Visualize dependency graph
    Graph {
        /// Target path (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Output graph in standard JSON schema format
        #[arg(long)]
        json: bool,
    },

    /// Test a single package version (e.g. lodash@4.17.15)
    Test {
        /// Package and version (e.g. lodash@4.17.15)
        target: String,

        /// Ecosystem (npm, PyPI, Go, crates.io, Maven)
        #[arg(default_value = "npm")]
        ecosystem: String,
    },

    /// Scan container image archive (.tar/.tar.gz), rootfs directory, or Dockerfile for OS package vulnerabilities
    Container {
        /// Target image archive (.tar/.tar.gz), rootfs directory, or Dockerfile (defaults to current directory)
        #[arg(default_value = ".")]
        target: PathBuf,

        /// Minimum severity threshold (low, medium, high, critical)
        #[arg(long)]
        severity_threshold: Option<String>,

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
        #[arg(long)]
        sbom: Option<String>,

        /// Save SBOM report to a file path
        #[arg(long)]
        sbom_file: Option<PathBuf>,

        /// CI/CD Quality Gate: fail on or above severity (low, medium, high, critical)
        #[arg(long)]
        fail_on: Option<String>,

        /// CI/CD Quality Gate: fail on license risk category (e.g. strong-copyleft)
        #[arg(long)]
        fail_on_licenses: Option<String>,
    },
}

pub async fn run() {
    let cli = Cli::parse();

    match cli.command {

        Commands::Licenses { path } => {
            let detection = match detect_and_parse(&path, true) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    exit(1);
                }
            };

            let audit = LicenseScanner::scan_graph_licenses(&detection.graph, &path);
            println!("\nLicense Compliance for {}:", path.display());
            println!(
                "Total: {} | Permissive: {} | Weak Copyleft: {} | Strong Copyleft: {}",
                audit.summary.total,
                audit.summary.permissive.to_string().green(),
                audit.summary.weak_copyleft.to_string().yellow(),
                if audit.summary.strong_copyleft > 0 {
                    audit.summary.strong_copyleft.to_string().red().bold().to_string()
                } else {
                    "0".green().to_string()
                }
            );
            println!("{}", "-".repeat(60));
            for r in audit.results {
                println!("- {}@{}: {} [{}]", r.package, r.version, r.license, r.category.as_str());
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
            println!("Analyzing project at {} for fixable vulnerabilities...", path.display());
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

            match LockfilePatcher::apply_fixes(&path, &output.remediations, dry_run) {
                Ok(patch_res) => {
                    if patch_res.modified || dry_run {
                        if dry_run {
                            println!("\n{}", "🔍 [Dry Run] Proposed patches for package.json:".cyan().bold());
                        } else {
                            println!("\n{}", "✔ Successfully applied patches to package.json!".green().bold());
                            if let Some(bak) = &patch_res.backup_file {
                                println!("  Backup created: {}", bak.display());
                            }
                        }

                        if !patch_res.changes.direct_upgrades.is_empty() {
                            println!("\n  Direct Upgrades:");
                            for u in &patch_res.changes.direct_upgrades {
                                println!("   ↳ {}: {} ➔ {} ({})", u.package, u.from, u.to, u.section);
                            }
                        }
                        if !patch_res.changes.transitive_overrides.is_empty() {
                            println!("\n  Transitive Overrides:");
                            for o in &patch_res.changes.transitive_overrides {
                                println!("   ↳ {} pinned to {}", o.package, o.pinned_to);
                            }
                        }

                        if create_pr {
                            println!("\nPreparing automated GitHub Pull Request...");
                            match PrCreator::create_and_open_pr(
                                &path,
                                &patch_res,
                                repo,
                                branch,
                                base,
                                token,
                                dry_run,
                            ).await {
                                Ok(pr_res) => {
                                    println!("\n{}", format!("✔ {}", pr_res.message).green().bold());
                                    if let Some(url) = pr_res.pr_url {
                                        println!("  🔗 Pull Request: {}", url.cyan().bold());
                                    }
                                }
                                Err(e) => {
                                    eprintln!("\n{} {}", "PR creation warning:".yellow().bold(), e);
                                }
                            }
                        } else if !dry_run {
                            println!("\nRun \"npm install\", \"yarn\", or \"pnpm install\" to update your lockfile.");
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

        Commands::Graph { path, json } => {
            let detection = match detect_and_parse(&path, true) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red().bold(), e);
                    exit(1);
                }
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&detection.graph.to_json()).unwrap());
            } else {
                println!("Dependency Graph for {}:", detection.manifest_file.display());
                println!("Root: {}", detection.graph.root_node_id);
                println!("Total packages: {}", detection.graph.get_all_pkgs().len());
                println!("Total nodes: {}", detection.graph.get_all_nodes().len());
                println!("Cycles: {}", if detection.graph.has_cycles() { "Yes".yellow() } else { "No".green() });
            }
        }

        Commands::Test { target, ecosystem } => {
            let parts: Vec<&str> = target.split('@').collect();
            if parts.len() < 2 {
                eprintln!("Error: specify package and version, e.g. \"vexa test lodash@4.17.15\"");
                exit(1);
            }
            let name = parts[0];
            let version = parts[1];

            println!("Checking {}@{} ({})...", name, version, ecosystem);
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
                Ok(res) => {
                    render_terminal_report(&res, &[], &[], None, None);
                }
                Err(e) => {
                    eprintln!("Scan error: {}", e);
                    exit(1);
                }
            }
        }

        Commands::Scan {
            path,
            reachable_only,
            prod_only,
            policy,
            severity_threshold,
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
            fail_on_licenses,
        } => {
            let options = ScanOptions {
                dev: !prod_only,
                reachable_only,
                severity_threshold,
                policy_file: policy,
                timeout_secs: 15,
                licenses: true,
            };

            match scan_project(&path, options).await {
                Ok(output) => {
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
                            eprintln!("{} Failed to write SARIF report to {}: {}", "Error:".red(), file_path.display(), e);
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
                            eprintln!("{} Failed to write HTML report to {}: {}", "Error:".red(), file_path.display(), e);
                        } else {
                            println!("✔ Interactive HTML dashboard saved to {}", file_path.display());
                        }
                    }

                    // 3. SBOM Report
                    let sbom_output = if sbom.is_some() || sbom_file.is_some() {
                        let fmt_str = sbom
                            .as_deref()
                            .or_else(|| sbom_file.as_ref().and_then(|p| p.extension()).and_then(|e| e.to_str()))
                            .unwrap_or("cyclonedx");
                        let fmt = SbomFormat::from_str_loose(fmt_str).unwrap_or(SbomFormat::CycloneDx);
                        Some(match fmt {
                            SbomFormat::CycloneDx => format_cyclonedx_sbom(
                                &output.dep_graph,
                                Some(&output.scan_result),
                                output.license_audit.as_ref(),
                            ),
                            SbomFormat::Spdx => format_spdx_sbom(
                                &output.dep_graph,
                                output.license_audit.as_ref(),
                            ),
                        })
                    } else {
                        None
                    };

                    if let (Some(file_path), Some(content)) = (&sbom_file, &sbom_output) {
                        if let Err(e) = std::fs::write(file_path, content) {
                            eprintln!("{} Failed to write SBOM report to {}: {}", "Error:".red(), file_path.display(), e);
                        } else {
                            println!("✔ SBOM report saved to {}", file_path.display());
                        }
                    }

                    // 4. Output routing
                    if html {
                        if let Some(content) = &html_output {
                            println!("{}", content);
                        }
                    } else if sbom.is_some() {
                        if let Some(content) = &sbom_output {
                            println!("{}", content);
                        }
                    } else if sarif {
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

                    // 5. CI/CD Quality Gate Evaluation
                    let gate_opts = QualityGateOptions {
                        fail_on_severity: fail_on.as_deref().map(SeverityLevel::from_str_loose),
                        fail_on_reachable,
                        fail_on_licenses,
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
                    eprintln!("Scan error: {}", e);
                    exit(2);
                }
            }
        }

        Commands::Container {
            target,
            severity_threshold,
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
        } => {
            println!("Scanning container target at {}...", target.display());
            match ContainerScanner::scan_target(&target).await {
                Ok(mut output) => {
                    if let Some(thresh) = &severity_threshold {
                        let min_level = SeverityLevel::from_str_loose(thresh);
                        output.scan_result.vulnerabilities.retain(|v| v.severity.level.weight() >= min_level.weight());
                        output.scan_result.vulnerabilities_count = output.scan_result.vulnerabilities.len();
                    }

                    let sarif_output = if sarif || sarif_file.is_some() {
                        Some(format_sarif_report(
                            &output.scan_result,
                            &[],
                            Some(&target),
                        ))
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
                        let fmt_str = sbom.as_deref().unwrap_or("cyclonedx");
                        let fmt = SbomFormat::from_str_loose(fmt_str).unwrap_or(SbomFormat::CycloneDx);
                        Some(match fmt {
                            SbomFormat::CycloneDx => format_cyclonedx_sbom(
                                &output.dep_graph,
                                Some(&output.scan_result),
                                output.license_audit.as_ref(),
                            ),
                            SbomFormat::Spdx => format_spdx_sbom(
                                &output.dep_graph,
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

                    if html {
                        if let Some(content) = &html_output {
                            println!("{}", content);
                        }
                    } else if sbom.is_some() {
                        if let Some(content) = &sbom_output {
                            println!("{}", content);
                        }
                    } else if sarif {
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
                        fail_on_licenses,
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
    }
}
