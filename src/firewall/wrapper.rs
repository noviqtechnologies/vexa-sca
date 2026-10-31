#![forbid(unsafe_code)]

use crate::scanner::kev::CisaKevCatalog;
use crate::scanner::vuln_scanner::VulnScanner;
use crate::supply_chain::local_analyzer::LocalSupplyChainAnalyzer;
use crate::types::SeverityLevel;
use colored::*;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::time::Duration;

pub struct FirewallWrapper;

#[derive(Debug, Clone)]
pub struct PackageToEvaluate {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: String,
}

impl FirewallWrapper {
    /// Parse CLI package manager invocation and evaluate security risk before execution
    pub async fn execute_wrapped(
        pm: &str,
        args: &[String],
        cache_dir: &Path,
    ) -> Result<i32, String> {
        let pm_lower = pm.to_lowercase();
        let valid_pms = ["npm", "pnpm", "yarn", "bun", "pip", "uv", "cargo"];
        if !valid_pms.contains(&pm_lower.as_str()) {
            return Err(format!(
                "Unsupported package manager '{}'. Supported: npm, pnpm, yarn, bun, pip, uv, cargo",
                pm
            ));
        }

        // Extract targeted packages from arguments or perform dry-run manifest resolution (DDD §3.4.2)
        let mut packages = Self::extract_packages_to_install(&pm_lower, args);
        let subcmd = args.first().map(|s| s.as_str()).unwrap_or("");
        if packages.is_empty() && (subcmd == "install" || subcmd == "i") {
            if let Ok(detection) = crate::parsers::detector::detect_and_parse(Path::new("."), false)
            {
                for pkg in detection.graph.get_all_pkgs() {
                    if pkg.name != detection.graph.root_pkg.name {
                        packages.push(PackageToEvaluate {
                            name: pkg.name.clone(),
                            version: Some(pkg.version.clone()),
                            ecosystem: pkg.ecosystem.clone(),
                        });
                    }
                }
            }
        }

        if !packages.is_empty() {
            println!(
                "{} Evaluating {} target package(s) with Vexa SCA Package Manager Firewall...",
                "•".cyan().bold(),
                packages.len()
            );

            let mut blocked_reasons = Vec::new();
            let kev_catalog = CisaKevCatalog::load_or_fetch(cache_dir, None).await;

            // Pre-flight check: Run Core 15 static rules on local workspace
            let ws_findings = LocalSupplyChainAnalyzer::scan_workspace(Path::new("."));
            for f in ws_findings {
                if f.severity == SeverityLevel::Critical {
                    blocked_reasons
                        .push(format!("[{}] {}: {}", f.rule_id, f.signal_name, f.message));
                }
            }

            for pkg in &packages {
                // 1. Typosquatting and Supply Chain static analysis (SC-010)
                let sc_findings = LocalSupplyChainAnalyzer::check_package(
                    &pkg.name,
                    pkg.version.as_deref().unwrap_or("*"),
                    &pkg.ecosystem,
                );
                for f in sc_findings {
                    if f.severity == SeverityLevel::Critical || f.severity == SeverityLevel::High {
                        blocked_reasons
                            .push(format!("[{}] {}: {}", f.rule_id, f.signal_name, f.message));
                    }
                }

                // 2. Check CISA KEV and public OSV even when version is unpinned
                let ver = pkg.version.as_deref().unwrap_or("*");
                let scanner = VulnScanner::new(None);
                let root_pkg =
                    crate::types::PkgInfo::new("firewall-check", "1.0.0", &pkg.ecosystem);
                let mut graph = crate::core::dep_graph::DepGraph::new(
                    root_pkg,
                    crate::core::dep_graph::PkgManagerInfo {
                        name: pkg.ecosystem.clone(),
                        version: "1.0".to_string(),
                    },
                );
                let target_pkg = crate::types::PkgInfo::new(&pkg.name, ver, &pkg.ecosystem);
                graph.add_pkg(target_pkg.clone());
                let node_id = format!("{}:{}@{}", pkg.ecosystem, pkg.name, ver);
                graph.add_node(
                    node_id.clone(),
                    target_pkg.id,
                    crate::core::dep_graph::NodeInfo {
                        scope: "prod".to_string(),
                        path: None,
                        integrity: None,
                    },
                );
                let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);

                if let Ok(scan_res) = scanner.scan_graph(&graph).await {
                    for v in scan_res.vulnerabilities {
                        if v.severity.level == SeverityLevel::Critical {
                            blocked_reasons.push(format!(
                                "[CRITICAL VULNERABILITY] {} in {}@{}: {}",
                                v.id, pkg.name, ver, v.title
                            ));
                        }
                        if let Some(cve) = &v.cve {
                            if kev_catalog.is_kev(cve) {
                                blocked_reasons.push(format!(
                                    "[CISA KEV EXPLOITED] Known exploited vulnerability {} in {}@{}",
                                    cve, pkg.name, ver
                                ));
                            }
                        }
                    }
                }

                // 3. Authenticated Team+ Mode: Check cloud firewall if API key is present
                if let Ok(api_key) = std::env::var("VEXA_SCA_API_KEY") {
                    if !api_key.trim().is_empty() {
                        let client = reqwest::Client::builder()
                            .timeout(Duration::from_millis(1500))
                            .build()
                            .unwrap_or_default();

                        let payload = serde_json::json!({
                            "package": pkg.name,
                            "version": pkg.version.as_deref().unwrap_or("latest"),
                            "ecosystem": pkg.ecosystem,
                        });

                        if let Ok(resp) = client
                            .post("https://api.vexasec.io/v1/firewall/evaluate")
                            .header("Authorization", format!("Bearer {}", api_key.trim()))
                            .json(&payload)
                            .send()
                            .await
                        {
                            if resp.status().is_success() {
                                if let Ok(eval_res) = resp.json::<serde_json::Value>().await {
                                    if eval_res.get("decision").and_then(|d| d.as_str())
                                        == Some("BLOCK")
                                    {
                                        let reason = eval_res
                                            .get("reason")
                                            .and_then(|r| r.as_str())
                                            .unwrap_or("Blocked by cloud security policy");
                                        blocked_reasons
                                            .push(format!("[CLOUD POLICY BLOCK] {}", reason));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if !blocked_reasons.is_empty() {
                eprintln!("\n{}", "================================================================================".red().bold());
                eprintln!(
                    "{}",
                    " [FIREWALL BLOCKED] Vexa SCA prevented package installation"
                        .red()
                        .bold()
                );
                eprintln!("{}\n", "================================================================================".red().bold());
                for reason in blocked_reasons {
                    eprintln!("  {} {}", "✖".red().bold(), reason);
                }
                eprintln!("\n{} Aborting command execution before installation scripts run (Exit Code 1).\n", "PROTECTION:".yellow().bold());
                return Ok(1);
            }

            println!("{} Package pre-flight evaluation passed cleanly. Executing underlying package manager...\n", "✔".green().bold());
        }

        // Exec underlying package manager via std::process::Command with zero shell interpolation
        let status: ExitStatus = Command::new(pm)
            .args(args)
            .status()
            .map_err(|e| format!("Failed to spawn underlying package manager '{}': {}", pm, e))?;

        Ok(status.code().unwrap_or(0))
    }

    pub fn extract_packages_to_install(pm: &str, args: &[String]) -> Vec<PackageToEvaluate> {
        let mut packages = Vec::new();
        if args.is_empty() {
            return packages;
        }

        let subcmd = args[0].as_str();
        let is_install_subcmd = match pm {
            "npm" => matches!(subcmd, "install" | "i" | "add"),
            "pnpm" => matches!(subcmd, "add" | "install" | "i"),
            "yarn" => matches!(subcmd, "add"),
            "bun" => matches!(subcmd, "add" | "install" | "i"),
            "pip" => matches!(subcmd, "install"),
            "uv" => matches!(subcmd, "add" | "pip"),
            "cargo" => matches!(subcmd, "add"),
            _ => false,
        };

        if !is_install_subcmd {
            return packages;
        }

        let ecosystem = match pm {
            "npm" | "pnpm" | "yarn" | "bun" => "npm",
            "pip" | "uv" => "PyPI",
            "cargo" => "crates.io",
            _ => "npm",
        };

        let start_idx = if pm == "uv" && subcmd == "pip" && args.len() > 1 && args[1] == "install" {
            2
        } else {
            1
        };

        let mut skip_next = false;
        for arg in &args[start_idx..] {
            let trimmed = arg.trim();
            if skip_next {
                skip_next = false;
                continue;
            }
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('-') {
                if matches!(
                    trimmed,
                    "-r" | "--requirement"
                        | "-f"
                        | "--find-links"
                        | "-i"
                        | "--index-url"
                        | "-c"
                        | "--constraint"
                        | "--features"
                        | "-F"
                        | "-p"
                        | "--package"
                        | "--target"
                        | "--rename"
                        | "--prefix"
                ) {
                    skip_next = true;
                }
                continue;
            }

            // Parse pkg@ver or pkg==ver
            if pm == "pip" || pm == "uv" {
                if let Some((n, v)) = trimmed.split_once("==") {
                    packages.push(PackageToEvaluate {
                        name: n.trim().to_string(),
                        version: Some(v.trim().to_string()),
                        ecosystem: ecosystem.to_string(),
                    });
                } else if let Some((n, v)) = trimmed.split_once(">=") {
                    packages.push(PackageToEvaluate {
                        name: n.trim().to_string(),
                        version: Some(v.trim().to_string()),
                        ecosystem: ecosystem.to_string(),
                    });
                } else {
                    packages.push(PackageToEvaluate {
                        name: trimmed.to_string(),
                        version: None,
                        ecosystem: ecosystem.to_string(),
                    });
                }
            } else if pm == "cargo" {
                if let Some((n, v)) = trimmed.split_once('@') {
                    packages.push(PackageToEvaluate {
                        name: n.trim().to_string(),
                        version: Some(v.trim().to_string()),
                        ecosystem: ecosystem.to_string(),
                    });
                } else {
                    packages.push(PackageToEvaluate {
                        name: trimmed.to_string(),
                        version: None,
                        ecosystem: ecosystem.to_string(),
                    });
                }
            } else {
                // npm / pnpm / yarn / bun: scoped packages like @foo/bar@1.2.3 or bar@1.2.3
                if trimmed.starts_with('@') {
                    if let Some(second_at) = trimmed[1..].find('@') {
                        let name = &trimmed[..second_at + 1];
                        let ver = &trimmed[second_at + 2..];
                        packages.push(PackageToEvaluate {
                            name: name.to_string(),
                            version: Some(ver.to_string()),
                            ecosystem: ecosystem.to_string(),
                        });
                    } else {
                        packages.push(PackageToEvaluate {
                            name: trimmed.to_string(),
                            version: None,
                            ecosystem: ecosystem.to_string(),
                        });
                    }
                } else if let Some((n, v)) = trimmed.split_once('@') {
                    packages.push(PackageToEvaluate {
                        name: n.to_string(),
                        version: Some(v.to_string()),
                        ecosystem: ecosystem.to_string(),
                    });
                } else {
                    packages.push(PackageToEvaluate {
                        name: trimmed.to_string(),
                        version: None,
                        ecosystem: ecosystem.to_string(),
                    });
                }
            }
        }

        packages
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_packages_npm() {
        let args = vec![
            "install".to_string(),
            "lodash@4.17.21".to_string(),
            "--save-dev".to_string(),
            "axios".to_string(),
        ];
        let pkgs = FirewallWrapper::extract_packages_to_install("npm", &args);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version.as_deref(), Some("4.17.21"));
        assert_eq!(pkgs[1].name, "axios");
        assert_eq!(pkgs[1].version, None);
    }

    #[test]
    fn test_extract_packages_pip() {
        let args = vec![
            "install".to_string(),
            "requests==2.31.0".to_string(),
            "-r".to_string(),
            "req.txt".to_string(),
            "urllib3".to_string(),
        ];
        let pkgs = FirewallWrapper::extract_packages_to_install("pip", &args);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version.as_deref(), Some("2.31.0"));
        assert_eq!(pkgs[1].name, "urllib3");
        assert_eq!(pkgs[1].version, None);
    }

    #[test]
    fn test_extract_packages_cargo() {
        let args = vec![
            "add".to_string(),
            "tokio@1.35.0".to_string(),
            "--features".to_string(),
            "full".to_string(),
        ];
        let pkgs = FirewallWrapper::extract_packages_to_install("cargo", &args);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "tokio");
        assert_eq!(pkgs[0].version.as_deref(), Some("1.35.0"));
    }
}
