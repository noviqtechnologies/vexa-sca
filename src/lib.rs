pub mod cli;
pub mod container;
pub mod core;
pub mod licenses;
pub mod parsers;
pub mod patcher;
pub mod policy;
pub mod reachability;
pub mod reporters;
pub mod scanner;
pub mod types;

use std::path::{Path, PathBuf};

use crate::core::dep_graph::DepGraph;
use crate::licenses::license_scanner::{LicenseAudit, LicenseScanner};
use crate::parsers::detector::{detect_and_parse, ManifestType};
use crate::policy::policy_engine::{PolicyEngine, SuppressedFinding};
use crate::reachability::reachability_engine::ReachabilityEngine;
use crate::scanner::remediator::Remediator;
use crate::scanner::vuln_scanner::{ScanResult, VulnScanner};
use crate::types::{ReachabilityStatus, RemediationAction, SeverityLevel};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub dev: bool,
    pub reachable_only: bool,
    pub severity_threshold: Option<SeverityLevel>,
    pub ignore_unfixed: bool,
    pub policy_file: Option<PathBuf>,
    pub timeout_secs: u64,
    pub licenses: bool,
    /// When true, do not fail the scan when the OSV advisory service is unavailable.
    /// Equivalent to passing `--allow-unavailable` on the CLI.
    pub allow_unavailable: bool,
    /// Path to baseline report file for PR-diff comparison per PRD v2.2 FR-016.
    pub baseline_file: Option<PathBuf>,
    /// When true, enforce CI automation profile semantics per PRD v2.2 FR-010a.
    pub is_ci_profile: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            dev: true,
            reachable_only: false,
            severity_threshold: None,
            ignore_unfixed: false,
            policy_file: None,
            timeout_secs: 15,
            licenses: true,
            allow_unavailable: false,
            baseline_file: None,
            is_ci_profile: false,
        }
    }
}

pub struct ProjectScanOutput {
    pub manifest_file: PathBuf,
    pub manifest_type: ManifestType,
    pub dep_graph: DepGraph,
    pub scan_result: ScanResult,
    pub suppressed: Vec<SuppressedFinding>,
    pub remediations: Vec<RemediationAction>,
    pub license_audit: Option<LicenseAudit>,
    pub policy_file: Option<PathBuf>,
    pub discovered_projects: Vec<PathBuf>,
}

/// Helper to load baseline fingerprints from previous JSON or SARIF report per FR-016.
pub fn load_baseline_fingerprints(baseline_path: &Path) -> std::collections::HashSet<String> {
    let mut fingerprints = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string(baseline_path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(vulns) = val.get("vulnerabilities").and_then(|v| v.as_array()) {
                for v in vulns {
                    if let Some(fp) = v.get("fingerprint").and_then(|f| f.as_str()) {
                        fingerprints.insert(fp.to_string());
                    } else if let Some(id) = v.get("id").and_then(|i| i.as_str()) {
                        fingerprints.insert(id.to_string());
                    }
                }
            }
            if let Some(runs) = val.get("runs").and_then(|r| r.as_array()) {
                for run in runs {
                    if let Some(results) = run.get("results").and_then(|res| res.as_array()) {
                        for res in results {
                            if let Some(fp) = res
                                .get("partialFingerprints")
                                .and_then(|p| p.get("vexaFindingFingerprint/v1"))
                                .and_then(|f| f.as_str())
                            {
                                fingerprints.insert(fp.to_string());
                            } else if let Some(rid) = res.get("ruleId").and_then(|r| r.as_str()) {
                                fingerprints.insert(rid.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    fingerprints
}

pub async fn scan_project(
    project_dir: &Path,
    options: ScanOptions,
) -> Result<ProjectScanOutput, String> {
    // 1. Detect and parse manifest into DepGraph
    let detection = detect_and_parse(project_dir, options.dev)?;

    // 2. Scan graph for vulnerabilities
    let scanner = VulnScanner::new(None);
    let mut raw_scan_result = scanner.scan_graph(&detection.graph).await?;

    // 3. Apply Policy Suppression Engine
    let policy_path = options
        .policy_file
        .or_else(|| PolicyEngine::find_policy_file(project_dir));
    let policy_engine = PolicyEngine::new(policy_path.as_deref());

    let (mut active, suppressed) =
        policy_engine.filter_vulnerabilities(&raw_scan_result.vulnerabilities, None);

    // 4. Run Reachability Analysis & Usage Signals (FR-001, FR-007a)
    let reachability_engine = ReachabilityEngine::new(project_dir);
    active = reachability_engine.evaluate_reachability(active);

    let unreachable_total = active
        .iter()
        .filter(|v| {
            v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Unreachable)
                .unwrap_or(false)
        })
        .count();

    // 5. Evaluate PR-Diff baseline if provided (FR-016)
    if let Some(base_path) = &options.baseline_file {
        let baseline_fps = load_baseline_fingerprints(base_path);
        for v in &mut active {
            v.is_new = !baseline_fps.contains(&v.fingerprint) && !baseline_fps.contains(&v.id);
            v.priority_score = v.compute_priority_score();
        }
        let new_count = active.iter().filter(|v| v.is_new).count();
        let baseline_count = active.iter().filter(|v| !v.is_new).count();
        raw_scan_result.new_vulnerabilities_count = new_count;
        raw_scan_result.baseline_vulnerabilities_count = baseline_count;
    } else {
        let count = active.len();
        raw_scan_result.new_vulnerabilities_count = count;
        raw_scan_result.baseline_vulnerabilities_count = 0;
    }

    // Filter to reachable only if requested
    if options.reachable_only {
        active.retain(|v| {
            v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Reachable)
                .unwrap_or(false)
        });
    }

    // Filter by severity threshold
    if let Some(min_level) = options.severity_threshold {
        active.retain(|v| v.severity.level.weight() >= min_level.weight());
    }

    // Filter unfixed if requested
    if options.ignore_unfixed {
        active.retain(|v| !v.fixed_in.is_empty());
    }

    // Sort by priority score first (FR-007, FR-008a)
    active.sort_by(|a, b| {
        b.priority_score
            .partial_cmp(&a.priority_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    raw_scan_result.vulnerabilities = active;
    raw_scan_result.vulnerabilities_count = raw_scan_result.vulnerabilities.len();
    raw_scan_result.unreachable_count = unreachable_total;

    // Determine ScanStatus (FR-005, FR-010a)
    let scan_status = if raw_scan_result.advisory_status.has_unreliable_data() {
        crate::types::ScanStatus::Incomplete
    } else if raw_scan_result.vulnerabilities.is_empty()
        || (options.baseline_file.is_some() && raw_scan_result.new_vulnerabilities_count == 0)
    {
        crate::types::ScanStatus::Pass
    } else {
        crate::types::ScanStatus::Fail
    };
    raw_scan_result.scan_status = scan_status;

    raw_scan_result.completeness.source_files_discovered = reachability_engine.source_files.len();
    raw_scan_result.completeness.source_files_analysed = reachability_engine.source_files.len();
    if reachability_engine.file_limit_hit {
        raw_scan_result
            .completeness
            .limits_hit
            .push("FILE_LIMIT_HIT".to_string());
    }

    // 6. Generate remediations
    let remediations = Remediator::generate_remediation(&raw_scan_result.vulnerabilities);

    // 7. License audit
    let license_audit = if options.licenses {
        Some(LicenseScanner::scan_graph_licenses(
            &detection.graph,
            project_dir,
        ))
    } else {
        None
    };

    Ok(ProjectScanOutput {
        manifest_file: detection.manifest_file,
        manifest_type: detection.manifest_type,
        dep_graph: detection.graph,
        scan_result: raw_scan_result,
        suppressed,
        remediations,
        license_audit,
        policy_file: policy_path,
        discovered_projects: detection.discovered_projects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_scan_project_e2e_npm_app() {
        let fixture_dir = Path::new("test/fixtures/npm-app");
        let output = scan_project(fixture_dir, ScanOptions::default())
            .await
            .expect("should scan npm-app");

        assert!(output.scan_result.scanned_packages_count >= 2);
        assert!(output.scan_result.vulnerabilities_count > 0);

        let lodash_vulns: Vec<_> = output
            .scan_result
            .vulnerabilities
            .iter()
            .filter(|v| v.package == "lodash")
            .collect();
        assert!(!lodash_vulns.is_empty());

        let lodash_rem = output.remediations.iter().find(|r| r.package == "lodash");
        assert!(lodash_rem.is_some());
        let rem = lodash_rem.unwrap();
        assert!(rem.target_version.is_some());
        assert_eq!(rem.action_type, "UPGRADE_DIRECT");
    }

    #[tokio::test]
    async fn test_scan_project_reachability_filter() {
        let fixture_dir = Path::new("test/fixtures/reachability-app");

        let normal = scan_project(fixture_dir, ScanOptions::default())
            .await
            .unwrap();
        let reachable_count = normal
            .scan_result
            .vulnerabilities
            .iter()
            .filter(|v| {
                v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Reachable)
                    .unwrap_or(false)
            })
            .count();
        let unreachable_count = normal
            .scan_result
            .vulnerabilities
            .iter()
            .filter(|v| {
                v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Unreachable)
                    .unwrap_or(false)
            })
            .count();

        assert!(reachable_count > 0);
        assert!(unreachable_count > 0);

        let filtered = scan_project(
            fixture_dir,
            ScanOptions {
                reachable_only: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(!filtered.scan_result.vulnerabilities.is_empty());
        assert!(filtered.scan_result.vulnerabilities.iter().all(|v| v
            .reachability
            .as_ref()
            .map(|r| r.status == ReachabilityStatus::Reachable)
            .unwrap_or(false)));
    }

    #[tokio::test]
    async fn test_scan_project_e2e_pnpm_app() {
        let fixture_dir = Path::new("test/fixtures/pnpm-app");
        let output = scan_project(fixture_dir, ScanOptions::default())
            .await
            .expect("should scan pnpm-app");

        assert_eq!(output.manifest_type, ManifestType::PnpmLock);
        assert_eq!(output.scan_result.scanned_packages_count, 2);
        assert!(output.scan_result.vulnerabilities_count > 0);

        let lodash_vulns: Vec<_> = output
            .scan_result
            .vulnerabilities
            .iter()
            .filter(|v| v.package == "lodash")
            .collect();
        assert!(!lodash_vulns.is_empty());
    }

    #[tokio::test]
    async fn test_scan_project_sarif_export() {
        let fixture_dir = Path::new("test/fixtures/npm-app");
        let output = scan_project(fixture_dir, ScanOptions::default())
            .await
            .expect("should scan npm-app");

        let sarif_json = crate::reporters::export::format_sarif_report(
            &output.scan_result,
            &output.remediations,
            Some(&output.manifest_file),
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&sarif_json).expect("valid SARIF JSON");
        assert_eq!(parsed["version"], "2.1.0");
        assert_eq!(parsed["runs"][0]["tool"]["driver"]["name"], "vexa-sca");
        assert!(!parsed["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_scan_project_html_dashboard() {
        let fixture_dir = Path::new("test/fixtures/npm-app");
        let output = scan_project(fixture_dir, ScanOptions::default())
            .await
            .unwrap();

        let html = crate::reporters::export::format_html_report(
            &output.scan_result,
            &output.suppressed,
            &output.remediations,
            output.license_audit.as_ref(),
            "sample-npm-app",
            Some(&output.manifest_file),
        );

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Vexa SCA Security Report"));
        assert!(html.contains("sample-npm-app"));
        assert!(html.contains("lodash"));
    }

    #[tokio::test]
    async fn test_scan_project_cyclonedx_sbom() {
        let fixture_dir = Path::new("test/fixtures/npm-app");
        let output = scan_project(fixture_dir, ScanOptions::default())
            .await
            .unwrap();

        let cdx_json = crate::reporters::export::format_cyclonedx_sbom(
            &output.dep_graph,
            Some(&output.scan_result),
            output.license_audit.as_ref(),
        );

        let parsed: serde_json::Value = serde_json::from_str(&cdx_json).unwrap();
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");
        assert!(parsed["components"].as_array().unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn test_scan_container_rootfs_fixture() {
        let fixture_dir = Path::new("test/fixtures/alpine-rootfs");
        let output =
            crate::container::container_scanner::ContainerScanner::scan_target(fixture_dir)
                .await
                .expect("should scan container rootfs");

        assert_eq!(output.os_info.id, "alpine");
        assert_eq!(output.packages.len(), 3);
        assert_eq!(output.packages[0].name, "musl");
        assert_eq!(output.packages[1].name, "busybox");
        assert_eq!(output.packages[2].name, "curl");
    }
}
