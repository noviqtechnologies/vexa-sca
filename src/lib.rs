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

    // 4. Run Reachability Analysis
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

    // Filter to reachable only if requested
    if options.reachable_only {
        active.retain(|v| {
            v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Reachable)
                .unwrap_or(false)
        });
    }

    // 5. Filter by severity threshold
    if let Some(min_level) = options.severity_threshold {
        active.retain(|v| v.severity.level.weight() >= min_level.weight());
    }

    // 6. Filter unfixed if requested
    if options.ignore_unfixed {
        active.retain(|v| !v.fixed_in.is_empty());
    }

    // Sort: Reachable first, then by severity
    active.sort_by(|a, b| {
        let reach_a = if a
            .reachability
            .as_ref()
            .map(|r| r.status == ReachabilityStatus::Reachable)
            .unwrap_or(false)
        {
            1
        } else {
            0
        };
        let reach_b = if b
            .reachability
            .as_ref()
            .map(|r| r.status == ReachabilityStatus::Reachable)
            .unwrap_or(false)
        {
            1
        } else {
            0
        };

        if reach_b != reach_a {
            reach_b.cmp(&reach_a)
        } else {
            b.severity.level.weight().cmp(&a.severity.level.weight())
        }
    });

    raw_scan_result.vulnerabilities = active;
    raw_scan_result.vulnerabilities_count = raw_scan_result.vulnerabilities.len();
    raw_scan_result.unreachable_count = unreachable_total;

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
