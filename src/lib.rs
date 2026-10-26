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
use crate::types::{ReachabilityStatus, RemediationAction, SeverityLevel, VulnerabilityFinding};

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
    /// Maximum number of source files to analyze for AST reachability (0 for unlimited).
    pub max_source_files: Option<usize>,
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
            max_source_files: None,
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
    pub all_vulnerabilities: Vec<VulnerabilityFinding>,
}

/// Helper to load baseline fingerprints from previous JSON or SARIF report per FR-016.
/// Handles UTF-8, UTF-8-BOM, and UTF-16 LE (the default encoding produced by PowerShell's
/// `>` redirect operator on Windows) so that `--baseline` works regardless of how the file
/// was generated.
pub fn load_baseline_fingerprints(baseline_path: &Path) -> std::collections::HashSet<String> {
    let mut fingerprints = std::collections::HashSet::new();

    let raw = match std::fs::read(baseline_path) {
        Ok(b) => b,
        Err(_) => return fingerprints,
    };

    // Decode: UTF-16 LE (BOM FF FE), UTF-8 BOM (EF BB BF), or plain UTF-8.
    let content: String = if raw.starts_with(&[0xFF, 0xFE]) {
        // UTF-16 LE with BOM
        let u16_pairs: Vec<u16> = raw[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&u16_pairs).to_string()
    } else if raw.starts_with(&[0xFE, 0xFF]) {
        // UTF-16 BE with BOM
        let u16_pairs: Vec<u16> = raw[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        String::from_utf16_lossy(&u16_pairs).to_string()
    } else if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
        // UTF-8 BOM — strip it
        String::from_utf8_lossy(&raw[3..]).to_string()
    } else {
        String::from_utf8_lossy(&raw).to_string()
    };

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
    fingerprints
}

pub async fn scan_project(
    project_dir: &Path,
    options: ScanOptions,
) -> Result<ProjectScanOutput, String> {
    // 1. Detect and parse manifest into DepGraph
    let detection = detect_and_parse(project_dir, options.dev)?;
    let multiple_project_scopes = detection.discovered_projects.len() > 1;

    // 2. Scan graph for vulnerabilities
    let scanner = VulnScanner::new(None);
    let mut raw_scan_result = scanner.scan_graph(&detection.graph).await?;

    // 3. Apply Policy Suppression Engine
    let policy_path = options
        .policy_file
        .or_else(|| PolicyEngine::find_policy_file(project_dir));
    let mut policy_engine = if let Some(ref p) = policy_path {
        PolicyEngine::load(p, None)
            .map_err(|e| format!("Policy configuration error in {}: {}", p.display(), e))?
    } else {
        PolicyEngine::default()
    };

    let (mut active, suppressed) =
        policy_engine.filter_vulnerabilities(&raw_scan_result.vulnerabilities, None);

    // 4. Run Reachability Analysis & Usage Signals (FR-001, FR-007a)
    let reachability_engine = if let Some(max_f) = options.max_source_files {
        ReachabilityEngine::new_with_limit(project_dir, max_f)
    } else {
        ReachabilityEngine::new(project_dir)
    };
    active = reachability_engine.evaluate_reachability(active);

    // The current graph merger does not retain enough project identity to bind an
    // imported source file to the exact lockfile scope that contributed a finding.
    // Keep the import evidence, but do not present it as a package-scoped proof.
    if multiple_project_scopes {
        for finding in &mut active {
            if let Some(reachability) = finding.reachability.as_mut() {
                if reachability.status == ReachabilityStatus::Reachable {
                    reachability.status = ReachabilityStatus::Unknown;
                    reachability.reason_code = Some(crate::types::ReasonCode::CrossFileUnresolved);
                }
            }
            if finding.reachability.as_ref().is_some_and(|r| {
                r.status == ReachabilityStatus::Unknown
                    && r.reason_code == Some(crate::types::ReasonCode::CrossFileUnresolved)
            }) {
                finding.reason_code = Some(crate::types::ReasonCode::CrossFileUnresolved);
            }
        }
    }

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

    // Preserve all active unsuppressed findings for decoupled quality gating
    let all_unsuppressed_findings = active.clone();

    // Filter to reachable only if requested.
    // IMPORTANT: track whether any findings have Unknown reachability due to
    // incomplete analysis (file limit hit, no source available, parse error,
    // dynamic construct, re-export, or unanalyzed symbols). Dropping
    // those findings while still emitting PASS would be a false-negative gate.
    let has_unknown_reachability = active.iter().any(|v| {
        v.reachability
            .as_ref()
            .map(|r| r.status == crate::types::ReachabilityStatus::Unknown)
            .unwrap_or(true)
    });

    let reachable_only_has_unanalyzed = options.reachable_only
        && (reachability_engine.file_limit_hit
            || reachability_engine.source_files.is_empty()
            || has_unknown_reachability);

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
    // reachable_only_has_unanalyzed: source was incomplete so we cannot claim
    // "nothing reachable" — that would be a false PASS.
    let scan_status = if raw_scan_result.advisory_status.has_unreliable_data()
        || reachable_only_has_unanalyzed
        || reachability_engine.file_limit_hit
        || reachability_engine.files_failed > 0
        || (multiple_project_scopes && !all_unsuppressed_findings.is_empty())
        || !detection.skipped_manifests.is_empty()
        || !detection.failed_manifests.is_empty()
    {
        crate::types::ScanStatus::Incomplete
    } else if raw_scan_result.vulnerabilities.is_empty()
        || (options.baseline_file.is_some() && raw_scan_result.new_vulnerabilities_count == 0)
    {
        crate::types::ScanStatus::Pass
    } else {
        crate::types::ScanStatus::Fail
    };
    raw_scan_result.scan_status = scan_status;

    raw_scan_result.completeness.manifests_detected = detection.discovered_projects.len().max(1);
    raw_scan_result.completeness.manifests_analysed = detection.projects.len();
    raw_scan_result.completeness.manifests_skipped =
        detection.skipped_manifests.len() + detection.failed_manifests.len();
    for (failed_path, err) in &detection.failed_manifests {
        raw_scan_result.completeness.limits_hit.push(format!(
            "MANIFEST_PARSE_FAILED ({}: {})",
            failed_path.display(),
            err
        ));
    }

    raw_scan_result.completeness.source_files_discovered = reachability_engine.files_discovered;
    raw_scan_result.completeness.source_files_analysed = reachability_engine.indexed_files.len();
    raw_scan_result.completeness.source_files_skipped = reachability_engine.files_skipped;
    raw_scan_result.completeness.source_files_failed = reachability_engine.files_failed;
    if multiple_project_scopes && !all_unsuppressed_findings.is_empty() {
        raw_scan_result
            .completeness
            .limits_hit
            .push("MONOREPO_REACHABILITY_SCOPE_UNRESOLVED".to_string());
    }
    if reachable_only_has_unanalyzed {
        raw_scan_result
            .completeness
            .limits_hit
            .push("REACHABLE_ONLY_ANALYSIS_UNKNOWN".to_string());
    }
    if reachability_engine.file_limit_hit {
        raw_scan_result.completeness.limits_hit.push(format!(
            "FILE_LIMIT_HIT (analyzed {} of {} discovered source files; {} skipped due to limit)",
            reachability_engine.source_files.len(),
            reachability_engine.files_discovered,
            reachability_engine.files_skipped
        ));
    }
    if reachability_engine.files_failed > 0 {
        raw_scan_result.completeness.limits_hit.push(format!(
            "SOURCE_DISCOVERY_OR_READ_FAILURE ({} traversal or file-read errors)",
            reachability_engine.files_failed
        ));
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
        all_vulnerabilities: all_unsuppressed_findings,
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
        let unknown_count = normal
            .scan_result
            .vulnerabilities
            .iter()
            .filter(|v| {
                v.reachability
                    .as_ref()
                    .map(|r| r.status == ReachabilityStatus::Unknown)
                    .unwrap_or(false)
            })
            .count();

        assert!(reachable_count > 0);
        assert!(unknown_count > 0);

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
    async fn test_reachable_only_does_not_turn_unknown_into_pass() {
        let fixture_dir = Path::new("test/fixtures/reachability-app");
        let filtered = scan_project(
            fixture_dir,
            ScanOptions {
                reachable_only: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // If any findings were unknown or unproven, status must never be PASS
        assert_ne!(
            filtered.scan_result.scan_status,
            crate::types::ScanStatus::Pass,
            "--reachable-only must never turn unanalyzed/unknown reachability into PASS"
        );
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
            None,
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

    #[tokio::test]
    async fn test_scan_project_monorepo_root_npm_plus_nested_pnpm() {
        let fixture_dir = Path::new("test/fixtures/monorepo-root-npm-plus-nested-pnpm");
        let output = scan_project(fixture_dir, ScanOptions::default())
            .await
            .expect("should scan monorepo");

        assert_eq!(output.manifest_type, ManifestType::NpmPackageLock);
        assert_eq!(output.scan_result.completeness.manifests_detected, 2);
        assert_eq!(output.scan_result.completeness.manifests_analysed, 2);
        assert!(output.scan_result.scanned_packages_count >= 2);

        let pkg_names: Vec<&str> = output
            .scan_result
            .vulnerabilities
            .iter()
            .map(|v| v.package.as_str())
            .collect();
        assert!(pkg_names.contains(&"lodash"), "lodash must be found");
        assert!(pkg_names.contains(&"minimist"), "minimist must be found");
    }
}
