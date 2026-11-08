#![forbid(unsafe_code)]

use crate::cloud::auth::AuthManager;
use crate::core::dep_graph::DepGraph;
use crate::scanner::vuln_scanner::ScanResult;
use crate::types::ReachabilityStatus;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexaFactsPayload {
    pub version: u32,
    pub timestamp: String,
    pub project_name: String,
    pub project_version: String,
    pub ecosystem: String,
    pub total_packages: usize,
    pub direct_dependencies: usize,
    pub transitive_dependencies: usize,
    pub packages: Vec<FactPackageItem>,
    pub reachable_vulnerabilities: usize,
    pub unreachable_vulnerabilities: usize,
    pub total_vulnerabilities: usize,
    pub findings: Vec<FactFindingItem>,
    #[serde(default)]
    pub code_findings: Vec<FactCodeFindingItem>,
    #[serde(default)]
    pub components: Vec<FactComponentItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactCodeFindingItem {
    pub rule_id: String,
    pub category: String,
    pub severity: String,
    pub title: String,
    #[serde(default)]
    pub cwe: Option<String>,
    pub file_path: String,
    pub line: usize,
    #[serde(default)]
    pub matched_sink: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactComponentItem {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub findings_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactPackageItem {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub is_direct: bool,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactFindingItem {
    pub id: String,
    pub package_name: String,
    pub package_version: String,
    pub severity: String,
    pub reachability: String,
    pub title: String,
    pub is_kev: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub scan_id: String,
    pub org_slug: String,
    pub project_slug: String,
    pub dashboard_url: String,
    pub status: String,
}

pub struct CloudClient;

impl CloudClient {
    /// Extract zero-code facts payload from a ScanResult and DepGraph (.vexa.facts.json specification)
    pub fn extract_facts(dep_graph: &DepGraph, result: &ScanResult) -> VexaFactsPayload {
        let pkgs = dep_graph.get_all_pkgs();
        let total_pkgs = pkgs.len();

        let root_deps = dep_graph
            .nodes
            .get(&dep_graph.root_node_id)
            .map(|n| n.deps.as_slice())
            .unwrap_or(&[]);

        let mut direct_count = 0;
        let mut fact_pkgs = Vec::new();

        for pkg in &pkgs {
            let is_root = pkg.name == dep_graph.root_pkg.name;
            if is_root {
                continue;
            }
            // Check if direct dependency of root
            let is_direct = root_deps.iter().any(|d| {
                if let Some(n) = dep_graph.nodes.get(d) {
                    n.pkg_id == pkg.id
                } else {
                    false
                }
            });

            if is_direct {
                direct_count += 1;
            }

            fact_pkgs.push(FactPackageItem {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                ecosystem: pkg.ecosystem.clone(),
                is_direct,
                scope: "prod".to_string(),
            });
        }

        let transitive_count = total_pkgs.saturating_sub(direct_count);

        let mut reachable_count = 0;
        let mut unreachable_count = 0;
        let mut fact_findings = Vec::new();

        for f in &result.vulnerabilities {
            let (reach_status, reach_str) = match &f.reachability {
                Some(r) => (r.status, r.status.as_str().to_string()),
                None => (ReachabilityStatus::Unknown, "UNKNOWN".to_string()),
            };

            if reach_status == ReachabilityStatus::Reachable {
                reachable_count += 1;
            } else if reach_status == ReachabilityStatus::Unreachable {
                unreachable_count += 1;
            }

            fact_findings.push(FactFindingItem {
                id: f.id.clone(),
                package_name: f.package.clone(),
                package_version: f.version.clone(),
                severity: f.severity.level.as_str().to_string(),
                reachability: reach_str,
                title: f.title.clone(),
                is_kev: f.is_kev,
            });
        }

        let mut code_findings = Vec::new();
        let mut sast_count = 0usize;
        let mut secret_count = 0usize;

        for cf in &result.code_findings {
            if cf.category == "SECRET" {
                secret_count += 1;
            } else {
                sast_count += 1;
            }
            code_findings.push(FactCodeFindingItem {
                rule_id: cf.rule_id.clone(),
                category: cf.category.clone(),
                severity: cf.severity.clone(),
                title: cf.title.clone(),
                cwe: cf.cwe.clone(),
                file_path: crate::scanner::sast::normalize_workspace_relative_path(
                    Path::new(""),
                    Path::new(&cf.file_path),
                ),
                line: cf.line,
                matched_sink: cf
                    .matched_sink
                    .as_deref()
                    .map(crate::scanner::sast::sanitize_sink_signature),
                remediation: cf.remediation.clone(),
            });
        }

        let mut components = vec![FactComponentItem {
            id: "vexa-sca-engine".to_string(),
            name: "Vexa Dependency & Reachability Engine".to_string(),
            status: "COMPLETED".to_string(),
            findings_count: fact_findings.len(),
        }];
        if sast_count > 0 || !result.code_findings.is_empty() {
            components.push(FactComponentItem {
                id: "vexa-sast-engine".to_string(),
                name: "Vexa Multi-Language SAST Engine".to_string(),
                status: "COMPLETED".to_string(),
                findings_count: sast_count,
            });
        }
        if secret_count > 0 {
            components.push(FactComponentItem {
                id: "vexa-secrets-engine".to_string(),
                name: "Vexa Zero-Leak Secret Scanner".to_string(),
                status: "COMPLETED".to_string(),
                findings_count: secret_count,
            });
        }

        let project_name = if !dep_graph.root_pkg.name.trim().is_empty() {
            dep_graph.root_pkg.name.clone()
        } else if let Ok(repo) = std::env::var("GITHUB_REPOSITORY") {
            if !repo.trim().is_empty() {
                repo
            } else {
                "workspace".to_string()
            }
        } else {
            "workspace".to_string()
        };

        VexaFactsPayload {
            version: 2,
            timestamp: chrono::Utc::now().to_rfc3339(),
            project_name,
            project_version: dep_graph.root_pkg.version.clone(),
            ecosystem: dep_graph.pkg_manager.name.clone(),
            total_packages: total_pkgs,
            direct_dependencies: direct_count,
            transitive_dependencies: transitive_count,
            packages: fact_pkgs,
            reachable_vulnerabilities: reachable_count,
            unreachable_vulnerabilities: unreachable_count,
            total_vulnerabilities: result.vulnerabilities.len(),
            findings: fact_findings,
            code_findings,
            components,
        }
    }

    /// Save `.vexa.facts.json` file in project directory (zero code retention schema)
    pub fn save_facts_file(
        project_dir: &Path,
        payload: &VexaFactsPayload,
    ) -> Result<std::path::PathBuf, String> {
        let facts_path = project_dir.join(".vexa.facts.json");
        let json = serde_json::to_string_pretty(payload)
            .map_err(|e| format!("Failed to serialize .vexa.facts.json: {}", e))?;
        std::fs::write(&facts_path, json)
            .map_err(|e| format!("Failed to write .vexa.facts.json: {}", e))?;
        Ok(facts_path)
    }

    /// Upload `.vexa.facts.json` to Vexa SCA Cloud API
    pub async fn upload_facts(
        payload: &VexaFactsPayload,
        api_base_url: Option<&str>,
    ) -> Result<SyncResult, String> {
        let token = AuthManager::get_token().ok_or_else(|| {
            "Authentication required to upload scan facts. Run 'vexa-sca auth login' first or set VEXA_TOKEN.".to_string()
        })?;

        let base_url = crate::cloud::auth::AuthManager::resolve_api_base_url(api_base_url);
        let sync_url = format!("{}/facts/sync", base_url);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to initialize HTTPS client for cloud upload: {}", e))?;

        let org_slug = std::env::var("VEXA_ORG")
            .or_else(|_| std::env::var("VEXA_ORG_SLUG"))
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| AuthManager::load_stored_credentials().and_then(|c| c.org_slug));

        let mut req = client
            .post(&sync_url)
            .header("Authorization", format!("Bearer {}", token));

        if let Some(ref org) = org_slug {
            req = req.header("X-Vexa-Org", org);
        }

        let resp =
            req.json(payload).send().await.map_err(|e| {
                format!("Failed to connect to Vexa SCA Cloud ({}): {}", sync_url, e)
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!(
                "Cloud upload failed with status {}: {}",
                status, body
            ));
        }

        let sync_result: SyncResult = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse sync response: {}", e))?;

        Ok(sync_result)
    }
}
