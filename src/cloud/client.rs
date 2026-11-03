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

        VexaFactsPayload {
            version: 1,
            timestamp: chrono::Utc::now().to_rfc3339(),
            project_name: dep_graph.root_pkg.name.clone(),
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
            .unwrap_or_default();

        let org_slug = std::env::var("VEXA_ORG")
            .or_else(|_| std::env::var("VEXA_ORG_SLUG"))
            .ok()
            .or_else(|| AuthManager::load_stored_credentials().and_then(|c| c.org_slug))
            .unwrap_or_else(|| "vexadev".to_string());

        let resp = client
            .post(&sync_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("X-Vexa-Org", org_slug)
            .json(payload)
            .send()
            .await
            .map_err(|e| format!("Failed to connect to Vexa SCA Cloud ({}): {}", sync_url, e))?;

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
