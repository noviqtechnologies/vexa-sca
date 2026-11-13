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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub propagation_path: Vec<String>,
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

            let is_dev_only = dep_graph
                .nodes
                .values()
                .filter(|n| n.pkg_id == pkg.id)
                .all(|n| n.info.scope == "dev")
                && dep_graph
                    .nodes
                    .values()
                    .any(|n| n.pkg_id == pkg.id && n.info.scope == "dev");
            let scope = if is_dev_only {
                "dev".to_string()
            } else {
                "prod".to_string()
            };

            fact_pkgs.push(FactPackageItem {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                ecosystem: pkg.ecosystem.clone(),
                is_direct,
                scope,
                license: None,
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

            let fixed_in = if f.fixed_in.is_empty() {
                None
            } else if let Some(cur) = crate::core::semver_utils::clean_or_coerce_version(&f.version)
            {
                let mut valid_upgrades: Vec<String> = f
                    .fixed_in
                    .iter()
                    .filter(|fix| {
                        crate::core::semver_utils::clean_or_coerce_version(fix)
                            .map(|v| v > cur)
                            .unwrap_or(false)
                    })
                    .cloned()
                    .collect();
                valid_upgrades.sort_by(|a, b| {
                    let va = crate::core::semver_utils::clean_or_coerce_version(a);
                    let vb = crate::core::semver_utils::clean_or_coerce_version(b);
                    match (va, vb) {
                        (Some(x), Some(y)) => x.cmp(&y),
                        _ => a.cmp(b),
                    }
                });
                let same_major = valid_upgrades.iter().find(|fix| {
                    crate::core::semver_utils::clean_or_coerce_version(fix)
                        .map(|v| v.major == cur.major)
                        .unwrap_or(false)
                });
                same_major
                    .cloned()
                    .or_else(|| valid_upgrades.first().cloned())
                    .or_else(|| f.fixed_in.last().cloned())
            } else {
                f.fixed_in.last().cloned()
            };

            let epss = f.epss.as_ref().and_then(|e| {
                if e.source != crate::types::EpssSource::Unavailable {
                    Some(e.score)
                } else {
                    None
                }
            });

            let call_site = f.reachability.as_ref().and_then(|r| {
                r.call_sites
                    .first()
                    .map(|cs| format!("{}:{} ({})", cs.file, cs.line, cs.matched_function))
            });

            let cwe = f
                .cwe_ids
                .first()
                .cloned()
                .or_else(|| f.cwes.first().cloned());

            let cvss_score = if f.severity.score > 0.0 {
                Some(f.severity.score)
            } else {
                None
            };

            let scope = Some(if f.is_transitive {
                "transitive".to_string()
            } else {
                "direct".to_string()
            });

            let propagation_path = f.paths.first().cloned().unwrap_or_default();

            fact_findings.push(FactFindingItem {
                id: f.id.clone(),
                package_name: f.package.clone(),
                package_version: f.version.clone(),
                severity: f.severity.level.as_str().to_string(),
                reachability: reach_str,
                title: f.title.clone(),
                is_kev: f.is_kev,
                fixed_in,
                epss,
                call_site,
                cwe,
                cvss_score,
                scope,
                propagation_path,
            });
        }

        let mut code_findings = Vec::new();
        let mut sast_count = 0usize;
        let mut secret_count = 0usize;
        let mut sc_count = 0usize;

        for cf in &result.code_findings {
            if cf.category == "SECRET" {
                secret_count += 1;
            } else if cf.category == "SUPPLY_CHAIN" {
                sc_count += 1;
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

        for sc in &result.supply_chain_findings {
            let sc_rel_path = sc
                .file_path
                .as_deref()
                .map(|p| {
                    crate::scanner::sast::normalize_workspace_relative_path(
                        Path::new(""),
                        Path::new(p),
                    )
                })
                .unwrap_or_else(|| "package.json".to_string());
            let sc_line = sc.line.unwrap_or(1);

            // Avoid sending duplicate findings if code_findings already contains a finding on this file and line
            if code_findings
                .iter()
                .any(|cf| cf.file_path == sc_rel_path && cf.line == sc_line)
            {
                continue;
            }

            sc_count += 1;
            let cwe = match sc.rule_id.as_str() {
                "SC-014" => Some("CWE-829".to_string()),
                "SC-007" => Some("CWE-200".to_string()),
                "SC-003" => Some("CWE-94".to_string()),
                "SC-004" => Some("CWE-78".to_string()),
                "SC-008" => Some("CWE-1036".to_string()),
                "SC-013" => Some("CWE-78".to_string()),
                _ => None,
            };

            let remediation = match sc.rule_id.as_str() {
                "SC-014" => Some(
                    "Pin GitHub Action to an immutable 40-character commit SHA (e.g. uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1) to prevent supply chain tampering."
                        .to_string(),
                ),
                "SC-007" => Some(
                    "Avoid direct access to host filesystem credentials or sensitive configuration files (/etc/passwd, .ssh, .aws)."
                        .to_string(),
                ),
                _ => Some(format!("Review supply chain signal '{}'", sc.signal_name)),
            };

            code_findings.push(FactCodeFindingItem {
                rule_id: sc.rule_id.clone(),
                category: "SUPPLY_CHAIN".to_string(),
                severity: sc.severity.as_str().to_string(),
                title: sc.message.clone(),
                cwe,
                file_path: sc_rel_path,
                line: sc_line,
                matched_sink: sc
                    .snippet
                    .as_deref()
                    .map(crate::scanner::sast::sanitize_sink_signature),
                remediation,
            });
        }

        let mut components = vec![FactComponentItem {
            id: "vexa-sca-engine".to_string(),
            name: "Vexa Dependency & Reachability Engine".to_string(),
            status: "COMPLETED".to_string(),
            findings_count: fact_findings.len(),
        }];
        if sast_count > 0 {
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
        if sc_count > 0 {
            components.push(FactComponentItem {
                id: "vexa-supply-chain-engine".to_string(),
                name: "Vexa Supply Chain Heuristics Engine".to_string(),
                status: "COMPLETED".to_string(),
                findings_count: sc_count,
            });
        }

        let project_name = Self::resolve_project_name(dep_graph);

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

    /// Resolve effective project name, prioritizing VEXA_PROJECT, then GITHUB_REPOSITORY
    /// when the root package is generic or an upstream Go/Git module path (e.g. forks).
    pub fn resolve_project_name(dep_graph: &DepGraph) -> String {
        Self::resolve_project_name_from_env(
            dep_graph,
            std::env::var("VEXA_PROJECT").ok().as_deref(),
            std::env::var("GITHUB_REPOSITORY").ok().as_deref(),
        )
    }

    /// Pure resolver for project name given dependency graph and optional environment overrides
    pub fn resolve_project_name_from_env(
        dep_graph: &DepGraph,
        env_project: Option<&str>,
        env_github_repo: Option<&str>,
    ) -> String {
        if let Some(proj) = env_project.map(|s| s.trim()) {
            if !proj.is_empty() {
                return proj.to_string();
            }
        }

        let pkg_name = dep_graph.root_pkg.name.trim();

        // In GitHub Actions, prefer GITHUB_REPOSITORY if root_pkg is generic or an upstream Go/Git path
        if let Some(gh_repo) = env_github_repo.map(|s| s.trim()) {
            if !gh_repo.is_empty()
                && (pkg_name.is_empty()
                    || pkg_name == "root"
                    || pkg_name == "workspace"
                    || pkg_name == "project"
                    || pkg_name.starts_with("github.com/")
                    || pkg_name.starts_with("gitlab.com/")
                    || pkg_name.starts_with("bitbucket.org/")
                    || pkg_name.starts_with("gopkg.in/"))
            {
                return gh_repo.to_string();
            }
        }

        if !pkg_name.is_empty() {
            pkg_name.to_string()
        } else {
            "workspace".to_string()
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

        // Log the resolved endpoint (stderr) so a wrong-environment upload is obvious.
        eprintln!("Uploading scan facts to {}", base_url);

        let resp =
            req.json(payload).send().await.map_err(|e| {
                format!("Failed to connect to Vexa SCA Cloud ({}): {}", sync_url, e)
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let hint = if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                format!(
                    " Hint: token was rejected by {}. If this key was issued for a different \
                     environment (dev/staging/prod), set VEXA_API_URL or the action's `api-url` \
                     input accordingly.",
                    base_url
                )
            } else {
                String::new()
            };
            return Err(format!(
                "Cloud upload failed with status {}: {}{}",
                status, body, hint
            ));
        }

        let sync_result: SyncResult = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse sync response: {}", e))?;

        Ok(sync_result)
    }
}
