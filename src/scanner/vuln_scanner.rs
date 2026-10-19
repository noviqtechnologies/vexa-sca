use crate::core::dep_graph::DepGraph;
use crate::core::semver_utils::extract_fixed_versions;
use crate::scanner::cache::VulnCache;
use crate::types::{PkgInfo, SeverityInfo, SeverityLevel, VulnerabilityFinding};
use reqwest::Client;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub scanned_packages_count: usize,
    pub vulnerabilities_count: usize,
    pub has_cycles: bool,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
}

pub struct VulnScanner {
    pub cache: VulnCache,
    pub batch_api_url: String,
    pub vuln_api_url: String,
    pub client: Client,
}

impl Default for VulnScanner {
    fn default() -> Self {
        Self::new(None)
    }
}

impl VulnScanner {
    pub fn new(cache: Option<VulnCache>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            cache: cache.unwrap_or_default(),
            batch_api_url: "https://api.osv.dev/v1/querybatch".to_string(),
            vuln_api_url: "https://api.osv.dev/v1/vulns".to_string(),
            client,
        }
    }

    pub async fn scan_graph(&self, dep_graph: &DepGraph) -> Result<ScanResult, String> {
        let pkgs = dep_graph.get_all_pkgs();
        let mut uncached: Vec<PkgInfo> = Vec::new();
        let mut results_map: HashMap<String, Vec<Value>> = HashMap::new();

        // 1. Check cache
        for pkg in &pkgs {
            if let Some(cached) = self.cache.get(pkg) {
                results_map.insert(pkg.id.clone(), cached);
            } else {
                uncached.push(pkg.clone());
            }
        }

        // 2. Query batch for uncached packages
        if !uncached.is_empty() {
            let fetched = self.fetch_batch(&uncached).await;
            for (pkg, raw_vulns) in uncached.iter().zip(fetched) {
                self.cache.set(pkg, &raw_vulns);
                results_map.insert(pkg.id.clone(), raw_vulns);
            }
        }

        // 3. Collect unique vuln IDs to fetch full advisory records
        let mut unique_vuln_ids = HashSet::new();
        for pkg in &pkgs {
            if let Some(raw_list) = results_map.get(&pkg.id) {
                for item in raw_list {
                    if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                        unique_vuln_ids.insert(id.to_string());
                    }
                }
            }
        }

        let full_advisories = self.fetch_advisories(unique_vuln_ids.into_iter().collect()).await;

        // 4. Construct enriched vulnerability findings
        let mut vulnerabilities = Vec::new();

        for pkg in &pkgs {
            let raw_list = match results_map.get(&pkg.id) {
                Some(l) => l,
                None => continue,
            };
            let paths_to_root = dep_graph.pkg_paths_to_root(&pkg.id, 10);
            let is_transitive = dep_graph.is_transitive(&pkg.id);

            for item in raw_list {
                let id = match item.get("id").and_then(|v| v.as_str()) {
                    Some(id) => id,
                    None => continue,
                };
                let adv = match full_advisories.get(id) {
                    Some(a) => a,
                    None => continue,
                };

                let severity = self.determine_severity(adv);
                let cve = adv
                    .get("aliases")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| {
                        arr.iter()
                            .filter_map(|a| a.as_str())
                            .find(|s| s.starts_with("CVE-"))
                            .map(|s| s.to_string())
                    });

                let cwes = self.extract_cwes(adv);
                let fixed_in = extract_fixed_versions(adv);

                let title = adv
                    .get("summary")
                    .and_then(|s| s.as_str())
                    .or_else(|| {
                        adv.get("details")
                            .and_then(|d| d.as_str())
                            .map(|s| &s[..s.len().min(100)])
                    })
                    .unwrap_or("Known Vulnerability")
                    .to_string();

                let references: Vec<String> = adv
                    .get("references")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|r| r.get("url").and_then(|u| u.as_str()))
                            .filter(|u| !crate::scanner::cache::has_blocked_vendor(u))
                            .take(3)
                            .map(|s| s.to_string())
                            .collect()
                    })
                    .unwrap_or_default();

                let paths_strings: Vec<Vec<String>> = paths_to_root
                    .iter()
                    .map(|p| p.iter().map(|node| format!("{}@{}", node.name, node.version)).collect())
                    .collect();

                vulnerabilities.push(VulnerabilityFinding {
                    id: id.to_string(),
                    title,
                    package: pkg.name.clone(),
                    version: pkg.version.clone(),
                    ecosystem: pkg.ecosystem.clone(),
                    pkg_id: pkg.id.clone(),
                    severity,
                    cve,
                    cwes,
                    fixed_in,
                    is_transitive,
                    paths: paths_strings,
                    details: adv.get("details").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    references,
                    reachability: None,
                });
            }
        }

        // Sort by severity (Critical -> High -> Medium -> Low)
        vulnerabilities.sort_by_key(|b| std::cmp::Reverse(b.severity.level.weight()));

        Ok(ScanResult {
            scanned_packages_count: pkgs.len(),
            vulnerabilities_count: vulnerabilities.len(),
            has_cycles: dep_graph.has_cycles(),
            vulnerabilities,
        })
    }

    async fn fetch_batch(&self, pkgs: &[PkgInfo]) -> Vec<Vec<Value>> {
        let queries: Vec<Value> = pkgs
            .iter()
            .map(|p| {
                serde_json::json!({
                    "package": {
                        "name": p.name,
                        "ecosystem": p.ecosystem,
                    },
                    "version": p.version,
                })
            })
            .collect();

        let body = serde_json::json!({ "queries": queries });

        match self
            .client
            .post(&self.batch_api_url)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(data) = resp.json::<Value>().await {
                    if let Some(results) = data.get("results").and_then(|r| r.as_array()) {
                        return results
                            .iter()
                            .map(|r| r.get("vulns").and_then(|v| v.as_array()).cloned().unwrap_or_default())
                            .collect();
                    }
                }
                vec![Vec::new(); pkgs.len()]
            }
            _ => vec![Vec::new(); pkgs.len()],
        }
    }

    async fn fetch_advisories(&self, vuln_ids: Vec<String>) -> HashMap<String, Value> {
        let mut map = HashMap::new();
        let mut to_fetch = Vec::new();

        for id in vuln_ids {
            if let Some(cached) = self.cache.get_advisory(&id) {
                map.insert(id, cached);
            } else {
                to_fetch.push(id);
            }
        }

        for chunk in to_fetch.chunks(10) {
            let mut set = tokio::task::JoinSet::new();
            for id in chunk {
                let id = id.clone();
                let client = self.client.clone();
                let url = format!("{}/{}", self.vuln_api_url, id);
                set.spawn(async move {
                    if let Ok(resp) = client.get(&url).send().await {
                        if resp.status().is_success() {
                            if let Ok(data) = resp.json::<Value>().await {
                                return Some((id, data));
                            }
                        }
                    }
                    None
                });
            }

            while let Some(res) = set.join_next().await {
                if let Ok(Some((id, data))) = res {
                    self.cache.set_advisory(&id, &data);
                    map.insert(id, data);
                }
            }
        }

        map
    }

    fn determine_severity(&self, adv: &Value) -> SeverityInfo {
        let mut score = None;
        let mut vector = None;

        if let Some(sev_arr) = adv.get("severity").and_then(|v| v.as_array()) {
            for s in sev_arr {
                let stype = s.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if stype == "CVSS_V3" || stype == "CVSS_V4" {
                    if let Some(sc) = s.get("score").and_then(|sc| sc.as_str()) {
                        vector = Some(sc.to_string());
                        score = self.estimate_score_from_cvss(sc);
                        break;
                    }
                }
            }
        }

        let db_sev = adv
            .get("database_specific")
            .and_then(|d| d.get("severity"))
            .and_then(|s| s.as_str());

        let mut level = SeverityLevel::Unknown;
        if let Some(s) = db_sev {
            level = SeverityLevel::from_str_loose(s);
        }

        if level == SeverityLevel::Unknown {
            if let Some(sc) = score {
                if sc >= 9.0 {
                    level = SeverityLevel::Critical;
                } else if sc >= 7.0 {
                    level = SeverityLevel::High;
                } else if sc >= 4.0 {
                    level = SeverityLevel::Medium;
                } else {
                    level = SeverityLevel::Low;
                }
            }
        }

        if level == SeverityLevel::Unknown {
            level = SeverityLevel::Medium;
        }

        let final_score = score.unwrap_or(match level {
            SeverityLevel::Critical => 9.5,
            SeverityLevel::High => 7.5,
            SeverityLevel::Medium => 5.5,
            SeverityLevel::Low => 2.5,
            SeverityLevel::Unknown => 5.0,
        });

        SeverityInfo {
            level,
            score: final_score,
            vector,
        }
    }

    fn estimate_score_from_cvss(&self, vector: &str) -> Option<f64> {
        if vector.contains("AV:N") && vector.contains("AC:L") && vector.contains("C:H") && vector.contains("I:H") {
            Some(9.8)
        } else if vector.contains("AV:N") && vector.contains("AC:L") {
            Some(7.5)
        } else {
            Some(6.0)
        }
    }

    fn extract_cwes(&self, adv: &Value) -> Vec<String> {
        let mut cwes = Vec::new();
        if let Some(ids) = adv
            .get("database_specific")
            .and_then(|d| d.get("cwe_ids"))
            .and_then(|c| c.as_array())
        {
            for id in ids {
                if let Some(s) = id.as_str() {
                    cwes.push(s.to_string());
                }
            }
        }
        cwes
    }
}
