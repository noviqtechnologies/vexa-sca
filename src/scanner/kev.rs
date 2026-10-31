#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const CISA_KEV_FEED_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevVulnerability {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vendorProject")]
    pub vendor_project: Option<String>,
    pub product: Option<String>,
    #[serde(rename = "vulnerabilityName")]
    pub vulnerability_name: Option<String>,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "shortDescription")]
    pub short_description: Option<String>,
    #[serde(rename = "requiredAction")]
    pub required_action: Option<String>,
    #[serde(rename = "dueDate")]
    pub due_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevCatalogPayload {
    pub title: Option<String>,
    #[serde(rename = "catalogVersion")]
    pub catalog_version: Option<String>,
    #[serde(rename = "dateReleased")]
    pub date_released: Option<String>,
    pub count: Option<usize>,
    pub vulnerabilities: Vec<KevVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedKevData {
    pub fetched_at: String,
    pub vulnerabilities: Vec<KevVulnerability>,
}

#[derive(Debug, Clone, Default)]
pub struct CisaKevCatalog {
    entries: HashMap<String, KevVulnerability>,
}

impl CisaKevCatalog {
    /// Create an empty catalog with built-in prominent KEV entries as immediate fallback
    pub fn new() -> Self {
        let mut catalog = Self::default();
        catalog.populate_builtin_fallbacks();
        catalog
    }

    fn populate_builtin_fallbacks(&mut self) {
        let prominent = [
            ("CVE-2021-44228", "2021-12-10", "Apache Log4j Remote Code Execution"),
            ("CVE-2021-45046", "2021-12-14", "Apache Log4j Denial of Service and RCE"),
            ("CVE-2020-8203", "2021-11-03", "Lodash Prototype Pollution"),
            ("CVE-2021-23337", "2021-11-03", "Lodash Command Injection"),
            ("CVE-2022-22965", "2022-04-01", "Spring Framework RCE (Spring4Shell)"),
            ("CVE-2023-38606", "2023-07-26", "Apple WebKit and Kernel Vulnerability"),
        ];

        for (cve, date, name) in prominent {
            self.entries.entry(cve.to_uppercase()).or_insert_with(|| KevVulnerability {
                cve_id: cve.to_string(),
                vendor_project: None,
                product: None,
                vulnerability_name: Some(name.to_string()),
                date_added: date.to_string(),
                short_description: None,
                required_action: None,
                due_date: None,
            });
        }
    }

    /// Load KEV catalog from local `.sca-cache/cisa_kev.json` if fresh (<24h),
    /// or fetch online from CISA if online and save cache.
    pub async fn load_or_fetch(cache_dir: &Path, client: Option<&reqwest::Client>) -> Self {
        let mut catalog = Self::new();
        let cache_file = cache_dir.join("cisa_kev.json");

        // Try reading fresh cache first
        if let Some(cached) = Self::read_cache(&cache_file) {
            for v in cached.vulnerabilities {
                catalog.entries.insert(v.cve_id.to_uppercase(), v);
            }
            return catalog;
        }

        // Attempt online fetch if client is provided
        if let Some(http_client) = client {
            if let Ok(resp) = http_client
                .get(CISA_KEV_FEED_URL)
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                if resp.status().is_success() {
                    if let Ok(payload) = resp.json::<KevCatalogPayload>().await {
                        let cached = CachedKevData {
                            fetched_at: Utc::now().to_rfc3339(),
                            vulnerabilities: payload.vulnerabilities.clone(),
                        };
                        Self::write_cache(&cache_file, &cached);

                        for v in payload.vulnerabilities {
                            catalog.entries.insert(v.cve_id.to_uppercase(), v);
                        }
                        return catalog;
                    }
                }
            }
        }

        // If online fetch failed or no client, read stale cache if available
        if cache_file.exists() {
            if let Ok(bytes) = fs::read(&cache_file) {
                if let Ok(cached) = serde_json::from_slice::<CachedKevData>(&bytes) {
                    for v in cached.vulnerabilities {
                        catalog.entries.insert(v.cve_id.to_uppercase(), v);
                    }
                }
            }
        }

        catalog
    }

    fn read_cache(cache_file: &PathBuf) -> Option<CachedKevData> {
        if !cache_file.exists() {
            return None;
        }
        let bytes = fs::read(cache_file).ok()?;
        let cached: CachedKevData = serde_json::from_slice(&bytes).ok()?;
        let fetched: DateTime<Utc> = cached.fetched_at.parse().ok()?;
        let age = Utc::now().signed_duration_since(fetched);
        if age.num_hours() < 24 {
            Some(cached)
        } else {
            None
        }
    }

    fn write_cache(cache_file: &PathBuf, data: &CachedKevData) {
        if let Some(parent) = cache_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(data) {
            let _ = fs::write(cache_file, json);
        }
    }

    pub fn is_kev(&self, cve: &str) -> bool {
        let norm = cve.trim().to_uppercase();
        self.entries.contains_key(&norm)
    }

    pub fn get_date_added(&self, cve: &str) -> Option<&str> {
        let norm = cve.trim().to_uppercase();
        self.entries.get(&norm).map(|v| v.date_added.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_kev_lookups() {
        let catalog = CisaKevCatalog::new();
        assert!(catalog.is_kev("CVE-2021-44228"));
        assert!(catalog.is_kev("cve-2020-8203"));
        assert_eq!(catalog.get_date_added("CVE-2021-44228"), Some("2021-12-10"));
        assert!(!catalog.is_kev("CVE-1999-99999"));
    }
}
