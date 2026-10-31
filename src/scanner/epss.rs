#![forbid(unsafe_code)]

use crate::types::{EpssInfo, EpssSource, VulnerabilityFinding};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EPSS_CACHE_TTL_MS: u64 = 86_400_000; // 24 hours
const EPSS_BATCH_CHUNK_SIZE: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirstOrgEpssData {
    cve: String,
    epss: String,
    percentile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirstOrgApiResponse {
    data: Option<Vec<FirstOrgEpssData>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEpssRecord {
    pub score: f64,
    pub percentile: f64,
    #[serde(default)]
    pub source: EpssSource,
    #[serde(default)]
    pub timestamp: u64,
}

pub struct EpssResolver {
    pub cache_path: PathBuf,
    pub api_base_url: String,
    pub client: Client,
    pub cache: Mutex<HashMap<String, CachedEpssRecord>>,
}

impl Default for EpssResolver {
    fn default() -> Self {
        Self::new(Path::new(".sca-cache"))
    }
}

impl EpssResolver {
    pub fn new(cache_dir: &Path) -> Self {
        let cache_path = cache_dir.join("epss_cache.json");
        let initial_cache = Self::load_cache(&cache_path).unwrap_or_default();

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            cache_path,
            api_base_url: "https://api.first.org/data/v1/epss".to_string(),
            client,
            cache: Mutex::new(initial_cache),
        }
    }

    fn load_cache(path: &Path) -> Option<HashMap<String, CachedEpssRecord>> {
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(path).ok()?;
        let raw_map: HashMap<String, serde_json::Value> = serde_json::from_str(&content).ok()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut cache = HashMap::new();
        for (k, v) in raw_map {
            if let Ok(rec) = serde_json::from_value::<CachedEpssRecord>(v.clone()) {
                if now.saturating_sub(rec.timestamp) < EPSS_CACHE_TTL_MS {
                    cache.insert(k, rec);
                }
            } else if let Ok(info) = serde_json::from_value::<EpssInfo>(v) {
                cache.insert(
                    k,
                    CachedEpssRecord {
                        score: info.score,
                        percentile: info.percentile,
                        source: EpssSource::Cache,
                        timestamp: now,
                    },
                );
            }
        }
        Some(cache)
    }

    pub fn save_cache(&self) {
        if let Ok(guard) = self.cache.lock() {
            if let Some(parent) = self.cache_path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&*guard) {
                let _ = fs::write(&self.cache_path, json);
            }
        }
    }

    /// Batch resolve EPSS scores for a slice of CVE IDs, chunking up to 100 CVEs per request
    pub async fn resolve_epss_batch(&self, cve_ids: &[String]) -> HashMap<String, EpssInfo> {
        let mut results: HashMap<String, EpssInfo> = HashMap::new();
        let mut uncached_cves: Vec<String> = Vec::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // 1. Check in-memory/loaded cache
        if let Ok(guard) = self.cache.lock() {
            for cve in cve_ids {
                let cve_clean = cve.trim().to_uppercase();
                if !cve_clean.starts_with("CVE-") {
                    results.insert(
                        cve_clean,
                        EpssInfo {
                            score: 0.0,
                            percentile: 0.0,
                            source: EpssSource::Unavailable,
                        },
                    );
                    continue;
                }
                if let Some(rec) = guard.get(&cve_clean) {
                    if now.saturating_sub(rec.timestamp) < EPSS_CACHE_TTL_MS {
                        results.insert(
                            cve_clean,
                            EpssInfo {
                                score: rec.score,
                                percentile: rec.percentile,
                                source: EpssSource::Cache,
                            },
                        );
                        continue;
                    }
                }
                uncached_cves.push(cve_clean);
            }
        }

        uncached_cves.sort();
        uncached_cves.dedup();

        if uncached_cves.is_empty() {
            return results;
        }

        // 2. Query FIRST.org in batches of up to 100 CVEs
        let mut new_cache_entries: Vec<(String, CachedEpssRecord)> = Vec::new();

        for chunk in uncached_cves.chunks(EPSS_BATCH_CHUNK_SIZE) {
            let cve_param = chunk.join(",");
            let url = format!("{}?cve={}", self.api_base_url, cve_param);

            let mut fetched_cves = HashSet::new();

            match tokio::time::timeout(Duration::from_secs(5), self.client.get(&url).send()).await {
                Ok(Ok(resp)) if resp.status().is_success() => {
                    if let Ok(api_data) = resp.json::<FirstOrgApiResponse>().await {
                        if let Some(data_list) = api_data.data {
                            for entry in data_list {
                                let cve_key = entry.cve.trim().to_uppercase();
                                if let (Ok(score), Ok(percentile)) =
                                    (entry.epss.parse::<f64>(), entry.percentile.parse::<f64>())
                                {
                                    results.insert(
                                        cve_key.clone(),
                                        EpssInfo {
                                            score,
                                            percentile,
                                            source: EpssSource::FirstOrg,
                                        },
                                    );
                                    new_cache_entries.push((
                                        cve_key.clone(),
                                        CachedEpssRecord {
                                            score,
                                            percentile,
                                            source: EpssSource::FirstOrg,
                                            timestamp: now,
                                        },
                                    ));
                                    fetched_cves.insert(cve_key);
                                }
                            }
                        }
                    }
                }
                _ => {
                    // Network timeout or non-success
                }
            }

            // Fill in missing entries from this chunk as Unavailable (strictly no heuristic fallback per DDD §3.3)
            for cve in chunk {
                if !fetched_cves.contains(cve) && !results.contains_key(cve) {
                    let info = EpssInfo {
                        score: 0.0,
                        percentile: 0.0,
                        source: EpssSource::Unavailable,
                    };
                    results.insert(cve.clone(), info.clone());
                    new_cache_entries.push((
                        cve.clone(),
                        CachedEpssRecord {
                            score: info.score,
                            percentile: info.percentile,
                            source: info.source,
                            timestamp: now,
                        },
                    ));
                }
            }
        }

        // 3. Save new records into cache
        if !new_cache_entries.is_empty() {
            if let Ok(mut guard) = self.cache.lock() {
                for (k, rec) in new_cache_entries {
                    guard.insert(k, rec);
                }
            }
            self.save_cache();
        }

        results
    }

    /// Resolve EPSS score for a single CVE
    pub async fn resolve_epss(&self, cve: &str, _cvss_score: f64) -> EpssInfo {
        let clean = cve.trim().to_uppercase();
        if !clean.starts_with("CVE-") {
            return EpssInfo {
                score: 0.0,
                percentile: 0.0,
                source: EpssSource::Unavailable,
            };
        }
        let batch = self.resolve_epss_batch(std::slice::from_ref(&clean)).await;
        batch.get(&clean).cloned().unwrap_or(EpssInfo {
            score: 0.0,
            percentile: 0.0,
            source: EpssSource::Unavailable,
        })
    }

    /// Enriches vulnerability findings with EPSS exploit prediction likelihood
    /// Batches all unique CVE queries into chunks of up to 100 for optimal latency
    pub async fn enrich_findings(&self, findings: &mut [VulnerabilityFinding]) {
        let mut unique_cves = Vec::new();
        for finding in findings.iter() {
            let cve_id = finding.cve.clone().or_else(|| {
                finding
                    .aliases
                    .iter()
                    .find(|a| a.starts_with("CVE-"))
                    .cloned()
            });
            if let Some(cve) = cve_id {
                unique_cves.push(cve);
            }
        }

        let resolved_map = self.resolve_epss_batch(&unique_cves).await;

        for finding in findings.iter_mut() {
            let cve_id = finding.cve.clone().or_else(|| {
                finding
                    .aliases
                    .iter()
                    .find(|a| a.starts_with("CVE-"))
                    .cloned()
            });

            if let Some(cve) = cve_id {
                let clean = cve.trim().to_uppercase();
                if let Some(info) = resolved_map.get(&clean) {
                    finding.epss = Some(info.clone());
                } else {
                    finding.epss = Some(EpssInfo {
                        score: 0.0,
                        percentile: 0.0,
                        source: EpssSource::Unavailable,
                    });
                }
            } else {
                finding.epss = Some(EpssInfo {
                    score: 0.0,
                    percentile: 0.0,
                    source: EpssSource::Unavailable,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epss_info_serialization() {
        let info = EpssInfo {
            score: 0.852,
            percentile: 0.985,
            source: EpssSource::FirstOrg,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"source\":\"first.org\""));
        let decoded: EpssInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, decoded);
    }

    #[tokio::test]
    async fn test_epss_missing_cve() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_epss_test_missing_{}", std::process::id()));
        let resolver = EpssResolver::new(&temp_dir);

        let res1 = resolver.resolve_epss("GHSA-1234-abcd", 7.5).await;
        assert_eq!(res1.source, EpssSource::Unavailable);
        assert_eq!(res1.score, 0.0);

        let res2 = resolver.resolve_epss("", 9.0).await;
        assert_eq!(res2.source, EpssSource::Unavailable);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_epss_stale_cache_handling() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_epss_test_stale_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let cache_file = temp_dir.join("epss_cache.json");

        // Write a stale cache entry (timestamp 48 hours ago)
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - (48 * 3600 * 1000);

        let mut stale_map = HashMap::new();
        stale_map.insert(
            "CVE-2020-8203".to_string(),
            CachedEpssRecord {
                score: 0.999,
                percentile: 0.999,
                source: EpssSource::Cache,
                timestamp: old_timestamp,
            },
        );
        fs::write(&cache_file, serde_json::to_string(&stale_map).unwrap()).unwrap();

        let mut resolver = EpssResolver::new(&temp_dir);
        resolver.api_base_url = "http://127.0.0.1:9/epss".to_string();

        let res = resolver.resolve_epss("CVE-2020-8203", 7.5).await;
        assert_ne!(res.source, EpssSource::Cache);
        assert_eq!(res.source, EpssSource::Unavailable);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_epss_network_timeout_or_unreachable() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_epss_test_timeout_{}", std::process::id()));
        let mut resolver = EpssResolver::new(&temp_dir);
        resolver.api_base_url = "http://192.0.2.1/epss".to_string();
        resolver.client = Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();

        let res = resolver.resolve_epss("CVE-2023-12345", 8.0).await;
        assert_eq!(res.source, EpssSource::Unavailable);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_epss_batch_query_chunks() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_epss_test_batch_{}", std::process::id()));
        let mut resolver = EpssResolver::new(&temp_dir);
        resolver.api_base_url = "http://192.0.2.1/epss".to_string();
        resolver.client = Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();

        let cves: Vec<String> = (1..=150).map(|i| format!("CVE-2024-{:04}", i)).collect();
        let res = resolver.resolve_epss_batch(&cves).await;
        assert_eq!(res.len(), 150);
        assert_eq!(
            res.get("CVE-2024-0001").unwrap().source,
            EpssSource::Unavailable
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
