use crate::types::{EpssInfo, EpssSource, VulnerabilityFinding};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EPSS_CACHE_TTL_MS: u64 = 86_400_000; // 24 hours

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
    pub allow_heuristic_fallback: bool,
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
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            cache_path,
            api_base_url: "https://api.first.org/data/v1/epss".to_string(),
            client,
            cache: Mutex::new(initial_cache),
            allow_heuristic_fallback: true,
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

    /// Resolve EPSS score for a CVE, checking memory -> disk cache -> FIRST.org API -> fallback
    pub async fn resolve_epss(&self, cve: &str, cvss_score: f64) -> EpssInfo {
        let cve_clean = cve.trim().to_uppercase();

        // 1. Missing or non-CVE identifier: EPSS is unavailable
        if !cve_clean.starts_with("CVE-") {
            return EpssInfo {
                score: 0.0,
                percentile: 0.0,
                source: EpssSource::Unavailable,
            };
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // 2. Check in-memory/loaded cache (enforce TTL)
        if let Ok(guard) = self.cache.lock() {
            if let Some(rec) = guard.get(&cve_clean) {
                if now.saturating_sub(rec.timestamp) < EPSS_CACHE_TTL_MS {
                    return EpssInfo {
                        score: rec.score,
                        percentile: rec.percentile,
                        source: EpssSource::Cache,
                    };
                }
            }
        }

        // 3. Attempt online fetch from FIRST.org EPSS API (timeout 3s)
        let url = format!("{}?cve={}", self.api_base_url, cve_clean);
        match self.client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(api_data) = resp.json::<FirstOrgApiResponse>().await {
                    if let Some(data_list) = api_data.data {
                        if let Some(first_entry) = data_list.first() {
                            if let (Ok(score), Ok(percentile)) = (
                                first_entry.epss.parse::<f64>(),
                                first_entry.percentile.parse::<f64>(),
                            ) {
                                let info = EpssInfo {
                                    score,
                                    percentile,
                                    source: EpssSource::FirstOrg,
                                };
                                if let Ok(mut guard) = self.cache.lock() {
                                    guard.insert(
                                        cve_clean.clone(),
                                        CachedEpssRecord {
                                            score,
                                            percentile,
                                            source: EpssSource::FirstOrg,
                                            timestamp: now,
                                        },
                                    );
                                }
                                self.save_cache();
                                return info;
                            }
                        } else {
                            // Empty data list: CVE is not indexed in FIRST.org EPSS
                            return EpssInfo {
                                score: 0.0,
                                percentile: 0.0,
                                source: EpssSource::Unavailable,
                            };
                        }
                    }
                }
            }
            _ => {
                // Request timed out, connection failed, or API returned error
            }
        }

        // 4. Fallback: If heuristic fallback is allowed, produce clearly labeled heuristic estimate.
        // Otherwise, declare EPSS unavailable.
        if self.allow_heuristic_fallback {
            let fallback = Self::estimate_fallback_epss(&cve_clean, cvss_score);
            if let Ok(mut guard) = self.cache.lock() {
                guard.insert(
                    cve_clean,
                    CachedEpssRecord {
                        score: fallback.score,
                        percentile: fallback.percentile,
                        source: EpssSource::Heuristic,
                        timestamp: now,
                    },
                );
            }
            self.save_cache();
            fallback
        } else {
            EpssInfo {
                score: 0.0,
                percentile: 0.0,
                source: EpssSource::Unavailable,
            }
        }
    }

    /// Enriches vulnerability findings with EPSS exploit prediction likelihood
    pub async fn enrich_findings(&self, findings: &mut [VulnerabilityFinding]) {
        for finding in findings.iter_mut() {
            let cve_id = finding.cve.clone().or_else(|| {
                finding
                    .aliases
                    .iter()
                    .find(|a| a.starts_with("CVE-"))
                    .cloned()
            });

            if let Some(cve) = cve_id {
                let epss = self.resolve_epss(&cve, finding.severity.score).await;
                finding.epss = Some(epss);
            } else {
                // Non-CVE advisories do not have EPSS data available
                finding.epss = Some(EpssInfo {
                    score: 0.0,
                    percentile: 0.0,
                    source: EpssSource::Unavailable,
                });
            }
        }
    }

    /// Statistical local exploit likelihood estimation (clearly labeled as heuristic)
    pub fn estimate_fallback_epss(cve: &str, cvss_score: f64) -> EpssInfo {
        let score: f64 = if cvss_score >= 9.0 {
            let base = 0.65 + ((cvss_score - 9.0) * 0.25);
            base.min(0.96)
        } else if cvss_score >= 7.0 {
            let base = 0.25 + ((cvss_score - 7.0) * 0.18);
            base.min(0.64)
        } else if cvss_score >= 4.0 {
            let base = 0.05 + ((cvss_score - 4.0) * 0.06);
            base.min(0.24)
        } else {
            0.008
        };

        let percentile: f64 = if score >= 0.70 {
            0.982
        } else if score >= 0.40 {
            0.945
        } else if score >= 0.20 {
            0.880
        } else if score >= 0.05 {
            0.720
        } else {
            0.450
        };

        let _ = cve;

        EpssInfo {
            score: (score * 1000.0).round() / 1000.0,
            percentile: (percentile * 1000.0).round() / 1000.0,
            source: EpssSource::Heuristic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epss_fallback_estimation() {
        let critical_epss = EpssResolver::estimate_fallback_epss("CVE-2021-44906", 9.8);
        assert!(
            critical_epss.score >= 0.70,
            "Critical CVSS should have high heuristic estimate"
        );
        assert!(critical_epss.percentile >= 0.95);
        assert_eq!(critical_epss.source, EpssSource::Heuristic);

        let high_epss = EpssResolver::estimate_fallback_epss("CVE-2020-8203", 7.4);
        assert!(high_epss.score >= 0.20 && high_epss.score <= 0.65);
        assert_eq!(high_epss.source, EpssSource::Heuristic);

        let low_epss = EpssResolver::estimate_fallback_epss("CVE-2021-1234", 3.2);
        assert!(low_epss.score < 0.05);
        assert_eq!(low_epss.source, EpssSource::Heuristic);
    }

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
        // Point to invalid endpoint with heuristic disabled to check cache freshness
        resolver.api_base_url = "http://127.0.0.1:9/epss".to_string();
        resolver.allow_heuristic_fallback = false;

        let res = resolver.resolve_epss("CVE-2020-8203", 7.5).await;
        // Stale cache should NOT be returned as valid cache
        assert_ne!(res.source, EpssSource::Cache);
        assert_eq!(res.source, EpssSource::Unavailable);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_epss_network_timeout_or_unreachable() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_epss_test_timeout_{}", std::process::id()));
        let mut resolver = EpssResolver::new(&temp_dir);
        // Use an unroutable IP with a tiny timeout
        resolver.api_base_url = "http://192.0.2.1/epss".to_string();
        resolver.client = Client::builder()
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        resolver.allow_heuristic_fallback = false;

        let res = resolver.resolve_epss("CVE-2023-12345", 8.0).await;
        assert_eq!(res.source, EpssSource::Unavailable);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_epss_malformed_api_response() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_epss_test_malformed_{}", std::process::id()));
        let mut resolver = EpssResolver::new(&temp_dir);
        // Even if API returns malformed or non-epss data, fall back gracefully
        resolver.api_base_url = "https://httpbin.org/status/500".to_string();
        resolver.allow_heuristic_fallback = true;

        let res = resolver.resolve_epss("CVE-2023-12345", 8.0).await;
        assert_eq!(res.source, EpssSource::Heuristic);
        assert!(res.score > 0.0);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
