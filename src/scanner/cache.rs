use crate::types::PkgInfo;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheState<T> {
    Fresh { data: T, age_secs: u64 },
    Stale { data: T, age_secs: u64 },
    Missing,
}

pub struct VulnCache {
    pub cache_dir: PathBuf,
    pub allow_stale: bool,
    pub offline: bool,
}

impl Default for VulnCache {
    fn default() -> Self {
        Self::new(Path::new(".sca-cache"))
    }
}

impl VulnCache {
    pub const SCHEMA_VERSION: u32 = 1;
    pub const DEFAULT_TTL_SECS: u64 = 86_400; // 24 hours

    pub fn new(cache_dir: &Path) -> Self {
        let cache_dir = cache_dir.to_path_buf();
        let _ = fs::create_dir_all(&cache_dir);
        let _ = fs::create_dir_all(cache_dir.join("advisories"));
        Self {
            cache_dir,
            allow_stale: false,
            offline: false,
        }
    }

    pub fn with_options(cache_dir: &Path, allow_stale: bool, offline: bool) -> Self {
        let cache_dir = cache_dir.to_path_buf();
        let _ = fs::create_dir_all(&cache_dir);
        let _ = fs::create_dir_all(cache_dir.join("advisories"));
        Self {
            cache_dir,
            allow_stale,
            offline,
        }
    }

    fn get_key(&self, pkg_info: &PkgInfo) -> String {
        let raw = format!(
            "{}:{}@{}",
            pkg_info.ecosystem, pkg_info.name, pkg_info.version
        );
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        let hash = hex::encode(hasher.finalize());
        hash[..16].to_string()
    }

    pub fn get_with_status(&self, pkg_info: &PkgInfo) -> CacheState<Vec<Value>> {
        let key = self.get_key(pkg_info);
        let file_path = self.cache_dir.join(format!("{}.json", key));
        if !file_path.exists() {
            return CacheState::Missing;
        }

        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => return CacheState::Missing,
        };

        let item: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return CacheState::Missing,
        };

        let timestamp_ms = match item.get("timestamp").and_then(|t| t.as_u64()) {
            Some(t) => t,
            None => return CacheState::Missing,
        };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let age_secs = now_ms.saturating_sub(timestamp_ms) / 1000;
        let vulns = match item.get("vulns").and_then(|v| v.as_array()) {
            Some(v) => v.clone(),
            None => return CacheState::Missing,
        };

        if age_secs < Self::DEFAULT_TTL_SECS {
            CacheState::Fresh {
                data: vulns,
                age_secs,
            }
        } else {
            CacheState::Stale {
                data: vulns,
                age_secs,
            }
        }
    }

    pub fn get(&self, pkg_info: &PkgInfo) -> Option<Vec<Value>> {
        match self.get_with_status(pkg_info) {
            CacheState::Fresh { data, .. } => Some(data),
            CacheState::Stale { data, .. } if self.allow_stale || self.offline => Some(data),
            _ => None,
        }
    }

    pub fn set(&self, pkg_info: &PkgInfo, vulns: &[Value]) {
        let key = self.get_key(pkg_info);
        let file_path = self.cache_dir.join(format!("{}.json", key));
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let data = serde_json::json!({
            "schema_version": Self::SCHEMA_VERSION,
            "pkg": pkg_info.id,
            "timestamp": now_ms,
            "vulns": vulns,
        });

        if let Ok(json_str) = serde_json::to_string(&data) {
            let _ = fs::write(file_path, json_str);
        }
    }

    pub fn get_advisory_with_status(&self, id: &str) -> CacheState<Value> {
        let file_path = self
            .cache_dir
            .join("advisories")
            .join(format!("{}.json", id));
        if !file_path.exists() {
            return CacheState::Missing;
        }
        let content = match fs::read_to_string(&file_path) {
            Ok(c) => c,
            Err(_) => return CacheState::Missing,
        };
        let item: Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return CacheState::Missing,
        };

        let (adv, timestamp_ms) = if let Some(inner) = item.get("advisory") {
            let ts = item.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0);
            (inner.clone(), ts)
        } else {
            // Legacy cache format
            (item, 0)
        };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let age_secs = if timestamp_ms > 0 {
            now_ms.saturating_sub(timestamp_ms) / 1000
        } else {
            0
        };

        if age_secs < Self::DEFAULT_TTL_SECS {
            CacheState::Fresh {
                data: adv,
                age_secs,
            }
        } else {
            CacheState::Stale {
                data: adv,
                age_secs,
            }
        }
    }

    pub fn get_advisory(&self, id: &str) -> Option<Value> {
        match self.get_advisory_with_status(id) {
            CacheState::Fresh { data, .. } => Some(data),
            CacheState::Stale { data, .. } if self.allow_stale || self.offline => Some(data),
            _ => None,
        }
    }

    pub fn set_advisory(&self, id: &str, advisory: &Value) {
        let file_path = self
            .cache_dir
            .join("advisories")
            .join(format!("{}.json", id));
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let wrapper = serde_json::json!({
            "schema_version": Self::SCHEMA_VERSION,
            "id": id,
            "timestamp": now_ms,
            "advisory": advisory
        });

        if let Ok(json_str) = serde_json::to_string(&wrapper) {
            let _ = fs::write(file_path, json_str);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_preserves_vendor_content_without_mutation() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_test_cache_{}", std::process::id()));
        let cache = VulnCache::new(&temp_dir);

        let adv_id = "SNYK-JS-LODASH-567746";
        let raw_advisory = serde_json::json!({
            "id": adv_id,
            "summary": "Prototype Pollution in lodash reported by snyk",
            "details": "Research conducted by snyk security team found prototype pollution vulnerability.",
            "references": [
                {"type": "ADVISORY", "url": "https://snyk.io/vuln/SNYK-JS-LODASH-567746"},
                {"type": "WEB", "url": "https://github.com/lodash/lodash/issues/4759"}
            ]
        });

        cache.set_advisory(adv_id, &raw_advisory);
        let retrieved = cache
            .get_advisory(adv_id)
            .expect("advisory should be retrieved from cache");

        assert_eq!(retrieved, raw_advisory);
        assert_eq!(retrieved["id"].as_str().unwrap(), "SNYK-JS-LODASH-567746");
        assert!(retrieved["details"].as_str().unwrap().contains("snyk"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_cache_hit_and_miss_lifecycle() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("vexa_cache_lifecycle_{}", unique));
        let cache = VulnCache::new(&temp_dir);
        let pkg = PkgInfo::new("demo-pkg", "1.0.0", "npm");

        // 1. Initial state: missing
        assert_eq!(cache.get_with_status(&pkg), CacheState::Missing);
        assert!(cache.get(&pkg).is_none());

        // 2. Set cache entry
        let vulns = vec![serde_json::json!({"id": "GHSA-test-123", "summary": "test vuln"})];
        cache.set(&pkg, &vulns);

        // 3. Cache hit: fresh
        match cache.get_with_status(&pkg) {
            CacheState::Fresh { data, age_secs } => {
                assert_eq!(data.len(), 1);
                assert_eq!(data[0]["id"], "GHSA-test-123");
                assert!(age_secs < 60);
            }
            other => panic!("expected Fresh, got {:?}", other),
        }
        assert!(cache.get(&pkg).is_some());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_cache_stale_detection_and_allow_stale_policy() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("vexa_cache_stale_{}", unique));
        let cache = VulnCache::new(&temp_dir);
        let pkg = PkgInfo::new("stale-pkg", "2.0.0", "npm");

        // Write an expired cache entry (timestamp from 48 hours ago)
        let key = cache.get_key(&pkg);
        let file_path = temp_dir.join(format!("{}.json", key));
        let forty_eight_hours_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - (48 * 3600 * 1000);

        let stale_json = serde_json::json!({
            "schema_version": VulnCache::SCHEMA_VERSION,
            "pkg": pkg.id,
            "timestamp": forty_eight_hours_ago,
            "vulns": [{"id": "GHSA-stale-entry"}]
        });
        fs::write(&file_path, stale_json.to_string()).unwrap();

        // Fresh check fails: returns Stale
        match cache.get_with_status(&pkg) {
            CacheState::Stale { data, age_secs } => {
                assert_eq!(data.len(), 1);
                assert!(age_secs >= 48 * 3600);
            }
            other => panic!("expected Stale, got {:?}", other),
        }

        // Standard get() ignores stale entry by default (cache miss for online scan)
        assert!(cache.get(&pkg).is_none());

        // Cache with allow_stale accepts stale data
        let stale_tolerant_cache = VulnCache::with_options(&temp_dir, true, false);
        assert!(stale_tolerant_cache.get(&pkg).is_some());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_cache_corrupt_data_treated_as_missing_without_crash() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("vexa_cache_corrupt_{}", unique));
        let cache = VulnCache::new(&temp_dir);
        let pkg = PkgInfo::new("corrupt-pkg", "1.0.0", "npm");

        let key = cache.get_key(&pkg);
        let file_path = temp_dir.join(format!("{}.json", key));

        // 1. Truncated / malformed JSON
        fs::write(&file_path, b"{ truncated json: ").unwrap();
        assert_eq!(cache.get_with_status(&pkg), CacheState::Missing);
        assert!(cache.get(&pkg).is_none());

        // 2. Corrupt schema (missing timestamp or vulns)
        fs::write(&file_path, b"{\"schema_version\": 1, \"other\": 123}").unwrap();
        assert_eq!(cache.get_with_status(&pkg), CacheState::Missing);

        // 3. Corrupt advisory detail
        let adv_path = temp_dir.join("advisories").join("GHSA-corrupt.json");
        fs::write(&adv_path, b"NOT_JSON").unwrap();
        assert_eq!(
            cache.get_advisory_with_status("GHSA-corrupt"),
            CacheState::Missing
        );
        assert!(cache.get_advisory("GHSA-corrupt").is_none());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
