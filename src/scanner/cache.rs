use crate::types::PkgInfo;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct VulnCache {
    pub cache_dir: PathBuf,
}

impl Default for VulnCache {
    fn default() -> Self {
        Self::new(Path::new(".sca-cache"))
    }
}

impl VulnCache {
    pub fn new(cache_dir: &Path) -> Self {
        let cache_dir = cache_dir.to_path_buf();
        let _ = fs::create_dir_all(&cache_dir);
        let _ = fs::create_dir_all(cache_dir.join("advisories"));
        Self { cache_dir }
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

    pub fn get(&self, pkg_info: &PkgInfo) -> Option<Vec<Value>> {
        let key = self.get_key(pkg_info);
        let file_path = self.cache_dir.join(format!("{}.json", key));
        if !file_path.exists() {
            return None;
        }

        let content = fs::read_to_string(&file_path).ok()?;
        let item: Value = serde_json::from_str(&content).ok()?;

        let timestamp = item.get("timestamp")?.as_u64()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis() as u64;

        // 24 hours TTL: 24 * 60 * 60 * 1000 = 86_400_000 ms
        if now.saturating_sub(timestamp) < 86_400_000 {
            item.get("vulns").and_then(|v| v.as_array()).cloned()
        } else {
            None
        }
    }

    pub fn set(&self, pkg_info: &PkgInfo, vulns: &[Value]) {
        let key = self.get_key(pkg_info);
        let file_path = self.cache_dir.join(format!("{}.json", key));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let data = serde_json::json!({
            "pkg": pkg_info.id,
            "timestamp": now,
            "vulns": vulns,
        });

        if let Ok(json_str) = serde_json::to_string(&data) {
            let _ = fs::write(file_path, json_str);
        }
    }

    pub fn get_advisory(&self, id: &str) -> Option<Value> {
        let file_path = self
            .cache_dir
            .join("advisories")
            .join(format!("{}.json", id));
        if !file_path.exists() {
            return None;
        }
        let content = fs::read_to_string(&file_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn set_advisory(&self, id: &str, advisory: &Value) {
        let file_path = self
            .cache_dir
            .join("advisories")
            .join(format!("{}.json", id));
        if let Ok(json_str) = serde_json::to_string(advisory) {
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

        // Set and retrieve advisory
        cache.set_advisory(adv_id, &raw_advisory);
        let retrieved = cache
            .get_advisory(adv_id)
            .expect("advisory should be retrieved from cache");

        // Must be semantically and byte-for-byte identical
        assert_eq!(retrieved, raw_advisory);
        assert_eq!(retrieved["id"].as_str().unwrap(), "SNYK-JS-LODASH-567746");
        assert!(retrieved["details"].as_str().unwrap().contains("snyk"));
        assert!(retrieved["references"][0]["url"]
            .as_str()
            .unwrap()
            .contains("snyk.io"));

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
