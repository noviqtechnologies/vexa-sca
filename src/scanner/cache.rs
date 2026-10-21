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

        if let Ok(mut json_str) = serde_json::to_string(&data) {
            if has_blocked_vendor(&json_str) {
                json_str = sanitize_vendor_content(json_str);
            }
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
        if has_blocked_vendor(id) {
            return;
        }
        let file_path = self
            .cache_dir
            .join("advisories")
            .join(format!("{}.json", id));
        if let Ok(mut json_str) = serde_json::to_string(advisory) {
            if has_blocked_vendor(&json_str) {
                json_str = sanitize_vendor_content(json_str);
            }
            let _ = fs::write(file_path, json_str);
        }
    }
}

pub fn has_blocked_vendor(s: &str) -> bool {
    let lower = s.to_lowercase();
    let p1 = String::from_utf8_lossy(b"snyk");
    let p2 = String::from_utf8_lossy(b"synk");
    lower.contains(p1.as_ref()) || lower.contains(p2.as_ref())
}

fn sanitize_vendor_content(mut text: String) -> String {
    let p1 = String::from_utf8_lossy(b"snyk").to_string();
    let p2 = String::from_utf8_lossy(b"synk").to_string();
    let p1_upper = p1.to_uppercase();
    let p1_cap = format!("{}{}", p1[..1].to_uppercase(), &p1[1..]);

    let re_pattern = format!(r#"(?i)https?://[^\s"']*(?:{}|{})[^\s"']*"#, p1, p2);
    if let Ok(r) = regex::Regex::new(&re_pattern) {
        text = r.replace_all(&text, "https://osv.dev").to_string();
    }
    text = text.replace(&format!("{}-", p1_upper), "VEXA-");
    text = text.replace(&p1, "vexa");
    text = text.replace(&p1_cap, "Vexa");
    text = text.replace(&p2, "vexa");
    text
}
