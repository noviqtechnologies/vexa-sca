use crate::core::dep_graph::DepGraph;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseCategory {
    #[serde(rename = "PERMISSIVE")]
    Permissive,
    #[serde(rename = "WEAK_COPYLEFT")]
    WeakCopyleft,
    #[serde(rename = "STRONG_COPYLEFT")]
    StrongCopyleft,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl LicenseCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            LicenseCategory::Permissive => "PERMISSIVE",
            LicenseCategory::WeakCopyleft => "WEAK_COPYLEFT",
            LicenseCategory::StrongCopyleft => "STRONG_COPYLEFT",
            LicenseCategory::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseRisk {
    pub level: String,
    pub score: u32,
}

impl LicenseCategory {
    pub fn risk(&self) -> LicenseRisk {
        match self {
            LicenseCategory::Permissive => LicenseRisk { level: "LOW".to_string(), score: 1 },
            LicenseCategory::WeakCopyleft => LicenseRisk { level: "MEDIUM".to_string(), score: 2 },
            LicenseCategory::StrongCopyleft => LicenseRisk { level: "HIGH".to_string(), score: 3 },
            LicenseCategory::Unknown => LicenseRisk { level: "UNKNOWN".to_string(), score: 0 },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizedLicense {
    pub id: String,
    pub category: LicenseCategory,
    pub risk: LicenseRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageLicenseResult {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub license: String,
    pub category: LicenseCategory,
    pub risk: LicenseRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicenseSummary {
    pub total: usize,
    pub permissive: usize,
    pub weak_copyleft: usize,
    pub strong_copyleft: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseAudit {
    pub summary: LicenseSummary,
    pub results: Vec<PackageLicenseResult>,
}

pub struct LicenseScanner;

impl LicenseScanner {
    pub fn categorize_license(raw: &str) -> CategorizedLicense {
        let clean = raw.trim().to_lowercase();
        if clean.is_empty() || clean == "unknown" {
            return CategorizedLicense {
                id: "UNKNOWN".to_string(),
                category: LicenseCategory::Unknown,
                risk: LicenseCategory::Unknown.risk(),
            };
        }

        // Permissive
        let permissive_keys = [
            "mit", "apache-2.0", "apache 2.0", "bsd-2-clause", "bsd-3-clause", "bsd",
            "isc", "cc0-1.0", "unlicense", "0bsd", "artistic-2.0", "zlib",
        ];
        for k in permissive_keys {
            if clean == k || clean.contains(k) {
                return CategorizedLicense {
                    id: raw.trim().to_string(),
                    category: LicenseCategory::Permissive,
                    risk: LicenseCategory::Permissive.risk(),
                };
            }
        }

        // Weak Copyleft
        let weak_keys = [
            "lgpl-2.1", "lgpl-3.0", "lgpl", "mpl-2.0", "mpl", "epl-1.0", "epl-2.0", "cddl-1.0",
        ];
        for k in weak_keys {
            if clean == k || clean.contains(k) {
                return CategorizedLicense {
                    id: raw.trim().to_string(),
                    category: LicenseCategory::WeakCopyleft,
                    risk: LicenseCategory::WeakCopyleft.risk(),
                };
            }
        }

        // Strong Copyleft
        let strong_keys = [
            "gpl-2.0", "gpl-3.0", "gpl", "agpl-3.0", "agpl", "sspl", "eupl-1.2", "eupl",
        ];
        for k in strong_keys {
            if clean == k || clean.contains(k) {
                return CategorizedLicense {
                    id: raw.trim().to_string(),
                    category: LicenseCategory::StrongCopyleft,
                    risk: LicenseCategory::StrongCopyleft.risk(),
                };
            }
        }

        CategorizedLicense {
            id: raw.trim().to_string(),
            category: LicenseCategory::Unknown,
            risk: LicenseCategory::Unknown.risk(),
        }
    }

    pub fn scan_graph_licenses(dep_graph: &DepGraph, project_dir: &Path) -> LicenseAudit {
        let packages = dep_graph.get_all_pkgs();
        let mut results = Vec::new();
        let mut summary = LicenseSummary {
            total: packages.len(),
            ..Default::default()
        };

        let lockfile_licenses = Self::read_lockfile_licenses(project_dir);

        for pkg in &packages {
            let raw_license = lockfile_licenses
                .get(&pkg.name)
                .cloned()
                .or_else(|| Self::find_package_json_license(project_dir, &pkg.name))
                .unwrap_or_else(|| "UNKNOWN".to_string());

            let cat = Self::categorize_license(&raw_license);
            match cat.category {
                LicenseCategory::Permissive => summary.permissive += 1,
                LicenseCategory::WeakCopyleft => summary.weak_copyleft += 1,
                LicenseCategory::StrongCopyleft => summary.strong_copyleft += 1,
                LicenseCategory::Unknown => summary.unknown += 1,
            }

            results.push(PackageLicenseResult {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                ecosystem: pkg.ecosystem.clone(),
                license: cat.id,
                category: cat.category,
                risk: cat.risk,
            });
        }

        // Sort by risk score (Strong Copyleft first, then Weak Copyleft)
        results.sort_by_key(|b| std::cmp::Reverse(b.risk.score));

        LicenseAudit { summary, results }
    }

    fn read_lockfile_licenses(project_dir: &Path) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let lock_path = project_dir.join("package-lock.json");
        if !lock_path.exists() {
            return map;
        }

        if let Ok(content) = fs::read_to_string(lock_path) {
            if let Ok(val) = serde_json::from_str::<Value>(&content) {
                if let Some(pkgs) = val.get("packages").and_then(|p| p.as_object()) {
                    for (_path, data) in pkgs {
                        if let (Some(name), Some(lic)) = (
                            data.get("name").and_then(|n| n.as_str()),
                            data.get("license"),
                        ) {
                            let lic_str = lic
                                .as_str()
                                .map(|s| s.to_string())
                                .or_else(|| lic.get("type").and_then(|t| t.as_str()).map(|s| s.to_string()));
                            if let Some(l) = lic_str {
                                map.insert(name.to_string(), l);
                            }
                        }
                    }
                }
            }
        }
        map
    }

    fn find_package_json_license(project_dir: &Path, pkg_name: &str) -> Option<String> {
        let pkg_json = project_dir
            .join("node_modules")
            .join(pkg_name)
            .join("package.json");
        if !pkg_json.exists() {
            return None;
        }

        let content = fs::read_to_string(pkg_json).ok()?;
        let data: Value = serde_json::from_str(&content).ok()?;

        if let Some(lic) = data.get("license") {
            if let Some(s) = lic.as_str() {
                return Some(s.to_string());
            }
            if let Some(t) = lic.get("type").and_then(|s| s.as_str()) {
                return Some(t.to_string());
            }
        }
        if let Some(licenses) = data.get("licenses").and_then(|l| l.as_array()) {
            if let Some(first) = licenses.first() {
                if let Some(t) = first.get("type").and_then(|s| s.as_str()) {
                    return Some(t.to_string());
                }
                if let Some(s) = first.as_str() {
                    return Some(s.to_string());
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_license_categorization() {
        assert_eq!(LicenseScanner::categorize_license("MIT").category, LicenseCategory::Permissive);
        assert_eq!(LicenseScanner::categorize_license("Apache-2.0").category, LicenseCategory::Permissive);
        assert_eq!(LicenseScanner::categorize_license("BSD-3-Clause").category, LicenseCategory::Permissive);
        assert_eq!(LicenseScanner::categorize_license("ISC").category, LicenseCategory::Permissive);

        let lgpl = LicenseScanner::categorize_license("LGPL-3.0");
        assert_eq!(lgpl.category, LicenseCategory::WeakCopyleft);
        assert_eq!(lgpl.risk.level, "MEDIUM");

        let gpl = LicenseScanner::categorize_license("GPL-3.0");
        assert_eq!(gpl.category, LicenseCategory::StrongCopyleft);
        assert_eq!(gpl.risk.level, "HIGH");

        let agpl = LicenseScanner::categorize_license("AGPL-3.0");
        assert_eq!(agpl.category, LicenseCategory::StrongCopyleft);
        assert_eq!(agpl.risk.level, "HIGH");
    }
}
