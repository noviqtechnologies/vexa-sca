use crate::core::dep_graph::DepGraph;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LicenseCategory {
    #[serde(rename = "PERMISSIVE")]
    Permissive,
    #[serde(rename = "WEAK_COPYLEFT")]
    WeakCopyleft,
    #[serde(rename = "STRONG_COPYLEFT")]
    StrongCopyleft,
    #[serde(rename = "UNKNOWN")]
    #[default]
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

impl Default for LicenseRisk {
    fn default() -> Self {
        LicenseRisk {
            level: "UNKNOWN".to_string(),
            score: 1,
        }
    }
}

impl LicenseCategory {
    pub fn risk(&self) -> LicenseRisk {
        match self {
            LicenseCategory::StrongCopyleft => LicenseRisk {
                level: "HIGH".to_string(),
                score: 3,
            },
            LicenseCategory::WeakCopyleft => LicenseRisk {
                level: "MEDIUM".to_string(),
                score: 2,
            },
            LicenseCategory::Unknown => LicenseRisk {
                level: "UNKNOWN".to_string(),
                score: 1,
            },
            LicenseCategory::Permissive => LicenseRisk {
                level: "LOW".to_string(),
                score: 0,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorizedLicense {
    pub id: String,
    pub category: LicenseCategory,
    pub risk: LicenseRisk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PackageLicenseResult {
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub license: String,
    pub category: LicenseCategory,
    pub risk: LicenseRisk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dep_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_note: Option<String>,
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
    /// Canonicalizes known SPDX identifiers and handles WITH exception expressions
    pub fn canonicalize_spdx_id(raw_token: &str) -> String {
        let t = raw_token.trim();
        let lower = t.to_lowercase();
        match lower.as_str() {
            "mit" => "MIT".to_string(),
            "apache-2.0" | "apache 2.0" | "apache/2.0" | "asl 2.0" | "apache" => {
                "Apache-2.0".to_string()
            }
            "bsd-2-clause" => "BSD-2-Clause".to_string(),
            "bsd-3-clause" => "BSD-3-Clause".to_string(),
            "bsd-1-clause" => "BSD-1-Clause".to_string(),
            "0bsd" => "0BSD".to_string(),
            "isc" => "ISC".to_string(),
            "cc0-1.0" | "cc0" => "CC0-1.0".to_string(),
            "unlicense" => "Unlicense".to_string(),
            "zlib" => "Zlib".to_string(),
            "unicode-3.0" => "Unicode-3.0".to_string(),
            "unicode-dfs-2016" => "Unicode-DFS-2016".to_string(),
            "unicode" => "Unicode-3.0".to_string(),
            "bsl-1.0" | "boost" => "BSL-1.0".to_string(),
            "cdla-permissive-2.0" | "cdla-permissive" => "CDLA-Permissive-2.0".to_string(),
            "mit-0" => "MIT-0".to_string(),
            "openssl" => "OpenSSL".to_string(),
            "curl" => "curl".to_string(),
            "libpng" => "libpng".to_string(),
            "artistic-2.0" => "Artistic-2.0".to_string(),
            "mpl-2.0" | "mpl" => "MPL-2.0".to_string(),
            "mpl-1.1" => "MPL-1.1".to_string(),
            "epl-1.0" => "EPL-1.0".to_string(),
            "epl-2.0" | "epl" => "EPL-2.0".to_string(),
            "cddl-1.0" | "cddl" => "CDDL-1.0".to_string(),
            "cddl-1.1" => "CDDL-1.1".to_string(),
            "lgpl-2.1" => "LGPL-2.1".to_string(),
            "lgpl-2.1-or-later" | "lgpl-2.1+" => "LGPL-2.1-or-later".to_string(),
            "lgpl-3.0" => "LGPL-3.0".to_string(),
            "lgpl-3.0-or-later" | "lgpl-3.0+" => "LGPL-3.0-or-later".to_string(),
            "lgpl" => "LGPL-3.0".to_string(),
            "gpl-2.0" => "GPL-2.0".to_string(),
            "gpl-2.0-or-later" | "gpl-2.0+" => "GPL-2.0-or-later".to_string(),
            "gpl-3.0" | "gpl" => "GPL-3.0".to_string(),
            "gpl-3.0-or-later" | "gpl-3.0+" => "GPL-3.0-or-later".to_string(),
            "agpl-3.0" | "agpl" => "AGPL-3.0".to_string(),
            "agpl-3.0-or-later" | "agpl-3.0+" => "AGPL-3.0-or-later".to_string(),
            "sspl" | "sspl-1.0" => "SSPL-1.0".to_string(),
            "eupl-1.1" => "EUPL-1.1".to_string(),
            "eupl-1.2" | "eupl" => "EUPL-1.2".to_string(),
            "cc-by-sa-4.0" | "cc-by-sa" => "CC-BY-SA-4.0".to_string(),
            "osl-3.0" | "osl" => "OSL-3.0".to_string(),
            _ => {
                let lower_with = lower.replace(" with ", " WITH ");
                if lower_with.contains(" WITH ") {
                    let parts: Vec<&str> = lower_with.splitn(2, " WITH ").collect();
                    if parts.len() == 2 {
                        let lic = Self::canonicalize_spdx_id(parts[0]);
                        let exc_raw = parts[1].trim();
                        let exc = if exc_raw.eq_ignore_ascii_case("llvm-exception") {
                            "LLVM-exception".to_string()
                        } else {
                            exc_raw.to_string()
                        };
                        return format!("{} WITH {}", lic, exc);
                    }
                }
                t.to_string()
            }
        }
    }

    /// Normalizes and canonicalizes SPDX license expressions:
    /// - Normalizes legacy slash ('/') and pipe ('|') delimiters to standard 'OR'
    /// - Sorts disjunctive terms alphabetically to deduplicate order variations (e.g. 'Apache-2.0 OR MIT')
    /// - Preserves nested expressions, parentheses, and AND conjunctions
    pub fn normalize_license_expression(raw: &str) -> String {
        let clean = raw.trim();
        if clean.is_empty()
            || clean.eq_ignore_ascii_case("unknown")
            || clean.eq_ignore_ascii_case("none")
            || clean.eq_ignore_ascii_case("null")
            || clean.eq_ignore_ascii_case("noassertion")
        {
            return "UNKNOWN".to_string();
        }

        // Pre-clean legacy Apache slashes
        let mut text = clean
            .replace("Apache/2.0", "Apache-2.0")
            .replace("apache/2.0", "Apache-2.0");

        // Convert legacy slash notation and pipe notation to standard SPDX boolean operator OR
        text = text
            .replace(" / ", " OR ")
            .replace('/', " OR ")
            .replace(" | ", " OR ");

        // Normalize boolean operators case-insensitively
        let re_and = regex::Regex::new(r"(?i)\s+and\s+|\s+&\s+").unwrap();
        text = re_and.replace_all(&text, " AND ").to_string();

        let re_or = regex::Regex::new(r"(?i)\s+or\s+").unwrap();
        text = re_or.replace_all(&text, " OR ").to_string();

        let re_with = regex::Regex::new(r"(?i)\s+with\s+").unwrap();
        text = re_with.replace_all(&text, " WITH ").to_string();

        Self::normalize_expr_ast(&text)
    }

    fn normalize_expr_ast(expr: &str) -> String {
        let clean = expr.trim();
        if clean.is_empty() {
            return String::new();
        }

        // Fast path: pure disjunctive OR expression without parentheses or conjunctions
        if !clean.contains(" AND ") && !clean.contains('(') {
            let mut parts: Vec<String> = clean
                .split(" OR ")
                .map(|p| Self::canonicalize_spdx_id(p.trim()))
                .filter(|p| !p.is_empty())
                .collect();
            parts.sort();
            parts.dedup();
            return parts.join(" OR ");
        }

        let and_parts = Self::split_top_level(clean, " AND ");
        if and_parts.len() > 1 {
            let norm_parts: Vec<String> = and_parts
                .iter()
                .map(|p| {
                    let unwrapped = Self::unwrap_parens(p);
                    if unwrapped != p.trim() {
                        format!("({})", Self::normalize_expr_ast(unwrapped))
                    } else {
                        Self::normalize_expr_ast(p)
                    }
                })
                .collect();
            return norm_parts.join(" AND ");
        }

        let or_parts = Self::split_top_level(clean, " OR ");
        if or_parts.len() > 1 {
            let mut norm_parts: Vec<String> = or_parts
                .iter()
                .map(|p| {
                    let unwrapped = Self::unwrap_parens(p);
                    if unwrapped != p.trim() {
                        format!("({})", Self::normalize_expr_ast(unwrapped))
                    } else {
                        Self::normalize_expr_ast(p)
                    }
                })
                .collect();
            norm_parts.sort();
            norm_parts.dedup();
            return norm_parts.join(" OR ");
        }

        let unwrapped = Self::unwrap_parens(clean);
        if unwrapped != clean {
            return format!("({})", Self::normalize_expr_ast(unwrapped));
        }

        Self::canonicalize_spdx_id(clean)
    }

    fn split_top_level(expr: &str, op: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut depth = 0;
        let mut last = 0;
        let bytes = expr.as_bytes();
        let op_len = op.len();

        let mut i = 0;
        while i < expr.len() {
            if bytes[i] == b'(' {
                depth += 1;
                i += 1;
            } else if bytes[i] == b')' {
                if depth > 0 {
                    depth -= 1;
                }
                i += 1;
            } else if depth == 0 && i + op_len <= expr.len() && &expr[i..i + op_len] == op {
                parts.push(expr[last..i].trim().to_string());
                i += op_len;
                last = i;
            } else {
                i += 1;
            }
        }
        if last < expr.len() {
            let rem = expr[last..].trim();
            if !rem.is_empty() {
                parts.push(rem.to_string());
            }
        }
        parts
    }

    fn unwrap_parens(mut s: &str) -> &str {
        s = s.trim();
        while s.starts_with('(') && s.ends_with(')') {
            let mut depth = 0;
            let mut full_wrap = true;
            for (idx, b) in s.bytes().enumerate() {
                if b == b'(' {
                    depth += 1;
                } else if b == b')' {
                    depth -= 1;
                    if depth == 0 && idx < s.len() - 1 {
                        full_wrap = false;
                        break;
                    }
                }
            }
            if full_wrap && depth == 0 {
                s = s[1..s.len() - 1].trim();
            } else {
                break;
            }
        }
        s
    }

    pub fn categorize_license(raw: &str) -> CategorizedLicense {
        let normalized_id = Self::normalize_license_expression(raw);
        if normalized_id == "UNKNOWN" {
            return CategorizedLicense {
                id: "UNKNOWN".to_string(),
                category: LicenseCategory::Unknown,
                risk: LicenseCategory::Unknown.risk(),
                resolution_note: None,
            };
        }

        let (category, resolution_note) = Self::eval_license_expr(&normalized_id);
        CategorizedLicense {
            id: normalized_id,
            category,
            risk: category.risk(),
            resolution_note,
        }
    }

    fn eval_license_expr(expr: &str) -> (LicenseCategory, Option<String>) {
        let clean = Self::unwrap_parens(expr.trim());
        if clean.is_empty() || clean == "UNKNOWN" {
            return (LicenseCategory::Unknown, None);
        }

        // Top-level conjunction AND: all obligations apply (worst-case risk)
        let and_parts = Self::split_top_level(clean, " AND ");
        if and_parts.len() > 1 {
            let mut highest_cat = LicenseCategory::Permissive;
            for part in and_parts {
                let (part_cat, _) = Self::eval_license_expr(&part);
                if part_cat == LicenseCategory::StrongCopyleft {
                    highest_cat = LicenseCategory::StrongCopyleft;
                    break;
                } else if part_cat == LicenseCategory::WeakCopyleft {
                    if highest_cat != LicenseCategory::StrongCopyleft {
                        highest_cat = LicenseCategory::WeakCopyleft;
                    }
                } else if part_cat == LicenseCategory::Unknown
                    && highest_cat == LicenseCategory::Permissive
                {
                    highest_cat = LicenseCategory::Unknown;
                }
            }
            return (highest_cat, None);
        }

        // Top-level disjunction OR: licensee can choose the most permissive option
        let or_parts = Self::split_top_level(clean, " OR ");
        if or_parts.len() > 1 {
            let mut has_permissive = false;
            let mut has_weak = false;
            let mut has_strong = false;
            let mut has_unknown = false;

            for part in or_parts {
                let (part_cat, _) = Self::eval_license_expr(&part);
                match part_cat {
                    LicenseCategory::Permissive => has_permissive = true,
                    LicenseCategory::WeakCopyleft => has_weak = true,
                    LicenseCategory::StrongCopyleft => has_strong = true,
                    LicenseCategory::Unknown => has_unknown = true,
                }
            }

            if has_permissive {
                let note = if has_weak || has_strong {
                    Some("Multi-licensed (OR); permissive option chosen under commercial compliance policy".to_string())
                } else {
                    None
                };
                return (LicenseCategory::Permissive, note);
            } else if has_weak {
                return (LicenseCategory::WeakCopyleft, None);
            } else if has_strong {
                return (LicenseCategory::StrongCopyleft, None);
            } else if has_unknown {
                return (LicenseCategory::Unknown, None);
            }
        }

        // Base single license classification
        let single_cat = Self::classify_single_license(clean);
        (single_cat, None)
    }

    fn classify_single_license(token: &str) -> LicenseCategory {
        let clean = token.trim().to_lowercase();
        if clean.is_empty()
            || clean == "unknown"
            || clean == "none"
            || clean == "null"
            || clean == "noassertion"
        {
            return LicenseCategory::Unknown;
        }

        // Weak Copyleft (must check before Strong because LGPL contains "gpl")
        let weak_indicators = ["lgpl", "mpl", "epl", "cddl"];
        if weak_indicators.iter().any(|k| clean.contains(k)) {
            return LicenseCategory::WeakCopyleft;
        }

        // Strong Copyleft
        let strong_indicators = ["gpl", "agpl", "sspl", "eupl", "cc-by-sa", "osl"];
        if strong_indicators.iter().any(|k| clean.contains(k)) {
            return LicenseCategory::StrongCopyleft;
        }

        // Permissive
        let permissive_indicators = [
            "mit",
            "apache",
            "asl",
            "bsd",
            "0bsd",
            "isc",
            "cc0",
            "unlicense",
            "artistic",
            "zlib",
            "unicode",
            "bsl",
            "boost",
            "cdla-permissive",
            "mit-0",
            "openssl",
            "curl",
            "libpng",
            "public-domain",
            "blessing",
            "bzip2",
        ];
        if permissive_indicators.iter().any(|k| clean.contains(k)) {
            return LicenseCategory::Permissive;
        }

        LicenseCategory::Unknown
    }

    pub fn scan_graph_licenses(dep_graph: &DepGraph, project_dir: &Path) -> LicenseAudit {
        Self::scan_graph_licenses_with_overrides(dep_graph, project_dir, None)
    }

    pub fn scan_graph_licenses_with_overrides(
        dep_graph: &DepGraph,
        project_dir: &Path,
        overrides: Option<&HashMap<String, String>>,
    ) -> LicenseAudit {
        let base_dir = if project_dir.is_file() {
            project_dir.parent().unwrap_or(project_dir)
        } else {
            project_dir
        };

        let packages = dep_graph.get_all_pkgs();
        let mut results = Vec::new();
        let mut summary = LicenseSummary {
            total: packages.len(),
            ..Default::default()
        };

        let lockfile_licenses = Self::read_lockfile_licenses(base_dir);

        for pkg in &packages {
            let key_with_ver = format!("{}@{}", pkg.name, pkg.version);
            let raw_license = overrides
                .and_then(|ov| ov.get(&key_with_ver).or_else(|| ov.get(&pkg.name)))
                .cloned()
                .or_else(|| lockfile_licenses.get(&key_with_ver).cloned())
                .or_else(|| lockfile_licenses.get(&pkg.name).cloned())
                .or_else(|| Self::find_package_json_license(base_dir, &pkg.name))
                .unwrap_or_else(|| "UNKNOWN".to_string());

            let cat = Self::categorize_license(&raw_license);
            match cat.category {
                LicenseCategory::Permissive => summary.permissive += 1,
                LicenseCategory::WeakCopyleft => summary.weak_copyleft += 1,
                LicenseCategory::StrongCopyleft => summary.strong_copyleft += 1,
                LicenseCategory::Unknown => summary.unknown += 1,
            }

            // Trace dependency ancestry chain from root to this package
            let dep_path = dep_graph
                .pkg_paths_to_root(&pkg.id, 1)
                .into_iter()
                .next()
                .and_then(|path| {
                    if path.len() >= 2 {
                        Some(
                            path.iter()
                                .map(|p| p.name.as_str())
                                .collect::<Vec<_>>()
                                .join(" -> "),
                        )
                    } else if path.len() == 1 {
                        Some(format!("{} (direct)", path[0].name))
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    if let Some(root_node) = dep_graph.nodes.get(&dep_graph.root_node_id) {
                        for dep_node_id in &root_node.deps {
                            if let Some(dep_node) = dep_graph.nodes.get(dep_node_id) {
                                if dep_node.pkg_id.starts_with(&format!("{}@", pkg.name))
                                    || dep_node.pkg_id == pkg.name
                                {
                                    return Some(format!(
                                        "{} -> {}",
                                        dep_graph.root_pkg.name, pkg.name
                                    ));
                                }
                            }
                        }
                    }
                    None
                });

            results.push(PackageLicenseResult {
                package: pkg.name.clone(),
                version: pkg.version.clone(),
                ecosystem: pkg.ecosystem.clone(),
                license: cat.id,
                category: cat.category,
                risk: cat.risk,
                dep_path,
                resolution_note: cat.resolution_note,
            });
        }

        // Sort by risk score (Strong Copyleft first, then Weak Copyleft, then Unknown)
        results.sort_by_key(|b| std::cmp::Reverse(b.risk.score));

        LicenseAudit { summary, results }
    }

    fn read_lockfile_licenses(project_dir: &Path) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let base_dir = if project_dir.is_file() {
            project_dir.parent().unwrap_or(project_dir)
        } else {
            project_dir
        };

        // 1. Node.js (package-lock.json)
        let lock_path = base_dir.join("package-lock.json");
        if lock_path.exists() {
            if let Ok(content) = fs::read_to_string(&lock_path) {
                if let Ok(val) = serde_json::from_str::<Value>(&content) {
                    if let Some(pkgs) = val.get("packages").and_then(|p| p.as_object()) {
                        for (_path, data) in pkgs {
                            if let (Some(name), Some(lic)) = (
                                data.get("name").and_then(|n| n.as_str()),
                                data.get("license"),
                            ) {
                                let lic_str = lic.as_str().map(|s| s.to_string()).or_else(|| {
                                    lic.get("type")
                                        .and_then(|t| t.as_str())
                                        .map(|s| s.to_string())
                                });
                                if let Some(l) = lic_str {
                                    map.insert(name.to_string(), l);
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Cargo / Rust
        let cargo_toml = base_dir.join("Cargo.toml");
        let cargo_lock = base_dir.join("Cargo.lock");
        if cargo_toml.exists() || cargo_lock.exists() {
            let cargo_licenses = Self::read_cargo_licenses(base_dir);
            map.extend(cargo_licenses);
        }

        map
    }

    fn read_cargo_licenses(base_dir: &Path) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let cargo_toml = base_dir.join("Cargo.toml");

        // Strategy 1: Fast metadata extraction via `cargo metadata --format-version 1`
        let mut cmd = std::process::Command::new("cargo");
        cmd.arg("metadata").arg("--format-version").arg("1");
        if cargo_toml.exists() {
            cmd.arg("--manifest-path").arg(&cargo_toml);
        } else {
            cmd.current_dir(base_dir);
        }

        if let Ok(output) = cmd.output() {
            if output.status.success() {
                if let Ok(val) = serde_json::from_slice::<Value>(&output.stdout) {
                    if let Some(packages) = val.get("packages").and_then(|p| p.as_array()) {
                        for pkg in packages {
                            let name = pkg.get("name").and_then(|n| n.as_str());
                            let version = pkg.get("version").and_then(|v| v.as_str());
                            let license = pkg
                                .get("license")
                                .and_then(|l| l.as_str())
                                .or_else(|| pkg.get("license_file").and_then(|l| l.as_str()));

                            if let (Some(n), Some(lic)) = (name, license) {
                                if let Some(v) = version {
                                    map.insert(format!("{}@{}", n, v), lic.to_string());
                                }
                                map.insert(n.to_string(), lic.to_string());
                            }
                        }
                        if !map.is_empty() {
                            return map;
                        }
                    }
                }
            }
        }

        // Strategy 2: Fallback to inspecting ~/.cargo/registry/src
        if let Some(cargo_home) = Self::find_cargo_home() {
            let reg_src = cargo_home.join("registry").join("src");
            if reg_src.is_dir() {
                if let Ok(entries) = fs::read_dir(&reg_src) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            Self::scan_crates_dir(&path, &mut map);
                        }
                    }
                }
            }
        }

        map
    }

    fn find_cargo_home() -> Option<std::path::PathBuf> {
        if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
            let p = std::path::PathBuf::from(cargo_home);
            if p.exists() {
                return Some(p);
            }
        }
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            let p = std::path::PathBuf::from(user_profile).join(".cargo");
            if p.exists() {
                return Some(p);
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = std::path::PathBuf::from(home).join(".cargo");
            if p.exists() {
                return Some(p);
            }
        }
        None
    }

    fn scan_crates_dir(crates_dir: &Path, map: &mut HashMap<String, String>) {
        if let Ok(entries) = fs::read_dir(crates_dir) {
            for entry in entries.flatten() {
                let dir_path = entry.path();
                if dir_path.is_dir() {
                    let toml_path = dir_path.join("Cargo.toml");
                    if toml_path.exists() {
                        if let Ok(content) = fs::read_to_string(&toml_path) {
                            if let Some(lic) = Self::extract_license_from_toml(&content) {
                                let dir_name = entry.file_name().to_string_lossy().to_string();
                                if let Some((name, ver)) = dir_name.rsplit_once('-') {
                                    map.insert(format!("{}@{}", name, ver), lic.clone());
                                    map.entry(name.to_string()).or_insert_with(|| lic.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn extract_license_from_toml(content: &str) -> Option<String> {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("license") {
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                if parts.len() == 2 && parts[0].trim() == "license" {
                    let lic = parts[1].trim().trim_matches('"').trim_matches('\'').trim();
                    if !lic.is_empty() {
                        return Some(lic.to_string());
                    }
                }
            }
        }
        None
    }

    fn find_package_json_license(project_dir: &Path, pkg_name: &str) -> Option<String> {
        let base_dir = if project_dir.is_file() {
            project_dir.parent().unwrap_or(project_dir)
        } else {
            project_dir
        };
        let pkg_json = base_dir
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
        assert_eq!(
            LicenseScanner::categorize_license("MIT").category,
            LicenseCategory::Permissive
        );
        assert_eq!(
            LicenseScanner::categorize_license("Apache-2.0").category,
            LicenseCategory::Permissive
        );
        assert_eq!(
            LicenseScanner::categorize_license("BSD-3-Clause").category,
            LicenseCategory::Permissive
        );
        assert_eq!(
            LicenseScanner::categorize_license("ISC").category,
            LicenseCategory::Permissive
        );
        assert_eq!(
            LicenseScanner::categorize_license("MIT OR Apache-2.0").category,
            LicenseCategory::Permissive
        );
        assert_eq!(
            LicenseScanner::categorize_license("Unicode-3.0").category,
            LicenseCategory::Permissive
        );

        // SPDX normalization and deduplication
        let dual_slash = LicenseScanner::categorize_license("MIT/Apache-2.0");
        assert_eq!(dual_slash.id, "Apache-2.0 OR MIT");
        assert_eq!(dual_slash.category, LicenseCategory::Permissive);

        let dual_rev = LicenseScanner::categorize_license("MIT OR Apache-2.0");
        assert_eq!(dual_rev.id, "Apache-2.0 OR MIT");

        // Multi-license policy resolution transparency note
        let multi_or = LicenseScanner::categorize_license("MIT OR Apache-2.0 OR LGPL-2.1-or-later");
        assert_eq!(multi_or.category, LicenseCategory::Permissive);
        assert!(multi_or.resolution_note.is_some());

        let lgpl = LicenseScanner::categorize_license("LGPL-3.0");
        assert_eq!(lgpl.category, LicenseCategory::WeakCopyleft);
        assert_eq!(lgpl.risk.level, "MEDIUM");

        let mpl = LicenseScanner::categorize_license("MPL-2.0");
        assert_eq!(mpl.category, LicenseCategory::WeakCopyleft);
        assert_eq!(mpl.risk.level, "MEDIUM");

        let gpl = LicenseScanner::categorize_license("GPL-3.0");
        assert_eq!(gpl.category, LicenseCategory::StrongCopyleft);
        assert_eq!(gpl.risk.level, "HIGH");

        let agpl = LicenseScanner::categorize_license("AGPL-3.0");
        assert_eq!(agpl.category, LicenseCategory::StrongCopyleft);
        assert_eq!(agpl.risk.level, "HIGH");

        // Conjunction AND worst-case risk evaluation
        let conjunctive_gpl = LicenseScanner::categorize_license("MIT AND GPL-3.0");
        assert_eq!(conjunctive_gpl.category, LicenseCategory::StrongCopyleft);

        let conjunctive_lgpl = LicenseScanner::categorize_license("LGPL-3.0 AND MIT");
        assert_eq!(conjunctive_lgpl.category, LicenseCategory::WeakCopyleft);

        let conjunctive_permissive = LicenseScanner::categorize_license("Apache-2.0 AND ISC");
        assert_eq!(conjunctive_permissive.category, LicenseCategory::Permissive);
    }
}
