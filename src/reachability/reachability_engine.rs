use crate::types::{CallSite, ReachabilityResult, ReachabilityStatus, VulnerabilityFinding};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct ReachabilityEngine {
    pub source_dir: PathBuf,
    pub source_files: Vec<PathBuf>,
    pub known_functions: HashMap<&'static str, Vec<&'static str>>,
}

impl ReachabilityEngine {
    pub fn new(source_dir: &Path) -> Self {
        let source_files = Self::find_source_files(source_dir, 200);

        let mut known = HashMap::new();
        // Lodash
        known.insert("CVE-2021-23337", vec!["template"]);
        known.insert("GHSA-35jh-r3h4-6jhm", vec!["template"]);
        known.insert("CVE-2020-8203", vec!["set", "setWith", "zipObjectDeep"]);
        known.insert(
            "GHSA-p6mc-m468-83gw",
            vec!["set", "setWith", "zipObjectDeep"],
        );
        known.insert("CVE-2026-2950", vec!["unset", "omit"]);
        known.insert("GHSA-f23m-r3pf-42rh", vec!["unset", "omit"]);
        known.insert("CVE-2020-28500", vec!["toNumber", "trim", "words"]);
        known.insert("GHSA-29mw-wpgm-hmr9", vec!["toNumber", "trim", "words"]);
        known.insert("CVE-2026-4800", vec!["template"]);
        known.insert("GHSA-r5fr-rjxr-66jc", vec!["template"]);
        known.insert("CVE-2025-13465", vec!["unset", "omit"]);
        known.insert("GHSA-xxjr-mmjv-4gpg", vec!["unset", "omit"]);

        // Minimist
        known.insert("CVE-2020-7598", vec!["minimist", "parse"]);
        known.insert("GHSA-vh95-rmgr-6w4m", vec!["minimist", "parse"]);
        known.insert("CVE-2021-44906", vec!["minimist", "parse"]);
        known.insert("GHSA-xvch-5gv4-984h", vec!["minimist", "parse"]);

        // Log4j Core
        known.insert(
            "CVE-2021-44228",
            vec!["error", "warn", "info", "debug", "trace", "fatal"],
        );
        known.insert(
            "GHSA-jfh8-c2jp-5v3q",
            vec!["error", "warn", "info", "debug", "trace", "fatal"],
        );

        // Requests
        known.insert("CVE-2024-35195", vec!["Session", "request"]);
        known.insert("GHSA-9wx4-h78v-vm56", vec!["Session", "request"]);

        Self {
            source_dir: source_dir.to_path_buf(),
            source_files,
            known_functions: known,
        }
    }

    fn find_source_files(dir: &Path, max_files: usize) -> Vec<PathBuf> {
        let valid_exts: HashSet<&str> =
            ["js", "ts", "mjs", "cjs", "jsx", "tsx", "py", "java", "go"]
                .iter()
                .cloned()
                .collect();

        let ignore_dirs: HashSet<&str> = [
            "node_modules",
            ".git",
            "dist",
            "build",
            ".sca-cache",
            "target",
            "vendor",
        ]
        .iter()
        .cloned()
        .collect();

        let mut files = Vec::new();

        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    let name = e.file_name().to_str().unwrap_or("");
                    !ignore_dirs.contains(name)
                } else {
                    true
                }
            })
            .filter_map(|e| e.ok())
        {
            if files.len() >= max_files {
                break;
            }
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                    if valid_exts.contains(ext) {
                        files.push(entry.path().to_path_buf());
                    }
                }
            }
        }

        files
    }

    pub fn evaluate_reachability(
        &self,
        mut vulnerabilities: Vec<VulnerabilityFinding>,
    ) -> Vec<VulnerabilityFinding> {
        for v in &mut vulnerabilities {
            let reach = self.check_vulnerability(v);
            v.reachability = Some(reach);
        }
        vulnerabilities
    }

    pub fn check_vulnerability(&self, vuln: &VulnerabilityFinding) -> ReachabilityResult {
        let target_functions: Option<Vec<String>> = if let Some(cve) = &vuln.cve {
            self.known_functions
                .get(cve.as_str())
                .map(|list| list.iter().map(|s| s.to_string()).collect())
        } else {
            None
        }
        .or_else(|| {
            self.known_functions
                .get(vuln.id.as_str())
                .map(|list| list.iter().map(|s| s.to_string()).collect())
        })
        .or_else(|| {
            vuln.aliases.iter().find_map(|alias| {
                self.known_functions
                    .get(alias.as_str())
                    .map(|list| list.iter().map(|s| s.to_string()).collect())
            })
        })
        .or_else(|| self.infer_functions_from_details(vuln));

        let pkg_name = if let Some(idx) = vuln.package.find(':') {
            &vuln.package[idx + 1..]
        } else {
            &vuln.package
        };

        let mut call_sites = Vec::new();

        for file_path in &self.source_files {
            let content = match fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let relative_path = file_path
                .strip_prefix(&self.source_dir)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let matches = self.inspect_file(&content, pkg_name, target_functions.as_deref());
            for m in matches {
                call_sites.push(CallSite {
                    file: relative_path.clone(),
                    line: m.0,
                    code: m.1,
                    matched_function: m.2,
                    is_specific_function_match: m.3,
                });
            }
        }

        if !call_sites.is_empty() {
            let has_specific = call_sites.iter().any(|c| c.is_specific_function_match);
            ReachabilityResult {
                status: ReachabilityStatus::Reachable,
                is_direct_call: has_specific,
                call_sites: call_sites.into_iter().take(5).collect(),
                target_functions: target_functions.unwrap_or_else(|| vec!["*".to_string()]),
            }
        } else {
            ReachabilityResult {
                status: if !self.source_files.is_empty() {
                    ReachabilityStatus::Unreachable
                } else {
                    ReachabilityStatus::Unknown
                },
                is_direct_call: false,
                call_sites: Vec::new(),
                target_functions: target_functions.unwrap_or_else(|| vec!["*".to_string()]),
            }
        }
    }

    fn infer_functions_from_details(&self, vuln: &VulnerabilityFinding) -> Option<Vec<String>> {
        let text = format!("{} {}", vuln.title, vuln.details.as_deref().unwrap_or(""));
        let re =
            Regex::new(r"(?i)`?_?\.([a-zA-Z0-9_]+)`?\s+function|function\s+`?([a-zA-Z0-9_]+)`?")
                .ok()?;
        if let Some(cap) = re.captures(&text) {
            let name = cap.get(1).or_else(|| cap.get(2))?.as_str();
            return Some(vec![name.to_string()]);
        }
        None
    }

    fn inspect_file(
        &self,
        content: &str,
        pkg_name: &str,
        target_functions: Option<&[String]>,
    ) -> Vec<(usize, String, String, bool)> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        let mut import_alias: Option<String> = None;
        let mut imported_named_functions: HashSet<String> = HashSet::new();

        // 1. Identify bindings
        let req_re =
            Regex::new(r#"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*require\(['"]([^'"]+)['"]\)"#)
                .unwrap();
        let esm_re =
            Regex::new(r#"import\s+(?:\*\s+as\s+)?([a-zA-Z0-9_$]+)\s+from\s+['"]([^'"]+)['"]"#)
                .unwrap();
        let named_esm_re = Regex::new(r#"import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]"#).unwrap();
        let py_re = Regex::new(r#"^import\s+([a-zA-Z0-9_]+)(?:\s+as\s+([a-zA-Z0-9_]+))?"#).unwrap();
        let py_from_re = Regex::new(r#"^from\s+([a-zA-Z0-9_]+)\s+import\s+(.+)"#).unwrap();

        for line in &lines {
            if let Some(cap) = req_re.captures(line) {
                if cap.get(2).map(|m| m.as_str()) == Some(pkg_name) {
                    import_alias = cap.get(1).map(|m| m.as_str().to_string());
                }
            }
            if let Some(cap) = esm_re.captures(line) {
                if cap.get(2).map(|m| m.as_str()) == Some(pkg_name) {
                    import_alias = cap.get(1).map(|m| m.as_str().to_string());
                }
            }
            if let Some(cap) = named_esm_re.captures(line) {
                if cap.get(2).map(|m| m.as_str()) == Some(pkg_name) {
                    if let Some(names_str) = cap.get(1) {
                        for name in names_str.as_str().split(',') {
                            let clean = name.split_whitespace().next().unwrap_or("").trim();
                            if !clean.is_empty() {
                                imported_named_functions.insert(clean.to_string());
                            }
                        }
                    }
                }
            }
            if let Some(cap) = py_re.captures(line) {
                if cap.get(1).map(|m| m.as_str()) == Some(pkg_name) {
                    let alias = cap.get(2).or_else(|| cap.get(1)).map(|m| m.as_str());
                    import_alias = alias.map(|s| s.to_string());
                }
            }
            if let Some(cap) = py_from_re.captures(line) {
                if cap.get(1).map(|m| m.as_str()) == Some(pkg_name) {
                    if let Some(names_str) = cap.get(2) {
                        for name in names_str.as_str().split(',') {
                            let clean = name.trim();
                            if !clean.is_empty() {
                                imported_named_functions.insert(clean.to_string());
                            }
                        }
                    }
                }
            }
        }

        if import_alias.is_none() && imported_named_functions.is_empty() {
            return matches;
        }

        // 2. Search call sites
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') {
                continue;
            }

            if let Some(targets) = target_functions {
                let mut matched = false;
                for fn_name in targets {
                    if let Some(alias) = &import_alias {
                        let pat = format!(
                            r"\b{}\.{}\s*\(",
                            regex::escape(alias),
                            regex::escape(fn_name)
                        );
                        if let Ok(re) = Regex::new(&pat) {
                            if re.is_match(line) {
                                matches.push((
                                    idx + 1,
                                    trimmed.chars().take(80).collect(),
                                    format!("{}.{}", alias, fn_name),
                                    true,
                                ));
                                matched = true;
                                break;
                            }
                        }
                    }

                    if imported_named_functions.contains(fn_name) {
                        let pat = format!(r"\b{}\s*\(", regex::escape(fn_name));
                        if let Ok(re) = Regex::new(&pat) {
                            if re.is_match(line) {
                                matches.push((
                                    idx + 1,
                                    trimmed.chars().take(80).collect(),
                                    fn_name.clone(),
                                    true,
                                ));
                                matched = true;
                                break;
                            }
                        }
                    }
                }
                if matched {
                    continue;
                }
            } else if let Some(alias) = &import_alias {
                let pat = format!(r"\b{}\s*\(", regex::escape(alias));
                if let Ok(re) = Regex::new(&pat) {
                    if re.is_match(line) {
                        matches.push((
                            idx + 1,
                            trimmed.chars().take(80).collect(),
                            format!("{}()", alias),
                            true,
                        ));
                    }
                }
            }
        }

        matches
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SeverityInfo, SeverityLevel};

    #[test]
    fn test_reachability_engine_fixture() {
        let fixture_dir = Path::new("test/fixtures/reachability-app");
        let engine = ReachabilityEngine::new(fixture_dir);

        let template_vuln = VulnerabilityFinding {
            id: "GHSA-35jh-r3h4-6jhm".to_string(),
            title: "Command Injection in lodash.template".to_string(),
            package: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "lodash@4.17.15".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::High,
                score: 7.5,
                vector: None,
            },
            cve: Some("CVE-2021-23337".to_string()),
            cwes: vec![],
            fixed_in: vec!["4.17.21".to_string()],
            ..Default::default()
        };

        let res1 = engine.check_vulnerability(&template_vuln);
        assert_eq!(res1.status, ReachabilityStatus::Reachable);
        assert!(!res1.call_sites.is_empty());
        assert_eq!(res1.call_sites[0].matched_function, "_.template");

        let unset_vuln = VulnerabilityFinding {
            id: "GHSA-f23m-r3pf-42rh".to_string(),
            title: "Prototype Pollution in lodash.unset".to_string(),
            package: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "lodash@4.17.15".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::High,
                score: 7.5,
                vector: None,
            },
            cve: Some("CVE-2026-2950".to_string()),
            ..Default::default()
        };

        let res2 = engine.check_vulnerability(&unset_vuln);
        assert_eq!(res2.status, ReachabilityStatus::Unreachable);
        assert!(res2.call_sites.is_empty());
    }
}
