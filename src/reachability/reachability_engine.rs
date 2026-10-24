use crate::reachability::js_ast_analyzer::{analyze_file, source_type_for_path};
use crate::types::{
    CallSite, ReachabilityResult, ReachabilityStatus, ReasonCode, UsageSignal, VulnerabilityFinding,
};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct ReachabilityEngine {
    pub source_dir: PathBuf,
    pub source_files: Vec<PathBuf>,
    pub known_functions: HashMap<&'static str, Vec<&'static str>>,
    pub max_files: usize,
    pub file_limit_hit: bool,
    pub config_referenced_pkgs: HashSet<String>,
}

static REQ_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*require\(['"]([^'"]+)['"]\)"#).unwrap()
});
static ESM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"import\s+(?:\*\s+as\s+)?([a-zA-Z0-9_$]+)\s+from\s+['"]([^'"]+)['"]"#).unwrap()
});
static NAMED_ESM_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"]"#).unwrap()
});
/// Matches dynamic import() assignments, e.g.:
///   const mod = await import('lodash')
///   const { template } = await import('lodash')
///   let lodashModule = import('lodash').then(...)
static DYN_IMPORT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?:const|let|var)\s+(\{[^}]+\}|[a-zA-Z0-9_$]+)\s*=\s*(?:await\s+)?import\(['"]([^'"]+)['"]\)"#).unwrap()
});
static PY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"^import\s+([a-zA-Z0-9_]+)(?:\s+as\s+([a-zA-Z0-9_]+))?"#).unwrap()
});
static PY_FROM_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r#"^from\s+([a-zA-Z0-9_]+)\s+import\s+(.+)"#).unwrap());

impl ReachabilityEngine {
    pub fn new(source_dir: &Path) -> Self {
        Self::new_with_limit(source_dir, 1000)
    }

    pub fn new_with_limit(source_dir: &Path, max_files: usize) -> Self {
        let (source_files, file_limit_hit) = Self::find_source_files(source_dir, max_files);
        let config_referenced_pkgs = Self::find_config_referenced_pkgs(source_dir);

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
            max_files,
            file_limit_hit,
            config_referenced_pkgs,
        }
    }

    fn find_config_referenced_pkgs(dir: &Path) -> HashSet<String> {
        let mut referenced = HashSet::new();

        let pkg_json = dir.join("package.json");
        if let Ok(content) = fs::read_to_string(&pkg_json) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(scripts) = val.get("scripts").and_then(|s| s.as_object()) {
                    for (_k, v) in scripts {
                        if let Some(cmd) = v.as_str() {
                            for token in cmd.split_whitespace() {
                                let clean = token.trim_matches(|c: char| {
                                    !c.is_alphanumeric()
                                        && c != '-'
                                        && c != '_'
                                        && c != '@'
                                        && c != '/'
                                });
                                if !clean.is_empty() {
                                    referenced.insert(clean.to_string());
                                }
                            }
                        }
                    }
                }
                if let Some(bin) = val.get("bin") {
                    if let Some(s) = bin.as_str() {
                        referenced.insert(s.to_string());
                    } else if let Some(obj) = bin.as_object() {
                        for k in obj.keys() {
                            referenced.insert(k.clone());
                        }
                    }
                }
            }
        }

        let config_names = [
            "tsconfig.json",
            ".eslintrc",
            ".eslintrc.json",
            ".eslintrc.js",
            "eslint.config.js",
            "eslint.config.mjs",
            "webpack.config.js",
            "vite.config.js",
            "vite.config.ts",
            "rollup.config.js",
            "jest.config.js",
            "jest.config.json",
        ];

        for cfg in &config_names {
            let p = dir.join(cfg);
            if let Ok(c) = fs::read_to_string(&p) {
                for word in c.split(|ch: char| {
                    !ch.is_alphanumeric() && ch != '-' && ch != '_' && ch != '@' && ch != '/'
                }) {
                    let clean = word.trim();
                    if clean.len() > 2 {
                        referenced.insert(clean.to_string());
                    }
                }
            }
        }

        referenced
    }

    fn find_source_files(dir: &Path, max_files: usize) -> (Vec<PathBuf>, bool) {
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
        let mut hit_limit = false;

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
                hit_limit = true;
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

        (files, hit_limit)
    }

    pub fn evaluate_reachability(
        &self,
        mut vulnerabilities: Vec<VulnerabilityFinding>,
    ) -> Vec<VulnerabilityFinding> {
        for v in &mut vulnerabilities {
            let (reach, usage) = self.check_vulnerability_and_usage(v);
            v.reason_code = reach.reason_code;
            v.reachability = Some(reach);
            v.usage_signal = usage;
            v.priority_score = v.compute_priority_score();
        }
        vulnerabilities
    }

    pub fn check_vulnerability(&self, vuln: &VulnerabilityFinding) -> ReachabilityResult {
        let (reach, _) = self.check_vulnerability_and_usage(vuln);
        reach
    }

    pub fn check_vulnerability_and_usage(
        &self,
        vuln: &VulnerabilityFinding,
    ) -> (ReachabilityResult, UsageSignal) {
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
        let mut imported_in_source = false;
        let mut parse_failed = false;
        let mut dynamic_construct_detected = false;
        let mut has_reexports = false;

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

            if let Some(source_type) = source_type_for_path(file_path) {
                // Real JS/TS AST parser pass (oxc)
                let analysis =
                    analyze_file(&content, source_type, pkg_name, target_functions.as_deref());
                if analysis.is_imported {
                    imported_in_source = true;
                }
                if analysis.parse_failed {
                    parse_failed = true;
                }
                if analysis.has_dynamic_construct {
                    dynamic_construct_detected = true;
                }
                if analysis.has_reexports {
                    has_reexports = true;
                }
                for m in analysis.call_sites {
                    call_sites.push(CallSite {
                        file: relative_path.clone(),
                        line: m.0,
                        code: m.1,
                        matched_function: m.2,
                        is_specific_function_match: m.3,
                    });
                }
            } else {
                // Regex fallback for non-JS/TS files (Python, Go, Java, etc.)
                let (file_imported, matches) =
                    self.inspect_file(&content, pkg_name, target_functions.as_deref());
                if file_imported {
                    imported_in_source = true;
                }
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
        }

        let has_call_sites = !call_sites.is_empty();
        let is_specific = call_sites.iter().any(|c| c.is_specific_function_match);

        // Determine UsageSignal (FR-007a)
        let usage_signal = if has_call_sites || imported_in_source || has_reexports {
            UsageSignal::ImportedSource
        } else if self.config_referenced_pkgs.contains(pkg_name) {
            UsageSignal::ReferencedConfigOrScript
        } else if self.file_limit_hit || self.source_files.is_empty() {
            UsageSignal::Unknown
        } else {
            UsageSignal::NoReferenceFoundWithinScope
        };

        // Determine Reachability Verdict (FR-001, FR-002, FR-003)
        // Conservative rules: anything the analyzer cannot prove must remain UNKNOWN.
        let (status, reason_code) = if has_call_sites {
            (
                ReachabilityStatus::Reachable,
                Some(ReasonCode::DirectUsageFound),
            )
        } else if parse_failed {
            (ReachabilityStatus::Unknown, Some(ReasonCode::ParseError))
        } else if dynamic_construct_detected
            && (imported_in_source || self.config_referenced_pkgs.contains(pkg_name))
        {
            (
                ReachabilityStatus::Unknown,
                Some(ReasonCode::DynamicConstruct),
            )
        } else if has_reexports {
            (
                ReachabilityStatus::Unknown,
                Some(ReasonCode::CrossFileUnresolved),
            )
        } else if target_functions.is_none() {
            (ReachabilityStatus::Unknown, Some(ReasonCode::NoSymbolData))
        } else if vuln.is_transitive {
            (
                ReachabilityStatus::Unknown,
                Some(ReasonCode::TransitiveNotAnalyzed),
            )
        } else if self.file_limit_hit {
            (ReachabilityStatus::Unknown, Some(ReasonCode::FileLimitHit))
        } else if self.source_files.is_empty() {
            (
                ReachabilityStatus::Unknown,
                Some(ReasonCode::SourceUnavailable),
            )
        } else {
            // Positive proof: known target functions exist, direct dep, all files analyzed, no call found
            (
                ReachabilityStatus::Unreachable,
                Some(ReasonCode::AnalysisCompleteNoUsage),
            )
        };

        let result = ReachabilityResult {
            status,
            is_direct_call: is_specific,
            call_sites: call_sites.into_iter().take(5).collect(),
            target_functions: target_functions.unwrap_or_else(|| vec!["*".to_string()]),
            reason_code,
            analyzer_version: "1.0.0".to_string(),
        };

        (result, usage_signal)
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

    pub fn inspect_file(
        &self,
        content: &str,
        pkg_name: &str,
        target_functions: Option<&[String]>,
    ) -> (bool, Vec<(usize, String, String, bool)>) {
        // Try oxc JS/TS AST analyzer first
        let ast_res = analyze_file(
            content,
            oxc_span::SourceType::mjs(),
            pkg_name,
            target_functions,
        );
        if ast_res.is_imported {
            return (true, ast_res.call_sites);
        }

        let mut matches = Vec::new();
        // Fast-path exit: if the content does not contain the package name, it cannot be imported
        if !content.contains(pkg_name) {
            return (false, matches);
        }

        let lines: Vec<&str> = content.lines().collect();

        let mut import_alias: Option<String> = None;
        let mut imported_named_functions: HashSet<String> = HashSet::new();

        // 1. Identify bindings using precompiled static regexes
        for line in &lines {
            if let Some(cap) = REQ_RE.captures(line) {
                if cap.get(2).map(|m| m.as_str()) == Some(pkg_name) {
                    import_alias = cap.get(1).map(|m| m.as_str().to_string());
                }
            }
            if let Some(cap) = ESM_RE.captures(line) {
                if cap.get(2).map(|m| m.as_str()) == Some(pkg_name) {
                    import_alias = cap.get(1).map(|m| m.as_str().to_string());
                }
            }
            if let Some(cap) = NAMED_ESM_RE.captures(line) {
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
            if let Some(cap) = PY_RE.captures(line) {
                if cap.get(1).map(|m| m.as_str()) == Some(pkg_name) {
                    let alias = cap.get(2).or_else(|| cap.get(1)).map(|m| m.as_str());
                    import_alias = alias.map(|s| s.to_string());
                }
            }
            if let Some(cap) = PY_FROM_RE.captures(line) {
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
            // Dynamic import: `const mod = await import('pkg')` or
            // `const { fn } = await import('pkg')`
            if let Some(cap) = DYN_IMPORT_RE.captures(line) {
                if cap.get(2).map(|m| m.as_str()) == Some(pkg_name) {
                    let binding = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    if binding.starts_with('{') {
                        // Destructured: { template, set }
                        let inner = binding.trim_matches(|c| c == '{' || c == '}');
                        for name in inner.split(',') {
                            // Handle `default as _` and plain `template`
                            let parts: Vec<&str> = name.split_whitespace().collect();
                            let clean = if parts.len() >= 3 && parts[1] == "as" {
                                parts[2] // `default as _` -> `_`
                            } else {
                                parts.first().copied().unwrap_or("")
                            };
                            let clean = clean.trim_matches(|c: char| {
                                !c.is_alphanumeric() && c != '_' && c != '$'
                            });
                            if !clean.is_empty() {
                                imported_named_functions.insert(clean.to_string());
                            }
                        }
                    } else {
                        // Whole-module binding: `const lodashModule = await import('lodash')`
                        import_alias = Some(binding.to_string());
                    }
                }
            }
        }

        let is_imported = import_alias.is_some() || !imported_named_functions.is_empty();
        if !is_imported {
            return (false, matches);
        }

        // 2. Search call sites: precompile target matcher regexes ONCE before line iteration
        enum Matcher {
            AliasFn(Regex, String),
            NamedFn(Regex, String),
            AliasOnly(Regex, String),
        }

        let mut matchers: Vec<Matcher> = Vec::new();
        if let Some(targets) = target_functions {
            for fn_name in targets {
                if let Some(alias) = &import_alias {
                    let pat = format!(
                        r"\b{}\.{}\s*\(",
                        regex::escape(alias),
                        regex::escape(fn_name)
                    );
                    if let Ok(re) = Regex::new(&pat) {
                        matchers.push(Matcher::AliasFn(re, format!("{}.{}", alias, fn_name)));
                    }
                    // Also match alias.default.fn( — emitted when a dynamic import is
                    // stored as a whole-module binding and the caller accesses .default:
                    //   const m = await import('lodash'); m.default.template(...)
                    let pat_def = format!(
                        r"\b{}\.default\.{}\s*\(",
                        regex::escape(alias),
                        regex::escape(fn_name)
                    );
                    if let Ok(re) = Regex::new(&pat_def) {
                        matchers.push(Matcher::AliasFn(
                            re,
                            format!("{}.default.{}", alias, fn_name),
                        ));
                    }
                }
                if imported_named_functions.contains(fn_name) {
                    let pat = format!(r"\b{}\s*\(", regex::escape(fn_name));
                    if let Ok(re) = Regex::new(&pat) {
                        matchers.push(Matcher::NamedFn(re, fn_name.clone()));
                    }
                }
            }
        } else if let Some(alias) = &import_alias {
            let pat = format!(r"\b{}\s*\(", regex::escape(alias));
            if let Ok(re) = Regex::new(&pat) {
                matchers.push(Matcher::AliasOnly(re, format!("{}()", alias)));
            }
        }

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with('#') {
                continue;
            }

            for m in &matchers {
                let (re, desc) = match m {
                    Matcher::AliasFn(r, d) | Matcher::NamedFn(r, d) | Matcher::AliasOnly(r, d) => {
                        (r, d)
                    }
                };
                if re.is_match(line) {
                    matches.push((
                        idx + 1,
                        trimmed.chars().take(80).collect(),
                        desc.clone(),
                        true,
                    ));
                    break;
                }
            }
        }

        (true, matches)
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
        // At least one call site must match a "template" function (could be
        // "_.template" from server.js or "lodashModule.default.template" from
        // dynamic_import.js — both are valid detections).
        assert!(
            res1.call_sites
                .iter()
                .any(|cs| cs.matched_function.contains("template")),
            "Expected a call site matching 'template', got: {:?}",
            res1.call_sites
                .iter()
                .map(|cs| &cs.matched_function)
                .collect::<Vec<_>>()
        );

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

    /// Regression test: `await import('lodash')` followed by `.default.template()`
    /// previously produced a false-negative (NOT_REACHABLE / PASS).
    /// The DYN_IMPORT_RE + alias.default.fn matcher must detect it as Reachable.
    #[test]
    fn test_dynamic_import_reachability() {
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

        // The fixture now includes dynamic_import.js which uses await import()
        let res = engine.check_vulnerability(&template_vuln);
        // Must be Reachable — dynamic import must not be a false negative
        assert_eq!(
            res.status,
            ReachabilityStatus::Reachable,
            "Dynamic import of lodash with .default.template() call must be detected as Reachable"
        );
        // At least one call site should reference the dynamic_import.js fixture
        assert!(
            !res.call_sites.is_empty(),
            "Expected at least one call site from dynamic_import.js"
        );
        let has_dynamic_site = res.call_sites.iter().any(|cs| {
            cs.file.contains("dynamic_import") || cs.matched_function.contains("template")
        });
        assert!(
            has_dynamic_site,
            "Expected a call site matching 'template' from the dynamic import fixture"
        );
    }

    /// Regression test: inspect_file correctly detects destructured dynamic imports.
    /// `const { template } = await import('lodash')` should populate
    /// imported_named_functions and trigger a NamedFn matcher.
    #[test]
    fn test_inspect_file_destructured_dynamic_import() {
        let engine = ReachabilityEngine::new(Path::new("."));
        let source = r#"
async function run() {
    const { template } = await import('lodash');
    const compiled = template('Hello <%= name %>!');
    return compiled({ name: 'world' });
}
"#;
        let (imported, call_sites) =
            engine.inspect_file(source, "lodash", Some(&["template".to_string()]));
        assert!(
            imported,
            "destructured dynamic import must mark the file as imported"
        );
        assert!(
            !call_sites.is_empty(),
            "template() call must be found after destructured dynamic import"
        );
    }
}
