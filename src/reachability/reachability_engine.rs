use crate::reachability::js_ast_analyzer::{
    analyze_file, source_type_for_path, ImportResolutionState,
};
use crate::reachability::workspace_index::WorkspaceAstIndex;
use crate::types::{
    ReachabilityResult, ReachabilityStatus, ReasonCode, UsageSignal, VulnerabilityFinding,
};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct IndexedFile {
    pub path: PathBuf,
    pub relative_path: String,
    pub is_test: bool,
    pub content: String,
    pub parse_failed: bool,
    pub has_dynamic_construct: bool,
    pub has_unresolved_dynamic: bool,
    pub has_reexports: bool,
    pub import_states: Vec<ImportResolutionState>,
}

pub struct ReachabilityEngine {
    pub source_dir: PathBuf,
    pub source_files: Vec<PathBuf>,
    pub indexed_files: Vec<IndexedFile>,
    pub ast_index: WorkspaceAstIndex,
    pub known_functions: HashMap<&'static str, Vec<&'static str>>,
    pub max_files: usize,
    pub files_discovered: usize,
    pub files_skipped: usize,
    pub files_failed: usize,
    pub file_limit_hit: bool,
    pub has_any_parse_failure: bool,
    pub has_any_unresolved_dynamic: bool,
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
static DYN_IMPORT_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"(?:const|let|var)\s+(\{[^}]+\}|[a-zA-Z0-9_$]+)\s*=\s*(?:await\s+)?import\(['"]([^'"]+)['"]\)"#).unwrap()
});
static PY_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r#"^import\s+([a-zA-Z0-9_]+)(?:\s+as\s+([a-zA-Z0-9_]+))?"#).unwrap()
});
static PY_FROM_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r#"^from\s+([a-zA-Z0-9_]+)\s+import\s+(.+)"#).unwrap());

pub fn is_test_path(rel_path: &str) -> bool {
    let s = rel_path.to_lowercase().replace('\\', "/");
    let name = s.rsplit('/').next().unwrap_or(&s);
    name.contains(".test.")
        || name.contains(".spec.")
        || name.starts_with("test_")
        || name.ends_with("_test.js")
        || name.ends_with("_test.ts")
        || name.ends_with("_test.mts")
        || name.ends_with("_test.cts")
        || s.contains("/test/")
        || s.contains("/tests/")
        || s.contains("/__tests__/")
        || s.starts_with("test/")
        || s.starts_with("tests/")
        || s.starts_with("__tests__/")
}

impl ReachabilityEngine {
    pub fn new(source_dir: &Path) -> Self {
        let max_files = std::env::var("VEXA_MAX_SOURCE_FILES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10_000);
        Self::new_with_limit(source_dir, max_files)
    }

    pub fn new_with_limit(source_dir: &Path, max_files: usize) -> Self {
        let ast_index = WorkspaceAstIndex::build(source_dir, max_files);
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

        let files_discovered = ast_index.files_discovered;
        let files_skipped = ast_index.files_skipped;
        let file_limit_hit = ast_index.file_limit_hit;
        let files_failed = ast_index.files_failed;
        let has_any_parse_failure = ast_index.has_any_parse_failure;
        let has_any_unresolved_dynamic = ast_index.has_any_unresolved_dynamic;
        let source_files: Vec<PathBuf> = ast_index.files.keys().cloned().collect();

        let indexed_files: Vec<IndexedFile> = ast_index
            .files
            .iter()
            .map(|(path, facts)| IndexedFile {
                path: path.clone(),
                relative_path: facts.relative_path.clone(),
                is_test: facts.is_test,
                content: String::new(),
                parse_failed: facts.parse_failed,
                has_dynamic_construct: facts.has_dynamic_loading,
                has_unresolved_dynamic: facts.has_dynamic_loading,
                has_reexports: facts.has_reexports || !facts.barrel_reexports.is_empty(),
                import_states: Vec::new(),
            })
            .collect();

        Self {
            source_dir: source_dir.to_path_buf(),
            source_files,
            indexed_files,
            ast_index,
            known_functions: known,
            max_files,
            files_discovered,
            files_skipped,
            files_failed,
            file_limit_hit,
            has_any_parse_failure,
            has_any_unresolved_dynamic,
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
            if let Ok(content) = fs::read_to_string(&p) {
                for token in content.split(|c: char| {
                    !c.is_alphanumeric() && c != '-' && c != '_' && c != '@' && c != '/'
                }) {
                    let clean = token.trim();
                    if !clean.is_empty()
                        && (clean.contains('/') || clean.starts_with('@') || clean.len() >= 3)
                    {
                        referenced.insert(clean.to_string());
                    }
                }
            }
        }

        referenced
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
        .or_else(|| {
            if !vuln.affected_symbols.is_empty() {
                Some(vuln.affected_symbols.clone())
            } else {
                None
            }
        })
        .or_else(|| self.infer_functions_from_details(vuln));

        let raw_pkg = if let Some(idx) = vuln.package.find(':') {
            &vuln.package[idx + 1..]
        } else {
            &vuln.package
        };

        let pkg_name = if let Some(idx) = raw_pkg.find('@') {
            if idx > 0 {
                &raw_pkg[..idx]
            } else {
                raw_pkg
            }
        } else {
            raw_pkg
        };

        let mut candidates = vec![pkg_name.to_string()];
        let lower = pkg_name.to_lowercase();
        if lower != pkg_name {
            candidates.push(lower.clone());
        }
        let hyphen = pkg_name.replace('_', "-");
        if hyphen != pkg_name {
            candidates.push(hyphen);
        }
        let under = pkg_name.replace('-', "_");
        if under != pkg_name {
            candidates.push(under);
        }
        match lower.as_str() {
            "pyyaml" | "yaml" => candidates.push("pyyaml".to_string()),
            "beautifulsoup4" | "bs4" => candidates.push("beautifulsoup4".to_string()),
            "pillow" | "pil" => candidates.push("pillow".to_string()),
            "opencv-python" | "cv2" => candidates.push("opencv-python".to_string()),
            _ => {}
        }

        let mut imported_in_prod = false;
        let mut imported_in_test = false;
        let mut dynamic_construct_detected = false;
        let mut has_reexports = false;
        let mut parse_failed = self.has_any_parse_failure;

        for cand in &candidates {
            if let Some(files) = self.ast_index.package_importers.get(cand) {
                for fpath in files {
                    if let Some(facts) = self.ast_index.files.get(fpath) {
                        if facts.is_test {
                            imported_in_test = true;
                        } else {
                            imported_in_prod = true;
                        }
                        if facts.has_dynamic_loading {
                            dynamic_construct_detected = true;
                        }
                        if facts.has_reexports || !facts.barrel_reexports.is_empty() {
                            has_reexports = true;
                        }
                        if facts.parse_failed {
                            parse_failed = true;
                        }
                    }
                }
            }
        }

        let mut prod_call_sites = Vec::new();
        let mut test_call_sites = Vec::new();
        let mut seen_sites: HashSet<(String, usize)> = HashSet::new();

        for cand in &candidates {
            if let Some(ref targets) = target_functions {
                for t in targets {
                    if let Some(sites) = self.ast_index.symbol_calls.get(&(cand.clone(), t.clone())) {
                        for s in sites {
                            if seen_sites.insert((s.file.clone(), s.line)) {
                                if is_test_path(&s.file) {
                                    test_call_sites.push(s.clone());
                                } else {
                                    prod_call_sites.push(s.clone());
                                }
                            }
                        }
                    }
                }
                // Check wildcard symbol
                if let Some(sites) = self.ast_index.symbol_calls.get(&(cand.clone(), "*".to_string())) {
                    for s in sites {
                        if seen_sites.insert((s.file.clone(), s.line)) {
                            if is_test_path(&s.file) {
                                test_call_sites.push(s.clone());
                            } else {
                                prod_call_sites.push(s.clone());
                            }
                        }
                    }
                }
            } else {
                for ((p, _sym), sites) in &self.ast_index.symbol_calls {
                    if p == cand {
                        for s in sites {
                            if seen_sites.insert((s.file.clone(), s.line)) {
                                if is_test_path(&s.file) {
                                    test_call_sites.push(s.clone());
                                } else {
                                    prod_call_sites.push(s.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        let has_prod_call_sites = !prod_call_sites.is_empty();
        let is_specific = prod_call_sites.iter().any(|c| c.is_specific_function_match)
            || test_call_sites.iter().any(|c| c.is_specific_function_match);

        // Determine UsageSignal per FR-007a
        let usage_signal = if has_prod_call_sites || imported_in_prod || has_reexports {
            UsageSignal::ImportedSource
        } else if !test_call_sites.is_empty()
            || imported_in_test
            || self.config_referenced_pkgs.contains(pkg_name)
        {
            UsageSignal::ReferencedConfigOrScript
        } else if self.file_limit_hit || self.source_files.is_empty() {
            UsageSignal::Unknown
        } else {
            UsageSignal::NoReferenceFoundWithinScope
        };

        // Determine Reachability Verdict under conservative positive-proof scope (DDD Section 3.2.3)
        let (status, reason_code) = if has_prod_call_sites {
            // Proven syntactic usage signal found in production code path
            (
                ReachabilityStatus::Reachable,
                Some(ReasonCode::DirectUsageFound),
            )
        } else if self.files_failed > 0 {
            (ReachabilityStatus::Unknown, Some(ReasonCode::AnalysisError))
        } else if parse_failed {
            // Syntax error prevented complete verification
            (ReachabilityStatus::Unknown, Some(ReasonCode::ParseError))
        } else if self.has_any_unresolved_dynamic {
            // Unresolved variable or dynamic import where package cannot be ruled out
            (
                ReachabilityStatus::Unknown,
                Some(ReasonCode::DynamicConstruct),
            )
        } else if dynamic_construct_detected
            && (imported_in_prod
                || imported_in_test
                || self.config_referenced_pkgs.contains(pkg_name))
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
        } else if self.file_limit_hit {
            (ReachabilityStatus::Unknown, Some(ReasonCode::FileLimitHit))
        } else if self.source_files.is_empty() {
            (
                ReachabilityStatus::Unknown,
                Some(ReasonCode::SourceUnavailable),
            )
        } else if vuln.is_transitive {
            (
                ReachabilityStatus::Unknown,
                Some(ReasonCode::TransitiveNotAnalyzed),
            )
        } else if imported_in_prod && target_functions.is_none() {
            // Package is imported in production, but no structured symbol data is available
            (ReachabilityStatus::Unknown, Some(ReasonCode::NoSymbolData))
        } else {
            // Positive proof of unreachability under complete coverage (BUG-004):
            // Either package has NO_REFERENCE_FOUND_WITHIN_SCOPE, or imported but target vulnerable symbols are not called
            (
                ReachabilityStatus::Unreachable,
                Some(ReasonCode::AnalysisCompleteNoUsage),
            )
        };

        let mut combined_call_sites = prod_call_sites;
        if combined_call_sites.is_empty() {
            combined_call_sites = test_call_sites;
        }

        let result = ReachabilityResult {
            status,
            is_direct_call: is_specific,
            call_sites: combined_call_sites.into_iter().take(5).collect(),
            target_functions: target_functions.unwrap_or_else(|| vec!["*".to_string()]),
            reason_code,
            analyzer_version: env!("CARGO_PKG_VERSION").to_string(),
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

    pub fn inspect_file_path(
        &self,
        path: &Path,
        content: &str,
        pkg_name: &str,
        target_functions: Option<&[String]>,
    ) -> (bool, Vec<(usize, String, String, bool)>) {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        // 1. JS / TS: dispatch via oxc_parser with source type derived from path (BUG-003)
        if let Some(source_type) = source_type_for_path(path) {
            let ast_res = analyze_file(content, source_type, pkg_name, target_functions);
            if !ast_res.parse_failed && ast_res.is_imported {
                return (true, ast_res.call_sites);
            }
        } else if ext == "rs" || ext == "py" || ext == "go" || ext == "java" {
            // Non-JS languages: do NOT pass to oxc_parser (BUG-003)
        } else {
            // Unknown extensions: do NOT pass to oxc_parser or map to mjs (BUG-003)
            return (false, Vec::new());
        }

        self.inspect_file_fallback(content, pkg_name, target_functions)
    }

    pub fn inspect_file(
        &self,
        content: &str,
        pkg_name: &str,
        target_functions: Option<&[String]>,
    ) -> (bool, Vec<(usize, String, String, bool)>) {
        // Only attempt oxc_parser if content looks like JS/TS, NOT Rust/Python/Go/Java (BUG-003)
        let is_rust = content.contains("fn ") || content.contains("use ") || content.contains("pub mod ");
        let is_python = content.contains("def ") || content.contains("import ") && content.contains(":\n");
        let is_go = content.contains("package ") || content.contains("func ");
        let is_java = content.contains("public class ") || content.contains("package ");

        if !is_rust && !is_python && !is_go && !is_java {
            let ast_res = analyze_file(
                content,
                oxc_span::SourceType::mjs(),
                pkg_name,
                target_functions,
            );
            if !ast_res.parse_failed && ast_res.is_imported {
                return (true, ast_res.call_sites);
            }
        }

        self.inspect_file_fallback(content, pkg_name, target_functions)
    }

    fn inspect_file_fallback(
        &self,
        content: &str,
        pkg_name: &str,
        target_functions: Option<&[String]>,
    ) -> (bool, Vec<(usize, String, String, bool)>) {

        if !content.contains(pkg_name) {
            return (false, Vec::new());
        }

        let lines: Vec<&str> = content.lines().collect();
        let mut matches = Vec::new();
        let mut import_alias: Option<String> = None;
        let mut imported_named_functions: HashSet<String> = HashSet::new();

        for line in &lines {
            if let Some(cap) = REQ_RE.captures(line) {
                if cap.get(2).map_or("", |m| m.as_str()) == pkg_name {
                    import_alias = Some(cap.get(1).unwrap().as_str().to_string());
                }
            } else if let Some(cap) = ESM_RE.captures(line) {
                if cap.get(2).map_or("", |m| m.as_str()) == pkg_name {
                    import_alias = Some(cap.get(1).unwrap().as_str().to_string());
                }
            } else if let Some(cap) = NAMED_ESM_RE.captures(line) {
                if cap.get(2).map_or("", |m| m.as_str()) == pkg_name {
                    if let Some(funcs) = cap.get(1) {
                        for f in funcs.as_str().split(',') {
                            let clean_f = f.split(" as ").next().unwrap().trim();
                            if !clean_f.is_empty() {
                                imported_named_functions.insert(clean_f.to_string());
                            }
                        }
                    }
                }
            } else if let Some(cap) = DYN_IMPORT_RE.captures(line) {
                if cap.get(2).map_or("", |m| m.as_str()) == pkg_name {
                    if let Some(binding) = cap.get(1) {
                        let b_str = binding.as_str().trim();
                        if b_str.starts_with('{') && b_str.ends_with('}') {
                            let inner = &b_str[1..b_str.len() - 1];
                            for f in inner.split(',') {
                                let clean = f.split(':').next().unwrap_or(f).trim();
                                if !clean.is_empty() {
                                    imported_named_functions.insert(clean.to_string());
                                }
                            }
                        } else {
                            import_alias = Some(b_str.to_string());
                        }
                    }
                }
            } else if let Some(cap) = PY_RE.captures(line) {
                if cap.get(1).map_or("", |m| m.as_str()) == pkg_name {
                    let alias = cap
                        .get(2)
                        .map(|m| m.as_str())
                        .unwrap_or_else(|| cap.get(1).unwrap().as_str());
                    import_alias = Some(alias.to_string());
                }
            } else if let Some(cap) = PY_FROM_RE.captures(line) {
                if cap.get(1).map_or("", |m| m.as_str()) == pkg_name {
                    if let Some(funcs) = cap.get(2) {
                        for f in funcs.as_str().split(',') {
                            let clean_f = f.split(" as ").next().unwrap().trim();
                            if !clean_f.is_empty() {
                                imported_named_functions.insert(clean_f.to_string());
                            }
                        }
                    }
                }
            }
        }

        let is_imported = import_alias.is_some() || !imported_named_functions.is_empty();
        if !is_imported {
            return (false, matches);
        }

        let targets: Vec<String> = if let Some(funcs) = target_functions {
            funcs.to_vec()
        } else {
            vec!["*".to_string()]
        };

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if let Some(alias) = &import_alias {
                for fn_name in &targets {
                    let pattern = if fn_name == "*" {
                        format!(r#"\b{}\.([a-zA-Z0-9_]+)\("#, regex::escape(alias))
                    } else {
                        format!(
                            r#"\b{}\.{}\("#,
                            regex::escape(alias),
                            regex::escape(fn_name)
                        )
                    };
                    if let Ok(re) = Regex::new(&pattern) {
                        if let Some(cap) = re.captures(trimmed) {
                            let matched_fn = if fn_name == "*" {
                                cap.get(1).map_or("*", |m| m.as_str()).to_string()
                            } else {
                                fn_name.clone()
                            };
                            matches.push((
                                line_num,
                                trimmed.chars().take(80).collect(),
                                format!("{}.{}", alias, matched_fn),
                                fn_name != "*",
                            ));
                            break;
                        }
                    }
                }
            }

            for fn_name in &imported_named_functions {
                let is_match = targets.contains(&"*".to_string()) || targets.contains(fn_name);
                if is_match {
                    let pattern = format!(r#"\b{}\("#, regex::escape(fn_name));
                    if let Ok(re) = Regex::new(&pattern) {
                        if re.is_match(trimmed) {
                            matches.push((
                                line_num,
                                trimmed.chars().take(80).collect(),
                                fn_name.clone(),
                                true,
                            ));
                            break;
                        }
                    }
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
            ..Default::default()
        };

        let res = engine.check_vulnerability(&template_vuln);
        assert_eq!(res.status, ReachabilityStatus::Reachable);
        assert!(!res.call_sites.is_empty());

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
        assert_eq!(res2.reason_code, Some(ReasonCode::AnalysisCompleteNoUsage));
        assert!(res2.call_sites.is_empty());
    }

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

        let res = engine.check_vulnerability(&template_vuln);
        assert_eq!(res.status, ReachabilityStatus::Reachable);
        assert!(!res.call_sites.is_empty());
    }

    #[test]
    fn test_inspect_file_destructured_dynamic_import() {
        let temp = temp_project("", "destructured-dynamic");
        let engine = ReachabilityEngine::new(&temp);
        let _ = std::fs::remove_dir_all(&temp);
        let source = r#"
async function run() {
    const { template } = await import('lodash');
    const compiled = template('Hello <%= name %>!');
    return compiled({ name: 'world' });
}
"#;
        let (imported, call_sites) =
            engine.inspect_file(source, "lodash", Some(&["template".to_string()]));
        assert!(imported);
        assert!(!call_sites.is_empty());
    }

    fn temp_project(source: &str, label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "vexa-reachability-{}-{}-{}",
            label,
            std::process::id(),
            unique
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.js"), source).unwrap();
        dir
    }

    fn lodash_template_finding() -> VulnerabilityFinding {
        VulnerabilityFinding {
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
            ..Default::default()
        }
    }

    #[test]
    fn chained_dynamic_import_without_binding_is_not_declared_unreachable() {
        let dir = temp_project(
            "import('lodash').then(({ template }) => template('Hello <%= name %>!'));",
            "chained-dynamic",
        );
        let engine = ReachabilityEngine::new_with_limit(&dir, 100);
        let result = engine.check_vulnerability(&lodash_template_finding());
        assert_ne!(result.status, ReachabilityStatus::Unreachable);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn shadowed_dynamic_import_binding_is_not_declared_unreachable() {
        let dir = temp_project(
            "const moduleName = 'lodash';\nasync function run() { const mod = await import(moduleName); mod.template('Hello'); function unrelated() { const moduleName = 'not-lodash'; return import(moduleName); } }",
            "shadowed-dynamic",
        );
        let engine = ReachabilityEngine::new_with_limit(&dir, 100);
        let result = engine.check_vulnerability(&lodash_template_finding());
        assert_ne!(result.status, ReachabilityStatus::Unreachable);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn reexports_star_and_named_is_not_declared_unreachable() {
        let dir = temp_project(
            "export * from 'lodash'; export { template } from 'lodash';",
            "reexports",
        );
        let engine = ReachabilityEngine::new_with_limit(&dir, 100);
        let result = engine.check_vulnerability(&lodash_template_finding());
        assert_ne!(result.status, ReachabilityStatus::Unreachable);
        assert_eq!(result.status, ReachabilityStatus::Unknown);
        assert_eq!(
            result.reason_code,
            Some(crate::types::ReasonCode::CrossFileUnresolved)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn syntax_error_in_source_is_not_declared_unreachable() {
        let dir = temp_project(
            "function broken() { if (true) { return 1; // missing closing braces",
            "syntax-error",
        );
        let engine = ReachabilityEngine::new_with_limit(&dir, 100);
        let result = engine.check_vulnerability(&lodash_template_finding());
        assert_ne!(result.status, ReachabilityStatus::Unreachable);
        assert_eq!(result.status, ReachabilityStatus::Unknown);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_syntactic_match_when_coverage_complete_yields_unreachable() {
        // Safe app with no lodash references
        let dir = temp_project(
            "console.log('completely unrelated application code');",
            "no-match",
        );
        let engine = ReachabilityEngine::new_with_limit(&dir, 100);
        let (result, usage) = engine.check_vulnerability_and_usage(&lodash_template_finding());
        // BUG-004: Direct dependency with complete coverage and no references -> proven Unreachable
        assert_eq!(result.status, ReachabilityStatus::Unreachable);
        assert_eq!(
            result.reason_code,
            Some(crate::types::ReasonCode::AnalysisCompleteNoUsage)
        );
        assert_eq!(
            usage,
            crate::types::UsageSignal::NoReferenceFoundWithinScope
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn bundler_plugin_dynamic_require_pattern_is_not_declared_unreachable() {
        let dir = temp_project(
            "const ctx = require.context('./plugins', true, /\\.js$/); const req = eval('require'); req('lodash');",
            "bundler-plugins",
        );
        let engine = ReachabilityEngine::new_with_limit(&dir, 100);
        let result = engine.check_vulnerability(&lodash_template_finding());
        assert_ne!(result.status, ReachabilityStatus::Unreachable);
        assert_eq!(result.status, ReachabilityStatus::Unknown);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn source_file_limit_hit_is_not_declared_unreachable() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vexa-limit-hit-{}", unique));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.js"), "console.log(1);").unwrap();
        std::fs::write(dir.join("b.js"), "console.log(2);").unwrap();
        std::fs::write(dir.join("c.js"), "console.log(3);").unwrap();

        // Limit to 1 file so files_skipped > 0 and file_limit_hit is true
        let engine = ReachabilityEngine::new_with_limit(&dir, 1);
        assert!(engine.file_limit_hit);
        let result = engine.check_vulnerability(&lodash_template_finding());
        assert_ne!(result.status, ReachabilityStatus::Unreachable);
        assert_eq!(result.status, ReachabilityStatus::Unknown);
        assert_eq!(
            result.reason_code,
            Some(crate::types::ReasonCode::FileLimitHit)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_rust_ast_reachability() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vexa-rust-reach-{}", unique));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("main.rs"),
            r#"
use serde_json::from_str;

fn main() {
    let _ = serde_json::from_str::<serde_json::Value>("{}");
}
"#,
        )
        .unwrap();

        let engine = ReachabilityEngine::new_with_limit(&dir, 100);
        let serde_vuln = VulnerabilityFinding {
            id: "RUSTSEC-2023-0001".to_string(),
            title: "Denial of Service in serde_json".to_string(),
            package: "serde-json".to_string(),
            version: "1.0.80".to_string(),
            ecosystem: "Cargo".to_string(),
            pkg_id: "serde-json@1.0.80".to_string(),
            affected_symbols: vec!["from_str".to_string()],
            ..Default::default()
        };

        let result = engine.check_vulnerability(&serde_vuln);
        assert_eq!(result.status, ReachabilityStatus::Reachable);
        assert!(!result.call_sites.is_empty());

        let unused_vuln = VulnerabilityFinding {
            id: "RUSTSEC-2023-0002".to_string(),
            title: "Flaw in to_vec".to_string(),
            package: "serde-json".to_string(),
            version: "1.0.80".to_string(),
            ecosystem: "Cargo".to_string(),
            pkg_id: "serde-json@1.0.80".to_string(),
            affected_symbols: vec!["to_vec".to_string()],
            ..Default::default()
        };

        let result2 = engine.check_vulnerability(&unused_vuln);
        assert_eq!(result2.status, ReachabilityStatus::Unreachable);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_python_ast_reachability() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vexa-python-reach-{}", unique));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("app.py"),
            r#"
import yaml

def load_config():
    return yaml.load("a: 1")
"#,
        )
        .unwrap();

        let engine = ReachabilityEngine::new_with_limit(&dir, 100);
        let pyyaml_vuln = VulnerabilityFinding {
            id: "PYSEC-2020-001".to_string(),
            title: "Code Execution in PyYAML load".to_string(),
            package: "pyyaml".to_string(),
            version: "5.3.1".to_string(),
            ecosystem: "PyPI".to_string(),
            pkg_id: "pyyaml@5.3.1".to_string(),
            affected_symbols: vec!["load".to_string()],
            ..Default::default()
        };

        let result = engine.check_vulnerability(&pyyaml_vuln);
        assert_eq!(result.status, ReachabilityStatus::Reachable);
        assert!(!result.call_sites.is_empty());

        let unused_vuln = VulnerabilityFinding {
            id: "PYSEC-2020-002".to_string(),
            title: "Flaw in dump".to_string(),
            package: "pyyaml".to_string(),
            version: "5.3.1".to_string(),
            ecosystem: "PyPI".to_string(),
            pkg_id: "pyyaml@5.3.1".to_string(),
            affected_symbols: vec!["dump".to_string()],
            ..Default::default()
        };

        let result2 = engine.check_vulnerability(&unused_vuln);
        assert_eq!(result2.status, ReachabilityStatus::Unreachable);
        let _ = std::fs::remove_dir_all(dir);
    }
}
