#![forbid(unsafe_code)]

use crate::reachability::js_ast_analyzer::{
    analyze_file, source_type_for_path, ImportResolutionState,
};
use crate::types::CallSite;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SourceLanguage {
    JavaScriptOrTypeScript,
    Rust,
    Python,
    Go,
    Java,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileAstFacts {
    pub relative_path: String,
    pub language: SourceLanguage,
    /// Map of external package name -> imported symbol names ("*" for namespace/default import)
    pub external_imports: HashMap<String, HashSet<String>>,
    /// Relative paths re-exported by this file
    pub barrel_reexports: Vec<String>,
    pub has_reexports: bool,
    /// Map of (package_name, symbol) -> call sites in this file
    pub call_sites: HashMap<(String, String), Vec<CallSite>>,
    pub has_dynamic_loading: bool,
    pub parse_failed: bool,
    pub is_test: bool,
}

pub struct WorkspaceAstIndex {
    pub files: HashMap<PathBuf, FileAstFacts>,
    /// Inverted index: package_name -> set of files importing it
    pub package_importers: HashMap<String, Vec<PathBuf>>,
    /// Inverted index: (package_name, symbol) -> call sites
    pub symbol_calls: HashMap<(String, String), Vec<CallSite>>,
    pub files_discovered: usize,
    pub files_analyzed: usize,
    pub files_skipped: usize,
    pub files_failed: usize,
    pub file_limit_hit: bool,
    pub parse_complete: bool,
    pub has_any_unresolved_dynamic: bool,
    pub has_any_parse_failure: bool,
}

impl WorkspaceAstIndex {
    pub fn build(source_dir: &Path, max_files: usize) -> Self {
        let (source_files, discovered, skipped, limit_hit, mut failed) =
            Self::find_source_files(source_dir, max_files);

        let mut files = HashMap::new();
        let mut package_importers: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let mut symbol_calls: HashMap<(String, String), Vec<CallSite>> = HashMap::new();
        let mut has_any_unresolved_dynamic = false;
        let mut has_any_parse_failure = false;

        for file_path in &source_files {
            let content = match fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => {
                    failed += 1;
                    continue;
                }
            };

            let rel_path = file_path
                .strip_prefix(source_dir)
                .unwrap_or(file_path)
                .to_string_lossy()
                .replace('\\', "/");

            let is_test = is_test_path(&rel_path);
            let ext = file_path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            let facts = if let Some(source_type) = source_type_for_path(file_path) {
                // JS / TS analysis via oxc_parser
                Self::analyze_js_file(
                    &content,
                    source_type,
                    &rel_path,
                    is_test,
                    &mut has_any_unresolved_dynamic,
                    &mut has_any_parse_failure,
                )
            } else if ext == "rs" {
                // Rust analysis
                Self::analyze_rust_file(&content, &rel_path, is_test)
            } else if ext == "py" {
                // Python analysis
                Self::analyze_python_file(&content, &rel_path, is_test)
            } else if ext == "go" {
                // Go analysis
                Self::analyze_go_file(&content, &rel_path, is_test)
            } else if ext == "java" {
                // Java analysis
                Self::analyze_java_file(&content, &rel_path, is_test)
            } else {
                continue;
            };

            for (pkg, sites) in &facts.call_sites {
                for site in sites {
                    symbol_calls
                        .entry(pkg.clone())
                        .or_default()
                        .push(site.clone());
                }
            }

            for pkg in facts.external_imports.keys() {
                package_importers
                    .entry(pkg.clone())
                    .or_default()
                    .push(file_path.clone());
            }

            files.insert(file_path.clone(), facts);
        }

        // Multi-hop barrel re-export resolution (up to 8 hops)
        for _ in 0..8 {
            let mut propagated = Vec::new();
            for (file_path, facts) in &files {
                for rel_reexport in &facts.barrel_reexports {
                    if let Some(target) = Self::resolve_local_reexport_path(
                        file_path.parent().unwrap_or(source_dir),
                        rel_reexport,
                    ) {
                        if let Some(target_facts) = files.get(&target) {
                            for (pkg, syms) in &target_facts.external_imports {
                                propagated.push((file_path.clone(), pkg.clone(), syms.clone()));
                            }
                        }
                    }
                }
            }
            if propagated.is_empty() {
                break;
            }
            let mut any_new = false;
            for (fpath, pkg, syms) in propagated {
                if let Some(facts) = files.get_mut(&fpath) {
                    let entry = facts.external_imports.entry(pkg.clone()).or_default();
                    for s in syms {
                        if entry.insert(s) {
                            any_new = true;
                        }
                    }
                    package_importers.entry(pkg).or_default().push(fpath);
                }
            }
            if !any_new {
                break;
            }
        }

        // Re-evaluate call sites and clear local barrel re-exports that were fully resolved in workspace
        let known_files: HashSet<PathBuf> = files.keys().cloned().collect();
        for (file_path, facts) in files.iter_mut() {
            if !facts.barrel_reexports.is_empty() {
                let reexport_dir = file_path.parent().unwrap_or(source_dir);
                let all_local_resolved = facts.barrel_reexports.iter().all(|rel| {
                    Self::resolve_local_reexport_path(reexport_dir, rel)
                        .map(|t| known_files.contains(&t))
                        .unwrap_or(false)
                });
                if all_local_resolved && !facts.has_reexports {
                    facts.barrel_reexports.clear();
                }
            }
        }

        let analyzed = files.len();
        let parse_complete = failed == 0 && !limit_hit && !has_any_parse_failure;

        Self {
            files,
            package_importers,
            symbol_calls,
            files_discovered: discovered,
            files_analyzed: analyzed,
            files_skipped: skipped,
            files_failed: failed,
            file_limit_hit: limit_hit,
            parse_complete,
            has_any_unresolved_dynamic,
            has_any_parse_failure,
        }
    }

    fn analyze_js_file(
        content: &str,
        source_type: oxc_span::SourceType,
        rel_path: &str,
        is_test: bool,
        has_any_unresolved_dynamic: &mut bool,
        has_any_parse_failure: &mut bool,
    ) -> FileAstFacts {
        let general_analysis = analyze_file(content, source_type, "", None);
        if general_analysis.parse_failed {
            *has_any_parse_failure = true;
        }
        if general_analysis.has_unresolved_dynamic {
            *has_any_unresolved_dynamic = true;
        }

        let mut external_imports: HashMap<String, HashSet<String>> = HashMap::new();
        let mut barrel_reexports = Vec::new();

        for state in general_analysis.import_states {
            match state {
                ImportResolutionState::LiteralPackageSpecifier(pkg)
                | ImportResolutionState::ResolvedConstantSpecifier(pkg) => {
                    let clean = pkg.trim().trim_matches('\'').trim_matches('"');
                    let base_pkg = if clean.starts_with('@') {
                        let parts: Vec<&str> = clean.split('/').collect();
                        if parts.len() >= 2 {
                            format!("{}/{}", parts[0], parts[1])
                        } else {
                            clean.to_string()
                        }
                    } else if let Some(idx) = clean.find('/') {
                        clean[..idx].to_string()
                    } else {
                        clean.to_string()
                    };
                    external_imports
                        .entry(base_pkg.clone())
                        .or_default()
                        .insert("*".to_string());
                    if base_pkg != clean {
                        external_imports
                            .entry(clean.to_string())
                            .or_default()
                            .insert("*".to_string());
                    }
                }
                ImportResolutionState::NonPackageImport(path) => {
                    if path.starts_with('.') {
                        barrel_reexports.push(path);
                    }
                }
                ImportResolutionState::UnresolvedDynamicSpecifier(_) => {
                    // Handled above
                }
            }
        }

        // If file has dynamic construct (eval, createRequire, etc.), check if tokens match packages
        let has_dynamic =
            general_analysis.has_dynamic_construct || general_analysis.has_unresolved_dynamic;
        if has_dynamic {
            for line in content.lines() {
                for token in line.split(|c: char| {
                    !c.is_alphanumeric() && c != '-' && c != '_' && c != '@' && c != '/'
                }) {
                    let clean = token.trim().trim_matches('\'').trim_matches('"');
                    if !clean.is_empty() && (clean.starts_with('@') || clean.len() >= 3) {
                        external_imports
                            .entry(clean.to_string())
                            .or_default()
                            .insert("*".to_string());
                    }
                }
            }
        }

        let mut call_sites: HashMap<(String, String), Vec<CallSite>> = HashMap::new();

        // Scan for call sites matching imported packages
        for pkg_name in external_imports.keys() {
            let spec_analysis = analyze_file(content, source_type, pkg_name, None);
            for m in spec_analysis.call_sites {
                let site = CallSite {
                    file: rel_path.to_string(),
                    line: m.0,
                    code: m.1,
                    matched_function: m.2.clone(),
                    is_specific_function_match: m.3,
                };
                let sym = if let Some(idx) = m.2.rfind('.') {
                    m.2[idx + 1..].to_string()
                } else {
                    m.2.clone()
                };
                call_sites
                    .entry((pkg_name.clone(), sym.clone()))
                    .or_default()
                    .push(site.clone());
                if sym != m.2 {
                    call_sites
                        .entry((pkg_name.clone(), m.2))
                        .or_default()
                        .push(site);
                }
            }
        }

        // Only mark has_reexports when external package re-exports exist that are not resolved local barrels
        let has_external_reexport = general_analysis.has_reexports && barrel_reexports.is_empty();

        FileAstFacts {
            relative_path: rel_path.to_string(),
            language: SourceLanguage::JavaScriptOrTypeScript,
            external_imports,
            barrel_reexports,
            has_reexports: has_external_reexport,
            call_sites,
            has_dynamic_loading: general_analysis.has_dynamic_construct
                || general_analysis.has_unresolved_dynamic,
            parse_failed: general_analysis.parse_failed,
            is_test,
        }
    }

    fn resolve_local_reexport_path(reexport_dir: &Path, rel_reexport: &str) -> Option<PathBuf> {
        let candidates = [
            reexport_dir.join(rel_reexport),
            reexport_dir.join(format!("{}.js", rel_reexport)),
            reexport_dir.join(format!("{}.ts", rel_reexport)),
            reexport_dir.join(format!("{}.mjs", rel_reexport)),
            reexport_dir.join(format!("{}.cjs", rel_reexport)),
            reexport_dir.join(format!("{}/index.js", rel_reexport)),
            reexport_dir.join(format!("{}/index.ts", rel_reexport)),
        ];
        candidates.into_iter().find(|c| c.is_file())
    }

    fn analyze_rust_file(content: &str, rel_path: &str, is_test: bool) -> FileAstFacts {
        let mut external_imports: HashMap<String, HashSet<String>> = HashMap::new();
        let mut call_sites: HashMap<(String, String), Vec<CallSite>> = HashMap::new();
        let lines: Vec<&str> = content.lines().collect();

        let use_re = Regex::new(r"use\s+([a-zA-Z0-9_]+)(?:::([a-zA-Z0-9_{},\s\*]+))?;").unwrap();
        let call_re = Regex::new(r"([a-zA-Z0-9_]+)::([a-zA-Z0-9_]+)(?:::<[^>]*>)?\s*\(").unwrap();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if let Some(cap) = use_re.captures(trimmed) {
                if let Some(crate_name) = cap.get(1) {
                    let crate_str = crate_name.as_str();
                    if crate_str != "crate"
                        && crate_str != "super"
                        && crate_str != "std"
                        && crate_str != "core"
                    {
                        let mut symbols = HashSet::new();
                        if let Some(syms) = cap.get(2) {
                            for s in syms.as_str().split(',') {
                                let clean = s.trim().trim_matches('{').trim_matches('}').trim();
                                if !clean.is_empty() {
                                    symbols.insert(clean.to_string());
                                }
                            }
                        }
                        if symbols.is_empty() {
                            symbols.insert("*".to_string());
                        }

                        // Index both underscore and hyphen forms for Cargo package resolution
                        let hyphenated = crate_str.replace('_', "-");
                        external_imports
                            .entry(crate_str.to_string())
                            .or_default()
                            .extend(symbols.clone());
                        external_imports
                            .entry(hyphenated)
                            .or_default()
                            .extend(symbols);
                    }
                }
            }

            for cap in call_re.captures_iter(trimmed) {
                if let (Some(c), Some(fn_name)) = (cap.get(1), cap.get(2)) {
                    let crate_str = c.as_str();
                    let fn_str = fn_name.as_str();
                    let site = CallSite {
                        file: rel_path.to_string(),
                        line: idx + 1,
                        code: trimmed.to_string(),
                        matched_function: fn_str.to_string(),
                        is_specific_function_match: true,
                    };
                    call_sites
                        .entry((crate_str.to_string(), fn_str.to_string()))
                        .or_default()
                        .push(site.clone());
                    let hyphenated = crate_str.replace('_', "-");
                    call_sites
                        .entry((hyphenated, fn_str.to_string()))
                        .or_default()
                        .push(site);
                }
            }

            for (crate_name, syms) in &external_imports {
                for sym in syms {
                    if sym != "*" {
                        let direct_pat = format!(r"\b{}(?:::<[^>]*>)?\s*\(", regex::escape(sym));
                        if let Ok(re) = Regex::new(&direct_pat) {
                            if re.is_match(trimmed) && !trimmed.starts_with("use ") {
                                let site = CallSite {
                                    file: rel_path.to_string(),
                                    line: idx + 1,
                                    code: trimmed.to_string(),
                                    matched_function: sym.clone(),
                                    is_specific_function_match: true,
                                };
                                call_sites
                                    .entry((crate_name.clone(), sym.clone()))
                                    .or_default()
                                    .push(site);
                            }
                        }
                    }
                }
            }
        }

        FileAstFacts {
            relative_path: rel_path.to_string(),
            language: SourceLanguage::Rust,
            external_imports,
            barrel_reexports: vec![],
            has_reexports: false,
            call_sites,
            has_dynamic_loading: false,
            parse_failed: false,
            is_test,
        }
    }

    fn analyze_python_file(content: &str, rel_path: &str, is_test: bool) -> FileAstFacts {
        let mut external_imports: HashMap<String, HashSet<String>> = HashMap::new();
        let mut call_sites: HashMap<(String, String), Vec<CallSite>> = HashMap::new();
        let lines: Vec<&str> = content.lines().collect();

        let import_re =
            Regex::new(r"^import\s+([a-zA-Z0-9_\.]+)(?:\s+as\s+([a-zA-Z0-9_]+))?").unwrap();
        let from_re =
            Regex::new(r"^from\s+([a-zA-Z0-9_\.]+)\s+import\s+([a-zA-Z0-9_,\s\*]+)").unwrap();
        let call_re = Regex::new(r"([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)\s*\(").unwrap();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if let Some(cap) = import_re.captures(trimmed) {
                if let Some(pkg) = cap.get(1) {
                    let base_pkg = pkg.as_str().split('.').next().unwrap_or(pkg.as_str());
                    let norm = normalize_python_pkg(base_pkg);
                    external_imports
                        .entry(norm)
                        .or_default()
                        .insert("*".to_string());
                }
            } else if let Some(cap) = from_re.captures(trimmed) {
                if let Some(pkg) = cap.get(1) {
                    let base_pkg = pkg.as_str().split('.').next().unwrap_or(pkg.as_str());
                    let norm = normalize_python_pkg(base_pkg);
                    let mut syms = HashSet::new();
                    if let Some(sym_list) = cap.get(2) {
                        for s in sym_list.as_str().split(',') {
                            let clean = s.trim();
                            if !clean.is_empty() {
                                syms.insert(clean.to_string());
                            }
                        }
                    }
                    if syms.is_empty() {
                        syms.insert("*".to_string());
                    }
                    external_imports.entry(norm).or_default().extend(syms);
                }
            }

            for cap in call_re.captures_iter(trimmed) {
                if let (Some(m), Some(f)) = (cap.get(1), cap.get(2)) {
                    let mod_name = normalize_python_pkg(m.as_str());
                    let fn_name = f.as_str();
                    let site = CallSite {
                        file: rel_path.to_string(),
                        line: idx + 1,
                        code: trimmed.to_string(),
                        matched_function: fn_name.to_string(),
                        is_specific_function_match: true,
                    };
                    call_sites
                        .entry((mod_name, fn_name.to_string()))
                        .or_default()
                        .push(site);
                }
            }
        }

        let has_dynamic = content.contains("exec(")
            || content.contains("eval(")
            || content.contains("__import__");

        FileAstFacts {
            relative_path: rel_path.to_string(),
            language: SourceLanguage::Python,
            external_imports,
            barrel_reexports: vec![],
            has_reexports: false,
            call_sites,
            has_dynamic_loading: has_dynamic,
            parse_failed: false,
            is_test,
        }
    }

    fn analyze_go_file(content: &str, rel_path: &str, is_test: bool) -> FileAstFacts {
        let mut external_imports: HashMap<String, HashSet<String>> = HashMap::new();
        let mut call_sites: HashMap<(String, String), Vec<CallSite>> = HashMap::new();
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.contains('/') {
                let pkg = trimmed.trim_matches('"');
                let pkg_name = pkg.split('/').next_back().unwrap_or(pkg);
                external_imports
                    .entry(pkg_name.to_string())
                    .or_default()
                    .insert("*".to_string());
                external_imports
                    .entry(pkg.to_string())
                    .or_default()
                    .insert("*".to_string());
            }

            for pkg in external_imports.keys() {
                if line.contains(&format!("{}.", pkg)) {
                    let site = CallSite {
                        file: rel_path.to_string(),
                        line: idx + 1,
                        code: trimmed.to_string(),
                        matched_function: "*".to_string(),
                        is_specific_function_match: false,
                    };
                    call_sites
                        .entry((pkg.clone(), "*".to_string()))
                        .or_default()
                        .push(site);
                }
            }
        }

        FileAstFacts {
            relative_path: rel_path.to_string(),
            language: SourceLanguage::Go,
            external_imports,
            barrel_reexports: vec![],
            has_reexports: false,
            call_sites,
            has_dynamic_loading: false,
            parse_failed: false,
            is_test,
        }
    }

    fn analyze_java_file(content: &str, rel_path: &str, is_test: bool) -> FileAstFacts {
        let mut external_imports: HashMap<String, HashSet<String>> = HashMap::new();
        let mut call_sites: HashMap<(String, String), Vec<CallSite>> = HashMap::new();
        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") && trimmed.ends_with(';') {
                let imp = trimmed
                    .trim_start_matches("import ")
                    .trim_end_matches(';')
                    .trim();
                let parts: Vec<&str> = imp.split('.').collect();
                if parts.len() >= 2 {
                    let pkg = parts[parts.len() - 2];
                    let sym = parts[parts.len() - 1];
                    external_imports
                        .entry(pkg.to_string())
                        .or_default()
                        .insert(sym.to_string());
                }
            }

            for (pkg, syms) in &external_imports {
                for sym in syms {
                    if sym != "*" && line.contains(sym) {
                        let site = CallSite {
                            file: rel_path.to_string(),
                            line: idx + 1,
                            code: trimmed.to_string(),
                            matched_function: sym.clone(),
                            is_specific_function_match: true,
                        };
                        call_sites
                            .entry((pkg.clone(), sym.clone()))
                            .or_default()
                            .push(site);
                    }
                }
            }
        }

        FileAstFacts {
            relative_path: rel_path.to_string(),
            language: SourceLanguage::Java,
            external_imports,
            barrel_reexports: vec![],
            has_reexports: false,
            call_sites,
            has_dynamic_loading: content.contains("Class.forName")
                || content.contains("Method.invoke"),
            parse_failed: false,
            is_test,
        }
    }

    fn find_source_files(
        source_dir: &Path,
        max_files: usize,
    ) -> (Vec<PathBuf>, usize, usize, bool, usize) {
        let valid_exts = [
            "js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts", "rs", "py", "go", "java",
        ];
        let ignore_dirs: HashSet<&str> = [
            "node_modules",
            "target",
            "vendor",
            ".git",
            "dist",
            "build",
            ".next",
            ".nuxt",
            ".cache",
            "coverage",
            "inputs",
            "outputs",
            "completed",
            "fixtures",
            "test-fixtures",
            ".work",
        ]
        .iter()
        .cloned()
        .collect();

        let mut discovered = 0;
        let mut skipped = 0;
        let mut failed = 0;
        let mut files = Vec::new();
        let mut limit_hit = false;

        let walker = WalkDir::new(source_dir).into_iter().filter_entry(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                !ignore_dirs.contains(name.as_ref()) && !name.starts_with('.')
            } else {
                true
            }
        });

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    failed += 1;
                    continue;
                }
            };

            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if valid_exts.contains(&ext_str.as_str()) {
                        discovered += 1;
                        if max_files > 0 && files.len() >= max_files {
                            limit_hit = true;
                            skipped += 1;
                        } else {
                            files.push(entry.path().to_path_buf());
                        }
                    }
                }
            }
        }

        files.sort();
        (files, discovered, skipped, limit_hit, failed)
    }
}

fn normalize_python_pkg(name: &str) -> String {
    let lower = name.to_lowercase().replace('_', "-");
    match lower.as_str() {
        "pyyaml" | "yaml" => "pyyaml".to_string(),
        "beautifulsoup4" | "bs4" => "beautifulsoup4".to_string(),
        "pillow" | "pil" => "pillow".to_string(),
        "opencv-python" | "cv2" => "opencv-python".to_string(),
        _ => lower,
    }
}

fn is_test_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("test")
        || lower.contains("spec")
        || lower.contains("__tests__")
        || lower.contains("__test__")
}
