#![forbid(unsafe_code)]

//! Real Python 3 AST-based import and call-site analyzer powered by `rustpython-parser`.
//!
//! Replaces regex-only Python import heuristics with an AST pass that handles:
//! - `import pkg` and `import pkg as alias`
//! - `import pkg.submod as alias`
//! - `from pkg import fn1, fn2 as local_fn`
//! - `from pkg import *`
//! - Dynamic constructs (`importlib.import_module`, `__import__`, `eval`, `exec`)
//!   marked conservatively as `has_unresolved_dynamic = true` so they are never
//!   silently classified as Unreachable.

use rustpython_parser::ast::{self, Expr, Mod, Ranged, Stmt};
use rustpython_parser::{parse, Mode};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default, Clone)]
pub struct PythonFileAnalysis {
    pub is_imported: bool,
    pub call_sites: Vec<(usize, String, String, bool)>,
    pub has_unresolved_dynamic: bool,
    pub parse_failed: bool,
}

fn normalize_py_pkg(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase().replace('-', "_");
    match lower.as_str() {
        "pyyaml" => "yaml".to_string(),
        "pillow" => "pil".to_string(),
        "beautifulsoup4" => "bs4".to_string(),
        "scikit_learn" => "sklearn".to_string(),
        "python_dateutil" => "dateutil".to_string(),
        "opencv_python" => "cv2".to_string(),
        _ => lower,
    }
}

fn module_matches_pkg(module_name: &str, pkg_name: &str) -> bool {
    let norm_pkg = normalize_py_pkg(pkg_name);
    let top_mod = module_name
        .split('.')
        .next()
        .unwrap_or(module_name)
        .to_ascii_lowercase()
        .replace('-', "_");
    top_mod == norm_pkg || module_name.to_ascii_lowercase().replace('-', "_") == norm_pkg
}

struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(src: &str) -> Self {
        let mut starts = vec![0usize];
        for (i, b) in src.bytes().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        Self { starts }
    }

    fn line_for_offset(&self, offset: usize) -> usize {
        match self.starts.binary_search(&offset) {
            Ok(idx) => idx + 1,
            Err(idx) => idx.max(1),
        }
    }
}

pub fn analyze_python_file(
    source: &str,
    pkg_name: &str,
    target_functions: Option<&[String]>,
) -> PythonFileAnalysis {
    let mut out = PythonFileAnalysis::default();
    let Ok(parsed) = parse(source, Mode::Module, "<vexa>") else {
        out.parse_failed = true;
        return out;
    };

    let Mod::Module(module) = parsed else {
        return out;
    };

    let lines_vec: Vec<&str> = source.lines().collect();
    let line_idx = LineIndex::new(source);

    let mut pkg_aliases: HashSet<String> = HashSet::new();
    // local_name -> original_exported_name
    let mut named_imports: HashMap<String, String> = HashMap::new();
    let mut has_star_import = false;

    collect_imports(
        &module.body,
        pkg_name,
        &mut out,
        &mut pkg_aliases,
        &mut named_imports,
        &mut has_star_import,
    );

    walk_stmts(
        &module.body,
        &lines_vec,
        &line_idx,
        target_functions,
        &pkg_aliases,
        &named_imports,
        has_star_import,
        &mut out,
    );

    out
}

fn collect_imports(
    stmts: &[Stmt],
    pkg_name: &str,
    out: &mut PythonFileAnalysis,
    pkg_aliases: &mut HashSet<String>,
    named_imports: &mut HashMap<String, String>,
    has_star_import: &mut bool,
) {
    for stmt in stmts {
        match stmt {
            Stmt::Import(imp) => {
                for alias in &imp.names {
                    let mod_name = alias.name.as_str();
                    if module_matches_pkg(mod_name, pkg_name) {
                        out.is_imported = true;
                        let local = alias
                            .asname
                            .as_ref()
                            .map(|a| a.as_str())
                            .unwrap_or_else(|| mod_name.split('.').next().unwrap_or(mod_name));
                        pkg_aliases.insert(local.to_string());
                    }
                    if mod_name == "importlib" || mod_name.starts_with("importlib.") {
                        out.has_unresolved_dynamic = true;
                    }
                }
            }
            Stmt::ImportFrom(imp_from) => {
                if let Some(ref mod_ident) = imp_from.module {
                    let mod_name = mod_ident.as_str();
                    if module_matches_pkg(mod_name, pkg_name) {
                        out.is_imported = true;
                        for alias in &imp_from.names {
                            let sym = alias.name.as_str();
                            if sym == "*" {
                                *has_star_import = true;
                            } else {
                                let local =
                                    alias.asname.as_ref().map(|a| a.as_str()).unwrap_or(sym);
                                named_imports.insert(local.to_string(), sym.to_string());
                            }
                        }
                    }
                    if mod_name == "importlib" {
                        out.has_unresolved_dynamic = true;
                    }
                }
            }
            Stmt::FunctionDef(f) => collect_imports(
                &f.body,
                pkg_name,
                out,
                pkg_aliases,
                named_imports,
                has_star_import,
            ),
            Stmt::AsyncFunctionDef(f) => collect_imports(
                &f.body,
                pkg_name,
                out,
                pkg_aliases,
                named_imports,
                has_star_import,
            ),
            Stmt::ClassDef(c) => collect_imports(
                &c.body,
                pkg_name,
                out,
                pkg_aliases,
                named_imports,
                has_star_import,
            ),
            Stmt::If(s) => {
                collect_imports(
                    &s.body,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
                collect_imports(
                    &s.orelse,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
            }
            Stmt::With(s) => collect_imports(
                &s.body,
                pkg_name,
                out,
                pkg_aliases,
                named_imports,
                has_star_import,
            ),
            Stmt::AsyncWith(s) => collect_imports(
                &s.body,
                pkg_name,
                out,
                pkg_aliases,
                named_imports,
                has_star_import,
            ),
            Stmt::For(s) => {
                collect_imports(
                    &s.body,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
                collect_imports(
                    &s.orelse,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
            }
            Stmt::AsyncFor(s) => {
                collect_imports(
                    &s.body,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
                collect_imports(
                    &s.orelse,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
            }
            Stmt::While(s) => {
                collect_imports(
                    &s.body,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
                collect_imports(
                    &s.orelse,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
            }
            Stmt::Try(s) => {
                collect_imports(
                    &s.body,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
                for h in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(eh) = h;
                    collect_imports(
                        &eh.body,
                        pkg_name,
                        out,
                        pkg_aliases,
                        named_imports,
                        has_star_import,
                    );
                }
                collect_imports(
                    &s.orelse,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
                collect_imports(
                    &s.finalbody,
                    pkg_name,
                    out,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                );
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_stmts(
    stmts: &[Stmt],
    lines_vec: &[&str],
    line_idx: &LineIndex,
    target_functions: Option<&[String]>,
    pkg_aliases: &HashSet<String>,
    named_imports: &HashMap<String, String>,
    has_star_import: bool,
    out: &mut PythonFileAnalysis,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(f) => walk_stmts(
                &f.body,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            ),
            Stmt::AsyncFunctionDef(f) => walk_stmts(
                &f.body,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            ),
            Stmt::ClassDef(c) => walk_stmts(
                &c.body,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            ),
            Stmt::If(s) => {
                walk_expr(
                    &s.test,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                walk_stmts(
                    &s.body,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                walk_stmts(
                    &s.orelse,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
            Stmt::Return(s) => {
                if let Some(ref v) = s.value {
                    walk_expr(
                        v,
                        lines_vec,
                        line_idx,
                        target_functions,
                        pkg_aliases,
                        named_imports,
                        has_star_import,
                        out,
                    );
                }
            }
            Stmt::Assign(s) => walk_expr(
                &s.value,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            ),
            Stmt::AnnAssign(s) => {
                if let Some(ref v) = s.value {
                    walk_expr(
                        v,
                        lines_vec,
                        line_idx,
                        target_functions,
                        pkg_aliases,
                        named_imports,
                        has_star_import,
                        out,
                    );
                }
            }
            Stmt::AugAssign(s) => walk_expr(
                &s.value,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            ),
            Stmt::Expr(s) => walk_expr(
                &s.value,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            ),
            Stmt::With(s) => walk_stmts(
                &s.body,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            ),
            Stmt::AsyncWith(s) => walk_stmts(
                &s.body,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            ),
            Stmt::For(s) => {
                walk_expr(
                    &s.iter,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                walk_stmts(
                    &s.body,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                walk_stmts(
                    &s.orelse,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
            Stmt::AsyncFor(s) => {
                walk_expr(
                    &s.iter,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                walk_stmts(
                    &s.body,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                walk_stmts(
                    &s.orelse,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
            Stmt::While(s) => {
                walk_expr(
                    &s.test,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                walk_stmts(
                    &s.body,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                walk_stmts(
                    &s.orelse,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
            Stmt::Try(s) => {
                walk_stmts(
                    &s.body,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                for h in &s.handlers {
                    let ast::ExceptHandler::ExceptHandler(eh) = h;
                    walk_stmts(
                        &eh.body,
                        lines_vec,
                        line_idx,
                        target_functions,
                        pkg_aliases,
                        named_imports,
                        has_star_import,
                        out,
                    );
                }
                walk_stmts(
                    &s.orelse,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
                walk_stmts(
                    &s.finalbody,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_expr(
    expr: &Expr,
    lines_vec: &[&str],
    line_idx: &LineIndex,
    target_functions: Option<&[String]>,
    pkg_aliases: &HashSet<String>,
    named_imports: &HashMap<String, String>,
    has_star_import: bool,
    out: &mut PythonFileAnalysis,
) {
    match expr {
        Expr::Call(call) => {
            let line_num = line_idx.line_for_offset(call.range().start().to_usize());
            let snippet = lines_vec
                .get(line_num.saturating_sub(1))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            match call.func.as_ref() {
                Expr::Name(n) => {
                    let name = n.id.as_str();
                    if name == "__import__" || name == "eval" || name == "exec" {
                        out.has_unresolved_dynamic = true;
                    }
                    if let Some(orig) = named_imports.get(name) {
                        let is_spec = target_functions
                            .map(|fns| fns.iter().any(|tf| tf == orig || tf == name))
                            .unwrap_or(false);
                        if target_functions.is_none() || is_spec {
                            out.call_sites
                                .push((line_num, snippet.clone(), orig.clone(), is_spec));
                        }
                    } else if has_star_import {
                        if let Some(fns) = target_functions {
                            if fns.iter().any(|tf| tf == name) {
                                out.call_sites.push((
                                    line_num,
                                    snippet.clone(),
                                    name.to_string(),
                                    true,
                                ));
                            }
                        }
                    }
                }
                Expr::Attribute(attr) => {
                    let method = attr.attr.as_str();
                    if let Expr::Name(base) = attr.value.as_ref() {
                        let base_name = base.id.as_str();
                        if base_name == "importlib" && method == "import_module" {
                            out.has_unresolved_dynamic = true;
                        }
                        if pkg_aliases.contains(base_name) {
                            let is_spec = target_functions
                                .map(|fns| fns.iter().any(|tf| tf == method))
                                .unwrap_or(false);
                            if target_functions.is_none() || is_spec {
                                out.call_sites.push((
                                    line_num,
                                    snippet.clone(),
                                    method.to_string(),
                                    is_spec,
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }

            walk_expr(
                &call.func,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            );
            for arg in &call.args {
                walk_expr(
                    arg,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
            for kw in &call.keywords {
                walk_expr(
                    &kw.value,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
        }
        Expr::BinOp(b) => {
            walk_expr(
                &b.left,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            );
            walk_expr(
                &b.right,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            );
        }
        Expr::UnaryOp(u) => walk_expr(
            &u.operand,
            lines_vec,
            line_idx,
            target_functions,
            pkg_aliases,
            named_imports,
            has_star_import,
            out,
        ),
        Expr::IfExp(i) => {
            walk_expr(
                &i.test,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            );
            walk_expr(
                &i.body,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            );
            walk_expr(
                &i.orelse,
                lines_vec,
                line_idx,
                target_functions,
                pkg_aliases,
                named_imports,
                has_star_import,
                out,
            );
        }
        Expr::List(l) => {
            for e in &l.elts {
                walk_expr(
                    e,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
        }
        Expr::Tuple(t) => {
            for e in &t.elts {
                walk_expr(
                    e,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
        }
        Expr::Dict(d) => {
            for v in &d.values {
                walk_expr(
                    v,
                    lines_vec,
                    line_idx,
                    target_functions,
                    pkg_aliases,
                    named_imports,
                    has_star_import,
                    out,
                );
            }
        }
        Expr::Await(a) => walk_expr(
            &a.value,
            lines_vec,
            line_idx,
            target_functions,
            pkg_aliases,
            named_imports,
            has_star_import,
            out,
        ),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_ast_aliased_and_from_imports() {
        let code = r#"
import yaml as y
from requests import get as http_get

def run():
    data = y.load("a: 1")
    return http_get("https://example.com")
"#;
        let yaml_res = analyze_python_file(code, "PyYAML", Some(&["load".to_string()]));
        assert!(!yaml_res.parse_failed);
        assert!(yaml_res.is_imported);
        assert_eq!(yaml_res.call_sites.len(), 1);
        assert_eq!(yaml_res.call_sites[0].2, "load");
        assert!(yaml_res.call_sites[0].3);

        let req_res = analyze_python_file(code, "requests", Some(&["get".to_string()]));
        assert!(req_res.is_imported);
        assert_eq!(req_res.call_sites.len(), 1);
        assert_eq!(req_res.call_sites[0].2, "get");
    }

    #[test]
    fn test_python_ast_marks_importlib_and_syntax_errors_conservatively() {
        let dyn_code = "import importlib\nmod = importlib.import_module('yaml')\n";
        let res = analyze_python_file(dyn_code, "yaml", None);
        assert!(res.has_unresolved_dynamic);

        let bad_code = "def broken(:\n  pass\n";
        let err_res = analyze_python_file(bad_code, "yaml", None);
        assert!(err_res.parse_failed);
    }
}
