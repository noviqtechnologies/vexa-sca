#![forbid(unsafe_code)]

//! Single-pass pure-Rust Python 3 AST import & call-site analyzer (`rustpython-parser`).
//! Shared by `vexa-sca` CLI (`WorkspaceAstIndex`) and `vexa-sca-cloud` GitHub App
//! so Python reachability never relies on regex heuristics or trips over comments/docstrings.

use rustpython_parser::ast::{self, Expr, Mod, Ranged, Stmt};
use rustpython_parser::{parse, Mode};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct PyCallSite {
    pub package: String,
    pub symbol: String,
    pub line: usize,
    pub snippet: String,
}

#[derive(Debug, Default, Clone)]
pub struct PyAstFacts {
    /// Normalized import module/package name -> 1-based line number of first import.
    pub imported_packages: HashMap<String, usize>,
    /// Normalized import module/package name -> imported symbol names (`*` for module/star imports).
    pub imported_symbols: HashMap<String, HashSet<String>>,
    /// Relative local imports (e.g. `from .utils import helper`) for cross-file resolution.
    pub relative_imports: Vec<String>,
    /// Verified call sites from AST traversal.
    pub call_sites: Vec<PyCallSite>,
    /// True if `eval()`, `exec()`, `__import__()`, or `importlib.import_module()` is present.
    pub has_unresolved_dynamic: bool,
    /// True if Python syntax parsing failed.
    pub parse_failed: bool,
}

/// Normalizes a Python package or module name to its canonical import root.
pub fn normalize_python_module(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase().replace('-', "_");
    match lower.as_str() {
        "pyyaml" => "yaml".to_string(),
        "pillow" => "pil".to_string(),
        "beautifulsoup4" => "bs4".to_string(),
        "scikit_learn" => "sklearn".to_string(),
        "python_dateutil" => "dateutil".to_string(),
        "opencv_python" => "cv2".to_string(),
        "python_jose" => "jose".to_string(),
        "pycryptodome" | "pycryptodomex" => "crypto".to_string(),
        "pyjwt" => "jwt".to_string(),
        _ => lower,
    }
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

/// Parses a Python 3 source buffer **once** with `rustpython-parser` and extracts
/// all external imports, relative local imports, call sites, and dynamic-execution flags.
pub fn analyze_python_single_pass(source: &str) -> PyAstFacts {
    let mut facts = PyAstFacts::default();
    let Ok(parsed) = parse(source, Mode::Module, "<vexa>") else {
        facts.parse_failed = true;
        return facts;
    };

    let Mod::Module(module) = parsed else {
        return facts;
    };

    let lines_vec: Vec<&str> = source.lines().collect();
    let line_idx = LineIndex::new(source);

    // local_alias -> normalized_pkg (e.g. `import yaml as y` => "y" -> "yaml")
    let mut module_aliases: HashMap<String, String> = HashMap::new();
    // local_ident -> (normalized_pkg, original_symbol) (e.g. `from yaml import safe_load as sl`)
    let mut named_aliases: HashMap<String, (String, String)> = HashMap::new();

    collect_imports_recursive(
        &module.body,
        &line_idx,
        &mut facts,
        &mut module_aliases,
        &mut named_aliases,
    );

    walk_stmts_for_calls(
        &module.body,
        &lines_vec,
        &line_idx,
        &module_aliases,
        &named_aliases,
        &mut facts,
    );

    facts
}

fn collect_imports_recursive(
    stmts: &[Stmt],
    line_idx: &LineIndex,
    facts: &mut PyAstFacts,
    module_aliases: &mut HashMap<String, String>,
    named_aliases: &mut HashMap<String, (String, String)>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::Import(imp) => {
                let line = line_idx.line_for_offset(imp.range().start().to_usize());
                for alias in &imp.names {
                    let full_name = alias.name.as_str();
                    let top = full_name.split('.').next().unwrap_or(full_name);
                    let norm = normalize_python_module(top);
                    if norm.is_empty() {
                        continue;
                    }
                    facts.imported_packages.entry(norm.clone()).or_insert(line);
                    facts
                        .imported_symbols
                        .entry(norm.clone())
                        .or_default()
                        .insert("*".to_string());
                    let local = alias
                        .asname
                        .as_ref()
                        .map(|a| a.as_str().to_string())
                        .unwrap_or_else(|| top.to_string());
                    module_aliases.insert(local, norm.clone());
                    module_aliases.insert(top.to_string(), norm);
                }
            }
            Stmt::ImportFrom(imp) => {
                let line = line_idx.line_for_offset(imp.range().start().to_usize());
                let level = imp.level.map(|l| l.to_usize()).unwrap_or(0);
                if level > 0 {
                    let dots = ".".repeat(level);
                    let mod_part = imp.module.as_ref().map(|m| m.as_str()).unwrap_or("");
                    facts.relative_imports.push(format!("{dots}{mod_part}"));
                    continue;
                }
                let Some(module_ident) = &imp.module else {
                    continue;
                };
                let full_mod = module_ident.as_str();
                let top = full_mod.split('.').next().unwrap_or(full_mod);
                let norm = normalize_python_module(top);
                if norm.is_empty() {
                    continue;
                }
                facts.imported_packages.entry(norm.clone()).or_insert(line);
                let sym_entry = facts.imported_symbols.entry(norm.clone()).or_default();
                for alias in &imp.names {
                    let orig = alias.name.as_str();
                    if orig == "*" {
                        sym_entry.insert("*".to_string());
                    } else {
                        sym_entry.insert(orig.to_string());
                        let local = alias
                            .asname
                            .as_ref()
                            .map(|a| a.as_str().to_string())
                            .unwrap_or_else(|| orig.to_string());
                        named_aliases.insert(local, (norm.clone(), orig.to_string()));
                    }
                }
            }
            Stmt::FunctionDef(f) => {
                collect_imports_recursive(&f.body, line_idx, facts, module_aliases, named_aliases);
            }
            Stmt::AsyncFunctionDef(f) => {
                collect_imports_recursive(&f.body, line_idx, facts, module_aliases, named_aliases);
            }
            Stmt::ClassDef(c) => {
                collect_imports_recursive(&c.body, line_idx, facts, module_aliases, named_aliases);
            }
            Stmt::If(i) => {
                collect_imports_recursive(&i.body, line_idx, facts, module_aliases, named_aliases);
                collect_imports_recursive(
                    &i.orelse,
                    line_idx,
                    facts,
                    module_aliases,
                    named_aliases,
                );
            }
            Stmt::For(f) => {
                collect_imports_recursive(&f.body, line_idx, facts, module_aliases, named_aliases);
                collect_imports_recursive(
                    &f.orelse,
                    line_idx,
                    facts,
                    module_aliases,
                    named_aliases,
                );
            }
            Stmt::AsyncFor(f) => {
                collect_imports_recursive(&f.body, line_idx, facts, module_aliases, named_aliases);
                collect_imports_recursive(
                    &f.orelse,
                    line_idx,
                    facts,
                    module_aliases,
                    named_aliases,
                );
            }
            Stmt::While(w) => {
                collect_imports_recursive(&w.body, line_idx, facts, module_aliases, named_aliases);
                collect_imports_recursive(
                    &w.orelse,
                    line_idx,
                    facts,
                    module_aliases,
                    named_aliases,
                );
            }
            Stmt::With(w) => {
                collect_imports_recursive(&w.body, line_idx, facts, module_aliases, named_aliases);
            }
            Stmt::AsyncWith(w) => {
                collect_imports_recursive(&w.body, line_idx, facts, module_aliases, named_aliases);
            }
            Stmt::Try(t) => {
                collect_imports_recursive(&t.body, line_idx, facts, module_aliases, named_aliases);
                collect_imports_recursive(
                    &t.orelse,
                    line_idx,
                    facts,
                    module_aliases,
                    named_aliases,
                );
                collect_imports_recursive(
                    &t.finalbody,
                    line_idx,
                    facts,
                    module_aliases,
                    named_aliases,
                );
                for h in &t.handlers {
                    let ast::ExceptHandler::ExceptHandler(eh) = h;
                    collect_imports_recursive(
                        &eh.body,
                        line_idx,
                        facts,
                        module_aliases,
                        named_aliases,
                    );
                }
            }
            Stmt::TryStar(t) => {
                collect_imports_recursive(&t.body, line_idx, facts, module_aliases, named_aliases);
                collect_imports_recursive(
                    &t.orelse,
                    line_idx,
                    facts,
                    module_aliases,
                    named_aliases,
                );
                collect_imports_recursive(
                    &t.finalbody,
                    line_idx,
                    facts,
                    module_aliases,
                    named_aliases,
                );
                for h in &t.handlers {
                    let ast::ExceptHandler::ExceptHandler(eh) = h;
                    collect_imports_recursive(
                        &eh.body,
                        line_idx,
                        facts,
                        module_aliases,
                        named_aliases,
                    );
                }
            }
            _ => {}
        }
    }
}

fn walk_stmts_for_calls(
    stmts: &[Stmt],
    lines_vec: &[&str],
    line_idx: &LineIndex,
    module_aliases: &HashMap<String, String>,
    named_aliases: &HashMap<String, (String, String)>,
    facts: &mut PyAstFacts,
) {
    for stmt in stmts {
        match stmt {
            Stmt::Expr(e) => {
                // Skip standalone string literals (module/function/class docstrings)
                if matches!(&*e.value, Expr::Constant(c) if matches!(c.value, ast::Constant::Str(_)))
                {
                    continue;
                }
                walk_expr(&e.value, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::Assign(a) => {
                walk_expr(&a.value, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::AnnAssign(a) => {
                if let Some(v) = &a.value {
                    walk_expr(v, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
            }
            Stmt::AugAssign(a) => {
                walk_expr(&a.value, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::Return(r) => {
                if let Some(v) = &r.value {
                    walk_expr(v, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
            }
            Stmt::FunctionDef(f) => {
                for dec in &f.decorator_list {
                    walk_expr(dec, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
                walk_stmts_for_calls(&f.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::AsyncFunctionDef(f) => {
                for dec in &f.decorator_list {
                    walk_expr(dec, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
                walk_stmts_for_calls(&f.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::ClassDef(c) => {
                for dec in &c.decorator_list {
                    walk_expr(dec, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
                walk_stmts_for_calls(&c.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::If(i) => {
                walk_expr(&i.test, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&i.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&i.orelse, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::For(f) => {
                walk_expr(&f.iter, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&f.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&f.orelse, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::AsyncFor(f) => {
                walk_expr(&f.iter, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&f.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&f.orelse, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::While(w) => {
                walk_expr(&w.test, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&w.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&w.orelse, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::With(w) => {
                for item in &w.items {
                    walk_expr(&item.context_expr, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
                walk_stmts_for_calls(&w.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::AsyncWith(w) => {
                for item in &w.items {
                    walk_expr(&item.context_expr, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
                walk_stmts_for_calls(&w.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            Stmt::Try(t) => {
                walk_stmts_for_calls(&t.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&t.orelse, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&t.finalbody, lines_vec, line_idx, module_aliases, named_aliases, facts);
                for h in &t.handlers {
                    let ast::ExceptHandler::ExceptHandler(eh) = h;
                    walk_stmts_for_calls(&eh.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
            }
            Stmt::TryStar(t) => {
                walk_stmts_for_calls(&t.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&t.orelse, lines_vec, line_idx, module_aliases, named_aliases, facts);
                walk_stmts_for_calls(&t.finalbody, lines_vec, line_idx, module_aliases, named_aliases, facts);
                for h in &t.handlers {
                    let ast::ExceptHandler::ExceptHandler(eh) = h;
                    walk_stmts_for_calls(&eh.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
            }
            Stmt::Raise(r) => {
                if let Some(exc) = &r.exc {
                    walk_expr(exc, lines_vec, line_idx, module_aliases, named_aliases, facts);
                }
            }
            Stmt::Assert(a) => {
                walk_expr(&a.test, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            _ => {}
        }
    }
}

fn walk_expr(
    expr: &Expr,
    lines_vec: &[&str],
    line_idx: &LineIndex,
    module_aliases: &HashMap<String, String>,
    named_aliases: &HashMap<String, (String, String)>,
    facts: &mut PyAstFacts,
) {
    match expr {
        Expr::Call(call) => {
            let line = line_idx.line_for_offset(call.range().start().to_usize());
            let snippet = lines_vec
                .get(line.saturating_sub(1))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();

            match &*call.func {
                Expr::Name(n) => {
                    let name = n.id.as_str();
                    if matches!(name, "eval" | "exec" | "__import__") {
                        facts.has_unresolved_dynamic = true;
                    }
                    if let Some((pkg, orig_sym)) = named_aliases.get(name) {
                        facts.call_sites.push(PyCallSite {
                            package: pkg.clone(),
                            symbol: orig_sym.clone(),
                            line,
                            snippet: snippet.clone(),
                        });
                    }
                }
                Expr::Attribute(attr) => {
                    let attr_name = attr.attr.as_str();
                    if attr_name == "import_module" {
                        facts.has_unresolved_dynamic = true;
                    }
                    if let Expr::Name(base) = &*attr.value {
                        let base_name = base.id.as_str();
                        if let Some(pkg) = module_aliases.get(base_name) {
                            facts.call_sites.push(PyCallSite {
                                package: pkg.clone(),
                                symbol: attr_name.to_string(),
                                line,
                                snippet: snippet.clone(),
                            });
                        } else if let Some((pkg, orig_sym)) = named_aliases.get(base_name) {
                            facts.call_sites.push(PyCallSite {
                                package: pkg.clone(),
                                symbol: attr_name.to_string(),
                                line,
                                snippet: snippet.clone(),
                            });
                            facts.call_sites.push(PyCallSite {
                                package: pkg.clone(),
                                symbol: orig_sym.clone(),
                                line,
                                snippet: snippet.clone(),
                            });
                        }
                    }
                }
                _ => {}
            }

            walk_expr(&call.func, lines_vec, line_idx, module_aliases, named_aliases, facts);
            for arg in &call.args {
                walk_expr(arg, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
            for kw in &call.keywords {
                walk_expr(&kw.value, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
        }
        Expr::Await(a) => walk_expr(&a.value, lines_vec, line_idx, module_aliases, named_aliases, facts),
        Expr::BinOp(b) => {
            walk_expr(&b.left, lines_vec, line_idx, module_aliases, named_aliases, facts);
            walk_expr(&b.right, lines_vec, line_idx, module_aliases, named_aliases, facts);
        }
        Expr::UnaryOp(u) => walk_expr(&u.operand, lines_vec, line_idx, module_aliases, named_aliases, facts),
        Expr::BoolOp(b) => {
            for v in &b.values {
                walk_expr(v, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
        }
        Expr::Compare(c) => {
            walk_expr(&c.left, lines_vec, line_idx, module_aliases, named_aliases, facts);
            for cmp in &c.comparators {
                walk_expr(cmp, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
        }
        Expr::IfExp(i) => {
            walk_expr(&i.test, lines_vec, line_idx, module_aliases, named_aliases, facts);
            walk_expr(&i.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
            walk_expr(&i.orelse, lines_vec, line_idx, module_aliases, named_aliases, facts);
        }
        Expr::List(l) => {
            for e in &l.elts {
                walk_expr(e, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
        }
        Expr::Tuple(t) => {
            for e in &t.elts {
                walk_expr(e, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
        }
        Expr::Dict(d) => {
            for v in &d.values {
                walk_expr(v, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
        }
        Expr::JoinedStr(j) => {
            for v in &j.values {
                walk_expr(v, lines_vec, line_idx, module_aliases, named_aliases, facts);
            }
        }
        Expr::FormattedValue(f) => {
            walk_expr(&f.value, lines_vec, line_idx, module_aliases, named_aliases, facts);
        }
        Expr::Subscript(s) => {
            walk_expr(&s.value, lines_vec, line_idx, module_aliases, named_aliases, facts);
            walk_expr(&s.slice, lines_vec, line_idx, module_aliases, named_aliases, facts);
        }
        Expr::Attribute(a) => {
            walk_expr(&a.value, lines_vec, line_idx, module_aliases, named_aliases, facts);
        }
        Expr::Lambda(l) => {
            walk_expr(&l.body, lines_vec, line_idx, module_aliases, named_aliases, facts);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_ast_parses_multiline_imports_aliases_and_ignores_comments_and_docstrings() {
        let src = r#"
"""
import fake_docstring_pkg
fake_docstring_pkg.run()
"""
# import commented_out_pkg
import yaml as y
from requests import (
    Session as HttpSession,
    get as http_get,
)
from .helpers import render

def fetch(url):
    data = y.load("a: 1")
    s = HttpSession()
    return http_get(url)
"#;
        let facts = analyze_python_single_pass(src);
        assert!(!facts.parse_failed);
        assert!(!facts.has_unresolved_dynamic);
        assert!(facts.imported_packages.contains_key("yaml"));
        assert!(facts.imported_packages.contains_key("requests"));
        assert!(!facts.imported_packages.contains_key("fake_docstring_pkg"));
        assert!(!facts.imported_packages.contains_key("commented_out_pkg"));
        assert_eq!(facts.relative_imports, vec![".helpers"]);
        assert!(facts
            .call_sites
            .iter()
            .any(|c| c.package == "yaml" && c.symbol == "load"));
        assert!(facts
            .call_sites
            .iter()
            .any(|c| c.package == "requests" && c.symbol == "Session"));
        assert!(facts
            .call_sites
            .iter()
            .any(|c| c.package == "requests" && c.symbol == "get"));
    }

    #[test]
    fn python_ast_flags_dynamic_imports_conservatively() {
        let src = "import importlib\nmod = importlib.import_module(user_pkg)\n";
        let facts = analyze_python_single_pass(src);
        assert!(facts.has_unresolved_dynamic);
    }
}
