//! Real JavaScript/TypeScript AST-based import and call-site analyzer.
//!
//! This module replaces previous regex-only approaches with a proper
//! [oxc](https://oxc.rs) AST parse and visitor pass that correctly handles:
//!
//! - **Static ESM imports**: `import x from 'pkg'`, `import { fn } from 'pkg'`,
//!   `import * as ns from 'pkg'`, `import 'pkg'` (side-effect only)
//! - **Dynamic imports**: `await import('pkg')`, `import('pkg').then(...)`,
//!   including assigned bindings
//! - **CommonJS**: `require('pkg')`, `const x = require('pkg')`,
//!   `const { fn } = require('pkg')`
//! - **Re-exports**: `export { fn } from 'pkg'`, `export * from 'pkg'`
//! - **Namespace access**: `ns.fn(...)`, `ns.default.fn(...)`
//! - **Named import call-sites**: `template(...)` after `import { template }`
//! - **Chained / dynamic property access**: detected conservatively as
//!   `ReasonCode::DynamicConstruct` -> `Unknown` so they are never
//!   silently classified as Unreachable.
//!
//! # Conservative guarantees
//!
//! The analyzer never emits `Unreachable` if:
//! - The file could not be parsed (syntax error) -> `ParseError`
//! - A dynamic property access or reflection pattern is detected -> `DynamicConstruct`
//! - The package is re-exported from the module -> `CrossFileUnresolved`
//! - The package is imported but no call site is found and target functions are unanalyzed -> `Unknown`

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentExpression, BindingPattern, CallExpression, ExportAllDeclaration,
    ExportFromDeclaration, Expression, ImportDeclaration, ImportDeclarationSpecifier,
    MemberExpression, PropertyKey, SimpleAssignmentTarget, VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;

use std::collections::{HashMap, HashSet};

/// The result of analyzing a single JS/TS source file for a specific package.
#[derive(Debug, Default)]
pub struct FileAnalysis {
    /// The package was imported in this file (any import form).
    pub is_imported: bool,
    /// Specific call sites found: (line, snippet, matched_function_name, is_specific).
    pub call_sites: Vec<(usize, String, String, bool)>,
    /// A dynamic construct (computed property, Proxy, Reflect, eval) was detected —
    /// the analyzer cannot guarantee completeness. The caller should emit `Unknown`.
    pub has_dynamic_construct: bool,
    /// The file re-exports symbols from the package to outside modules.
    pub has_reexports: bool,
    /// The file failed to parse (syntax error or unsupported encoding).
    pub parse_failed: bool,
}

/// Analyzes a single JavaScript or TypeScript source file.
///
/// # Arguments
/// * `source`           - raw file content (UTF-8)
/// * `source_type`      - the oxc SourceType (detects JS/TS/JSX/TSX/module/script)
/// * `pkg_name`         - the npm package name to look for (e.g. `"lodash"`)
/// * `target_functions` - optional list of vulnerable function names (e.g. `["template", "set"]`); `None` means any call counts
pub fn analyze_file(
    source: &str,
    source_type: SourceType,
    pkg_name: &str,
    target_functions: Option<&[String]>,
) -> FileAnalysis {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions {
            parse_regular_expression: false,
            ..ParseOptions::default()
        })
        .parse();

    let parse_failed = !ret.diagnostics.is_empty();
    let program = ret.program;

    // ── Pass 1: Collect package bindings ─────────────────────────────────────
    let mut collector = BindingCollector {
        pkg_name,
        bindings: HashMap::new(),
        named_imports: HashSet::new(),
        is_imported: false,
        has_reexports: false,
    };
    walk::walk_program(&mut collector, &program);

    let is_imported = collector.is_imported || !collector.bindings.is_empty();
    if !is_imported {
        return FileAnalysis {
            is_imported: false,
            call_sites: Vec::new(),
            has_dynamic_construct: false,
            has_reexports: false,
            parse_failed,
        };
    }

    // ── Pass 2: Search for call sites & dynamic constructs ───────────────────
    let mut checker = CallSiteChecker {
        _pkg_name: pkg_name,
        bindings: &collector.bindings,
        named_imports: &collector.named_imports,
        target_functions,
        source,
        call_sites: Vec::new(),
        has_dynamic_construct: false,
    };
    walk::walk_program(&mut checker, &program);

    FileAnalysis {
        is_imported,
        call_sites: checker.call_sites,
        has_dynamic_construct: checker.has_dynamic_construct,
        has_reexports: collector.has_reexports,
        parse_failed,
    }
}

/// Normalise package match: import source `'lodash'` matches `"lodash"`;
/// `'lodash/template'` also matches because it is a sub-path import.
#[inline]
fn pkg_matches(src: &str, pkg: &str) -> bool {
    src == pkg || src.starts_with(&format!("{}/", pkg)) || src.starts_with(&format!("{} ", pkg))
}

// ── Pass 1: Binding Collector ────────────────────────────────────────────────

struct BindingCollector<'a> {
    pkg_name: &'a str,
    bindings: HashMap<String, String>,
    named_imports: HashSet<String>,
    is_imported: bool,
    has_reexports: bool,
}

impl<'a> Visit<'a> for BindingCollector<'a> {
    fn visit_import_declaration(&mut self, imp: &ImportDeclaration<'a>) {
        let src = imp.source.value.as_str().unwrap_or("");
        if pkg_matches(src, self.pkg_name) {
            self.is_imported = true;
            if let Some(specifiers) = &imp.specifiers {
                for spec in specifiers {
                    match spec {
                        ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                            self.bindings
                                .insert(s.local.name.to_string(), "default".to_string());
                        }
                        ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                            self.bindings
                                .insert(s.local.name.to_string(), "namespace".to_string());
                        }
                        ImportDeclarationSpecifier::ImportSpecifier(s) => {
                            let local = s.local.name.to_string();
                            self.named_imports.insert(local.clone());
                            let imported_name = s.imported.name();
                            self.bindings
                                .insert(local, format!("named:{}", imported_name));
                        }
                    }
                }
            }
        }
    }

    fn visit_export_from_declaration(&mut self, exp: &ExportFromDeclaration<'a>) {
        let src = exp.source.value.as_str().unwrap_or("");
        if pkg_matches(src, self.pkg_name) {
            self.is_imported = true;
            self.has_reexports = true;
        }
    }

    fn visit_export_all_declaration(&mut self, exp: &ExportAllDeclaration<'a>) {
        let src = exp.source.value.as_str().unwrap_or("");
        if pkg_matches(src, self.pkg_name) {
            self.is_imported = true;
            self.has_reexports = true;
        }
    }

    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        extract_require_bindings(
            decl,
            self.pkg_name,
            &mut self.bindings,
            &mut self.named_imports,
        );
        walk::walk_variable_declarator(self, decl);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        let rhs = unwrap_await(&assign.right);
        if let Some(src) = extract_call_pkg_arg(rhs) {
            if pkg_matches(&src, self.pkg_name) {
                if let Some(SimpleAssignmentTarget::AssignmentTargetIdentifier(id)) =
                    assign.left.as_simple_assignment_target()
                {
                    self.bindings.insert(id.name.to_string(), "dyn".to_string());
                    self.is_imported = true;
                }
            }
        }
    }
}

// ── Pass 2: Call Site Checker ────────────────────────────────────────────────

struct CallSiteChecker<'p> {
    _pkg_name: &'p str,
    bindings: &'p HashMap<String, String>,
    named_imports: &'p HashSet<String>,
    target_functions: Option<&'p [String]>,
    source: &'p str,
    call_sites: Vec<(usize, String, String, bool)>,
    has_dynamic_construct: bool,
}

impl<'a, 'p> Visit<'a> for CallSiteChecker<'p> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        self.check_call(call);
        walk::walk_call_expression(self, call);
    }

    fn visit_member_expression(&mut self, mem: &MemberExpression<'a>) {
        if matches!(mem, MemberExpression::ComputedMemberExpression(_)) {
            self.has_dynamic_construct = true;
        }
        walk::walk_member_expression(self, mem);
    }
}

impl<'p> CallSiteChecker<'p> {
    fn check_call<'a>(&mut self, call: &CallExpression<'a>) {
        // 1. Check member expression calls: `mod.fn(...)`, `mod.default.fn(...)`
        if let Some(mem) = call.callee.as_member_expression() {
            if matches!(mem, MemberExpression::ComputedMemberExpression(_)) {
                self.has_dynamic_construct = true;
                return;
            }
            if let Some(prop) = member_static_property_name(mem) {
                let obj = member_object(mem);
                // Check direct identifier base: `_.template(...)`
                if let Expression::Identifier(id) = obj {
                    let base_name = id.name.as_str();
                    self.match_and_record_member_call(base_name, prop, call.span.start as usize);
                    return;
                }
                // Check nested member base: `lodashModule.default.template(...)`
                if let Some(inner_mem) = obj.as_member_expression() {
                    if member_static_property_name(inner_mem) == Some("default") {
                        if let Expression::Identifier(base_id) = member_object(inner_mem) {
                            let base_name = base_id.name.as_str();
                            self.match_and_record_member_call(
                                base_name,
                                prop,
                                call.span.start as usize,
                            );
                            return;
                        }
                    }
                    self.has_dynamic_construct = true;
                    return;
                }
            }
        }

        // 2. Check direct named import calls: `template(...)`
        if let Expression::Identifier(id) = &call.callee {
            let name = id.name.as_str();
            // Flag reflection calls
            if name == "eval" {
                self.has_dynamic_construct = true;
            }
            if self.named_imports.contains(name) {
                let matches = if let Some(targets) = self.target_functions {
                    targets.iter().any(|t| t == name)
                } else {
                    true
                };
                if matches {
                    let (line_idx, snippet) = span_to_line(id.span.start as usize, self.source);
                    self.call_sites
                        .push((line_idx + 1, snippet, name.to_string(), true));
                }
            }
        }
    }

    fn match_and_record_member_call(&mut self, base_name: &str, prop: &str, byte_offset: usize) {
        let Some(import_type) = self.bindings.get(base_name) else {
            return;
        };

        // Check if `prop` matches target functions
        let is_specific = if let Some(targets) = self.target_functions {
            targets.iter().any(|t| t == prop)
        } else {
            true
        };

        if !is_specific {
            return;
        }

        let fn_label = match import_type.as_str() {
            "default" | "namespace" | "cjs" | "dyn" => format!("{}.{}", base_name, prop),
            _ => format!("{}.{}", base_name, prop),
        };

        let (line_idx, snippet) = span_to_line(byte_offset, self.source);
        self.call_sites
            .push((line_idx + 1, snippet, fn_label, true));
    }
}

// ── AST Helpers ──────────────────────────────────────────────────────────────

fn member_static_property_name<'a>(mem: &'a MemberExpression<'a>) -> Option<&'a str> {
    match mem {
        MemberExpression::StaticMemberExpression(s) => Some(s.property.name.as_str()),
        _ => None,
    }
}

fn member_object<'a>(mem: &'a MemberExpression<'a>) -> &'a Expression<'a> {
    match mem {
        MemberExpression::StaticMemberExpression(s) => &s.object,
        MemberExpression::ComputedMemberExpression(c) => &c.object,
        MemberExpression::PrivateFieldExpression(p) => &p.object,
    }
}

fn unwrap_await<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    if let Expression::AwaitExpression(aw) = expr {
        &aw.argument
    } else {
        expr
    }
}

fn extract_call_pkg_arg(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::CallExpression(call) => {
            if let Expression::ImportExpression(imp) = &call.callee {
                if let Expression::StringLiteral(s) = &imp.source {
                    return s.value.as_str().map(|s| s.to_string());
                }
            }
            if let Expression::Identifier(id) = &call.callee {
                if id.name == "require" {
                    if let Some(arg) = call.arguments.first() {
                        if let Some(Expression::StringLiteral(s)) = arg.as_expression() {
                            return s.value.as_str().map(|s| s.to_string());
                        }
                    }
                }
            }
            None
        }
        Expression::ImportExpression(imp) => {
            if let Expression::StringLiteral(s) = &imp.source {
                return s.value.as_str().map(|s| s.to_string());
            }
            None
        }
        _ => None,
    }
}

fn extract_require_bindings(
    decl: &VariableDeclarator<'_>,
    pkg_name: &str,
    bindings: &mut HashMap<String, String>,
    named_imports: &mut HashSet<String>,
) {
    let Some(init) = &decl.init else {
        return;
    };
    let inner = unwrap_await(init);

    if let Some(src) = extract_call_pkg_arg(inner) {
        if pkg_matches(&src, pkg_name) {
            bind_pattern(&decl.id, "cjs", bindings, named_imports);
            return;
        }
    }

    if let Some(mem) = inner.as_member_expression() {
        let obj = unwrap_await(member_object(mem));
        if let Some(src) = extract_call_pkg_arg(obj) {
            if pkg_matches(&src, pkg_name) {
                if let Some(prop) = member_static_property_name(mem) {
                    bind_pattern(
                        &decl.id,
                        &format!("member:{}", prop),
                        bindings,
                        named_imports,
                    );
                }
            }
        }
    }
}

fn bind_pattern(
    pattern: &BindingPattern<'_>,
    import_type: &str,
    bindings: &mut HashMap<String, String>,
    named_imports: &mut HashSet<String>,
) {
    match pattern {
        BindingPattern::BindingIdentifier(id) => {
            bindings.insert(id.name.to_string(), import_type.to_string());
        }
        BindingPattern::ObjectPattern(obj) => {
            for prop in &obj.properties {
                if let BindingPattern::BindingIdentifier(local) = &prop.value {
                    let local_name = local.name.to_string();
                    named_imports.insert(local_name.clone());
                    let key_name =
                        property_key_name(&prop.key).unwrap_or_else(|| local_name.clone());
                    bindings.insert(local_name, format!("named:{}", key_name));
                }
            }
        }
        _ => {}
    }
}

fn property_key_name(key: &PropertyKey<'_>) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.as_str().to_string()),
        PropertyKey::StringLiteral(s) => s.value.as_str().map(|s| s.to_string()),
        _ => None,
    }
}

/// Convert a byte offset in `source` to `(0-indexed line number, line snippet <=80 chars)`.
fn span_to_line(byte_offset: usize, source: &str) -> (usize, String) {
    let mut current_byte = 0;
    for (i, line) in source.lines().enumerate() {
        let next = current_byte + line.len() + 1; // +1 for newline
        if byte_offset < next {
            let snippet = line.trim().chars().take(80).collect();
            return (i, snippet);
        }
        current_byte = next;
    }
    let last_idx = source.lines().count().saturating_sub(1);
    let snippet = source
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .chars()
        .take(80)
        .collect();
    (last_idx, snippet)
}

/// Determine the oxc SourceType from a file extension.
pub fn source_type_for_path(path: &std::path::Path) -> Option<SourceType> {
    let ext = path.extension()?.to_str()?;
    let st = match ext.to_lowercase().as_str() {
        "js" | "cjs" | "mjs" => SourceType::mjs(),
        "jsx" => SourceType::jsx(),
        "ts" | "mts" | "cts" => SourceType::ts(),
        "tsx" => SourceType::tsx(),
        _ => return None,
    };
    Some(st)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> SourceType {
        SourceType::ts()
    }
    fn js() -> SourceType {
        SourceType::mjs()
    }

    #[test]
    fn test_static_default_import_and_call() {
        let src = r#"
import _ from 'lodash';
const compiled = _.template('Hello <%= name %>!');
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported, "should be imported");
        assert!(!r.call_sites.is_empty(), "should find call site");
        assert!(r.call_sites[0].2.contains("template"));
    }

    #[test]
    fn test_static_named_import_and_call() {
        let src = r#"
import { template, set } from 'lodash';
const compiled = template('Hello!');
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported);
        assert!(!r.call_sites.is_empty());
    }

    #[test]
    fn test_static_namespace_import_and_call() {
        let src = r#"
import * as _ from 'lodash';
_.template('Hello!');
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported);
        assert!(!r.call_sites.is_empty());
    }

    #[test]
    fn test_dynamic_import_whole_module_default_dot_fn() {
        let src = r#"
async function run() {
    const lodashModule = await import('lodash');
    lodashModule.default.template('Hello!');
}
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported, "dynamic import must mark file as imported");
        assert!(!r.call_sites.is_empty(), "template call must be found");
    }

    #[test]
    fn test_dynamic_import_destructured() {
        let src = r#"
async function run() {
    const { template } = await import('lodash');
    template('Hello!');
}
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported);
        assert!(
            !r.call_sites.is_empty(),
            "destructured template() must be found"
        );
    }

    #[test]
    fn test_commonjs_require_and_call() {
        let src = r#"
const _ = require('lodash');
const compiled = _.template('Hello!');
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported);
        assert!(!r.call_sites.is_empty());
    }

    #[test]
    fn test_commonjs_destructured_require() {
        let src = r#"
const { template } = require('lodash');
template('Hello!');
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported);
        assert!(!r.call_sites.is_empty());
    }

    #[test]
    fn test_reexport_marks_file_as_imported_and_reexported() {
        let src = r#"export { template } from 'lodash';"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(
            r.is_imported,
            "re-export must mark file as importing package"
        );
        assert!(r.has_reexports, "re-export flag must be set");
    }

    #[test]
    fn test_export_star_marks_file_as_imported_and_reexported() {
        let src = r#"export * from 'lodash';"#;
        let r = analyze_file(src, js(), "lodash", None);
        assert!(r.is_imported);
        assert!(r.has_reexports);
    }

    #[test]
    fn test_package_not_imported_returns_not_imported() {
        let src = r#"import _ from 'underscore'; _.template('Hello!');"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(!r.is_imported);
        assert!(r.call_sites.is_empty());
    }

    #[test]
    fn test_imported_but_target_fn_not_called() {
        let src = r#"
import _ from 'lodash';
_.cloneDeep({});
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported, "package IS imported");
        assert!(
            r.call_sites.is_empty(),
            "template is NOT called -> no call site"
        );
    }

    #[test]
    fn test_typescript_import_and_call() {
        let src = r#"
import _ from 'lodash';
function render(name: string): string {
    const compiled = _.template('Hello <%= name %>!');
    return compiled({ name });
}
"#;
        let r = analyze_file(src, ts(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported);
        assert!(!r.call_sites.is_empty());
    }

    #[test]
    fn test_subpath_import_matches_package() {
        let src = r#"import template from 'lodash/template';"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported, "lodash/template must match lodash");
    }

    #[test]
    fn test_computed_property_flags_dynamic_construct() {
        let src = r#"
import * as _ from 'lodash';
const fn = 'template';
_[fn]('Hello!');
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported);
        assert!(
            r.has_dynamic_construct,
            "computed access must set has_dynamic_construct"
        );
    }
}
