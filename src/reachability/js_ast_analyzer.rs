//! Real JavaScript/TypeScript AST-based import and call-site analyzer.
//!
//! This module replaces previous regex-only approaches with a proper
//! [oxc](https://oxc.rs) AST parse and visitor pass that correctly handles:
//!
//! - **Static ESM imports**: `import x from 'pkg'`, `import { fn } from 'pkg'`,
//!   `import * as ns from 'pkg'`, `import 'pkg'` (side-effect only)
//! - **Dynamic imports**: `await import('pkg')`, `import('pkg').then(...)`,
//!   including variable and constant-folded imports
//! - **CommonJS**: `require('pkg')`, `const x = require('pkg')`,
//!   `const { fn } = require('pkg')`, `createRequire`
//! - **Re-exports**: `export { fn } from 'pkg'`, `export * from 'pkg'`, cross-file re-exports
//! - **Namespace access**: `ns.fn(...)`, `ns.default.fn(...)`
//! - **Named import call-sites**: `template(...)` after `import { template }`
//! - **Unresolved dynamic constructs & computed property access**: detected conservatively
//!   so they are never silently classified as Unreachable.

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    AssignmentExpression, BindingPattern, CallExpression, ExportAllDeclaration,
    ExportFromDeclaration, Expression, ImportDeclaration, ImportDeclarationSpecifier,
    MemberExpression, NewExpression, PropertyKey, SimpleAssignmentTarget, VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Import resolution classification per P0 requirements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportResolutionState {
    LiteralPackageSpecifier(String),
    ResolvedConstantSpecifier(String),
    UnresolvedDynamicSpecifier(String),
    NonPackageImport(String),
}

/// The result of analyzing a single JS/TS source file for a specific package.
#[derive(Debug, Default, Clone)]
pub struct FileAnalysis {
    /// The package was imported in this file (literal, constant-resolved, or subpath).
    pub is_imported: bool,
    /// Detailed resolution states of all import/require constructs found in file.
    pub import_states: Vec<ImportResolutionState>,
    /// Specific call sites found: (line, snippet, matched_function_name, is_specific).
    pub call_sites: Vec<(usize, String, String, bool)>,
    /// A dynamic construct (computed property, Proxy, Reflect, eval, createRequire) was detected.
    pub has_dynamic_construct: bool,
    /// An unresolved dynamic import or require expression was found.
    pub has_unresolved_dynamic: bool,
    /// The file re-exports symbols from the package or contains external re-exports.
    pub has_reexports: bool,
    /// The file failed to parse (syntax error or unsupported encoding).
    pub parse_failed: bool,
}

/// Analyzes a single JavaScript or TypeScript source file.
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

    // ── Pass 0: Collect local constant string declarations ────────────────────
    let mut const_collector = ConstantCollector {
        constants: HashMap::new(),
    };
    walk::walk_program(&mut const_collector, &program);

    // ── Pass 1: Collect package bindings & import resolution states ───────────
    let mut collector = BindingCollector {
        pkg_name,
        constants: &const_collector.constants,
        bindings: HashMap::new(),
        named_imports: HashSet::new(),
        import_states: Vec::new(),
        is_imported: false,
        has_reexports: false,
        has_unresolved_dynamic: false,
        has_dynamic_construct: false,
    };
    walk::walk_program(&mut collector, &program);

    let is_imported = collector.is_imported || !collector.bindings.is_empty();

    // ── Pass 2: Search for call sites & dynamic constructs ───────────────────
    let mut checker = CallSiteChecker {
        _pkg_name: pkg_name,
        bindings: &collector.bindings,
        named_imports: &collector.named_imports,
        target_functions,
        source,
        call_sites: Vec::new(),
        has_dynamic_construct: collector.has_dynamic_construct,
    };
    walk::walk_program(&mut checker, &program);

    FileAnalysis {
        is_imported,
        import_states: collector.import_states,
        call_sites: checker.call_sites,
        has_dynamic_construct: checker.has_dynamic_construct,
        has_unresolved_dynamic: collector.has_unresolved_dynamic,
        has_reexports: collector.has_reexports,
        parse_failed,
    }
}

/// Normalise package match: import source `'lodash'` matches `"lodash"`;
/// `'lodash/template'` also matches because it is a sub-path import.
#[inline]
pub fn pkg_matches(src: &str, pkg: &str) -> bool {
    let clean = src.trim().trim_matches('\'').trim_matches('"');
    clean == pkg
        || clean.starts_with(&format!("{}/", pkg))
        || clean.starts_with(&format!("{} ", pkg))
}

fn extract_string_literal(expr: &Expression<'_>) -> Option<String> {
    match expr {
        Expression::StringLiteral(s) => s.value.as_str().map(|v| v.to_string()),
        Expression::TemplateLiteral(t) if t.expressions.is_empty() && t.quasis.len() == 1 => {
            t.quasis.first().map(|q| q.value.raw.as_str().to_string())
        }
        _ => None,
    }
}

fn resolve_specifier_state(
    expr: &Expression<'_>,
    constants: &HashMap<String, String>,
) -> ImportResolutionState {
    if let Some(s) = extract_string_literal(expr) {
        if s.starts_with('.') || s.starts_with('/') {
            ImportResolutionState::NonPackageImport(s)
        } else {
            ImportResolutionState::LiteralPackageSpecifier(s)
        }
    } else if let Expression::Identifier(id) = expr {
        if let Some(s) = constants.get(id.name.as_str()) {
            if s.starts_with('.') || s.starts_with('/') {
                ImportResolutionState::NonPackageImport(s.clone())
            } else {
                ImportResolutionState::ResolvedConstantSpecifier(s.clone())
            }
        } else {
            ImportResolutionState::UnresolvedDynamicSpecifier(id.name.to_string())
        }
    } else {
        ImportResolutionState::UnresolvedDynamicSpecifier("<dynamic-expr>".to_string())
    }
}

// ── Pass 0: Constant Collector ───────────────────────────────────────────────

struct ConstantCollector {
    constants: HashMap<String, String>,
}

impl<'a> Visit<'a> for ConstantCollector {
    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        if let BindingPattern::BindingIdentifier(id) = &decl.id {
            if let Some(init) = &decl.init {
                let unwrapped = unwrap_await(init);
                if let Some(lit) = extract_string_literal(unwrapped) {
                    self.constants.insert(id.name.to_string(), lit);
                }
            }
        }
        walk::walk_variable_declarator(self, decl);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        if let Some(SimpleAssignmentTarget::AssignmentTargetIdentifier(id)) =
            assign.left.as_simple_assignment_target()
        {
            let unwrapped = unwrap_await(&assign.right);
            if let Some(lit) = extract_string_literal(unwrapped) {
                self.constants.insert(id.name.to_string(), lit);
            }
        }
        walk::walk_assignment_expression(self, assign);
    }
}

// ── Pass 1: Binding Collector ────────────────────────────────────────────────

struct BindingCollector<'a> {
    pkg_name: &'a str,
    constants: &'a HashMap<String, String>,
    bindings: HashMap<String, String>,
    named_imports: HashSet<String>,
    import_states: Vec<ImportResolutionState>,
    is_imported: bool,
    has_reexports: bool,
    has_unresolved_dynamic: bool,
    has_dynamic_construct: bool,
}

impl<'a> Visit<'a> for BindingCollector<'a> {
    fn visit_import_declaration(&mut self, imp: &ImportDeclaration<'a>) {
        let src = imp.source.value.as_str().unwrap_or("");
        let state = if src.starts_with('.') || src.starts_with('/') {
            ImportResolutionState::NonPackageImport(src.to_string())
        } else {
            ImportResolutionState::LiteralPackageSpecifier(src.to_string())
        };
        self.import_states.push(state);

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
        walk::walk_import_declaration(self, imp);
    }

    fn visit_export_from_declaration(&mut self, exp: &ExportFromDeclaration<'a>) {
        let src = exp.source.value.as_str().unwrap_or("");
        if pkg_matches(src, self.pkg_name) {
            self.is_imported = true;
            self.has_reexports = true;
        } else if src.starts_with('.') || src.starts_with('/') {
            self.has_reexports = true;
        }
        walk::walk_export_from_declaration(self, exp);
    }

    fn visit_export_all_declaration(&mut self, exp: &ExportAllDeclaration<'a>) {
        let src = exp.source.value.as_str().unwrap_or("");
        if pkg_matches(src, self.pkg_name) {
            self.is_imported = true;
            self.has_reexports = true;
        } else if src.starts_with('.') || src.starts_with('/') {
            self.has_reexports = true;
        }
        walk::walk_export_all_declaration(self, exp);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // 1. Check for dynamic import() or require()
        let callee = &call.callee;
        let mut is_require = false;
        let mut is_import = false;

        if let Expression::ImportExpression(imp) = callee {
            is_import = true;
            let state = resolve_specifier_state(&imp.source, self.constants);
            self.handle_import_specifier_state(state, None);
        } else if let Expression::Identifier(id) = callee {
            if id.name == "require" {
                is_require = true;
                if let Some(arg) = call.arguments.first() {
                    if let Some(arg_expr) = arg.as_expression() {
                        let state = resolve_specifier_state(arg_expr, self.constants);
                        self.handle_import_specifier_state(state, None);
                    }
                }
            } else if id.name == "createRequire" || id.name == "eval" {
                self.has_dynamic_construct = true;
            }
        }

        // Also detect Reflection methods
        if let Some(mem) = callee.as_member_expression() {
            if let Expression::Identifier(base_id) = member_object(mem) {
                if base_id.name == "Reflect" {
                    self.has_dynamic_construct = true;
                }
            }
        }

        let _ = (is_require, is_import);
        walk::walk_call_expression(self, call);
    }

    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        if let Some(init) = &decl.init {
            let unwrapped = unwrap_await(init);

            // Handle `const x = require(...)` or `const x = await import(...)`
            if let Some((spec_expr, is_member_prop)) = extract_require_or_import_call(unwrapped) {
                let state = resolve_specifier_state(spec_expr, self.constants);
                match &state {
                    ImportResolutionState::LiteralPackageSpecifier(pkg)
                    | ImportResolutionState::ResolvedConstantSpecifier(pkg) => {
                        if pkg_matches(pkg, self.pkg_name) {
                            self.is_imported = true;
                            if let Some(prop) = is_member_prop {
                                bind_pattern(
                                    &decl.id,
                                    &format!("member:{}", prop),
                                    &mut self.bindings,
                                    &mut self.named_imports,
                                );
                            } else {
                                bind_pattern(
                                    &decl.id,
                                    "dyn",
                                    &mut self.bindings,
                                    &mut self.named_imports,
                                );
                            }
                        }
                    }
                    ImportResolutionState::UnresolvedDynamicSpecifier(_) => {
                        self.has_unresolved_dynamic = true;
                        self.has_dynamic_construct = true;
                    }
                    ImportResolutionState::NonPackageImport(_) => {}
                }
                self.import_states.push(state);
            }
        }
        walk::walk_variable_declarator(self, decl);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        let unwrapped = unwrap_await(&assign.right);
        if let Some((spec_expr, _)) = extract_require_or_import_call(unwrapped) {
            let state = resolve_specifier_state(spec_expr, self.constants);
            match &state {
                ImportResolutionState::LiteralPackageSpecifier(pkg)
                | ImportResolutionState::ResolvedConstantSpecifier(pkg) => {
                    if pkg_matches(pkg, self.pkg_name) {
                        self.is_imported = true;
                        if let Some(SimpleAssignmentTarget::AssignmentTargetIdentifier(id)) =
                            assign.left.as_simple_assignment_target()
                        {
                            self.bindings.insert(id.name.to_string(), "dyn".to_string());
                        }
                    }
                }
                ImportResolutionState::UnresolvedDynamicSpecifier(_) => {
                    self.has_unresolved_dynamic = true;
                    self.has_dynamic_construct = true;
                }
                ImportResolutionState::NonPackageImport(_) => {}
            }
            self.import_states.push(state);
        }
        walk::walk_assignment_expression(self, assign);
    }

    fn visit_member_expression(&mut self, mem: &MemberExpression<'a>) {
        if matches!(mem, MemberExpression::ComputedMemberExpression(_)) {
            self.has_dynamic_construct = true;
        }
        walk::walk_member_expression(self, mem);
    }

    fn visit_new_expression(&mut self, new_expr: &NewExpression<'a>) {
        if let Expression::Identifier(id) = &new_expr.callee {
            if id.name == "Proxy" {
                self.has_dynamic_construct = true;
            }
        }
        walk::walk_new_expression(self, new_expr);
    }
}

impl<'a> BindingCollector<'a> {
    fn handle_import_specifier_state(
        &mut self,
        state: ImportResolutionState,
        binding_opt: Option<&BindingPattern<'a>>,
    ) {
        match &state {
            ImportResolutionState::LiteralPackageSpecifier(s)
            | ImportResolutionState::ResolvedConstantSpecifier(s) => {
                if pkg_matches(s, self.pkg_name) {
                    self.is_imported = true;
                    if let Some(pattern) = binding_opt {
                        bind_pattern(pattern, "dyn", &mut self.bindings, &mut self.named_imports);
                    }
                }
            }
            ImportResolutionState::UnresolvedDynamicSpecifier(_) => {
                self.has_unresolved_dynamic = true;
                self.has_dynamic_construct = true;
            }
            ImportResolutionState::NonPackageImport(_) => {}
        }
        self.import_states.push(state);
    }
}

fn extract_require_or_import_call<'a>(
    expr: &'a Expression<'a>,
) -> Option<(&'a Expression<'a>, Option<String>)> {
    if let Expression::CallExpression(call) = expr {
        if let Expression::Identifier(id) = &call.callee {
            if id.name == "require" {
                if let Some(arg) = call.arguments.first() {
                    return arg.as_expression().map(|e| (e, None));
                }
            }
        }
        if let Expression::ImportExpression(imp) = &call.callee {
            return Some((&imp.source, None));
        }
    }
    if let Expression::ImportExpression(imp) = expr {
        return Some((&imp.source, None));
    }
    if let Some(mem) = expr.as_member_expression() {
        let prop = member_static_property_name(mem).map(|p| p.to_string());
        let obj = unwrap_await(member_object(mem));
        if let Some((spec, _)) = extract_require_or_import_call(obj) {
            return Some((spec, prop));
        }
    }
    None
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

    fn visit_new_expression(&mut self, new_expr: &NewExpression<'a>) {
        if let Expression::Identifier(id) = &new_expr.callee {
            if id.name == "Proxy" {
                self.has_dynamic_construct = true;
            }
        }
        walk::walk_new_expression(self, new_expr);
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
        let Some(_) = self.bindings.get(base_name) else {
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

        let fn_label = format!("{}.{}", base_name, prop);
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
    fn test_constant_foldable_dynamic_import() {
        let src = r#"
const pkg = 'lodash';
async function run() {
    const mod = await import(pkg);
    mod.template('Hello!');
}
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported, "constant-folded import must be recognized");
        assert!(
            !r.call_sites.is_empty(),
            "call site on resolved constant import must be found"
        );
    }

    #[test]
    fn test_constant_foldable_require() {
        let src = r#"
const name = 'lodash';
const _ = require(name);
_.template('Hello!');
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(r.is_imported, "constant-folded require must be recognized");
        assert!(
            !r.call_sites.is_empty(),
            "call site on resolved require must be found"
        );
    }

    #[test]
    fn test_unresolved_variable_import_marks_uncertainty() {
        let src = r#"
async function run(dynamicModule) {
    const mod = await import(dynamicModule);
    return mod;
}
"#;
        let r = analyze_file(src, js(), "lodash", Some(&["template".to_string()]));
        assert!(
            r.has_unresolved_dynamic,
            "unresolved import must mark has_unresolved_dynamic"
        );
        assert!(
            r.has_dynamic_construct,
            "unresolved import must mark has_dynamic_construct"
        );
        assert!(r
            .import_states
            .iter()
            .any(|s| matches!(s, ImportResolutionState::UnresolvedDynamicSpecifier(_))));
    }

    #[test]
    fn test_create_require_flags_dynamic_construct() {
        let src = r#"
import { createRequire } from 'module';
const customReq = createRequire(import.meta.url);
const mod = customReq('lodash');
"#;
        let r = analyze_file(src, js(), "lodash", None);
        assert!(
            r.has_dynamic_construct,
            "createRequire must be flagged as dynamic construct"
        );
    }

    #[test]
    fn test_proxy_and_eval_flag_dynamic_construct() {
        let src = r#"
const p = new Proxy({}, {});
eval("console.log('hi')");
"#;
        let r = analyze_file(src, js(), "lodash", None);
        assert!(
            r.has_dynamic_construct,
            "Proxy and eval must flag dynamic construct"
        );
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

    #[test]
    fn test_syntax_error_sets_parse_failed() {
        let src = r#"function badSyntax( { let x = ;"#;
        let r = analyze_file(src, js(), "lodash", None);
        assert!(r.parse_failed, "syntax error must set parse_failed");
    }
}
