#![forbid(unsafe_code)]

//! Single-pass `oxc_parser` JavaScript/TypeScript AST import & call-site extractor.
//! Used by both `vexa-sca` CLI and `vexa-sca-cloud` ephemeral GitHub App scanning
//! so JS/TS reachability never falls back to fragile line regexes.

use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingPattern, CallExpression, Expression, ImportDeclaration, ImportDeclarationSpecifier,
    ImportExpression, MemberExpression, NewExpression, PropertyKey, VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct JsAstFacts {
    /// External package name -> 1-based line number of first import/require.
    pub imported_packages: HashMap<String, usize>,
    /// `(package_name, symbol_name)` -> 1-based line number of first call site.
    pub called_symbols: HashMap<(String, String), usize>,
    pub has_unresolved_dynamic: bool,
    pub parse_failed: bool,
}

/// Normalizes a JS/TS module specifier (`@scope/pkg/sub` -> `@scope/pkg`, `lodash/merge` -> `lodash`).
pub fn normalize_js_pkg_specifier(spec: &str) -> String {
    let clean = spec.trim().trim_matches('\'').trim_matches('"');
    if clean.starts_with('@') {
        let parts: Vec<&str> = clean.split('/').collect();
        if parts.len() >= 2 {
            return format!("{}/{}", parts[0], parts[1]);
        }
    }
    clean.split('/').next().unwrap_or(clean).to_string()
}

/// Determines the `oxc_span::SourceType` from a file extension (`js`, `jsx`, `ts`, `tsx`, `mjs`, `cjs`).
pub fn source_type_for_ext(ext: &str) -> SourceType {
    match ext.to_ascii_lowercase().as_str() {
        "ts" | "mts" | "cts" => SourceType::ts(),
        "tsx" => SourceType::tsx(),
        "jsx" => SourceType::jsx(),
        "cjs" => SourceType::cjs(),
        _ => SourceType::mjs(),
    }
}

fn line_number_at(source: &str, byte_offset: u32) -> usize {
    let idx = (byte_offset as usize).min(source.len());
    source[..idx].bytes().filter(|&b| b == b'\n').count() + 1
}

/// Parses a JS/TS source buffer **once** with `oxc_parser` and extracts all external
/// package imports (`import`, `require`, `import()`) and symbol call sites.
pub fn analyze_js_ts_single_pass(source: &str, ext: &str) -> JsAstFacts {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, source_type_for_ext(ext))
        .with_options(ParseOptions {
            parse_regular_expression: false,
            ..ParseOptions::default()
        })
        .parse();

    let parse_failed = !ret.diagnostics.is_empty();
    let program = ret.program;

    let mut collector = JsImportAndBindingCollector {
        source,
        imported_packages: HashMap::new(),
        namespace_aliases: HashMap::new(),
        named_aliases: HashMap::new(),
        has_unresolved_dynamic: false,
    };
    walk::walk_program(&mut collector, &program);

    let mut call_checker = JsCallSiteVisitor {
        source,
        namespace_aliases: &collector.namespace_aliases,
        named_aliases: &collector.named_aliases,
        called_symbols: HashMap::new(),
    };
    walk::walk_program(&mut call_checker, &program);

    JsAstFacts {
        imported_packages: collector.imported_packages,
        called_symbols: call_checker.called_symbols,
        has_unresolved_dynamic: collector.has_unresolved_dynamic,
        parse_failed,
    }
}

struct JsImportAndBindingCollector<'a> {
    source: &'a str,
    imported_packages: HashMap<String, usize>,
    /// `local_ident` -> `package_name` (default/namespace imports, `const _ = require('lodash')`)
    namespace_aliases: HashMap<String, String>,
    /// `local_ident` -> `(package_name, original_symbol)` (named/destructured imports)
    named_aliases: HashMap<String, (String, String)>,
    has_unresolved_dynamic: bool,
}

impl<'a> JsImportAndBindingCollector<'a> {
    fn record_specifier(&mut self, raw: &str, line: usize) -> Option<String> {
        let clean = raw.trim().trim_matches('\'').trim_matches('"');
        if clean.is_empty() || clean.starts_with('.') || clean.starts_with('/') {
            return None;
        }
        let pkg = normalize_js_pkg_specifier(clean);
        self.imported_packages.entry(pkg.clone()).or_insert(line);
        Some(pkg)
    }
}

impl<'a> Visit<'a> for JsImportAndBindingCollector<'a> {
    fn visit_import_declaration(&mut self, decl: &ImportDeclaration<'a>) {
        let line = line_number_at(self.source, decl.span.start);
        let Some(raw) = decl.source.value.as_str() else {
            return;
        };
        let Some(pkg) = self.record_specifier(raw, line) else {
            return;
        };
        if let Some(specifiers) = &decl.specifiers {
            for spec in specifiers {
                match spec {
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                        self.namespace_aliases
                            .insert(s.local.name.to_string(), pkg.clone());
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                        self.namespace_aliases
                            .insert(s.local.name.to_string(), pkg.clone());
                    }
                    ImportDeclarationSpecifier::ImportSpecifier(s) => {
                        let orig = s.imported.name().to_string();
                        self.named_aliases
                            .insert(s.local.name.to_string(), (pkg.clone(), orig));
                    }
                }
            }
        }
    }

    fn visit_import_expression(&mut self, expr: &ImportExpression<'a>) {
        let line = line_number_at(self.source, expr.span.start);
        if let Expression::StringLiteral(s) = &expr.source {
            if let Some(raw) = s.value.as_str() {
                self.record_specifier(raw, line);
            }
        } else {
            self.has_unresolved_dynamic = true;
        }
        walk::walk_import_expression(self, expr);
    }

    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        if let Some(Expression::CallExpression(call)) = &decl.init {
            if let Expression::Identifier(callee) = &call.callee {
                if callee.name == "require" {
                    let line = line_number_at(self.source, call.span.start);
                    if let Some(arg) = call.arguments.first() {
                        if let Some(Expression::StringLiteral(s)) = arg.as_expression() {
                            if let Some(raw) = s.value.as_str() {
                                if let Some(pkg) = self.record_specifier(raw, line) {
                                    match &decl.id {
                                        BindingPattern::BindingIdentifier(id) => {
                                            self.namespace_aliases.insert(id.name.to_string(), pkg);
                                        }
                                        BindingPattern::ObjectPattern(obj) => {
                                            for prop in &obj.properties {
                                                let orig = match &prop.key {
                                                    PropertyKey::StaticIdentifier(id) => {
                                                        Some(id.name.to_string())
                                                    }
                                                    PropertyKey::StringLiteral(lit) => {
                                                        lit.value.as_str().map(|s| s.to_string())
                                                    }
                                                    _ => None,
                                                };
                                                if let (
                                                    Some(orig_name),
                                                    BindingPattern::BindingIdentifier(local),
                                                ) = (orig, &prop.value)
                                                {
                                                    self.named_aliases.insert(
                                                        local.name.to_string(),
                                                        (pkg.clone(), orig_name),
                                                    );
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        } else {
                            self.has_unresolved_dynamic = true;
                        }
                    }
                }
            }
        }
        walk::walk_variable_declarator(self, decl);
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = &call.callee {
            if callee.name == "require" {
                let line = line_number_at(self.source, call.span.start);
                if let Some(arg) = call.arguments.first() {
                    if let Some(Expression::StringLiteral(s)) = arg.as_expression() {
                        if let Some(raw) = s.value.as_str() {
                            self.record_specifier(raw, line);
                        }
                    } else {
                        self.has_unresolved_dynamic = true;
                    }
                }
            }
        }
        walk::walk_call_expression(self, call);
    }
}

struct JsCallSiteVisitor<'a> {
    source: &'a str,
    namespace_aliases: &'a HashMap<String, String>,
    named_aliases: &'a HashMap<String, (String, String)>,
    called_symbols: HashMap<(String, String), usize>,
}

impl<'a> JsCallSiteVisitor<'a> {
    fn inspect_callee(&mut self, callee: &Expression<'a>, line: usize) {
        match callee {
            Expression::Identifier(id) => {
                let name = id.name.as_str();
                if let Some((pkg, orig)) = self.named_aliases.get(name) {
                    self.called_symbols
                        .entry((pkg.clone(), orig.to_ascii_lowercase()))
                        .or_insert(line);
                } else if let Some(pkg) = self.namespace_aliases.get(name) {
                    self.called_symbols
                        .entry((pkg.clone(), "default".to_string()))
                        .or_insert(line);
                }
            }
            Expression::StaticMemberExpression(member) => {
                if let Expression::Identifier(obj) = &member.object {
                    if let Some(pkg) = self.namespace_aliases.get(obj.name.as_str()) {
                        let prop = member.property.name.to_ascii_lowercase();
                        self.called_symbols
                            .entry((pkg.clone(), prop))
                            .or_insert(line);
                    }
                }
            }
            Expression::ComputedMemberExpression(member) => {
                if let Expression::Identifier(obj) = &member.object {
                    if let Some(pkg) = self.namespace_aliases.get(obj.name.as_str()) {
                        if let Expression::StringLiteral(lit) = &member.expression {
                            if let Some(prop) = lit.value.as_str() {
                                self.called_symbols
                                    .entry((pkg.clone(), prop.to_ascii_lowercase()))
                                    .or_insert(line);
                            }
                        }
                    }
                }
            }
            _ => {
                if let Some(MemberExpression::StaticMemberExpression(m)) =
                    callee.as_member_expression()
                {
                    if let Expression::Identifier(obj) = &m.object {
                        if let Some(pkg) = self.namespace_aliases.get(obj.name.as_str()) {
                            self.called_symbols
                                .entry((pkg.clone(), m.property.name.to_ascii_lowercase()))
                                .or_insert(line);
                        }
                    }
                }
            }
        }
    }
}

impl<'a> Visit<'a> for JsCallSiteVisitor<'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        let line = line_number_at(self.source, call.span.start);
        self.inspect_callee(&call.callee, line);
        walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, expr: &NewExpression<'a>) {
        let line = line_number_at(self.source, expr.span.start);
        self.inspect_callee(&expr.callee, line);
        walk::walk_new_expression(self, expr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_pass_ast_extracts_esm_and_cjs_imports_and_calls() {
        let src = r#"
import _ from 'lodash';
import { template as tpl } from 'lodash';
const axios = require('axios');
// import fake from 'commented-out-pkg';
const out = _.merge({}, {});
tpl("<%= name %>");
axios.get("https://example.com");
"#;
        let facts = analyze_js_ts_single_pass(src, "ts");
        assert!(!facts.parse_failed);
        assert!(facts.imported_packages.contains_key("lodash"));
        assert!(facts.imported_packages.contains_key("axios"));
        assert!(
            !facts.imported_packages.contains_key("commented-out-pkg"),
            "AST must ignore commented-out imports"
        );
        assert!(facts
            .called_symbols
            .contains_key(&("lodash".to_string(), "merge".to_string())));
        assert!(facts
            .called_symbols
            .contains_key(&("lodash".to_string(), "template".to_string())));
        assert!(facts
            .called_symbols
            .contains_key(&("axios".to_string(), "get".to_string())));
    }
}
