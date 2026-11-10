#![forbid(unsafe_code)]

use crate::scanner::sast::{sanitize_sink_signature, CodeFinding};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    CallExpression, Expression, MemberExpression, NewExpression, ObjectPropertyKind, PropertyKey,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;
use std::collections::HashSet;

/// Result of AST-based SAST scanning for a single JS/TS file.
pub struct JsAstSastResult {
    pub findings: Vec<CodeFinding>,
    pub parse_failed: bool,
    pub parse_error: Option<String>,
}

/// Scans a JavaScript or TypeScript source string using the OXC AST parser.
/// Provides semantic, AST-level sink identification and intra-procedural taint verification.
pub fn scan_js_ts_ast(rel_path: &str, source: &str, source_type: SourceType) -> JsAstSastResult {
    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions {
            parse_regular_expression: false,
            ..ParseOptions::default()
        })
        .parse();

    let parse_failed = !ret.diagnostics.is_empty();
    let parse_error = ret.diagnostics.first().map(|d| format!("{:?}", d));

    let mut visitor = JsSastVisitor {
        rel_path,
        source,
        findings: Vec::new(),
        reported_lines: HashSet::new(),
    };

    walk::walk_program(&mut visitor, &ret.program);

    JsAstSastResult {
        findings: visitor.findings,
        parse_failed,
        parse_error,
    }
}

struct JsSastVisitor<'a> {
    rel_path: &'a str,
    source: &'a str,
    findings: Vec<CodeFinding>,
    reported_lines: HashSet<(String, usize)>,
}

impl<'a, 'b> Visit<'b> for JsSastVisitor<'a> {
    fn visit_call_expression(&mut self, call: &CallExpression<'b>) {
        self.check_call_expression(call);
        walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, new_expr: &NewExpression<'b>) {
        self.check_new_expression(new_expr);
        walk::walk_new_expression(self, new_expr);
    }

    fn visit_member_expression(&mut self, mem: &MemberExpression<'b>) {
        self.check_member_expression(mem);
        walk::walk_member_expression(self, mem);
    }
}

impl<'a> JsSastVisitor<'a> {
    fn check_call_expression<'b>(&mut self, call: &CallExpression<'b>) {
        // 1. VEXA-SAST-001: OS Command Injection (child_process.exec, execSync, shelljs.exec)
        if let Some((callee_name, is_spawn)) = self.resolve_exec_or_spawn_callee(&call.callee) {
            let (line, _) = span_to_line(call.span.start as usize, self.source);
            if is_spawn {
                // Check if spawn has shell: true option
                if call.arguments.len() >= 3 {
                    if let Some(opt_arg) = call.arguments.get(2) {
                        if let Some(expr) = opt_arg.as_expression() {
                            if self.has_shell_true_option(expr) {
                                self.add_finding(
                                    "VEXA-SAST-001",
                                    "CRITICAL",
                                    "OS Command Injection",
                                    Some("CWE-78"),
                                    line,
                                    "child_process.spawn(..., {shell: true})",
                                    "Avoid invoking shells in spawn(); use execFile() or spawn() with argument arrays.",
                                );
                            }
                        }
                    }
                }
            } else {
                // It is an exec / execSync call
                if let Some(first_arg) = call.arguments.first() {
                    if let Some(expr) = first_arg.as_expression() {
                        if self.is_dynamic_or_concatenated(expr) {
                            let sink_label = format!("{}(...)", callee_name);
                            self.add_finding(
                                "VEXA-SAST-001",
                                "CRITICAL",
                                "OS Command Injection",
                                Some("CWE-78"),
                                line,
                                &sink_label,
                                "Use child_process.execFile() or spawn() with an argument array instead of invoking a shell.",
                            );
                        }
                    }
                }
            }
        }

        // 2. VEXA-SAST-002: Dynamic Code Evaluation (eval, vm.runInContext, etc.)
        if let Some(eval_sink) = self.resolve_eval_callee(&call.callee) {
            let (line, _) = span_to_line(call.span.start as usize, self.source);
            if let Some(first_arg) = call.arguments.first() {
                if let Some(expr) = first_arg.as_expression() {
                    if self.is_dynamic_or_concatenated(expr) {
                        self.add_finding(
                            "VEXA-SAST-002",
                            "HIGH",
                            "Arbitrary Code Execution via Dynamic Evaluation",
                            Some("CWE-94"),
                            line,
                            &eval_sink,
                            "Eliminate dynamic eval() and vm execution; use structured JSON parsing or safe dispatch tables.",
                        );
                    }
                }
            }
        }

        // 3. VEXA-SAST-003: Insecure Deserialization (serialize.unserialize)
        if let Some(deser_sink) = self.resolve_deserialization_callee(&call.callee) {
            let (line, _) = span_to_line(call.span.start as usize, self.source);
            self.add_finding(
                "VEXA-SAST-003",
                "CRITICAL",
                "Insecure Deserialization of Untrusted Data",
                Some("CWE-502"),
                line,
                &deser_sink,
                "Replace node-serialize/serialize-javascript with JSON.parse() or a schema-validated deserializer.",
            );
        }

        // 4. VEXA-SAST-004: SQL Injection via String Interpolation / Concatenation
        if let Some(sql_sink) = self.resolve_sql_query_callee(&call.callee) {
            if let Some(first_arg) = call.arguments.first() {
                if let Some(expr) = first_arg.as_expression() {
                    if self.is_dynamic_or_concatenated(expr) {
                        let (line, _) = span_to_line(call.span.start as usize, self.source);
                        self.add_finding(
                            "VEXA-SAST-004",
                            "CRITICAL",
                            "SQL Injection via Unparameterized Query",
                            Some("CWE-89"),
                            line,
                            &sql_sink,
                            "Use parameterized queries (e.g. $1, ? placeholders) instead of string concatenation or template interpolation.",
                        );
                    }
                }
            }
        }

        // 5. VEXA-SAST-007: Weak Cryptographic Hash (MD5 / SHA-1)
        if let Some(crypto_sink) = self.resolve_weak_crypto_callee(call) {
            let (line, _) = span_to_line(call.span.start as usize, self.source);
            self.add_finding(
                "VEXA-SAST-007",
                "MEDIUM",
                "Use of Broken or Risky Cryptographic Hash (MD5/SHA-1)",
                Some("CWE-327"),
                line,
                &crypto_sink,
                "Use SHA-256 or SHA-512 instead of MD5 or SHA-1 for security-sensitive hashing.",
            );
        }
    }

    fn check_new_expression<'b>(&mut self, new_expr: &NewExpression<'b>) {
        if let Expression::Identifier(id) = &new_expr.callee {
            if id.name == "Function" {
                if let Some(first_arg) = new_expr.arguments.first() {
                    if let Some(expr) = first_arg.as_expression() {
                        if self.is_dynamic_or_concatenated(expr) {
                            let (line, _) = span_to_line(new_expr.span.start as usize, self.source);
                            self.add_finding(
                                "VEXA-SAST-002",
                                "HIGH",
                                "Arbitrary Code Execution via Dynamic Evaluation",
                                Some("CWE-94"),
                                line,
                                "new Function(...)",
                                "Eliminate dynamic Function constructor calls; use static functions.",
                            );
                        }
                    }
                }
            }
        }
    }

    fn check_member_expression<'b>(&mut self, mem: &MemberExpression<'b>) {
        // Check for rejectUnauthorized: false in object assignments
        if let MemberExpression::StaticMemberExpression(s) = mem {
            if s.property.name == "rejectUnauthorized" {
                let (line, _) = span_to_line(s.span.start as usize, self.source);
                let snippet = line_snippet(self.source, line);
                if snippet.contains("false") || snippet.contains("0") {
                    self.add_finding(
                        "VEXA-SAST-008",
                        "HIGH",
                        "Improper TLS Certificate Validation (rejectUnauthorized: false)",
                        Some("CWE-295"),
                        line,
                        "rejectUnauthorized: false",
                        "Enable TLS certificate validation by setting rejectUnauthorized: true.",
                    );
                }
            }
        }
    }

    fn resolve_exec_or_spawn_callee<'b>(&self, callee: &Expression<'b>) -> Option<(String, bool)> {
        // Direct identifier: `exec(...)`, `execSync(...)`
        if let Expression::Identifier(id) = callee {
            let name = id.name.as_str();
            if name == "exec" || name == "execSync" {
                return Some((name.to_string(), false));
            }
            if name == "spawn" || name == "spawnSync" {
                return Some((name.to_string(), true));
            }
        }

        // Member expressions: `cp.exec`, `child_process.exec`, `shelljs.exec`
        if let Some(mem) = callee.as_member_expression() {
            if let Some(prop_name) = member_prop_name(mem) {
                if prop_name == "exec" || prop_name == "execSync" {
                    return Some((format!("child_process.{}", prop_name), false));
                }
                if prop_name == "spawn" || prop_name == "spawnSync" {
                    return Some((format!("child_process.{}", prop_name), true));
                }
            }
        }

        None
    }

    fn resolve_eval_callee<'b>(&self, callee: &Expression<'b>) -> Option<String> {
        if let Expression::Identifier(id) = callee {
            if id.name == "eval" {
                return Some("eval(...)".to_string());
            }
        }
        if let Some(mem) = callee.as_member_expression() {
            if let Some(prop_name) = member_prop_name(mem) {
                if prop_name == "runInContext"
                    || prop_name == "runInNewContext"
                    || prop_name == "runInThisContext"
                {
                    return Some(format!("vm.{}(...)", prop_name));
                }
            }
        }
        None
    }

    fn resolve_deserialization_callee<'b>(&self, callee: &Expression<'b>) -> Option<String> {
        if let Some(mem) = callee.as_member_expression() {
            if let Some(prop) = member_prop_name(mem) {
                if prop == "unserialize" {
                    return Some("serialize.unserialize(...)".to_string());
                }
            }
        }
        None
    }

    fn resolve_sql_query_callee<'b>(&self, callee: &Expression<'b>) -> Option<String> {
        if let Some(mem) = callee.as_member_expression() {
            if let Some(prop) = member_prop_name(mem) {
                if prop == "query" || prop == "raw" || prop == "$queryRawUnsafe" {
                    return Some(format!(".{}(...)", prop));
                }
            }
        }
        None
    }

    fn resolve_weak_crypto_callee<'b>(&self, call: &CallExpression<'b>) -> Option<String> {
        if let Some(mem) = call.callee.as_member_expression() {
            if let Some(prop) = member_prop_name(mem) {
                if prop == "createHash" {
                    if let Some(first_arg) = call.arguments.first() {
                        if let Some(Expression::StringLiteral(s)) = first_arg.as_expression() {
                            if let Some(val_str) = s.value.as_str() {
                                let val = val_str.to_lowercase();
                                if val == "md5" || val == "sha1" {
                                    return Some(format!("createHash('{}')", val));
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn has_shell_true_option<'b>(&self, expr: &Expression<'b>) -> bool {
        if let Expression::ObjectExpression(obj) = expr {
            for prop in &obj.properties {
                if let ObjectPropertyKind::ObjectProperty(p) = prop {
                    let key = match &p.key {
                        PropertyKey::StaticIdentifier(id) => Some(id.name.as_str()),
                        PropertyKey::StringLiteral(s) => s.value.as_str(),
                        _ => None,
                    };
                    if key == Some("shell") {
                        if let Expression::BooleanLiteral(b) = &p.value {
                            return b.value;
                        }
                        if let Expression::NumericLiteral(n) = &p.value {
                            return n.value == 1.0;
                        }
                    }
                }
            }
        }
        false
    }

    /// Evaluates if an expression argument is dynamic, interpolated, or concatenated.
    /// Pure string literals (e.g. "git status", 'ls') are recognized as SAFE (returns false).
    fn is_dynamic_or_concatenated<'b>(&self, expr: &Expression<'b>) -> bool {
        match expr {
            // Static string literal -> SAFE, not tainted
            Expression::StringLiteral(_) => false,
            // Numeric or boolean literal -> SAFE
            Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_) => false,
            // Template literal: if it has expressions, it is dynamic!
            Expression::TemplateLiteral(t) => !t.expressions.is_empty(),
            // Binary expression: e.g. "ping " + host
            Expression::BinaryExpression(_) => true,
            // Identifier variable: e.g. exec(cmd)
            Expression::Identifier(_) => true,
            // Member expression: e.g. exec(req.query.cmd)
            Expression::StaticMemberExpression(_)
            | Expression::ComputedMemberExpression(_)
            | Expression::PrivateFieldExpression(_) => true,
            // Call expression: e.g. exec(getCommand())
            Expression::CallExpression(_) => true,
            _ => true,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_finding(
        &mut self,
        rule_id: &str,
        severity: &str,
        title: &str,
        cwe: Option<&str>,
        line: usize,
        sink: &str,
        remediation: &str,
    ) {
        let key = (rule_id.to_string(), line);
        if !self.reported_lines.insert(key) {
            return;
        }

        self.findings.push(CodeFinding {
            rule_id: rule_id.to_string(),
            category: "SAST".to_string(),
            severity: severity.to_string(),
            title: title.to_string(),
            cwe: cwe.map(|c| c.to_string()),
            file_path: self.rel_path.to_string(),
            line,
            matched_sink: Some(sanitize_sink_signature(sink)),
            remediation: Some(remediation.to_string()),
        });
    }
}

/// Convert a byte offset in `source` to `(1-indexed line number, line snippet <=80 chars)`.
fn span_to_line(byte_offset: usize, source: &str) -> (usize, String) {
    let mut current_byte = 0;
    for (i, line) in source.lines().enumerate() {
        let next = current_byte + line.len() + 1; // +1 for newline
        if byte_offset < next {
            let snippet = line.trim().chars().take(80).collect();
            return (i + 1, snippet);
        }
        current_byte = next;
    }
    let count = source.lines().count();
    let line_num = if count == 0 { 1 } else { count };
    let snippet = source
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .chars()
        .take(80)
        .collect();
    (line_num, snippet)
}

fn line_snippet(source: &str, line_num: usize) -> &str {
    source.lines().nth(line_num.saturating_sub(1)).unwrap_or("")
}

fn member_prop_name<'a>(mem: &'a MemberExpression<'a>) -> Option<&'a str> {
    match mem {
        MemberExpression::StaticMemberExpression(s) => Some(s.property.name.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ast_sast_detects_multiline_exec_injection() {
        let code = r#"
const cp = require('child_process');

function runPing(targetHost) {
    cp.exec(
        "ping -c 1 " +
        targetHost
    );
}
"#;
        let res = scan_js_ts_ast("src/ping.js", code, SourceType::mjs());
        assert_eq!(res.findings.len(), 1);
        let f = &res.findings[0];
        assert_eq!(f.rule_id, "VEXA-SAST-001");
        assert_eq!(f.cwe.as_deref(), Some("CWE-78"));
        assert_eq!(f.matched_sink.as_deref(), Some("child_process.exec(...)"));
        assert_eq!(f.line, 5);
    }

    #[test]
    fn test_ast_sast_suppresses_benign_static_literal_exec() {
        let code = r#"
const cp = require('child_process');

function checkGit() {
    cp.exec("git status");
}
"#;
        let res = scan_js_ts_ast("src/git.js", code, SourceType::mjs());
        assert_eq!(
            res.findings.len(),
            0,
            "Benign static literal exec should not be flagged"
        );
    }

    #[test]
    fn test_ast_sast_detects_template_sqli() {
        let code = r#"
async function getUser(db, userId) {
    return await db.query(
        `SELECT * FROM users WHERE id = ${userId}`
    );
}
"#;
        let res = scan_js_ts_ast("src/db.ts", code, SourceType::ts());
        assert_eq!(res.findings.len(), 1);
        let f = &res.findings[0];
        assert_eq!(f.rule_id, "VEXA-SAST-004");
        assert_eq!(f.cwe.as_deref(), Some("CWE-89"));
        assert_eq!(f.line, 3);
    }

    #[test]
    fn test_ast_sast_detects_spawn_shell_true() {
        let code = r#"
const { spawn } = require('child_process');

function run(cmd) {
    spawn('sh', ['-c', cmd], { shell: true });
}
"#;
        let res = scan_js_ts_ast("src/spawn.js", code, SourceType::mjs());
        assert_eq!(res.findings.len(), 1);
        let f = &res.findings[0];
        assert_eq!(f.rule_id, "VEXA-SAST-001");
        assert_eq!(f.cwe.as_deref(), Some("CWE-78"));
        assert_eq!(f.line, 5);
    }
}
