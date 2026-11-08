#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// A Zero-Code-Sync SAST or Secret finding.
/// Raw source code lines are NEVER stored in this struct; only the canonical sink signature
/// (`matched_sink`, capped at <= 64 chars) and POSIX-normalized `file_path` + `line` are retained.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeFinding {
    pub rule_id: String,
    pub category: String, // "SAST" | "SECRET" | "SUPPLY_CHAIN"
    pub severity: String, // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    pub title: String,
    pub cwe: Option<String>,
    pub file_path: String,
    pub line: usize,
    pub matched_sink: Option<String>,
    pub remediation: Option<String>,
}

/// Normalize any Windows (`\`), macOS, or Linux file path relative to `workspace_root`
/// into a clean POSIX forward-slash path (`src/os-ijection.py`) for GitHub `#L12` deep links.
pub fn normalize_workspace_relative_path(workspace_root: &Path, file_path: &Path) -> String {
    let rel = file_path
        .strip_prefix(workspace_root)
        .unwrap_or(file_path)
        .to_string_lossy()
        .replace('\\', "/");

    let mut s = rel.trim().to_string();
    // Strip Windows extended-length prefix or drive letter if still present
    if let Some(stripped) = s.strip_prefix("//?/") {
        s = stripped.to_string();
    }
    if s.len() >= 2 && s.as_bytes()[1] == b':' && s.as_bytes()[0].is_ascii_alphabetic() {
        s = s[2..].to_string();
    }
    while s.starts_with("./") {
        s = s[2..].to_string();
    }
    while s.starts_with('/') {
        s = s[1..].to_string();
    }
    let parts: Vec<&str> = s
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != "." && *seg != "..")
        .collect();
    parts.join("/")
}

/// Enforces Zero-Code-Sync Invariant 3:
/// Strips newlines and caps the canonical sink signature at <= 64 characters.
pub fn sanitize_sink_signature(raw: &str) -> String {
    let first_line = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let count = first_line.chars().count();
    if count <= 64 {
        first_line.to_string()
    } else {
        let prefix: String = first_line.chars().take(61).collect();
        format!("{prefix}...")
    }
}

pub struct SastScanner;

impl SastScanner {
    /// Scan first-party source files in `workspace_root` across Python, JS/TS, Go, Rust, and Java.
    /// Executes 100% locally in <50ms and emits only canonical sink signatures (zero raw source code).
    pub fn scan_workspace(workspace_root: &Path) -> Vec<CodeFinding> {
        let mut findings = Vec::new();
        Self::walk_dir(workspace_root, workspace_root, 0, &mut findings);
        findings
    }

    fn walk_dir(root: &Path, current: &Path, depth: usize, findings: &mut Vec<CodeFinding>) {
        if depth > 8 {
            return;
        }
        if current.is_file() {
            Self::scan_file(root, current, findings);
            return;
        }
        let Ok(entries) = fs::read_dir(current) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if name.starts_with('.')
                    || name == "node_modules"
                    || name == "target"
                    || name == "vendor"
                    || name == "dist"
                    || name == "build"
                    || name == "__pycache__"
                    || name == "venv"
                    || name == ".venv"
                {
                    continue;
                }
                Self::walk_dir(root, &path, depth + 1, findings);
            } else if path.is_file() {
                Self::scan_file(root, &path, findings);
            }
        }
    }

    pub fn scan_file(root: &Path, file_path: &Path, findings: &mut Vec<CodeFinding>) {
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let is_supported = matches!(
            ext.as_str(),
            "py" | "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "go" | "rs" | "java"
        );
        if !is_supported {
            return;
        }

        if let Ok(meta) = fs::metadata(file_path) {
            if meta.len() > 2 * 1024 * 1024 {
                return;
            }
        }

        let Ok(content) = fs::read_to_string(file_path) else {
            return;
        };

        let rel_path = normalize_workspace_relative_path(root, file_path);

        for (idx, raw_line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = raw_line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
            {
                continue;
            }

            // 1. VEXA-SAST-001: OS Command Injection (CWE-78)
            if let Some((sink, remediation)) = Self::detect_os_command_injection(&ext, trimmed) {
                findings.push(CodeFinding {
                    rule_id: "VEXA-SAST-001".to_string(),
                    category: "SAST".to_string(),
                    severity: "CRITICAL".to_string(),
                    title: "OS Command Injection".to_string(),
                    cwe: Some("CWE-78".to_string()),
                    file_path: rel_path.clone(),
                    line: line_num,
                    matched_sink: Some(sanitize_sink_signature(sink)),
                    remediation: Some(remediation.to_string()),
                });
                continue;
            }

            // 2. VEXA-SAST-002: Dangerous Dynamic Code Execution / Eval (CWE-94)
            if let Some((sink, remediation)) = Self::detect_eval_injection(&ext, trimmed) {
                findings.push(CodeFinding {
                    rule_id: "VEXA-SAST-002".to_string(),
                    category: "SAST".to_string(),
                    severity: "HIGH".to_string(),
                    title: "Arbitrary Code Execution via Dynamic Evaluation".to_string(),
                    cwe: Some("CWE-94".to_string()),
                    file_path: rel_path.clone(),
                    line: line_num,
                    matched_sink: Some(sanitize_sink_signature(sink)),
                    remediation: Some(remediation.to_string()),
                });
                continue;
            }

            // 3. VEXA-SAST-003: Insecure Deserialization (CWE-502)
            if let Some((sink, remediation)) = Self::detect_insecure_deserialization(&ext, trimmed)
            {
                findings.push(CodeFinding {
                    rule_id: "VEXA-SAST-003".to_string(),
                    category: "SAST".to_string(),
                    severity: "CRITICAL".to_string(),
                    title: "Insecure Deserialization of Untrusted Data".to_string(),
                    cwe: Some("CWE-502".to_string()),
                    file_path: rel_path.clone(),
                    line: line_num,
                    matched_sink: Some(sanitize_sink_signature(sink)),
                    remediation: Some(remediation.to_string()),
                });
                continue;
            }

            // 4. VEXA-SAST-004: SQL Injection via String Interpolation (CWE-89)
            if let Some((sink, remediation)) = Self::detect_sql_injection(trimmed) {
                findings.push(CodeFinding {
                    rule_id: "VEXA-SAST-004".to_string(),
                    category: "SAST".to_string(),
                    severity: "CRITICAL".to_string(),
                    title: "SQL Injection via Unparameterized Query".to_string(),
                    cwe: Some("CWE-89".to_string()),
                    file_path: rel_path.clone(),
                    line: line_num,
                    matched_sink: Some(sanitize_sink_signature(sink)),
                    remediation: Some(remediation.to_string()),
                });
                continue;
            }

            // 5. VEXA-SAST-005: Cross-Site Scripting / Raw HTML Injection (CWE-79)
            if let Some((sink, remediation)) = Self::detect_xss(&ext, trimmed) {
                findings.push(CodeFinding {
                    rule_id: "VEXA-SAST-005".to_string(),
                    category: "SAST".to_string(),
                    severity: "HIGH".to_string(),
                    title: "Cross-Site Scripting (XSS) via Raw DOM Injection".to_string(),
                    cwe: Some("CWE-79".to_string()),
                    file_path: rel_path.clone(),
                    line: line_num,
                    matched_sink: Some(sanitize_sink_signature(sink)),
                    remediation: Some(remediation.to_string()),
                });
                continue;
            }

            // 6. VEXA-SAST-006: Path Traversal / Arbitrary File Access (CWE-22)
            if let Some((sink, remediation)) = Self::detect_path_traversal(&ext, trimmed) {
                findings.push(CodeFinding {
                    rule_id: "VEXA-SAST-006".to_string(),
                    category: "SAST".to_string(),
                    severity: "CRITICAL".to_string(),
                    title: "Path Traversal / Arbitrary File Access".to_string(),
                    cwe: Some("CWE-22".to_string()),
                    file_path: rel_path.clone(),
                    line: line_num,
                    matched_sink: Some(sanitize_sink_signature(sink)),
                    remediation: Some(remediation.to_string()),
                });
                continue;
            }

            // 7. VEXA-SAST-007: Weak Cryptographic Hash (MD5 / SHA-1) (CWE-327)
            if let Some((sink, remediation)) = Self::detect_weak_crypto(trimmed) {
                findings.push(CodeFinding {
                    rule_id: "VEXA-SAST-007".to_string(),
                    category: "SAST".to_string(),
                    severity: "MEDIUM".to_string(),
                    title: "Use of Broken or Risky Cryptographic Hash (MD5/SHA-1)".to_string(),
                    cwe: Some("CWE-327".to_string()),
                    file_path: rel_path.clone(),
                    line: line_num,
                    matched_sink: Some(sanitize_sink_signature(sink)),
                    remediation: Some(remediation.to_string()),
                });
                continue;
            }

            // 8. VEXA-SAST-008: Disabled TLS Certificate Verification (CWE-295)
            if let Some((sink, remediation)) = Self::detect_disabled_tls(trimmed) {
                findings.push(CodeFinding {
                    rule_id: "VEXA-SAST-008".to_string(),
                    category: "SAST".to_string(),
                    severity: "HIGH".to_string(),
                    title: "Improper TLS Certificate Validation (verify=False)".to_string(),
                    cwe: Some("CWE-295".to_string()),
                    file_path: rel_path.clone(),
                    line: line_num,
                    matched_sink: Some(sanitize_sink_signature(sink)),
                    remediation: Some(remediation.to_string()),
                });
                continue;
            }

            // 9. VEXA-SAST-009: Server-Side Request Forgery (SSRF) (CWE-918)
            if let Some((sink, remediation)) = Self::detect_ssrf(&ext, trimmed) {
                findings.push(CodeFinding {
                    rule_id: "VEXA-SAST-009".to_string(),
                    category: "SAST".to_string(),
                    severity: "HIGH".to_string(),
                    title: "Server-Side Request Forgery (SSRF) via Untrusted URL".to_string(),
                    cwe: Some("CWE-918".to_string()),
                    file_path: rel_path.clone(),
                    line: line_num,
                    matched_sink: Some(sanitize_sink_signature(sink)),
                    remediation: Some(remediation.to_string()),
                });
            }
        }
    }

    fn detect_os_command_injection(ext: &str, line: &str) -> Option<(&'static str, &'static str)> {
        if ext == "py" {
            if line.contains("os.system(") {
                return Some((
                    "os.system(...)",
                    "Replace os.system() with subprocess.run([cmd, arg1], shell=False) to prevent shell command injection.",
                ));
            }
            if line.contains("os.popen(") {
                return Some((
                    "os.popen(...)",
                    "Replace os.popen() with subprocess.run([cmd, arg1], shell=False, capture_output=True).",
                ));
            }
            if (line.contains("subprocess.call(")
                || line.contains("subprocess.run(")
                || line.contains("subprocess.Popen(")
                || line.contains("subprocess.check_output("))
                && (line.contains("shell=True") || line.contains("shell = True"))
            {
                return Some((
                    "subprocess(..., shell=True)",
                    "Pass command arguments as a list and set shell=False in subprocess calls.",
                ));
            }
        } else if matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
            let has_exec_call = line.contains("child_process.exec(")
                || line.contains("child_process.execSync(")
                || line.contains("cp.exec(")
                || line.contains("cp.execSync(")
                || line.contains("childProcess.exec(")
                || line.contains("childProcess.execSync(")
                || line.contains("shelljs.exec(")
                || line.starts_with("exec(")
                || line.contains(" exec(")
                || line.contains("=exec(")
                || line.contains("(exec(")
                || line.contains("await exec(")
                || line.starts_with("execSync(")
                || line.contains(" execSync(")
                || line.contains("=execSync(")
                || line.contains("(execSync(")
                || line.contains("await execSync(");

            let is_pure_decl = (line.starts_with("import ") || line.starts_with("export "))
                && !line.contains("exec(");

            let is_spawn_shell = (line.contains("spawn(") || line.contains(".spawn("))
                && (line.contains("shell: true")
                    || line.contains("shell:true")
                    || line.contains("shell: 1"));

            if (has_exec_call && !is_pure_decl) || is_spawn_shell {
                return Some((
                    "child_process.exec(...)",
                    "Use child_process.execFile() or spawn() with an argument array instead of invoking a shell.",
                ));
            }
        } else if ext == "go" {
            if line.contains("exec.Command(\"sh\", \"-c\"")
                || line.contains("exec.Command(\"bash\", \"-c\"")
                || line.contains("exec.Command(\"cmd\", \"/C\"")
            {
                return Some((
                    "exec.Command(\"sh\", \"-c\", ...)",
                    "Pass the binary name and separate arguments directly to exec.Command() without a shell.",
                ));
            }
        } else if ext == "rs" {
            if (line.contains("Command::new(\"sh\")")
                || line.contains("Command::new(\"bash\")")
                || line.contains("Command::new(\"cmd\")"))
                && (line.contains(".arg(\"-c\")") || line.contains(".arg(\"/C\")"))
            {
                return Some((
                    "Command::new(\"sh\").arg(\"-c\")",
                    "Invoke the target executable directly via std::process::Command::new(bin).args([...]) without a shell.",
                ));
            }
        } else if ext == "java" && line.contains("Runtime.getRuntime().exec(") {
            return Some((
                "Runtime.getRuntime().exec(...)",
                "Use ProcessBuilder with a parameterized command list instead of Runtime.exec(String).",
            ));
        }
        None
    }

    fn detect_eval_injection(ext: &str, line: &str) -> Option<(&'static str, &'static str)> {
        if ext == "py" {
            if line.starts_with("eval(")
                || line.contains(" eval(")
                || line.contains("=eval(")
                || line.contains("(eval(")
            {
                return Some((
                    "eval(...)",
                    "Replace eval() with ast.literal_eval() or JSON parsing (json.loads).",
                ));
            }
            if line.starts_with("exec(") || line.contains(" exec(") {
                return Some((
                    "exec(...)",
                    "Avoid executing dynamic Python code strings with exec().",
                ));
            }
        } else if matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
            let is_eval = line.starts_with("eval(")
                || line.starts_with("eval ")
                || line.contains(" eval(")
                || line.contains("=eval(")
                || line.contains("(eval(")
                || line.contains("await eval(")
                || line.contains("window.eval(")
                || line.contains("global.eval(");

            if is_eval {
                return Some((
                    "eval(...)",
                    "Replace eval() with JSON.parse() or a safe expression parser.",
                ));
            }
            if line.contains("new Function(") {
                return Some((
                    "new Function(...)",
                    "Avoid constructing functions dynamically from strings.",
                ));
            }
            if (line.contains("setTimeout(") || line.contains("setInterval("))
                && (line.contains('`') || line.contains('"') || line.contains('\''))
                && (line.contains("${") || line.contains('+'))
            {
                return Some((
                    "setTimeout(stringCode, ...)",
                    "Pass a function reference to setTimeout/setInterval instead of a dynamically constructed string.",
                ));
            }
        }
        None
    }

    fn detect_insecure_deserialization(
        ext: &str,
        line: &str,
    ) -> Option<(&'static str, &'static str)> {
        if ext == "py" {
            if line.contains("pickle.loads(") || line.contains("pickle.load(") {
                return Some((
                    "pickle.loads(...)",
                    "Do not unpickle untrusted data. Use JSON or a schema-validated format like Pydantic/Protobuf.",
                ));
            }
            if line.contains("yaml.load(")
                && !line.contains("SafeLoader")
                && !line.contains("safe_load")
            {
                return Some((
                    "yaml.load(...)",
                    "Use yaml.safe_load() or pass Loader=yaml.SafeLoader to prevent arbitrary object instantiation.",
                ));
            }
        }
        None
    }

    fn detect_sql_injection(line: &str) -> Option<(&'static str, &'static str)> {
        let lower = line.to_lowercase();
        let has_sql_keyword = lower.contains("select ")
            || lower.contains("insert into ")
            || lower.contains("update ")
            || lower.contains("delete from ");

        if has_sql_keyword {
            let has_python_fstring =
                lower.contains(".execute(f\"") || lower.contains(".execute(f'");
            let has_template_interp = line.contains("${");
            let has_concat = line.contains('+');
            let is_query_sink = lower.contains(".query(")
                || lower.contains(".execute(")
                || lower.contains("rawquery(")
                || lower.contains("queryrawunsafe(")
                || lower.contains("$queryrawunsafe(")
                || lower.contains("cursor.execute(");

            let has_unparameterized_str = lower.contains("\"select")
                || lower.contains("'select")
                || lower.contains("`select")
                || lower.contains("\"insert")
                || lower.contains("'insert")
                || lower.contains("\"update")
                || lower.contains("'update")
                || lower.contains("\"delete")
                || lower.contains("'delete");

            if has_python_fstring
                || (is_query_sink && (has_template_interp || has_concat))
                || (has_unparameterized_str && (has_template_interp || has_concat))
            {
                return Some((
                    "db.query(\"SELECT ... \" + input)",
                    "Use parameterized queries / prepared statements instead of string concatenation or template interpolation.",
                ));
            }
        }
        None
    }

    fn detect_path_traversal(ext: &str, line: &str) -> Option<(&'static str, &'static str)> {
        if matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
            let lower = line.to_lowercase();
            let is_fs = lower.contains("fs.readfile(")
                || lower.contains("fs.readfilesync(")
                || lower.contains("fs.createreadstream(")
                || lower.contains("fs.writefile(")
                || lower.contains("fs.writefilesync(")
                || lower.contains("fs.promises.readfile(")
                || lower.contains("fs.promises.writefile(")
                || lower.contains("res.sendfile(")
                || lower.contains("res.download(");

            if is_fs {
                let has_untrusted = line.contains("req.query")
                    || line.contains("req.params")
                    || line.contains("req.body")
                    || line.contains("${")
                    || line.contains('+')
                    || lower.contains("userinput")
                    || lower.contains("filepath")
                    || lower.contains("filename")
                    || lower.contains("user_input");

                if has_untrusted {
                    return Some((
                        "fs.readFile(userInput, ...)",
                        "Validate and sanitize paths using path.resolve() against a safe base directory and disallow directory traversal ('..').",
                    ));
                }
            }
        } else if ext == "py" {
            let lower = line.to_lowercase();
            if lower.contains("open(")
                && (lower.contains("request.args")
                    || lower.contains("request.form")
                    || lower.contains("user_input")
                    || line.contains('+')
                    || lower.contains("f\""))
            {
                return Some((
                    "open(user_path, ...)",
                    "Validate paths against an allowlist and ensure canonical paths stay inside the intended root directory.",
                ));
            }
        }
        None
    }

    fn detect_xss(ext: &str, line: &str) -> Option<(&'static str, &'static str)> {
        if matches!(ext, "js" | "jsx" | "ts" | "tsx") {
            let lower = line.to_lowercase();
            if line.contains("dangerouslySetInnerHTML") {
                return Some((
                    "dangerouslySetInnerHTML={{ __html: ... }}",
                    "Sanitize HTML with DOMPurify before rendering or use standard React text nodes.",
                ));
            }
            if line.contains(".innerHTML =") || line.contains(".innerHTML=") {
                return Some((
                    "element.innerHTML = ...",
                    "Use element.textContent instead of innerHTML when rendering untrusted input.",
                ));
            }
            if line.contains("document.write(") || line.contains("document.writeln(") {
                return Some((
                    "document.write(...)",
                    "Use modern DOM manipulation APIs (document.createElement, textContent) instead of document.write().",
                ));
            }
            if (lower.contains("res.send(") || lower.contains("res.write("))
                && line.contains('<')
                && (line.contains("${") || line.contains('+') || line.contains("req."))
            {
                return Some((
                    "res.send(<html> + input)",
                    "Escape user input or use a template engine with auto-escaping enabled to prevent Cross-Site Scripting (XSS).",
                ));
            }
        }
        None
    }

    fn detect_ssrf(ext: &str, line: &str) -> Option<(&'static str, &'static str)> {
        if matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
            let lower = line.to_lowercase();
            let is_http_client = lower.contains("axios.get(")
                || lower.contains("axios.post(")
                || lower.contains("axios(")
                || lower.contains("fetch(")
                || lower.contains("http.get(")
                || lower.contains("https.get(")
                || lower.contains("request.get(");

            if is_http_client {
                let has_untrusted = line.contains("req.query")
                    || line.contains("req.params")
                    || line.contains("req.body")
                    || line.contains("${")
                    || line.contains('+')
                    || lower.contains("userinput")
                    || lower.contains("targeturl")
                    || lower.contains("target_url");

                if has_untrusted {
                    return Some((
                        "fetch(untrustedUrl, ...)",
                        "Validate target URLs against a strict domain allowlist and block private IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254).",
                    ));
                }
            }
        }
        None
    }

    fn detect_weak_crypto(line: &str) -> Option<(&'static str, &'static str)> {
        if line.contains("hashlib.md5(")
            || line.contains("createHash('md5')")
            || line.contains("createHash(\"md5\")")
        {
            return Some((
                "hashlib.md5(...)",
                "Replace MD5 with SHA-256 (hashlib.sha256) or Argon2/bcrypt for password hashing.",
            ));
        }
        if line.contains("hashlib.sha1(")
            || line.contains("createHash('sha1')")
            || line.contains("createHash(\"sha1\")")
        {
            return Some((
                "hashlib.sha1(...)",
                "Replace SHA-1 with SHA-256 (hashlib.sha256) for collision-resistant cryptographic hashing.",
            ));
        }
        None
    }

    fn detect_disabled_tls(line: &str) -> Option<(&'static str, &'static str)> {
        if (line.contains("requests.") || line.contains("httpx."))
            && (line.contains("verify=False") || line.contains("verify = False"))
        {
            return Some((
                "requests.get(..., verify=False)",
                "Enable TLS certificate verification (verify=True) or provide a trusted CA bundle path.",
            ));
        }
        if line.contains("NODE_TLS_REJECT_UNAUTHORIZED") && line.contains("'0'") {
            return Some((
                "NODE_TLS_REJECT_UNAUTHORIZED = '0'",
                "Do not disable Node.js TLS certificate verification in production.",
            ));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_os_injection_py_and_enforce_zero_code_sink_signature() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_sast_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let py_file = temp_dir.join("os-ijection.py");
        fs::write(
            &py_file,
            "import os\nimport sys\n\ndef run_ping(host):\n    # Super secret proprietary code comment\n    os.system(\"ping -c 1 \" + host)\n",
        )
        .unwrap();

        let findings = SastScanner::scan_workspace(&temp_dir);
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.rule_id, "VEXA-SAST-001");
        assert_eq!(f.category, "SAST");
        assert_eq!(f.severity, "CRITICAL");
        assert_eq!(f.cwe.as_deref(), Some("CWE-78"));
        assert_eq!(f.file_path, "os-ijection.py");
        assert_eq!(f.line, 6);
        // Zero-Code-Sync Invariant: matched_sink only contains canonical signature, NOT "ping -c 1" or proprietary variable names!
        assert_eq!(f.matched_sink.as_deref(), Some("os.system(...)"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_detect_eval_pickle_sqli_xss_tls() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_sast_multi_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        fs::write(
            temp_dir.join("vuln.py"),
            "import pickle, requests\ndata = pickle.loads(raw_bytes)\nres = eval(user_expr)\nrequests.get('https://example.com', verify=False)\n",
        )
        .unwrap();

        let findings = SastScanner::scan_workspace(&temp_dir);
        assert_eq!(findings.len(), 3);
        let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(rule_ids.contains(&"VEXA-SAST-003")); // pickle.loads
        assert!(rule_ids.contains(&"VEXA-SAST-002")); // eval
        assert!(rule_ids.contains(&"VEXA-SAST-008")); // verify=False

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_detect_typescript_sast_vulnerabilities() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_sast_ts_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let ts_code = r#"
import { exec } from "child_process";
import fs from "fs";
import axios from "axios";

export function handleUser(req: any, res: any) {
    const userInput = req.query.cmd;
    exec("ping -c 1 " + userInput);

    const data = fs.readFileSync(req.query.file);
    db.query("SELECT * FROM users WHERE id = " + req.query.id);

    res.send("<h1>Welcome " + req.query.name + "</h1>");
    axios.get(req.query.url);
}
"#;
        fs::write(temp_dir.join("vul01.ts"), ts_code).unwrap();

        let findings = SastScanner::scan_workspace(&temp_dir);
        assert!(
            !findings.is_empty(),
            "Should detect vulnerabilities in vul01.ts"
        );

        let rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(
            rule_ids.contains(&"VEXA-SAST-001"),
            "Should detect OS Command Injection"
        );
        assert!(
            rule_ids.contains(&"VEXA-SAST-006"),
            "Should detect Path Traversal"
        );
        assert!(
            rule_ids.contains(&"VEXA-SAST-004"),
            "Should detect SQL Injection"
        );
        assert!(rule_ids.contains(&"VEXA-SAST-005"), "Should detect XSS");
        assert!(rule_ids.contains(&"VEXA-SAST-009"), "Should detect SSRF");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
