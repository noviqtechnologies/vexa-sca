use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::scanner::sast::{normalize_workspace_relative_path, CodeFinding};

struct SecretRule {
    rule_id: &'static str,
    cwe_id: &'static str,
    title: &'static str,
    severity: &'static str,
    sink_symbol: &'static str,
    remediation_hint: &'static str,
    pattern: Regex,
}

/// Zero-Code-Sync Local Secret & Credential Scanner.
/// Scans local workspace files for hardcoded API keys, tokens, and private keys,
/// and aggressively masks every matched credential before storing it in `CodeFinding`.
pub struct SecretScanner;

/// Masks any raw secret value (`abc...xyz` -> `abc***REDACTED***xyz`) so raw credentials
/// are NEVER stored in memory structs, CLI JSON reports, or `.vexa.facts.json`.
pub fn mask_secret(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() <= 8 {
        "***REDACTED_SECRET***".to_string()
    } else {
        let prefix: String = trimmed.chars().take(4).collect();
        let suffix: String = trimmed
            .chars()
            .rev()
            .take(3)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("{}***REDACTED***{}", prefix, suffix)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretCoverage {
    pub files_discovered: usize,
    pub files_analysed: usize,
    pub files_skipped: usize,
    pub files_failed: usize,
    pub limits_hit: Vec<String>,
}

impl SecretScanner {
    pub fn scan_workspace(workspace_root: &Path) -> Vec<CodeFinding> {
        let (findings, _) = Self::scan_workspace_with_coverage(workspace_root);
        findings
    }

    pub fn scan_workspace_with_coverage(
        workspace_root: &Path,
    ) -> (Vec<CodeFinding>, SecretCoverage) {
        let rules = Self::build_rules();
        let mut findings = Vec::new();
        let mut coverage = SecretCoverage::default();
        Self::walk_dir(
            workspace_root,
            workspace_root,
            0,
            &rules,
            &mut findings,
            &mut coverage,
        );
        (findings, coverage)
    }

    fn walk_dir(
        root: &Path,
        current: &Path,
        depth: usize,
        rules: &[SecretRule],
        findings: &mut Vec<CodeFinding>,
        coverage: &mut SecretCoverage,
    ) {
        if depth > 8 {
            let rel = normalize_workspace_relative_path(root, current);
            coverage
                .limits_hit
                .push(format!("secrets_depth_limit_exceeded: {}", rel));
            coverage.files_skipped += 1;
            return;
        }
        let entries = match fs::read_dir(current) {
            Ok(e) => e,
            Err(_) => {
                let rel = normalize_workspace_relative_path(root, current);
                coverage.files_failed += 1;
                coverage
                    .limits_hit
                    .push(format!("secrets_dir_unreadable: {}", rel));
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() {
                if Self::should_skip_dir(&file_name) {
                    continue;
                }
                Self::walk_dir(root, &path, depth + 1, rules, findings, coverage);
            } else if path.is_file() {
                if Self::should_skip_file(&file_name) {
                    continue;
                }
                coverage.files_discovered += 1;
                let rel_path = normalize_workspace_relative_path(root, &path);
                if let Ok(metadata) = entry.metadata() {
                    if metadata.len() > 1_048_576 {
                        coverage.files_skipped += 1;
                        coverage
                            .limits_hit
                            .push(format!("secrets_file_size_exceeded: {}", rel_path));
                        continue;
                    }
                }
                match fs::read_to_string(&path) {
                    Ok(content) => {
                        coverage.files_analysed += 1;
                        Self::scan_file_content(&rel_path, &content, rules, findings);
                    }
                    Err(_) => {
                        coverage.files_failed += 1;
                        coverage
                            .limits_hit
                            .push(format!("secrets_file_unreadable: {}", rel_path));
                    }
                }
            }
        }
    }

    fn should_skip_dir(dir_name: &str) -> bool {
        if dir_name.starts_with('.') {
            return true;
        }
        let lower = dir_name.to_ascii_lowercase();
        matches!(
            lower.as_str(),
            "node_modules"
                | "target"
                | "dist"
                | "build"
                | "vendor"
                | "__pycache__"
                | "venv"
                | "__tests__"
                | "test"
                | "tests"
                | "testdata"
                | "fixtures"
                | "mock"
                | "mocks"
                | "e2e"
                | "cypress"
        )
    }

    fn should_skip_file(file_name: &str) -> bool {
        let lower = file_name.to_ascii_lowercase();
        if lower.ends_with(".lock")
            || lower == "package-lock.json"
            || lower == "pnpm-lock.yaml"
            || lower == "cargo.lock"
            || lower == "go.sum"
            || lower == ".vexa.facts.json"
            || lower.ends_with(".test.ts")
            || lower.ends_with(".test.tsx")
            || lower.ends_with(".test.js")
            || lower.ends_with(".test.jsx")
            || lower.ends_with(".spec.ts")
            || lower.ends_with(".spec.tsx")
            || lower.ends_with(".spec.js")
            || lower.ends_with(".spec.jsx")
            || lower.ends_with("_test.go")
            || lower.ends_with("_test.py")
            || lower.starts_with("test_")
        {
            return true;
        }

        let ext = Path::new(file_name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        let is_supported = matches!(
            ext.as_str(),
            "py" | "js"
                | "jsx"
                | "ts"
                | "tsx"
                | "mjs"
                | "cjs"
                | "go"
                | "rs"
                | "java"
                | "json"
                | "yaml"
                | "yml"
                | "toml"
                | "env"
                | "conf"
                | "cfg"
                | "ini"
                | "pem"
                | "key"
        );
        !is_supported
    }

    fn scan_file_content(
        rel_path: &str,
        content: &str,
        rules: &[SecretRule],
        findings: &mut Vec<CodeFinding>,
    ) {
        let has_pem_end = content.contains("-----END ");

        for (idx, line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
                || trimmed.starts_with('#')
            {
                continue;
            }

            let lower_trimmed = trimmed.to_ascii_lowercase();
            // Skip regex definitions (e.g. const R_PEM = /-----BEGIN.../)
            if trimmed.starts_with('/')
                || trimmed.contains("= /")
                || trimmed.contains(": /")
                || trimmed.contains("RegExp(")
            {
                continue;
            }
            // Skip UI form placeholders, example comments, and mock hints
            let is_placeholder = lower_trimmed.contains("placeholder")
                || lower_trimmed.starts_with("// example")
                || lower_trimmed.starts_with("# example")
                || lower_trimmed.contains("example:")
                || lower_trimmed.contains("sample_secret")
                || lower_trimmed.contains("fake_secret");
            if is_placeholder {
                continue;
            }

            for rule in rules {
                // If checking for cryptographic private keys, require that the file actually contains a complete PEM block
                if rule.rule_id == "VEXA-SEC-004" && !has_pem_end {
                    continue;
                }

                if let Some(mat) = rule.pattern.find(trimmed) {
                    let masked = mask_secret(mat.as_str());
                    findings.push(CodeFinding {
                        rule_id: rule.rule_id.to_string(),
                        category: "SECRET".to_string(),
                        severity: rule.severity.to_string(),
                        title: rule.title.to_string(),
                        cwe: Some(rule.cwe_id.to_string()),
                        file_path: rel_path.to_string(),
                        line: line_no,
                        matched_sink: Some(format!("{} ({})", rule.sink_symbol, masked)),
                        remediation: Some(rule.remediation_hint.to_string()),
                    });
                    // Avoid emitting duplicate secret alerts on the same line
                    break;
                }
            }
        }
    }

    fn build_rules() -> Vec<SecretRule> {
        vec![
            SecretRule {
                rule_id: "VEXA-SEC-001",
                cwe_id: "CWE-798",
                title: "Hardcoded AWS Access Key ID",
                severity: "CRITICAL",
                sink_symbol: "AWS_ACCESS_KEY_ID",
                remediation_hint: "Revoke this AWS key in IAM immediately and load credentials from IAM roles or environment variables.",
                pattern: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("valid regex"),
            },
            SecretRule {
                rule_id: "VEXA-SEC-002",
                cwe_id: "CWE-798",
                title: "Hardcoded GitHub Personal Access Token",
                severity: "CRITICAL",
                sink_symbol: "GITHUB_TOKEN",
                remediation_hint: "Revoke this GitHub token in Developer Settings and use GitHub Actions secrets instead.",
                pattern: Regex::new(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{22,255}\b")
                    .expect("valid regex"),
            },
            SecretRule {
                rule_id: "VEXA-SEC-003",
                cwe_id: "CWE-798",
                title: "Hardcoded Live Payment or AI API Key",
                severity: "CRITICAL",
                sink_symbol: "API_SECRET_KEY",
                remediation_hint: "Rotate this API key immediately and inject it via runtime secret management.",
                pattern: Regex::new(r"\b(?:sk_live_[0-9a-zA-Z]{16,}|sk-proj-[0-9a-zA-Z_\-]{20,}|sk-ant-[0-9a-zA-Z_\-]{20,})\b")
                    .expect("valid regex"),
            },
            SecretRule {
                rule_id: "VEXA-SEC-004",
                cwe_id: "CWE-798",
                title: "Hardcoded Cryptographic Private Key",
                severity: "CRITICAL",
                sink_symbol: "PRIVATE_KEY_HEADER",
                remediation_hint: "Remove the private key from version control, rotate the keypair, and load keys from a secure vault.",
                pattern: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")
                    .expect("valid regex"),
            },
            SecretRule {
                rule_id: "VEXA-SEC-005",
                cwe_id: "CWE-798",
                title: "Hardcoded Security Scanner API Token",
                severity: "HIGH",
                sink_symbol: "SECURITY_API_TOKEN",
                remediation_hint: "Never commit security API tokens to source code. Store VEXA_SECURITY_API_KEY in GitHub Actions Secrets.",
                pattern: Regex::new(r"\b(?:vexasec_[A-Za-z0-9_\-]{16,}|vexa_pat_[A-Za-z0-9_\-]{16,}|sktsec_[A-Za-z0-9_\-]{16,})\b")
                    .expect("valid regex"),
            },
            SecretRule {
                rule_id: "VEXA-SEC-006",
                cwe_id: "CWE-798",
                title: "Hardcoded Password or Private Secret",
                severity: "HIGH",
                sink_symbol: "HARDCODED_SECRET",
                remediation_hint: "Avoid hardcoding plaintext secrets or credentials in source code. Inject secrets using environment variables or a secret vault.",
                pattern: Regex::new(r#"(?i)\b(?:password|passwd|pwd|api_secret|client_secret)\s*[:=]\s*["'][^"'\s]{4,}["']"#)
                    .expect("valid regex"),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_and_mask_secrets_zero_leak() {
        let rules = SecretScanner::build_rules();
        let mut findings = Vec::new();
        let raw_aws = "AKIAIOSFODNN7EXAMPLE";
        let raw_gh = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD";
        let raw_vexa = "vexasec_SecretTokenValue1234567890";
        let sample = format!(
            "const aws = \"{}\";\nconst gh = \"{}\";\nconst token = \"{}\";\n",
            raw_aws, raw_gh, raw_vexa
        );

        SecretScanner::scan_file_content("src/config.ts", &sample, &rules, &mut findings);
        assert_eq!(findings.len(), 3);

        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialized.contains(raw_aws),
            "Raw AWS key must never appear in findings"
        );
        assert!(
            !serialized.contains(raw_gh),
            "Raw GitHub token must never appear in findings"
        );
        assert!(
            !serialized.contains(raw_vexa),
            "Raw Vexa token must never appear in findings"
        );
        assert!(serialized.contains("***REDACTED***"));
    }
}
