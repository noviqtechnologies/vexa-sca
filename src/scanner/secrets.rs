use regex::Regex;
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

impl SecretScanner {
    pub fn scan_workspace(workspace_root: &Path) -> Vec<CodeFinding> {
        let rules = Self::build_rules();
        let mut findings = Vec::new();
        Self::walk_dir(workspace_root, workspace_root, &rules, &mut findings);
        findings
    }

    fn walk_dir(
        root: &Path,
        current: &Path,
        rules: &[SecretRule],
        findings: &mut Vec<CodeFinding>,
    ) {
        let entries = match fs::read_dir(current) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() {
                if Self::should_skip_dir(&file_name) {
                    continue;
                }
                Self::walk_dir(root, &path, rules, findings);
            } else if path.is_file() {
                if Self::should_skip_file(&file_name) {
                    continue;
                }
                if let Ok(metadata) = entry.metadata() {
                    if metadata.len() > 1_048_576 {
                        continue;
                    }
                }
                if let Ok(content) = fs::read_to_string(&path) {
                    let rel_path = normalize_workspace_relative_path(root, &path);
                    Self::scan_file_content(&rel_path, &content, rules, findings);
                }
            }
        }
    }

    fn should_skip_dir(dir_name: &str) -> bool {
        matches!(
            dir_name,
            ".git"
                | "node_modules"
                | "target"
                | "dist"
                | "build"
                | ".next"
                | "vendor"
                | "__pycache__"
                | ".venv"
                | "venv"
                | ".idea"
                | ".vscode"
        )
    }

    fn should_skip_file(file_name: &str) -> bool {
        let lower = file_name.to_ascii_lowercase();
        lower.ends_with(".lock")
            || lower == "package-lock.json"
            || lower == "pnpm-lock.yaml"
            || lower == "cargo.lock"
            || lower == "go.sum"
            || lower == ".vexa.facts.json"
            || lower.ends_with(".min.js")
            || lower.ends_with(".png")
            || lower.ends_with(".jpg")
            || lower.ends_with(".jpeg")
            || lower.ends_with(".gif")
            || lower.ends_with(".ico")
            || lower.ends_with(".woff")
            || lower.ends_with(".woff2")
            || lower.ends_with(".ttf")
            || lower.ends_with(".exe")
            || lower.ends_with(".dll")
            || lower.ends_with(".so")
            || lower.ends_with(".dylib")
            || lower.ends_with(".wasm")
    }

    fn scan_file_content(
        rel_path: &str,
        content: &str,
        rules: &[SecretRule],
        findings: &mut Vec<CodeFinding>,
    ) {
        for (idx, line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            for rule in rules {
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
