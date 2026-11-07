use serde_json::Value;
use std::fs;
use std::path::Path;

use crate::scanner::sast::{
    normalize_workspace_relative_path, sanitize_sink_signature, CodeFinding,
};

/// Universal SARIF v2.1.0 Ingestor (CodeQL, Semgrep, Bandit, Gosec, Brakeman, Clippy).
/// Strictly enforces Vexa's Zero-Code-Sync Invariant by stripping `region.snippet.text`
/// and normalizing all file paths to POSIX forward slashes (`/`).
pub struct SarifIngestor;

impl SarifIngestor {
    pub fn parse_sarif_file(
        workspace_root: &Path,
        sarif_path: &Path,
    ) -> Result<Vec<CodeFinding>, String> {
        let content = fs::read_to_string(sarif_path).map_err(|e| {
            format!(
                "Failed to read SARIF file '{}': {}",
                sarif_path.display(),
                e
            )
        })?;
        Self::parse_sarif_str(workspace_root, &content)
    }

    pub fn parse_sarif_str(
        workspace_root: &Path,
        content: &str,
    ) -> Result<Vec<CodeFinding>, String> {
        let doc: Value = serde_json::from_str(content)
            .map_err(|e| format!("Invalid SARIF JSON document: {}", e))?;

        let runs = doc
            .get("runs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "SARIF document missing 'runs' array".to_string())?;

        let mut findings = Vec::new();

        for run in runs {
            let tool_name = run
                .pointer("/tool/driver/name")
                .and_then(|v| v.as_str())
                .unwrap_or("SARIF");

            let results = match run.get("results").and_then(|v| v.as_array()) {
                Some(r) => r,
                None => continue,
            };

            for res in results {
                let rule_id = res
                    .get("ruleId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("SARIF-RULE")
                    .to_string();

                let level = res
                    .get("level")
                    .and_then(|v| v.as_str())
                    .unwrap_or("warning");

                let severity = match level.to_ascii_lowercase().as_str() {
                    "error" => "HIGH",
                    "warning" => "MEDIUM",
                    "note" | "none" => "LOW",
                    _ => "MEDIUM",
                }
                .to_string();

                let message_text = res
                    .pointer("/message/text")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Static analysis finding reported via SARIF");

                let title = message_text
                    .lines()
                    .next()
                    .unwrap_or("Static analysis finding")
                    .chars()
                    .take(140)
                    .collect::<String>();

                let first_loc = res.pointer("/locations/0/physicalLocation");

                let raw_uri = first_loc
                    .and_then(|loc| loc.pointer("/artifactLocation/uri"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                let cleaned_uri = raw_uri.strip_prefix("file://").unwrap_or(raw_uri);
                let normalized_path =
                    normalize_workspace_relative_path(workspace_root, Path::new(cleaned_uri));

                let line_start = first_loc
                    .and_then(|loc| loc.pointer("/region/startLine"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1) as usize;

                // Explicitly ignore `region.snippet.text` so raw source code is NEVER ingested!
                let sink_symbol = sanitize_sink_signature(&format!("{}::{}", tool_name, rule_id));

                let cwe_id = res
                    .pointer("/properties/cwe")
                    .and_then(|v| v.as_str())
                    .unwrap_or("CWE-1000")
                    .to_string();

                findings.push(CodeFinding {
                    rule_id,
                    category: "SAST".to_string(),
                    severity,
                    title,
                    cwe: Some(cwe_id),
                    file_path: normalized_path,
                    line: line_start,
                    matched_sink: Some(sink_symbol),
                    remediation: Some(format!(
                        "Review and remediate finding reported by {} at line {}.",
                        tool_name, line_start
                    )),
                });
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sarif_ingestion_strips_raw_code() {
        let sarif_json = r#"{
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Semgrep"
                        }
                    },
                    "results": [
                        {
                            "ruleId": "python.lang.security.audit.os-system",
                            "level": "error",
                            "message": {
                                "text": "OS Command Injection via os.system"
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src\\handlers\\os-ijection.py"
                                        },
                                        "region": {
                                            "startLine": 19,
                                            "endLine": 19,
                                            "snippet": {
                                                "text": "os.system(\"ping \" + SUPER_SECRET_INTERNAL_CODE)"
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;

        let findings = SarifIngestor::parse_sarif_str(Path::new("/workspace"), sarif_json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file_path, "src/handlers/os-ijection.py");
        assert_eq!(findings[0].line, 19);
        assert_eq!(findings[0].severity, "HIGH");

        let serialized = serde_json::to_string(&findings).unwrap();
        assert!(
            !serialized.contains("SUPER_SECRET_INTERNAL_CODE"),
            "SARIF snippet text must be completely stripped"
        );
    }
}
