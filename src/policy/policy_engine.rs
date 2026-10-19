use crate::types::VulnerabilityFinding;
use chrono::{Local, NaiveDate};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyRule {
    pub reason: Option<String>,
    pub expires: Option<String>,
    pub created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionMatch {
    pub rule_id: String,
    pub reason: String,
    pub expires: Option<String>,
    pub created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedFinding {
    pub vulnerability: VulnerabilityFinding,
    pub suppression: SuppressionMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyRules {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub ignore: HashMap<String, serde_yaml::Value>,
}

fn default_version() -> String {
    "v1.0.0".to_string()
}

pub struct PolicyEngine {
    pub policy_file_path: Option<PathBuf>,
    pub rules: PolicyRules,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(None)
    }
}

impl PolicyEngine {
    pub fn new(policy_file_path: Option<&Path>) -> Self {
        let mut engine = Self {
            policy_file_path: policy_file_path.map(|p| p.to_path_buf()),
            rules: PolicyRules::default(),
        };

        if let Some(path) = policy_file_path {
            if path.exists() {
                let _ = engine.load_policy_file(path);
            }
        }

        engine
    }

    pub fn find_policy_file(project_dir: &Path) -> Option<PathBuf> {
        let candidates = [
            ".vexa-sca.json",
            ".vexa-sca",
            ".vexa.json",
            ".vexa",
        ];

        for c in candidates {
            let full = project_dir.join(c);
            if full.exists() {
                return Some(full);
            }
        }
        None
    }

    pub fn load_policy_file(&mut self, path: &Path) -> Result<(), String> {
        self.policy_file_path = Some(path.to_path_buf());
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file: {}", e))?;
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Ok(());
        }

        if trimmed.starts_with('{') {
            if let Ok(json_rules) = serde_json::from_str::<PolicyRules>(trimmed) {
                self.rules = json_rules;
                return Ok(());
            }
        }

        let yaml_rules: PolicyRules = serde_yaml::from_str(trimmed)
            .map_err(|e| format!("Invalid YAML/JSON policy: {}", e))?;
        self.rules = yaml_rules;
        Ok(())
    }

    pub fn filter_vulnerabilities(
        &self,
        vulnerabilities: &[VulnerabilityFinding],
        current_date: Option<NaiveDate>,
    ) -> (Vec<VulnerabilityFinding>, Vec<SuppressedFinding>) {
        let now = current_date.unwrap_or_else(|| Local::now().date_naive());
        let mut active = Vec::new();
        let mut suppressed = Vec::new();

        for v in vulnerabilities {
            if let Some(supp) = self.check_suppression(v, now) {
                suppressed.push(SuppressedFinding {
                    vulnerability: v.clone(),
                    suppression: supp,
                });
            } else {
                active.push(v.clone());
            }
        }

        (active, suppressed)
    }

    pub fn check_suppression(&self, vuln: &VulnerabilityFinding, current_date: NaiveDate) -> Option<SuppressionMatch> {
        let mut ids_to_check = vec![vuln.id.as_str()];
        if let Some(cve) = &vuln.cve {
            ids_to_check.push(cve.as_str());
        }
        ids_to_check.push(vuln.pkg_id.as_str());

        for id in ids_to_check {
            if let Some(raw_rule) = self.rules.ignore.get(id) {
                let rule_list = Self::parse_rule_value(raw_rule);
                for rule in rule_list {
                    let mut is_expired = false;
                    if let Some(exp_str) = &rule.expires {
                        if let Ok(exp_date) = NaiveDate::parse_from_str(exp_str, "%Y-%m-%d") {
                            if exp_date < current_date {
                                is_expired = true;
                            }
                        }
                    }

                    if !is_expired {
                        return Some(SuppressionMatch {
                            rule_id: id.to_string(),
                            reason: rule.reason.unwrap_or_else(|| "Suppressed via Vexa SCA policy".to_string()),
                            expires: rule.expires,
                            created: rule.created,
                        });
                    }
                }
            }
        }

        None
    }

    fn parse_rule_value(val: &serde_yaml::Value) -> Vec<PolicyRule> {
        let mut result = Vec::new();

        if let Some(arr) = val.as_sequence() {
            for item in arr {
                if let Ok(rule) = serde_yaml::from_value::<PolicyRule>(item.clone()) {
                    result.push(rule);
                } else if let Some(map) = item.as_mapping() {
                    let reason = map
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let expires = map
                        .get("expires")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let created = map
                        .get("created")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    result.push(PolicyRule { reason, expires, created });
                }
            }
        } else if let Ok(rule) = serde_yaml::from_value::<PolicyRule>(val.clone()) {
            result.push(rule);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SeverityInfo, SeverityLevel};

    #[test]
    fn test_policy_engine_vexa_fixture() {
        let vexa_file = Path::new("test/fixtures/policy-app/.vexa-sca");
        let engine = PolicyEngine::new(Some(vexa_file));

        assert!(engine.rules.ignore.contains_key("CVE-2021-23337"));
        assert!(engine.rules.ignore.contains_key("GHSA-29mw-wpgm-hmr9"));

        let vuln1 = VulnerabilityFinding {
            id: "GHSA-35jh-r3h4-6jhm".to_string(),
            title: "Vuln 1".to_string(),
            package: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "lodash@4.17.15".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::High,
                score: 7.5,
                vector: None,
            },
            cve: Some("CVE-2021-23337".to_string()),
            cwes: vec![],
            fixed_in: vec![],
            is_transitive: false,
            paths: vec![],
            details: None,
            references: vec![],
            reachability: None,
        };

        let vuln2 = VulnerabilityFinding {
            id: "GHSA-unignored-xxxx".to_string(),
            title: "Vuln 2".to_string(),
            package: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "lodash@4.17.15".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::High,
                score: 7.5,
                vector: None,
            },
            cve: Some("CVE-2099-0000".to_string()),
            cwes: vec![],
            fixed_in: vec![],
            is_transitive: false,
            paths: vec![],
            details: None,
            references: vec![],
            reachability: None,
        };

        let date_2026 = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        let (active, suppressed) = engine.filter_vulnerabilities(&[vuln1, vuln2], Some(date_2026));

        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].vulnerability.cve.as_deref(), Some("CVE-2021-23337"));
        assert_eq!(suppressed[0].suppression.reason, "Not exposed to external untrusted inputs");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "GHSA-unignored-xxxx");
    }

    #[test]
    fn test_policy_engine_expired_rule() {
        let mut engine = PolicyEngine::default();
        let yaml_str = r#"
ignore:
  CVE-2020-0001:
    - reason: "Old temporary waiver"
      expires: "2020-01-01"
"#;
        engine.rules = serde_yaml::from_str(yaml_str).unwrap();

        let vuln = VulnerabilityFinding {
            id: "GHSA-1234".to_string(),
            title: "Vuln".to_string(),
            package: "pkg".to_string(),
            version: "1.0.0".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "pkg@1.0.0".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::Medium,
                score: 5.5,
                vector: None,
            },
            cve: Some("CVE-2020-0001".to_string()),
            cwes: vec![],
            fixed_in: vec![],
            is_transitive: false,
            paths: vec![],
            details: None,
            references: vec![],
            reachability: None,
        };

        let date_2026 = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        let (active, suppressed) = engine.filter_vulnerabilities(&[vuln], Some(date_2026));

        assert_eq!(suppressed.len(), 0);
        assert_eq!(active.len(), 1);
    }
}
