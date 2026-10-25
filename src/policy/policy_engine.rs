use crate::types::VulnerabilityFinding;
use chrono::{Local, NaiveDate};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PolicyError {
    IoError(String),
    SyntaxError(String),
    UnsupportedVersion(String),
    MissingReason {
        rule_id: String,
    },
    MissingExpires {
        rule_id: String,
    },
    InvalidExpiresDate {
        rule_id: String,
        date: String,
    },
    InvalidCreatedDate {
        rule_id: String,
        date: String,
    },
    CreatedAfterExpires {
        rule_id: String,
        created: String,
        expires: String,
    },
    WaiverLifetimeExceeded {
        rule_id: String,
        days: i64,
        max_days: u32,
    },
    UnknownField {
        rule_id: String,
        field: String,
    },
    MissingOwner {
        rule_id: String,
    },
    MissingTicket {
        rule_id: String,
    },
    DuplicateRuleId(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(s) => write!(f, "Policy file not found or unreadable: {}", s),
            Self::SyntaxError(s) => write!(f, "Invalid YAML/JSON syntax in policy: {}", s),
            Self::UnsupportedVersion(s) => write!(
                f,
                "Unsupported policy schema version '{}' (expected 'v1.0.0')",
                s
            ),
            Self::MissingReason { rule_id } => write!(
                f,
                "Rule '{}' missing or empty required field 'reason'",
                rule_id
            ),
            Self::MissingExpires { rule_id } => write!(
                f,
                "Rule '{}' missing required field 'expires' (format YYYY-MM-DD)",
                rule_id
            ),
            Self::InvalidExpiresDate { rule_id, date } => write!(
                f,
                "Rule '{}' has malformed expiry date '{}' (expected YYYY-MM-DD)",
                rule_id, date
            ),
            Self::InvalidCreatedDate { rule_id, date } => write!(
                f,
                "Rule '{}' has malformed created date '{}' (expected YYYY-MM-DD)",
                rule_id, date
            ),
            Self::CreatedAfterExpires {
                rule_id,
                created,
                expires,
            } => write!(
                f,
                "Rule '{}' created date '{}' is after expiry date '{}'",
                rule_id, created, expires
            ),
            Self::WaiverLifetimeExceeded {
                rule_id,
                days,
                max_days,
            } => write!(
                f,
                "Rule '{}' waiver duration of {} days exceeds maximum allowed lifetime of {} days",
                rule_id, days, max_days
            ),
            Self::UnknownField { rule_id, field } => write!(
                f,
                "Rule '{}' contains unknown or misspelled field(s): {}",
                rule_id, field
            ),
            Self::MissingOwner { rule_id } => {
                write!(f, "Rule '{}' missing required audit field 'owner'", rule_id)
            }
            Self::MissingTicket { rule_id } => write!(
                f,
                "Rule '{}' missing required audit field 'ticket'",
                rule_id
            ),
            Self::DuplicateRuleId(s) => {
                write!(f, "Duplicate rule identifier '{}' found in policy", s)
            }
        }
    }
}

impl std::error::Error for PolicyError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub reason: String,
    pub expires: String,
    pub owner: String,
    pub ticket: String,
    #[serde(default)]
    pub created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionMatch {
    pub rule_id: String,
    pub reason: String,
    pub expires: String,
    pub owner: String,
    pub ticket: String,
    pub created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressedFinding {
    pub vulnerability: VulnerabilityFinding,
    pub suppression: SuppressionMatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiredRuleDiagnostic {
    pub rule_id: String,
    pub expires: String,
    pub owner: String,
    pub ticket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRulesRaw {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub max_waiver_days: Option<u32>,
    #[serde(default)]
    pub ignore: HashMap<String, serde_yaml::Value>,
}

impl Default for PolicyRulesRaw {
    fn default() -> Self {
        Self {
            version: default_version(),
            max_waiver_days: Some(90),
            ignore: HashMap::new(),
        }
    }
}

fn default_version() -> String {
    "v1.0.0".to_string()
}

#[derive(Debug, Clone)]
pub struct ValidatedPolicy {
    pub version: String,
    pub max_waiver_days: u32,
    pub rules: HashMap<String, Vec<PolicyRule>>,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    pub policy_file_path: Option<PathBuf>,
    pub policy: ValidatedPolicy,
    pub expired_diagnostics: Vec<ExpiredRuleDiagnostic>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self {
            policy_file_path: None,
            policy: ValidatedPolicy {
                version: default_version(),
                max_waiver_days: 90,
                rules: HashMap::new(),
            },
            expired_diagnostics: Vec::new(),
        }
    }
}

impl PolicyEngine {
    pub fn new(policy_file_path: Option<&Path>) -> Self {
        if let Some(path) = policy_file_path {
            if path.exists() {
                if let Ok(engine) = Self::load(path, None) {
                    return engine;
                }
            }
        }
        Self::default()
    }

    /// Loads a policy file from path with strict schema and constraint validation.
    pub fn load(path: &Path, current_date: Option<NaiveDate>) -> Result<Self, PolicyError> {
        let content = fs::read(path).map_err(|e| PolicyError::IoError(e.to_string()))?;
        Self::from_bytes(&content, Some(path), current_date)
    }

    /// Parses policy from raw bytes (handling UTF-8 BOM).
    pub fn from_bytes(
        bytes: &[u8],
        path: Option<&Path>,
        current_date: Option<NaiveDate>,
    ) -> Result<Self, PolicyError> {
        let text = strip_bom(bytes);
        Self::from_str(text, path, current_date)
    }

    /// Parses policy from a string slice with strict validation.
    pub fn from_str(
        content: &str,
        path: Option<&Path>,
        current_date: Option<NaiveDate>,
    ) -> Result<Self, PolicyError> {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return Ok(Self {
                policy_file_path: path.map(|p| p.to_path_buf()),
                policy: ValidatedPolicy {
                    version: default_version(),
                    max_waiver_days: 90,
                    rules: HashMap::new(),
                },
                expired_diagnostics: Vec::new(),
            });
        }

        // Parse YAML or JSON into PolicyRulesRaw with unknown fields rejected
        let raw: PolicyRulesRaw = if trimmed.starts_with('{') {
            serde_json::from_str(trimmed)
                .map_err(|e| PolicyError::SyntaxError(format!("JSON syntax error: {}", e)))?
        } else {
            serde_yaml::from_str(trimmed)
                .map_err(|e| PolicyError::SyntaxError(format!("YAML syntax error: {}", e)))?
        };

        let now = current_date.unwrap_or_else(|| Local::now().date_naive());
        let validated = Self::validate_raw(raw, now)?;

        Ok(Self {
            policy_file_path: path.map(|p| p.to_path_buf()),
            policy: validated,
            expired_diagnostics: Vec::new(),
        })
    }

    pub fn find_policy_file(project_dir: &Path) -> Option<PathBuf> {
        let candidates = [".vexa-sca.json", ".vexa-sca", ".vexa.json", ".vexa"];
        for c in candidates {
            let full = project_dir.join(c);
            if full.exists() {
                return Some(full);
            }
        }
        None
    }

    fn validate_raw(
        raw: PolicyRulesRaw,
        current_date: NaiveDate,
    ) -> Result<ValidatedPolicy, PolicyError> {
        let version_normalized = raw.version.trim();
        if version_normalized != "v1.0.0"
            && version_normalized != "v1"
            && version_normalized != "1.0.0"
        {
            return Err(PolicyError::UnsupportedVersion(raw.version));
        }

        let max_waiver_days = raw.max_waiver_days.unwrap_or(90);
        let mut validated_rules: HashMap<String, Vec<PolicyRule>> = HashMap::new();

        for (id, val) in raw.ignore {
            let rules_vec =
                Self::parse_and_validate_rule_value(&id, &val, max_waiver_days, current_date)?;
            validated_rules.insert(id, rules_vec);
        }

        Ok(ValidatedPolicy {
            version: raw.version,
            max_waiver_days,
            rules: validated_rules,
        })
    }

    fn parse_and_validate_rule_value(
        rule_id: &str,
        val: &serde_yaml::Value,
        max_waiver_days: u32,
        current_date: NaiveDate,
    ) -> Result<Vec<PolicyRule>, PolicyError> {
        let mut rules = Vec::new();

        if let Some(arr) = val.as_sequence() {
            for item in arr {
                let rule: PolicyRule = serde_yaml::from_value(item.clone()).map_err(|e| {
                    let msg = e.to_string();
                    if msg.contains("unknown field") {
                        let field = msg
                            .split("unknown field `")
                            .nth(1)
                            .and_then(|s| s.split('`').next())
                            .unwrap_or("unknown");
                        PolicyError::UnknownField {
                            rule_id: rule_id.to_string(),
                            field: field.to_string(),
                        }
                    } else if msg.contains("missing field `reason`") {
                        PolicyError::MissingReason {
                            rule_id: rule_id.to_string(),
                        }
                    } else if msg.contains("missing field `expires`") {
                        PolicyError::MissingExpires {
                            rule_id: rule_id.to_string(),
                        }
                    } else if msg.contains("missing field `owner`") {
                        PolicyError::MissingOwner {
                            rule_id: rule_id.to_string(),
                        }
                    } else if msg.contains("missing field `ticket`") {
                        PolicyError::MissingTicket {
                            rule_id: rule_id.to_string(),
                        }
                    } else {
                        PolicyError::SyntaxError(format!(
                            "Invalid rule format for {}: {}",
                            rule_id, e
                        ))
                    }
                })?;
                Self::validate_single_rule(rule_id, &rule, max_waiver_days, current_date)?;
                rules.push(rule);
            }
        } else {
            let rule: PolicyRule = serde_yaml::from_value(val.clone()).map_err(|e| {
                let msg = e.to_string();
                if msg.contains("unknown field") {
                    let field = msg
                        .split("unknown field `")
                        .nth(1)
                        .and_then(|s| s.split('`').next())
                        .unwrap_or("unknown");
                    PolicyError::UnknownField {
                        rule_id: rule_id.to_string(),
                        field: field.to_string(),
                    }
                } else if msg.contains("missing field `reason`") {
                    PolicyError::MissingReason {
                        rule_id: rule_id.to_string(),
                    }
                } else if msg.contains("missing field `expires`") {
                    PolicyError::MissingExpires {
                        rule_id: rule_id.to_string(),
                    }
                } else if msg.contains("missing field `owner`") {
                    PolicyError::MissingOwner {
                        rule_id: rule_id.to_string(),
                    }
                } else if msg.contains("missing field `ticket`") {
                    PolicyError::MissingTicket {
                        rule_id: rule_id.to_string(),
                    }
                } else {
                    PolicyError::SyntaxError(format!("Invalid rule format for {}: {}", rule_id, e))
                }
            })?;
            Self::validate_single_rule(rule_id, &rule, max_waiver_days, current_date)?;
            rules.push(rule);
        }

        Ok(rules)
    }

    fn validate_single_rule(
        rule_id: &str,
        rule: &PolicyRule,
        max_waiver_days: u32,
        current_date: NaiveDate,
    ) -> Result<(), PolicyError> {
        if rule.reason.trim().is_empty() {
            return Err(PolicyError::MissingReason {
                rule_id: rule_id.to_string(),
            });
        }
        if rule.owner.trim().is_empty() {
            return Err(PolicyError::MissingOwner {
                rule_id: rule_id.to_string(),
            });
        }
        if rule.ticket.trim().is_empty() {
            return Err(PolicyError::MissingTicket {
                rule_id: rule_id.to_string(),
            });
        }

        let exp_date =
            NaiveDate::parse_from_str(rule.expires.trim(), "%Y-%m-%d").map_err(|_| {
                PolicyError::InvalidExpiresDate {
                    rule_id: rule_id.to_string(),
                    date: rule.expires.clone(),
                }
            })?;

        if let Some(created_str) = &rule.created {
            let created_date =
                NaiveDate::parse_from_str(created_str.trim(), "%Y-%m-%d").map_err(|_| {
                    PolicyError::InvalidCreatedDate {
                        rule_id: rule_id.to_string(),
                        date: created_str.clone(),
                    }
                })?;

            if created_date > exp_date {
                return Err(PolicyError::CreatedAfterExpires {
                    rule_id: rule_id.to_string(),
                    created: created_str.clone(),
                    expires: rule.expires.clone(),
                });
            }

            if max_waiver_days > 0 {
                let duration = (exp_date - created_date).num_days();
                if duration > max_waiver_days as i64 {
                    return Err(PolicyError::WaiverLifetimeExceeded {
                        rule_id: rule_id.to_string(),
                        days: duration,
                        max_days: max_waiver_days,
                    });
                }
            }
        } else if max_waiver_days > 0 && exp_date > current_date {
            let duration = (exp_date - current_date).num_days();
            if duration > max_waiver_days as i64 {
                return Err(PolicyError::WaiverLifetimeExceeded {
                    rule_id: rule_id.to_string(),
                    days: duration,
                    max_days: max_waiver_days,
                });
            }
        }

        Ok(())
    }

    pub fn filter_vulnerabilities(
        &mut self,
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

    pub fn check_suppression(
        &mut self,
        vuln: &VulnerabilityFinding,
        current_date: NaiveDate,
    ) -> Option<SuppressionMatch> {
        let mut ids_to_check = vec![vuln.id.as_str()];
        if let Some(cve) = &vuln.cve {
            ids_to_check.push(cve.as_str());
        }
        for alias in &vuln.aliases {
            ids_to_check.push(alias.as_str());
        }
        ids_to_check.push(vuln.pkg_id.as_str());

        for id in ids_to_check {
            if let Some(rule_list) = self.policy.rules.get(id) {
                for rule in rule_list {
                    if let Ok(exp_date) = NaiveDate::parse_from_str(rule.expires.trim(), "%Y-%m-%d")
                    {
                        if exp_date < current_date {
                            // Expired rule: treat as active vulnerability and record diagnostic
                            self.expired_diagnostics.push(ExpiredRuleDiagnostic {
                                rule_id: id.to_string(),
                                expires: rule.expires.clone(),
                                owner: rule.owner.clone(),
                                ticket: rule.ticket.clone(),
                            });
                            continue;
                        }

                        return Some(SuppressionMatch {
                            rule_id: id.to_string(),
                            reason: rule.reason.clone(),
                            expires: rule.expires.clone(),
                            owner: rule.owner.clone(),
                            ticket: rule.ticket.clone(),
                            created: rule.created.clone(),
                        });
                    }
                }
            }
        }

        None
    }
}

fn strip_bom(bytes: &[u8]) -> &str {
    let clean = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    };
    std::str::from_utf8(clean).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SeverityInfo, SeverityLevel};

    #[test]
    fn test_policy_engine_vexa_fixture() {
        let vexa_file = Path::new("test/fixtures/policy-app/.vexa-sca");
        let date_2026 = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        let mut engine =
            PolicyEngine::load(vexa_file, Some(date_2026)).expect("Fixture policy must load");

        assert!(engine.policy.rules.contains_key("CVE-2021-23337"));
        assert!(engine.policy.rules.contains_key("GHSA-29mw-wpgm-hmr9"));

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
            ..Default::default()
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
            ..Default::default()
        };

        let (active, suppressed) = engine.filter_vulnerabilities(&[vuln1, vuln2], Some(date_2026));

        assert_eq!(suppressed.len(), 1);
        assert_eq!(
            suppressed[0].vulnerability.cve.as_deref(),
            Some("CVE-2021-23337")
        );
        assert_eq!(suppressed[0].suppression.owner, "security@company.com");
        assert_eq!(suppressed[0].suppression.ticket, "SEC-101");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "GHSA-unignored-xxxx");
    }

    #[test]
    fn test_policy_engine_expired_rule() {
        let yaml = r#"
version: v1.0.0
max_waiver_days: 365
ignore:
  CVE-2021-23337:
    reason: "Temporary waiver"
    expires: "2025-01-01"
    owner: "sec-team"
    ticket: "SEC-99"
"#;
        let date_2026 = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        let mut engine = PolicyEngine::from_str(yaml, None, Some(date_2026)).unwrap();

        let vuln = VulnerabilityFinding {
            id: "CVE-2021-23337".to_string(),
            ..Default::default()
        };

        let (active, suppressed) = engine.filter_vulnerabilities(&[vuln], Some(date_2026));
        assert_eq!(suppressed.len(), 0, "Expired rule must not suppress");
        assert_eq!(active.len(), 1, "Vulnerability must remain active");
        assert_eq!(engine.expired_diagnostics.len(), 1);
        assert_eq!(engine.expired_diagnostics[0].rule_id, "CVE-2021-23337");
    }

    #[test]
    fn test_policy_engine_missing_expiry_fails() {
        let yaml = r#"
version: v1.0.0
ignore:
  CVE-2021-23337:
    reason: "No expiry provided"
    owner: "sec-team"
    ticket: "SEC-1"
"#;
        let res = PolicyEngine::from_str(yaml, None, None);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            PolicyError::MissingExpires { .. }
        ));
    }

    #[test]
    fn test_policy_engine_missing_reason_fails() {
        let yaml = r#"
version: v1.0.0
ignore:
  CVE-2021-23337:
    reason: "   "
    expires: "2026-12-31"
    owner: "sec-team"
    ticket: "SEC-1"
"#;
        let res = PolicyEngine::from_str(yaml, None, None);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            PolicyError::MissingReason { .. }
        ));
    }

    #[test]
    fn test_policy_engine_unknown_field_fails() {
        let yaml = r#"
version: v1.0.0
ignore:
  CVE-2021-23337:
    reason: "Valid reason"
    expires: "2026-12-31"
    owner: "sec-team"
    ticket: "SEC-1"
    expirse: "2026-12-31"
"#;
        let res = PolicyEngine::from_str(yaml, None, None);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            PolicyError::UnknownField { .. }
        ));
    }

    #[test]
    fn test_policy_engine_malformed_date_fails() {
        let yaml = r#"
version: v1.0.0
ignore:
  CVE-2021-23337:
    reason: "Valid reason"
    expires: "31-12-2026"
    owner: "sec-team"
    ticket: "SEC-1"
"#;
        let res = PolicyEngine::from_str(yaml, None, None);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            PolicyError::InvalidExpiresDate { .. }
        ));
    }

    #[test]
    fn test_policy_engine_created_after_expires_fails() {
        let yaml = r#"
version: v1.0.0
ignore:
  CVE-2021-23337:
    reason: "Valid reason"
    created: "2026-12-31"
    expires: "2026-01-01"
    owner: "sec-team"
    ticket: "SEC-1"
"#;
        let res = PolicyEngine::from_str(yaml, None, None);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            PolicyError::CreatedAfterExpires { .. }
        ));
    }

    #[test]
    fn test_policy_engine_max_waiver_exceeded_fails() {
        let yaml = r#"
version: v1.0.0
max_waiver_days: 90
ignore:
  CVE-2021-23337:
    reason: "Valid reason"
    created: "2026-01-01"
    expires: "2026-12-31"
    owner: "sec-team"
    ticket: "SEC-1"
"#;
        let res = PolicyEngine::from_str(yaml, None, None);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            PolicyError::WaiverLifetimeExceeded { .. }
        ));
    }

    #[test]
    fn test_policy_engine_utf8_bom() {
        let yaml_str = "version: v1.0.0\nmax_waiver_days: 365\nignore:\n  CVE-1234:\n    reason: ok\n    expires: 2026-12-31\n    owner: sec\n    ticket: T-1\n";
        let mut bom_bytes = vec![0xEF, 0xBB, 0xBF];
        bom_bytes.extend_from_slice(yaml_str.as_bytes());

        let engine = PolicyEngine::from_bytes(&bom_bytes, None, None);
        assert!(engine.is_ok());
        assert!(engine.unwrap().policy.rules.contains_key("CVE-1234"));
    }

    #[test]
    fn test_policy_engine_unsupported_version() {
        let yaml = r#"
version: v99.0.0
ignore: {}
"#;
        let res = PolicyEngine::from_str(yaml, None, None);
        assert!(res.is_err());
        assert!(matches!(
            res.err().unwrap(),
            PolicyError::UnsupportedVersion(_)
        ));
    }
}
