use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SeverityLevel {
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "LOW")]
    Low,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl SeverityLevel {
    pub fn weight(&self) -> u32 {
        match self {
            SeverityLevel::Critical => 4,
            SeverityLevel::High => 3,
            SeverityLevel::Medium => 2,
            SeverityLevel::Low => 1,
            SeverityLevel::Unknown => 0,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SeverityLevel::Critical => "CRITICAL",
            SeverityLevel::High => "HIGH",
            SeverityLevel::Medium => "MEDIUM",
            SeverityLevel::Low => "LOW",
            SeverityLevel::Unknown => "UNKNOWN",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        let up = s.to_uppercase();
        if up.contains("CRIT") {
            SeverityLevel::Critical
        } else if up.contains("HIGH") {
            SeverityLevel::High
        } else if up.contains("MOD") || up.contains("MED") {
            SeverityLevel::Medium
        } else if up.contains("LOW") {
            SeverityLevel::Low
        } else {
            SeverityLevel::Unknown
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    #[serde(rename = "npm")]
    Npm,
    #[serde(rename = "PyPI")]
    PyPi,
    #[serde(rename = "Maven")]
    Maven,
    #[serde(rename = "RubyGems")]
    RubyGems,
    #[serde(rename = "Go")]
    Go,
    #[serde(rename = "crates.io")]
    CratesIo,
    #[serde(untagged)]
    Other(String),
}

impl Ecosystem {
    pub fn as_str(&self) -> &str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPi => "PyPI",
            Ecosystem::Maven => "Maven",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Go => "Go",
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Other(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PkgInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub purl: String,
}

impl PkgInfo {
    pub fn new(name: impl Into<String>, version: impl Into<String>, ecosystem: impl Into<String>) -> Self {
        let name = name.into();
        let version = version.into();
        let ecosystem = ecosystem.into();
        let id = format!("{}@{}", name, version);
        let purl = format!("pkg:{}/{}@{}", ecosystem, name, version);
        Self {
            id,
            name,
            version,
            ecosystem,
            purl,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityInfo {
    pub level: SeverityLevel,
    pub score: f64,
    pub vector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub file: String,
    pub line: usize,
    pub code: String,
    pub matched_function: String,
    pub is_specific_function_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReachabilityStatus {
    #[serde(rename = "REACHABLE")]
    Reachable,
    #[serde(rename = "UNREACHABLE")]
    Unreachable,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityResult {
    pub status: ReachabilityStatus,
    pub is_direct_call: bool,
    pub call_sites: Vec<CallSite>,
    pub target_functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub id: String,
    pub title: String,
    pub package: String,
    pub version: String,
    pub ecosystem: String,
    pub pkg_id: String,
    pub severity: SeverityInfo,
    pub cve: Option<String>,
    pub cwes: Vec<String>,
    pub fixed_in: Vec<String>,
    pub is_transitive: bool,
    pub paths: Vec<Vec<String>>,
    pub details: Option<String>,
    pub references: Vec<String>,
    pub reachability: Option<ReachabilityResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationAction {
    pub package: String,
    pub current_version: String,
    pub is_transitive: bool,
    pub target_version: Option<String>,
    pub action_type: String,
    pub advice: String,
    pub resolved_vulnerability_count: usize,
    pub vulnerability_ids: Vec<String>,
}
