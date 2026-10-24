use serde::{Deserialize, Serialize};

/// Represents the status of an advisory database lookup for a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryStatus {
    /// All packages were checked successfully against the live OSV API.
    #[default]
    Success,
    /// All packages were served from local cache; no network request was made.
    CacheHit,
    /// Some packages were checked but others failed (network / parse error).
    PartialFailure,
    /// The advisory service was completely unreachable or returned an error for all packages.
    Unavailable,
    /// The upstream service returned a response that could not be parsed.
    MalformedUpstreamResponse,
}

impl AdvisoryStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::CacheHit => "cache_hit",
            Self::PartialFailure => "partial_failure",
            Self::Unavailable => "unavailable",
            Self::MalformedUpstreamResponse => "malformed_upstream_response",
        }
    }

    /// Returns true when the advisory service could not be reached for all uncached packages.
    pub fn is_service_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable | Self::MalformedUpstreamResponse)
    }

    /// Returns true when the advisory result is at least partially unreliable.
    pub fn has_unreliable_data(&self) -> bool {
        matches!(
            self,
            Self::Unavailable | Self::MalformedUpstreamResponse | Self::PartialFailure
        )
    }
}

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
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        ecosystem: impl Into<String>,
    ) -> Self {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReasonCode {
    #[serde(rename = "NO_SYMBOL_DATA")]
    NoSymbolData,
    #[serde(rename = "TRANSITIVE_NOT_ANALYZED")]
    TransitiveNotAnalyzed,
    #[serde(rename = "UNSUPPORTED_LANGUAGE")]
    UnsupportedLanguage,
    #[serde(rename = "UNSUPPORTED_SYNTAX")]
    UnsupportedSyntax,
    #[serde(rename = "UNSUPPORTED_CONFIG")]
    UnsupportedConfig,
    #[serde(rename = "FILE_LIMIT_HIT")]
    FileLimitHit,
    #[serde(rename = "PACKAGE_LIMIT_HIT")]
    PackageLimitHit,
    #[serde(rename = "DYNAMIC_CONSTRUCT")]
    DynamicConstruct,
    #[serde(rename = "ANALYSIS_ERROR")]
    AnalysisError,
    #[serde(rename = "SOURCE_UNAVAILABLE")]
    SourceUnavailable,
    #[serde(rename = "ANALYSIS_COMPLETE_NO_USAGE")]
    AnalysisCompleteNoUsage,
    #[serde(rename = "DIRECT_USAGE_FOUND")]
    DirectUsageFound,
}

impl ReasonCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoSymbolData => "NO_SYMBOL_DATA",
            Self::TransitiveNotAnalyzed => "TRANSITIVE_NOT_ANALYZED",
            Self::UnsupportedLanguage => "UNSUPPORTED_LANGUAGE",
            Self::UnsupportedSyntax => "UNSUPPORTED_SYNTAX",
            Self::UnsupportedConfig => "UNSUPPORTED_CONFIG",
            Self::FileLimitHit => "FILE_LIMIT_HIT",
            Self::PackageLimitHit => "PACKAGE_LIMIT_HIT",
            Self::DynamicConstruct => "DYNAMIC_CONSTRUCT",
            Self::AnalysisError => "ANALYSIS_ERROR",
            Self::SourceUnavailable => "SOURCE_UNAVAILABLE",
            Self::AnalysisCompleteNoUsage => "ANALYSIS_COMPLETE_NO_USAGE",
            Self::DirectUsageFound => "DIRECT_USAGE_FOUND",
        }
    }
}

/// Repository usage signal per PRD v2.2 FR-007a.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum UsageSignal {
    #[serde(rename = "IMPORTED_SOURCE")]
    ImportedSource,
    #[serde(rename = "REFERENCED_CONFIG_OR_SCRIPT")]
    ReferencedConfigOrScript,
    #[serde(rename = "NO_REFERENCE_FOUND_WITHIN_SCOPE")]
    NoReferenceFoundWithinScope,
    #[serde(rename = "UNKNOWN")]
    #[default]
    Unknown,
}

impl UsageSignal {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ImportedSource => "IMPORTED_SOURCE",
            Self::ReferencedConfigOrScript => "REFERENCED_CONFIG_OR_SCRIPT",
            Self::NoReferenceFoundWithinScope => "NO_REFERENCE_FOUND_WITHIN_SCOPE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Top-level scan status per PRD v2.2 FR-005, FR-008a, FR-010a.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    #[default]
    Pass,
    Fail,
    Incomplete,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Incomplete => "INCOMPLETE",
        }
    }
}

/// Completeness metrics and limits per PRD v2.2 FR-003, FR-004.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompletenessReport {
    pub manifests_detected: usize,
    pub manifests_analysed: usize,
    pub manifests_skipped: usize,
    pub packages_discovered: usize,
    pub packages_resolved: usize,
    pub packages_unresolved: usize,
    pub packages_checked: usize,
    pub source_files_discovered: usize,
    pub source_files_analysed: usize,
    pub source_files_skipped: usize,
    pub source_files_failed: usize,
    pub limits_hit: Vec<String>,
    pub advisory_source: String,
    pub advisory_status: AdvisoryStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReachabilityStatus {
    #[serde(rename = "REACHABLE")]
    Reachable,
    #[serde(rename = "NOT_REACHABLE", alias = "UNREACHABLE")]
    Unreachable,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl ReachabilityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reachable => "REACHABLE",
            Self::Unreachable => "NOT_REACHABLE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityResult {
    pub status: ReachabilityStatus,
    pub is_direct_call: bool,
    pub call_sites: Vec<CallSite>,
    pub target_functions: Vec<String>,
    #[serde(default)]
    pub reason_code: Option<ReasonCode>,
    #[serde(default = "default_analyzer_version")]
    pub analyzer_version: String,
}

fn default_analyzer_version() -> String {
    "1.0.0".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AdvisoryCategory {
    #[serde(rename = "vulnerability")]
    #[default]
    Vulnerability,
    #[serde(rename = "unmaintained")]
    Unmaintained,
    #[serde(rename = "informational")]
    Informational,
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
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub advisory_category: AdvisoryCategory,
    #[serde(default)]
    pub epss: Option<EpssInfo>,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub usage_signal: UsageSignal,
    #[serde(default)]
    pub reason_code: Option<ReasonCode>,
    #[serde(default)]
    pub priority_score: f64,
    #[serde(default)]
    pub is_new: bool,
}

impl VulnerabilityFinding {
    /// Calculate deterministic stable fingerprint per PRD v2.2 FR-006:
    /// Normalized from ecosystem, package, advisory ID, and scope.
    pub fn calculate_fingerprint(ecosystem: &str, package: &str, id: &str, scope: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(ecosystem.to_lowercase().as_bytes());
        hasher.update(b":");
        hasher.update(package.to_lowercase().as_bytes());
        hasher.update(b":");
        hasher.update(id.to_uppercase().as_bytes());
        hasher.update(b":");
        hasher.update(scope.to_lowercase().as_bytes());
        let res = hex::encode(hasher.finalize());
        res[0..16].to_string()
    }

    /// Compute deterministic priority score per PRD v2.2 FR-007.
    pub fn compute_priority_score(&self) -> f64 {
        let mut score = match self.severity.level {
            SeverityLevel::Critical => 40.0,
            SeverityLevel::High => 30.0,
            SeverityLevel::Medium => 20.0,
            SeverityLevel::Low => 10.0,
            SeverityLevel::Unknown => 0.0,
        };

        if !self.is_transitive {
            score += 15.0;
        }

        match self.usage_signal {
            UsageSignal::ImportedSource => score += 20.0,
            UsageSignal::ReferencedConfigOrScript => score += 10.0,
            UsageSignal::Unknown => score += 5.0,
            UsageSignal::NoReferenceFoundWithinScope => score += 0.0,
        }

        if !self.fixed_in.is_empty() {
            score += 10.0;
        }

        if let Some(epss) = &self.epss {
            if epss.source == EpssSource::FirstOrg || epss.source == EpssSource::Cache {
                score += epss.score * 15.0;
            }
        }

        if self.is_new {
            score += 5.0;
        }

        score
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum EpssSource {
    #[serde(rename = "first.org")]
    FirstOrg,
    #[serde(rename = "cache")]
    Cache,
    #[serde(rename = "heuristic")]
    Heuristic,
    #[serde(rename = "unavailable")]
    #[default]
    Unavailable,
}

impl EpssSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstOrg => "first.org",
            Self::Cache => "cache",
            Self::Heuristic => "heuristic",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EpssInfo {
    pub score: f64,
    pub percentile: f64,
    #[serde(default)]
    pub source: EpssSource,
}

impl Default for VulnerabilityFinding {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            package: String::new(),
            version: String::new(),
            ecosystem: String::new(),
            pkg_id: String::new(),
            severity: SeverityInfo {
                level: SeverityLevel::Unknown,
                score: 0.0,
                vector: None,
            },
            cve: None,
            cwes: vec![],
            fixed_in: vec![],
            is_transitive: false,
            paths: vec![],
            details: None,
            references: vec![],
            reachability: None,
            aliases: vec![],
            advisory_category: AdvisoryCategory::Vulnerability,
            epss: None,
            fingerprint: String::new(),
            usage_signal: UsageSignal::Unknown,
            reason_code: None,
            priority_score: 0.0,
            is_new: false,
        }
    }
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
    #[serde(default)]
    pub highest_severity: Option<SeverityLevel>,
}
