use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageReport {
    pub plan_tier: String,
    pub is_unlimited: bool,
    pub monthly_limit: Option<usize>,
    pub scans_this_month: usize,
    pub billing_period: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LocalUsageData {
    pub current_period: String, // e.g. "2026-10"
    pub scans_count: usize,
    pub last_scan_timestamp: Option<String>,
}

pub struct CloudUsageLimiter {
    usage_file: PathBuf,
}

impl Default for CloudUsageLimiter {
    fn default() -> Self {
        Self::new(Path::new(".sca-cache"))
    }
}

impl CloudUsageLimiter {
    pub fn new(cache_dir: &Path) -> Self {
        Self {
            usage_file: cache_dir.join("usage.json"),
        }
    }

    fn current_period() -> String {
        let now = Utc::now();
        format!("{:04}-{:02}", now.year(), now.month())
    }

    fn load_data(&self) -> LocalUsageData {
        if self.usage_file.exists() {
            if let Ok(content) = fs::read_to_string(&self.usage_file) {
                if let Ok(data) = serde_json::from_str::<LocalUsageData>(&content) {
                    if data.current_period == Self::current_period() {
                        return data;
                    }
                }
            }
        }
        LocalUsageData {
            current_period: Self::current_period(),
            scans_count: 0,
            last_scan_timestamp: None,
        }
    }

    fn save_data(&self, data: &LocalUsageData) {
        if let Some(parent) = self.usage_file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(data) {
            let _ = fs::write(&self.usage_file, json);
        }
    }

    /// Check quota and get current usage status.
    /// In Free Developer Edition, local CLI and open source scans are 100% UNLIMITED.
    pub fn get_usage_report(&self) -> UsageReport {
        let data = self.load_data();
        UsageReport {
            plan_tier: "Free / Developer Edition ($0)".to_string(),
            is_unlimited: true,
            monthly_limit: None,
            scans_this_month: data.scans_count,
            billing_period: data.current_period,
            status: "Active (Unrestricted)".to_string(),
            message: "Unlimited local CLI and open-source repository tests".to_string(),
        }
    }

    /// Record a scan execution without ever blocking or throttling
    pub fn record_scan(&self) -> UsageReport {
        let mut data = self.load_data();
        data.scans_count += 1;
        data.last_scan_timestamp = Some(Utc::now().to_rfc3339());
        self.save_data(&data);

        self.get_usage_report()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_tier_is_unlimited() {
        let temp_dir = std::env::temp_dir().join("vexa_test_usage");
        let limiter = CloudUsageLimiter::new(&temp_dir);
        let report = limiter.get_usage_report();

        assert!(
            report.is_unlimited,
            "Free Developer tier must be unlimited for local scans"
        );
        assert_eq!(
            report.monthly_limit, None,
            "Monthly limit should be None for unlimited"
        );
        assert_eq!(report.status, "Active (Unrestricted)");

        let updated = limiter.record_scan();
        assert_eq!(updated.scans_this_month, 1);
        assert!(updated.is_unlimited);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
