use crate::core::dep_graph::DepGraph;
use crate::core::semver_utils::extract_fixed_versions;
use crate::scanner::cache::VulnCache;
use crate::scanner::epss::EpssResolver;
use crate::types::{
    AdvisoryCategory, AdvisoryStatus, CompletenessReport, PkgInfo, ScanStatus, SeverityInfo,
    SeverityLevel, UsageSignal, VulnerabilityFinding,
};
use reqwest::Client;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Internal result of a single OSV batch query attempt.
pub enum BatchFetchOutcome {
    /// Successfully retrieved advisory IDs (may be empty if no vulns).
    Success(Vec<Vec<Value>>),
    /// The HTTP request failed or returned a non-2xx status.
    NetworkError,
    /// The response body could not be parsed as expected JSON.
    ParseError,
}

#[derive(Debug, Clone, Default)]
pub struct AdvisoryFetchResult {
    pub records: HashMap<String, Value>,
    pub failed_ids: Vec<String>,
    pub retry_exhausted_ids: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub scanned_packages_count: usize,
    pub vulnerabilities_count: usize,
    pub has_cycles: bool,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    pub unreachable_count: usize,
    /// Status of the advisory database lookup for this scan.
    pub advisory_status: AdvisoryStatus,
    /// Number of packages that were successfully checked (cache hit or live query).
    pub packages_checked: usize,
    /// Number of packages that could NOT be checked due to advisory service failure.
    pub packages_unavailable: usize,
    /// Top-level scan status (PASS, FAIL, INCOMPLETE).
    pub scan_status: ScanStatus,
    /// Completeness metrics and limits.
    pub completeness: CompletenessReport,
    /// Number of new findings relative to baseline.
    pub new_vulnerabilities_count: usize,
    /// Number of baseline findings.
    pub baseline_vulnerabilities_count: usize,
    /// Detailed diagnostic list of packages that were unavailable.
    pub unavailable_packages: Vec<String>,
}

pub struct VulnScanner {
    pub cache: VulnCache,
    pub batch_api_url: String,
    pub vuln_api_url: String,
    pub client: Client,
    pub epss_resolver: EpssResolver,
}

impl Default for VulnScanner {
    fn default() -> Self {
        Self::new(None)
    }
}

impl VulnScanner {
    pub fn new(cache: Option<VulnCache>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            cache: cache.unwrap_or_default(),
            batch_api_url: "https://api.osv.dev/v1/querybatch".to_string(),
            vuln_api_url: "https://api.osv.dev/v1/vulns".to_string(),
            client,
            epss_resolver: EpssResolver::default(),
        }
    }

    pub async fn scan_graph(&self, dep_graph: &DepGraph) -> Result<ScanResult, String> {
        let pkgs = dep_graph.get_all_pkgs();
        let mut uncached: Vec<PkgInfo> = Vec::new();
        let mut results_map: HashMap<String, Vec<Value>> = HashMap::new();
        let total_pkgs = pkgs.len();

        // 1. Check cache
        for pkg in &pkgs {
            if let Some(cached) = self.cache.get(pkg) {
                results_map.insert(pkg.id.clone(), cached);
            } else {
                uncached.push(pkg.clone());
            }
        }

        let cached_count = total_pkgs - uncached.len();
        let mut packages_unavailable: usize = 0;
        let mut had_network_error = false;
        let mut had_parse_error = false;
        let mut unavailable_packages: Vec<String> = Vec::new();

        // 2. Query batch for uncached packages — chunk requests into bounded batches of 100
        // (optimal for api.osv.dev) and run with bounded concurrency (up to 4 concurrent batches).
        // Each chunk is retried up to MAX_RETRIES times with exponential backoff before its
        // packages are marked unavailable with explicit diagnostics.
        const CHUNK_SIZE: usize = 100;
        const MAX_CONCURRENT_BATCHES: usize = 4;
        const MAX_RETRIES: u32 = 3;

        let chunks: Vec<Vec<PkgInfo>> = uncached.chunks(CHUNK_SIZE).map(|c| c.to_vec()).collect();

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_BATCHES));
        let mut join_set = tokio::task::JoinSet::new();

        for chunk in chunks {
            let sem_clone = sem.clone();
            let client = self.client.clone();
            let batch_api_url = self.batch_api_url.clone();
            join_set.spawn(async move {
                let _permit = sem_clone.acquire().await.ok();
                let mut last_outcome = BatchFetchOutcome::NetworkError;
                for attempt in 0..MAX_RETRIES {
                    if attempt > 0 {
                        let backoff_ms = 250u64 * (1u64 << (attempt - 1)); // 250ms, 500ms
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                    }
                    last_outcome = Self::fetch_batch_raw(&client, &batch_api_url, &chunk).await;
                    match &last_outcome {
                        BatchFetchOutcome::Success(_) => break,
                        BatchFetchOutcome::ParseError => break, // not transient, don't retry
                        BatchFetchOutcome::NetworkError => {}   // retry
                    }
                }
                (chunk, last_outcome)
            });
        }

        while let Some(res) = join_set.join_next().await {
            if let Ok((chunk, outcome)) = res {
                match outcome {
                    BatchFetchOutcome::Success(fetched) => {
                        for (pkg, raw_vulns) in chunk.iter().zip(fetched) {
                            self.cache.set(pkg, &raw_vulns);
                            results_map.insert(pkg.id.clone(), raw_vulns);
                        }
                    }
                    BatchFetchOutcome::NetworkError => {
                        had_network_error = true;
                        packages_unavailable += chunk.len();
                        for pkg in &chunk {
                            unavailable_packages.push(format!(
                                "{} (network timeout/failure after {} retries)",
                                pkg.id, MAX_RETRIES
                            ));
                        }
                    }
                    BatchFetchOutcome::ParseError => {
                        had_parse_error = true;
                        packages_unavailable += chunk.len();
                        for pkg in &chunk {
                            unavailable_packages
                                .push(format!("{} (malformed upstream OSV response)", pkg.id));
                        }
                    }
                }
            }
        }

        // Determine advisory status
        let mut advisory_status = if had_network_error {
            if cached_count == 0 {
                AdvisoryStatus::Unavailable
            } else {
                AdvisoryStatus::PartialFailure
            }
        } else if had_parse_error {
            AdvisoryStatus::MalformedUpstreamResponse
        } else if uncached.is_empty() && cached_count > 0 {
            AdvisoryStatus::CacheHit
        } else {
            AdvisoryStatus::Success
        };

        let packages_checked = total_pkgs - packages_unavailable;

        // 3. Collect unique vuln IDs to fetch full advisory records
        let mut unique_vuln_ids = HashSet::new();
        for pkg in &pkgs {
            if let Some(raw_list) = results_map.get(&pkg.id) {
                for item in raw_list {
                    if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                        unique_vuln_ids.insert(id.to_string());
                    }
                }
            }
        }

        let full_advisories = self
            .fetch_advisories(unique_vuln_ids.into_iter().collect())
            .await;

        if !full_advisories.failed_ids.is_empty() {
            advisory_status = AdvisoryStatus::PartialFailure;
            packages_unavailable += full_advisories.failed_ids.len();
            for failed_id in &full_advisories.failed_ids {
                unavailable_packages.push(format!(
                    "advisory:{} (detail fetch failed after retries)",
                    failed_id
                ));
            }
        }

        // 4. Construct enriched and deduplicated vulnerability findings
        let mut vulnerabilities = Vec::new();

        for pkg in &pkgs {
            let raw_list = match results_map.get(&pkg.id) {
                Some(l) => l,
                None => continue,
            };
            let paths_to_root = dep_graph.pkg_paths_to_root(&pkg.id, 10);
            let is_transitive = dep_graph.is_transitive(&pkg.id);
            let paths_strings: Vec<Vec<String>> = paths_to_root
                .iter()
                .map(|p| {
                    p.iter()
                        .map(|node| format!("{}@{}", node.name, node.version))
                        .collect()
                })
                .collect();

            // Collect unique full advisories for this package
            let mut pkg_advisories = Vec::new();
            let mut seen_ids = HashSet::new();
            for item in raw_list {
                if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                    if seen_ids.insert(id) {
                        if let Some(adv) = full_advisories.records.get(id) {
                            pkg_advisories.push(adv);
                        }
                    }
                }
            }

            // Cluster overlapping advisories (e.g. GHSA + RUSTSEC + CVE referencing each other)
            let clusters = self.cluster_advisories(&pkg_advisories);

            for cluster in clusters {
                if let Some(finding) =
                    self.merge_cluster_into_finding(pkg, is_transitive, &paths_strings, &cluster)
                {
                    vulnerabilities.push(finding);
                }
            }
        }

        // Enrich findings with EPSS exploit prediction likelihood
        self.epss_resolver
            .enrich_findings(&mut vulnerabilities)
            .await;

        // Sort by severity (Critical -> High -> Medium -> Low)
        vulnerabilities.sort_by_key(|b| std::cmp::Reverse(b.severity.level.weight()));

        let scan_status = if advisory_status.has_unreliable_data() {
            ScanStatus::Incomplete
        } else if vulnerabilities.is_empty() {
            ScanStatus::Pass
        } else {
            ScanStatus::Fail
        };

        let mut package_completeness_states = std::collections::HashMap::new();
        for pkg in &pkgs {
            if unavailable_packages.iter().any(|u| u.starts_with(&pkg.id)) {
                package_completeness_states.insert(pkg.id.clone(), "UNAVAILABLE".to_string());
            } else if uncached.iter().any(|u| u.id == pkg.id) {
                package_completeness_states
                    .insert(pkg.id.clone(), "LIVE_QUERY_SUCCESS".to_string());
            } else {
                package_completeness_states.insert(pkg.id.clone(), "CACHE_HIT".to_string());
            }
        }

        let completeness = CompletenessReport {
            manifests_detected: 1,
            manifests_analysed: 1,
            manifests_skipped: 0,
            packages_discovered: total_pkgs,
            packages_resolved: total_pkgs,
            packages_unresolved: 0,
            packages_checked,
            source_files_discovered: 0,
            source_files_analysed: 0,
            source_files_skipped: 0,
            source_files_failed: 0,
            limits_hit: Vec::new(),
            advisory_source: "OSV (api.osv.dev)".to_string(),
            advisory_status,
            unavailable_packages: unavailable_packages.clone(),
            package_completeness_states,
        };

        let vulns_count = vulnerabilities.len();
        Ok(ScanResult {
            scanned_packages_count: total_pkgs,
            vulnerabilities_count: vulns_count,
            has_cycles: dep_graph.has_cycles(),
            vulnerabilities,
            unreachable_count: 0,
            advisory_status,
            packages_checked,
            packages_unavailable,
            scan_status,
            completeness,
            new_vulnerabilities_count: vulns_count,
            baseline_vulnerabilities_count: 0,
            unavailable_packages,
        })
    }

    pub async fn fetch_batch_raw(
        client: &Client,
        batch_api_url: &str,
        pkgs: &[PkgInfo],
    ) -> BatchFetchOutcome {
        let queries: Vec<Value> = pkgs
            .iter()
            .map(|p| {
                serde_json::json!({
                    "package": {
                        "name": p.name,
                        "ecosystem": p.ecosystem,
                    },
                    "version": p.version,
                })
            })
            .collect();

        let body = serde_json::json!({ "queries": queries });

        let resp = match client.post(batch_api_url).json(&body).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(_) | Err(_) => {
                return BatchFetchOutcome::NetworkError;
            }
        };

        let data = match resp.json::<Value>().await {
            Ok(d) => d,
            Err(_) => return BatchFetchOutcome::ParseError,
        };

        let results = match data.get("results").and_then(|r| r.as_array()) {
            Some(arr) => arr,
            None => return BatchFetchOutcome::ParseError,
        };

        // If the server returned a different number of results than queries, treat as parse error
        if results.len() != pkgs.len() {
            return BatchFetchOutcome::ParseError;
        }

        let mut fetched = Vec::with_capacity(results.len());
        for (idx, r) in results.iter().enumerate() {
            let mut vulns = r
                .get("vulns")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            // P0.3: Follow OSV next_page_token if paginated
            let mut next_token = r
                .get("next_page_token")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string());

            while let Some(token) = next_token {
                if let Some(pkg) = pkgs.get(idx) {
                    let query_url = batch_api_url.replace("querybatch", "query");
                    let page_body = serde_json::json!({
                        "package": {
                            "name": pkg.name,
                            "ecosystem": pkg.ecosystem,
                        },
                        "version": pkg.version,
                        "page_token": token,
                    });
                    if let Ok(page_resp) = client.post(&query_url).json(&page_body).send().await {
                        if page_resp.status().is_success() {
                            if let Ok(page_data) = page_resp.json::<Value>().await {
                                if let Some(extra_vulns) =
                                    page_data.get("vulns").and_then(|v| v.as_array())
                                {
                                    vulns.extend(extra_vulns.clone());
                                }
                                next_token = page_data
                                    .get("next_page_token")
                                    .and_then(|t| t.as_str())
                                    .map(|s| s.to_string());
                                continue;
                            }
                        }
                    }
                }
                break;
            }

            fetched.push(vulns);
        }

        BatchFetchOutcome::Success(fetched)
    }

    pub async fn fetch_batch(&self, pkgs: &[PkgInfo]) -> BatchFetchOutcome {
        Self::fetch_batch_raw(&self.client, &self.batch_api_url, pkgs).await
    }

    pub async fn fetch_advisories(&self, vuln_ids: Vec<String>) -> AdvisoryFetchResult {
        let mut result = AdvisoryFetchResult::default();
        let mut to_fetch = Vec::new();

        for id in vuln_ids {
            if let Some(cached) = self.cache.get_advisory(&id) {
                result.records.insert(id, cached);
            } else {
                to_fetch.push(id);
            }
        }

        const ADVISORY_CONCURRENCY: usize = 16;
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(ADVISORY_CONCURRENCY));
        let mut set = tokio::task::JoinSet::new();

        for id in to_fetch {
            let sem_clone = sem.clone();
            let client = self.client.clone();
            let url = format!("{}/{}", self.vuln_api_url, id);
            set.spawn(async move {
                let _permit = sem_clone.acquire().await.ok();
                for attempt in 0..2 {
                    if attempt > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                    if let Ok(resp) = client.get(&url).send().await {
                        if resp.status().is_success() {
                            if let Ok(data) = resp.json::<Value>().await {
                                return Ok((id.clone(), data));
                            }
                        }
                    }
                }
                Err(id)
            });
        }

        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok((id, data))) => {
                    self.cache.set_advisory(&id, &data);
                    result.records.insert(id, data);
                }
                Ok(Err(failed_id)) => {
                    result.failed_ids.push(failed_id.clone());
                    result.retry_exhausted_ids.push(failed_id);
                }
                Err(_) => {}
            }
        }

        result
    }

    fn determine_severity(&self, adv: &Value) -> SeverityInfo {
        let mut score = None;
        let mut vector = None;

        if let Some(sev_arr) = adv.get("severity").and_then(|v| v.as_array()) {
            for s in sev_arr {
                let stype = s.get("type").and_then(|t| t.as_str()).unwrap_or("");
                if stype == "CVSS_V3" || stype == "CVSS_V4" {
                    if let Some(sc) = s.get("score").and_then(|sc| sc.as_str()) {
                        vector = Some(sc.to_string());
                        if let Ok(num) = sc.parse::<f64>() {
                            score = Some(num);
                        } else if let Some(computed) = self.calculate_cvss_v3_score(sc) {
                            score = Some(computed);
                        } else {
                            score = self.estimate_score_from_cvss(sc);
                        }
                        break;
                    }
                }
            }
        }

        let db_sev = adv
            .get("database_specific")
            .and_then(|d| d.get("severity"))
            .and_then(|s| s.as_str());

        let mut level = SeverityLevel::Unknown;
        if let Some(s) = db_sev {
            level = SeverityLevel::from_str_loose(s);
        }

        // Harmonize severity level with standard CVSS v3.1 / v4 qualitative rating scale
        if let Some(sc) = score {
            let cvss_level = if sc >= 9.0 {
                SeverityLevel::Critical
            } else if sc >= 7.0 {
                SeverityLevel::High
            } else if sc >= 4.0 {
                SeverityLevel::Medium
            } else if sc > 0.0 {
                SeverityLevel::Low
            } else {
                SeverityLevel::Unknown
            };

            // CVSS qualitative score is authoritative when vector or score is present
            if cvss_level != SeverityLevel::Unknown {
                level = cvss_level;
            }
        }

        if level == SeverityLevel::Unknown {
            level = SeverityLevel::Medium;
        }

        let final_score = score.unwrap_or(match level {
            SeverityLevel::Critical => 9.5,
            SeverityLevel::High => 7.5,
            SeverityLevel::Medium => 5.5,
            SeverityLevel::Low => 2.5,
            SeverityLevel::Unknown => 5.0,
        });

        SeverityInfo {
            level,
            score: final_score,
            vector,
        }
    }

    /// Calculates standard CVSS v3.1 base score from a vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
    fn calculate_cvss_v3_score(&self, vector: &str) -> Option<f64> {
        let mut av: Option<f64> = None;
        let mut ac: Option<f64> = None;
        let mut pr: Option<&str> = None;
        let mut ui: Option<f64> = None;
        let mut s_changed = false;
        let mut c: Option<f64> = None;
        let mut i: Option<f64> = None;
        let mut a: Option<f64> = None;

        for part in vector.split('/') {
            let mut kv = part.split(':');
            let k = kv.next().unwrap_or("").trim();
            let v = kv.next().unwrap_or("").trim();
            match k {
                "AV" => {
                    av = match v {
                        "N" => Some(0.85),
                        "A" => Some(0.62),
                        "L" => Some(0.55),
                        "P" => Some(0.20),
                        _ => None,
                    }
                }
                "AC" => {
                    ac = match v {
                        "L" => Some(0.77),
                        "H" => Some(0.44),
                        _ => None,
                    }
                }
                "PR" => pr = Some(v),
                "UI" => {
                    ui = match v {
                        "N" => Some(0.85),
                        "R" => Some(0.62),
                        _ => None,
                    }
                }
                "S" => s_changed = v == "C",
                "C" => {
                    c = match v {
                        "H" => Some(0.56),
                        "L" => Some(0.22),
                        "N" => Some(0.0),
                        _ => None,
                    }
                }
                "I" => {
                    i = match v {
                        "H" => Some(0.56),
                        "L" => Some(0.22),
                        "N" => Some(0.0),
                        _ => None,
                    }
                }
                "A" => {
                    a = match v {
                        "H" => Some(0.56),
                        "L" => Some(0.22),
                        "N" => Some(0.0),
                        _ => None,
                    }
                }
                _ => {}
            }
        }

        let pr_val = match (pr?, s_changed) {
            ("N", _) => 0.85,
            ("L", false) => 0.62,
            ("L", true) => 0.68,
            ("H", false) => 0.27,
            ("H", true) => 0.50,
            _ => return None,
        };

        let av = av?;
        let ac = ac?;
        let ui = ui?;
        let c = c?;
        let i = i?;
        let a = a?;

        let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
        if iss <= 0.0 {
            return Some(0.0);
        }

        let impact = if s_changed {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
        } else {
            6.42 * iss
        };

        let exploitability = 8.22 * av * ac * pr_val * ui;

        let raw_score = if s_changed {
            (1.08 * (impact + exploitability)).min(10.0)
        } else {
            (impact + exploitability).min(10.0)
        };

        let rounded = (raw_score * 10.0).ceil() / 10.0;
        Some(rounded)
    }

    fn estimate_score_from_cvss(&self, vector: &str) -> Option<f64> {
        if vector.contains("AV:N")
            && vector.contains("AC:L")
            && vector.contains("C:H")
            && vector.contains("I:H")
        {
            Some(9.8)
        } else if vector.contains("AV:N") && vector.contains("AC:L") {
            Some(7.5)
        } else {
            Some(6.0)
        }
    }

    fn extract_cwes(&self, adv: &Value) -> Vec<String> {
        let mut cwes = Vec::new();
        if let Some(ids) = adv
            .get("database_specific")
            .and_then(|d| d.get("cwe_ids"))
            .and_then(|c| c.as_array())
        {
            for id in ids {
                if let Some(s) = id.as_str() {
                    cwes.push(s.to_string());
                }
            }
        }
        cwes
    }

    fn cluster_advisories<'a>(&self, advisories: &[&'a Value]) -> Vec<Vec<&'a Value>> {
        let n = advisories.len();
        if n <= 1 {
            return advisories.iter().map(|&a| vec![a]).collect();
        }

        // Build identifier sets for each advisory (ID + aliases)
        let mut id_sets: Vec<HashSet<String>> = Vec::with_capacity(n);
        for adv in advisories {
            let mut set = HashSet::new();
            if let Some(id) = adv.get("id").and_then(|v| v.as_str()) {
                set.insert(id.to_string());
            }
            if let Some(aliases) = adv.get("aliases").and_then(|v| v.as_array()) {
                for a in aliases {
                    if let Some(s) = a.as_str() {
                        set.insert(s.to_string());
                    }
                }
            }
            id_sets.push(set);
        }

        // Disjoint-set union
        let mut parent: Vec<usize> = (0..n).collect();

        fn find(mut i: usize, parent: &mut [usize]) -> usize {
            while parent[i] != i {
                parent[i] = parent[parent[i]];
                i = parent[i];
            }
            i
        }

        for i in 0..n {
            for j in (i + 1)..n {
                // If they share any ID or alias, union them
                if id_sets[i].iter().any(|id| id_sets[j].contains(id)) {
                    let root_i = find(i, &mut parent);
                    let root_j = find(j, &mut parent);
                    if root_i != root_j {
                        parent[root_i] = root_j;
                    }
                }
            }
        }

        let mut groups: HashMap<usize, Vec<&'a Value>> = HashMap::new();
        for (i, adv) in advisories.iter().enumerate().take(n) {
            let root = find(i, &mut parent);
            groups.entry(root).or_default().push(*adv);
        }

        groups.into_values().collect()
    }

    fn merge_cluster_into_finding(
        &self,
        pkg: &PkgInfo,
        is_transitive: bool,
        paths_strings: &[Vec<String>],
        cluster: &[&Value],
    ) -> Option<VulnerabilityFinding> {
        if cluster.is_empty() {
            return None;
        }

        // 1. Gather all IDs and Aliases
        let mut all_ids = HashSet::new();
        let mut primary_candidates = Vec::new();

        for adv in cluster {
            if let Some(id) = adv.get("id").and_then(|v| v.as_str()) {
                all_ids.insert(id.to_string());
                primary_candidates.push(id.to_string());
            }
            if let Some(aliases) = adv.get("aliases").and_then(|v| v.as_array()) {
                for a in aliases {
                    if let Some(s) = a.as_str() {
                        all_ids.insert(s.to_string());
                    }
                }
            }
        }

        // Find CVE if available
        let cve = all_ids.iter().find(|id| id.starts_with("CVE-")).cloned();

        // Determine primary ID (Prefer GHSA -> CVE -> RUSTSEC -> others)
        let primary_id = primary_candidates
            .iter()
            .find(|id| id.starts_with("GHSA-"))
            .cloned()
            .or_else(|| cve.clone())
            .or_else(|| {
                primary_candidates
                    .iter()
                    .find(|id| id.starts_with("RUSTSEC-"))
                    .cloned()
            })
            .unwrap_or_else(|| {
                primary_candidates
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "UNKNOWN".to_string())
            });

        let mut aliases: Vec<String> = all_ids.into_iter().filter(|id| id != &primary_id).collect();
        aliases.sort();

        // 2. Classify Category (Security Vulnerability vs Unmaintained vs Informational)
        let is_unmaintained = cluster.iter().any(|adv| {
            let sum = adv
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let det = adv
                .get("details")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            sum.contains("is unmaintained")
                || sum.contains("unmaintained crate")
                || sum.contains("unmaintained;")
                || det.contains("is unmaintained")
                || det.contains("unmaintained crate")
                || det.contains("unmaintained;")
                || det.contains("has been unmaintained")
        });

        let advisory_category = if is_unmaintained {
            AdvisoryCategory::Unmaintained
        } else {
            AdvisoryCategory::Vulnerability
        };

        // 3. Determine Highest Severity across the cluster
        let severity = if is_unmaintained {
            SeverityInfo {
                level: SeverityLevel::Low,
                score: 2.0,
                vector: None,
            }
        } else {
            let mut highest_sev: Option<SeverityInfo> = None;
            for adv in cluster {
                let s = self.determine_severity(adv);
                match &highest_sev {
                    None => highest_sev = Some(s),
                    Some(cur) => {
                        if s.level.weight() > cur.level.weight()
                            || (s.level.weight() == cur.level.weight() && s.score > cur.score)
                        {
                            highest_sev = Some(s);
                        }
                    }
                }
            }
            highest_sev.unwrap_or(SeverityInfo {
                level: SeverityLevel::Medium,
                score: 5.0,
                vector: None,
            })
        };

        // 4. Extract union of fixed versions
        let mut fixed_in_set = HashSet::new();
        for adv in cluster {
            for f in extract_fixed_versions(adv) {
                fixed_in_set.insert(f);
            }
        }
        let mut fixed_in: Vec<String> = fixed_in_set.into_iter().collect();
        fixed_in.sort();

        // 5. Extract union of CWEs
        let mut cwe_set = HashSet::new();
        for adv in cluster {
            for cwe in self.extract_cwes(adv) {
                cwe_set.insert(cwe);
            }
        }
        let mut cwes: Vec<String> = cwe_set.into_iter().collect();
        cwes.sort();

        // 6. Best title / summary
        let title_extracted = cluster
            .iter()
            .filter_map(|adv| adv.get("summary").and_then(|s| s.as_str()))
            .map(|s| s.trim())
            .filter(|s| s.len() > 5)
            .max_by_key(|s| s.len())
            .map(|s| s.to_string())
            .or_else(|| {
                cluster
                    .iter()
                    .filter_map(|adv| adv.get("details").and_then(|d| d.as_str()))
                    .find_map(|s| {
                        let first_line =
                            s.lines().find(|l| !l.trim().is_empty()).unwrap_or(s).trim();
                        let clean = first_line
                            .trim_start_matches('#')
                            .trim_start_matches('*')
                            .trim_start_matches('-')
                            .trim();
                        if clean.is_empty() {
                            return None;
                        }
                        if clean.len() <= 120 {
                            Some(clean.to_string())
                        } else {
                            let truncate_at = clean[..120].rfind(' ').unwrap_or(120);
                            Some(format!("{}...", &clean[..truncate_at]))
                        }
                    })
            });

        let title = title_extracted.unwrap_or_else(|| {
            if let Some(cve_id) = &cve {
                format!("Security vulnerability ({}) affecting {}", cve_id, pkg.name)
            } else {
                format!("Security advisory affecting {}", pkg.name)
            }
        });

        // 7. References
        let mut ref_set = HashSet::new();
        for adv in cluster {
            if let Some(arr) = adv.get("references").and_then(|v| v.as_array()) {
                for r in arr {
                    if let Some(u) = r.get("url").and_then(|u| u.as_str()) {
                        ref_set.insert(u.to_string());
                    }
                }
            }
        }
        let mut references: Vec<String> = ref_set.into_iter().take(4).collect();
        references.sort();

        // 8. Details
        let details = cluster
            .iter()
            .filter_map(|adv| adv.get("details").and_then(|d| d.as_str()))
            .max_by_key(|s| s.len())
            .map(|s| s.to_string());

        let scope = if is_transitive {
            "transitive"
        } else {
            "direct"
        };
        let fingerprint = VulnerabilityFinding::calculate_fingerprint(
            &pkg.ecosystem,
            &pkg.name,
            &pkg.version,
            &primary_id,
            scope,
        );

        let mut finding = VulnerabilityFinding {
            id: primary_id,
            title,
            package: pkg.name.clone(),
            version: pkg.version.clone(),
            ecosystem: pkg.ecosystem.clone(),
            pkg_id: pkg.id.clone(),
            severity,
            cve,
            cwes,
            fixed_in,
            is_transitive,
            paths: paths_strings.to_vec(),
            details,
            references,
            reachability: None,
            aliases,
            advisory_category,
            epss: None,
            fingerprint,
            usage_signal: UsageSignal::Unknown,
            reason_code: None,
            priority_score: 0.0,
            is_new: false,
        };
        finding.priority_score = finding.compute_priority_score();

        Some(finding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_advisories_and_merge() {
        let scanner = VulnScanner::default();

        let adv1 = serde_json::json!({
            "id": "GHSA-3v94-mw7p-v465",
            "aliases": ["CVE-2026-93657", "RUSTSEC-2026-0118"],
            "summary": "NSEC3 closest-encloser proof validation loop",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
            "affected": [{"ranges": [{"events": [{"fixed": "0.26.1"}]}]}]
        });

        let adv2 = serde_json::json!({
            "id": "RUSTSEC-2026-0118",
            "aliases": ["CVE-2026-93657", "GHSA-3v94-mw7p-v465"],
            "summary": "NSEC3 closest-encloser proof validation enters unbounded loop",
            "database_specific": {"severity": "MODERATE"},
            "affected": [{"ranges": [{"events": [{"fixed": "0.26.0-beta.1"}]}]}]
        });

        let adv3_distinct = serde_json::json!({
            "id": "RUSTSEC-2026-0119",
            "aliases": ["CVE-2026-99999"],
            "summary": "CPU exhaustion in message encoding",
            "affected": [{"ranges": [{"events": [{"fixed": "0.26.1"}]}]}]
        });

        let list = vec![&adv1, &adv2, &adv3_distinct];
        let clusters = scanner.cluster_advisories(&list);

        // adv1 and adv2 must cluster together; adv3 is separate
        assert_eq!(clusters.len(), 2);

        let pkg = PkgInfo::new("hickory-proto", "0.25.2", "crates.io");
        let merged1 = scanner
            .merge_cluster_into_finding(&pkg, true, &[], &[&adv1, &adv2])
            .unwrap();

        assert_eq!(merged1.cve.as_deref(), Some("CVE-2026-93657"));
        assert_eq!(merged1.severity.level, SeverityLevel::High);
        assert!(merged1.fixed_in.contains(&"0.26.1".to_string()));
        assert!(merged1.fixed_in.contains(&"0.26.0-beta.1".to_string()));
        assert_eq!(merged1.advisory_category, AdvisoryCategory::Vulnerability);
    }

    #[test]
    fn test_unmaintained_crate_classification() {
        let scanner = VulnScanner::default();

        let adv = serde_json::json!({
            "id": "RUSTSEC-2024-0384",
            "summary": "`instant` is unmaintained",
            "details": "The maintainer has archived the repository."
        });

        let pkg = PkgInfo::new("instant", "0.1.13", "crates.io");
        let finding = scanner
            .merge_cluster_into_finding(&pkg, true, &[], &[&adv])
            .unwrap();

        assert_eq!(finding.advisory_category, AdvisoryCategory::Unmaintained);
        assert_eq!(finding.severity.level, SeverityLevel::Low);
    }

    #[test]
    fn test_cvss_score_harmonizes_moderate_database_severity() {
        let scanner = VulnScanner::default();

        let adv = serde_json::json!({
            "id": "GHSA-6f2x-v7q7-m7m5",
            "summary": "hickory-resolver follows irrelevant CNAME records",
            "database_specific": {"severity": "MODERATE"},
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]
        });

        let sev = scanner.determine_severity(&adv);
        // CVSS 7.5 must harmonize MODERATE (Medium) to High
        assert_eq!(sev.level, SeverityLevel::High);
        assert_eq!(sev.score, 7.5);
    }

    #[test]
    fn test_merge_cluster_preserves_vendor_references_and_id() {
        let scanner = VulnScanner::default();
        let adv = serde_json::json!({
            "id": "SNYK-JS-LODASH-567746",
            "aliases": ["CVE-2020-8203"],
            "summary": "Prototype Pollution in snyk report",
            "details": "Vendor details with snyk advisories and https://snyk.io/vuln/SNYK-JS-LODASH-567746",
            "references": [
                {"url": "https://snyk.io/vuln/SNYK-JS-LODASH-567746"},
                {"url": "https://github.com/lodash/lodash/commit/e2a663"}
            ]
        });

        let pkg = PkgInfo::new("lodash", "4.17.15", "npm");
        let finding = scanner
            .merge_cluster_into_finding(&pkg, false, &[], &[&adv])
            .expect("should merge finding");

        // Assert references are preserved exactly
        assert!(finding
            .references
            .contains(&"https://snyk.io/vuln/SNYK-JS-LODASH-567746".to_string()));
        assert!(finding
            .references
            .contains(&"https://github.com/lodash/lodash/commit/e2a663".to_string()));
        assert!(finding.details.as_ref().unwrap().contains("snyk"));
        assert_eq!(finding.cve.as_deref(), Some("CVE-2020-8203"));
    }

    /// Verifies that a scan against an unreachable OSV API endpoint returns
    /// `AdvisoryStatus::Unavailable` and marks all packages as unavailable.
    /// This prevents the fail-open false-negative: an outage must NOT produce
    /// a clean report with zero vulnerabilities and exit code 0.
    #[tokio::test]
    async fn test_scan_graph_advisory_unavailable_when_api_unreachable() {
        use crate::core::dep_graph::{DepGraph, PkgManagerInfo};
        use crate::scanner::cache::VulnCache;

        // Use a clean temporary cache directory to guarantee no cache hits
        let temp_dir = std::env::temp_dir().join(format!(
            "vexa_scanner_outage_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let cache = VulnCache::new(&temp_dir);

        // Point the scanner at an unreachable local port so all requests fail fast
        let unreachable_url = "http://127.0.0.1:19999/v1/querybatch".to_string();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(300))
            .build()
            .unwrap();

        let scanner = VulnScanner {
            cache,
            batch_api_url: unreachable_url,
            client,
            ..VulnScanner::default()
        };

        let root = PkgInfo::new("my-app", "1.0.0", "npm");
        let mut graph = DepGraph::new(
            root,
            PkgManagerInfo {
                name: "npm".to_string(),
                version: "8.0.0".to_string(),
            },
        );
        let dep = PkgInfo::new("test-pkg-outage-target", "1.0.0", "npm");
        graph.add_pkg(dep);

        let result = scanner
            .scan_graph(&graph)
            .await
            .expect("scan_graph should not return Err on network failure");

        // The advisory status must NOT be success — it must signal unavailability
        assert!(
            result.advisory_status.has_unreliable_data(),
            "Expected advisory_status to indicate unreliable data when API is unreachable, got {:?}",
            result.advisory_status
        );

        // packages_unavailable must match the number of uncached packages queried
        assert!(
            result.packages_unavailable > 0,
            "Expected packages_unavailable > 0 when API is unreachable"
        );

        // The report must NOT claim zero dependencies were scanned
        assert_eq!(
            result.scanned_packages_count, 1,
            "scanned_packages_count should reflect the number of packages in the graph"
        );

        // Vulnerabilities must be empty (no false findings), but the status signals incompleteness
        assert!(
            result.vulnerabilities.is_empty(),
            "No vulnerabilities should be fabricated from a failed advisory query"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
