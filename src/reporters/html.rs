use crate::licenses::license_scanner::{LicenseAudit, LicenseCategory};
use crate::policy::policy_engine::SuppressedFinding;
use crate::scanner::vuln_scanner::ScanResult;
use crate::types::{ReachabilityStatus, RemediationAction, SeverityLevel};
use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;

/// Formats a complete, self-contained, interactive single-file HTML audit dashboard.
/// Fully offline-ready with zero external dependencies (no CDNs required).
pub fn format_html_report(
    scan_result: &ScanResult,
    suppressed: &[SuppressedFinding],
    remediations: &[RemediationAction],
    license_audit: Option<&LicenseAudit>,
    project_name: &str,
    manifest_file: Option<&Path>,
) -> String {
    let timestamp = Utc::now().to_rfc2822();
    let manifest_display = manifest_file
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "package-lock.json".to_string());

    let critical_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity.level == SeverityLevel::Critical)
        .count();
    let high_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity.level == SeverityLevel::High)
        .count();
    let medium_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| v.severity.level == SeverityLevel::Medium)
        .count();
    let low_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.severity.level == SeverityLevel::Low || v.severity.level == SeverityLevel::Unknown
        })
        .count();

    let reachable_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Reachable)
                .unwrap_or(false)
        })
        .count();
    let unreachable_count = scan_result
        .vulnerabilities
        .iter()
        .filter(|v| {
            v.reachability
                .as_ref()
                .map(|r| r.status == ReachabilityStatus::Unreachable)
                .unwrap_or(false)
        })
        .count();

    let rem_map: HashMap<(&str, &str), &RemediationAction> = remediations
        .iter()
        .map(|r| ((r.package.as_str(), r.current_version.as_str()), r))
        .collect();
    let rem_by_pkg: HashMap<&str, &RemediationAction> = remediations
        .iter()
        .map(|r| (r.package.as_str(), r))
        .collect();

    let mut vuln_cards_html = String::new();
    for (idx, vuln) in scan_result.vulnerabilities.iter().enumerate() {
        let (reach_badge, reach_class, call_site_block) = match &vuln.reachability {
            Some(r) if r.status == ReachabilityStatus::Reachable => {
                let snippet_html = if let Some(site) = r.call_sites.first() {
                    format!(
                        "<div class=\"call-site\"><div class=\"site-loc\">📍 <code>{}:{}</code></div><pre><code>{}</code></pre></div>",
                        html_escape(&site.file),
                        site.line,
                        html_escape(&site.code)
                    )
                } else {
                    String::new()
                };
                (
                    "<span class=\"badge badge-reachable\">🚨 REACHABLE</span>",
                    "reachable",
                    snippet_html,
                )
            }
            Some(r) if r.status == ReachabilityStatus::Unreachable => (
                "<span class=\"badge badge-unreachable\">🛡️ UNREACHABLE</span>",
                "unreachable",
                String::new(),
            ),
            _ => (
                "<span class=\"badge badge-muted\">NOT EVALUATED</span>",
                "not-evaluated",
                String::new(),
            ),
        };

        let sev_level = vuln.severity.level.as_str().to_lowercase();
        let cve_str = vuln.cve.as_deref().unwrap_or(&vuln.id);

        let remediation_html = if let Some(rem) = rem_map
            .get(&(vuln.package.as_str(), vuln.version.as_str()))
            .or_else(|| rem_by_pkg.get(vuln.package.as_str()))
        {
            let target_str = rem
                .target_version
                .as_deref()
                .unwrap_or("latest non-vulnerable");
            format!(
                "<div class=\"rem-box\"><span class=\"rem-icon\">💡</span> <div><strong>Remediation:</strong> {} (target: <code>{}</code>)</div></div>",
                html_escape(&rem.advice),
                html_escape(target_str)
            )
        } else if !vuln.fixed_in.is_empty() {
            format!(
                "<div class=\"rem-box\"><span class=\"rem-icon\">💡</span> <div><strong>Upgrade available:</strong> Upgrade to version <code>{}</code></div></div>",
                html_escape(&vuln.fixed_in.join(", "))
            )
        } else {
            "<div class=\"rem-box rem-warn\"><span class=\"rem-icon\">⚠️</span> <div>No official upstream fix released yet. Check policy suppression.</div></div>".to_string()
        };

        let path_str = vuln
            .paths
            .first()
            .map(|p| p.join(" ➔ "))
            .unwrap_or_else(|| vuln.pkg_id.clone());

        let references_html = vuln
            .references
            .iter()
            .map(|r| {
                format!(
                    "<a href=\"{}\" target=\"_blank\" rel=\"noopener\" class=\"ref-link\">{}</a>",
                    html_escape(r),
                    html_escape(r)
                )
            })
            .collect::<Vec<_>>()
            .join("");

        let epss_badge = if let Some(ref epss) = vuln.epss {
            let pct = epss.score * 100.0;
            format!(
                r#"<span class="badge" style="background: rgba(14, 165, 233, 0.2); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.4);" title="EPSS Exploit Prediction: {:.1}% likelihood within 30 days">EPSS {:.1}%</span>"#,
                pct, pct
            )
        } else {
            String::new()
        };

        vuln_cards_html.push_str(&format!(
            r#"<div class="card vuln-card sev-{sev_level} {reach_class}" data-sev="{sev_level}" data-reach="{reach_class}">
                <div class="card-header" onclick="toggleCard({idx})">
                    <div class="header-left">
                        <span class="badge badge-{sev_level}">{sev_text} ({score:.1})</span>
                        {reach_badge}
                        {epss_badge}
                        <span class="pkg-name"><code>{pkg_id}</code></span>
                        <span class="vuln-id">[{id_text}]</span>
                    </div>
                    <div class="header-right">
                        <span class="chevron" id="chevron-{idx}">▼</span>
                    </div>
                </div>
                <div class="card-body" id="body-{idx}">
                    <h3 class="vuln-title">{title}</h3>
                    {call_site_block}
                    <div class="detail-row"><strong>Propagation Path:</strong> <code class="path-code">{path_str}</code></div>
                    <div class="detail-row"><strong>Details:</strong> <p class="vuln-desc">{details}</p></div>
                    {remediation_html}
                    <div class="detail-row"><strong>References:</strong> <div class="ref-container">{references_html}</div></div>
                </div>
            </div>"#,
            idx = idx,
            sev_level = sev_level,
            sev_text = vuln.severity.level.as_str(),
            score = vuln.severity.score,
            reach_badge = reach_badge,
            epss_badge = epss_badge,
            reach_class = reach_class,
            pkg_id = html_escape(&vuln.pkg_id),
            id_text = html_escape(cve_str),
            title = html_escape(&vuln.title),
            call_site_block = call_site_block,
            path_str = html_escape(&path_str),
            details = html_escape(vuln.details.as_deref().unwrap_or(&vuln.title)),
            remediation_html = remediation_html,
            references_html = references_html,
        ));
    }

    let licenses_section = if let Some(audit) = license_audit {
        let mut rows = String::new();
        for r in &audit.results {
            let cat_class = match r.category {
                LicenseCategory::Permissive => "cat-permissive",
                LicenseCategory::WeakCopyleft => "cat-weak",
                LicenseCategory::StrongCopyleft => "cat-strong",
                LicenseCategory::Unknown => "cat-unknown",
            };
            rows.push_str(&format!(
                "<tr><td><code>{}@{}</code></td><td><span class=\"badge {cat_class}\">{}</span></td><td>{}</td></tr>",
                html_escape(&r.package),
                html_escape(&r.version),
                html_escape(r.category.as_str()),
                html_escape(&r.license)
            ));
        }

        format!(
            r#"<section class="section" id="licenses-sec">
                <h2>License Compliance Audit</h2>
                <div class="stats-row">
                    <div class="stat-pill"><strong>Total:</strong> {}</div>
                    <div class="stat-pill stat-safe"><strong>Permissive:</strong> {}</div>
                    <div class="stat-pill stat-warn"><strong>Weak Copyleft:</strong> {}</div>
                    <div class="stat-pill stat-danger"><strong>Strong Copyleft:</strong> {}</div>
                </div>
                <table class="lic-table">
                    <thead><tr><th>Package</th><th>Risk Category</th><th>Declared License</th></tr></thead>
                    <tbody>{}</tbody>
                </table>
            </section>"#,
            audit.summary.total,
            audit.summary.permissive,
            audit.summary.weak_copyleft,
            audit.summary.strong_copyleft,
            rows
        )
    } else {
        String::new()
    };

    let suppressed_section = if !suppressed.is_empty() {
        let mut rows = String::new();
        for s in suppressed {
            rows.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&s.vulnerability.pkg_id),
                html_escape(&s.vulnerability.id),
                html_escape(&s.suppression.reason),
                html_escape(s.suppression.expires.as_deref().unwrap_or("Never"))
            ));
        }
        format!(
            r#"<section class="section" id="suppressed-sec">
                <h2>Suppressed Policy Findings</h2>
                <table class="lic-table">
                    <thead><tr><th>Package</th><th>Vulnerability</th><th>Audit Reason</th><th>Expires</th></tr></thead>
                    <tbody>{}</tbody>
                </table>
            </section>"#,
            rows
        )
    } else {
        String::new()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vexa SCA - Security Audit Report</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --surface-hover: #1f242c;
            --border: #30363d;
            --text: #c9d1d9;
            --text-muted: #8b949e;
            --heading: #f0f6fc;
            --primary: #58a6ff;
            --crit: #ff5555;
            --high: #ff7b72;
            --med: #d29922;
            --low: #58a6ff;
            --safe: #3fb950;
            --radius: 8px;
            --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        h1 {{ color: var(--heading); font-size: 24px; display: flex; align-items: center; gap: 8px; }}
        .header-meta {{ color: var(--text-muted); font-size: 13px; text-align: right; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 16px;
            text-align: center;
        }}
        .stat-val {{ font-size: 32px; font-weight: 700; color: var(--heading); }}
        .stat-label {{ font-size: 13px; color: var(--text-muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .val-crit {{ color: var(--crit); }}
        .val-high {{ color: var(--high); }}
        .val-med {{ color: var(--med); }}
        .val-low {{ color: var(--low); }}
        .val-reach {{ color: #f85149; }}
        .controls {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            align-items: center;
        }}
        .search-box {{
            flex: 1;
            min-width: 260px;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 10px 14px;
            color: var(--text);
            font-size: 14px;
            outline: none;
        }}
        .search-box:focus {{ border-color: var(--primary); }}
        .filter-btn {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 8px 14px;
            color: var(--text);
            cursor: pointer;
            font-size: 13px;
            transition: all 0.2s;
        }}
        .filter-btn.active, .filter-btn:hover {{
            background: #21262d;
            border-color: var(--primary);
            color: var(--primary);
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(255, 85, 85, 0.2); color: var(--crit); border: 1px solid var(--crit); }}
        .badge-high {{ background: rgba(255, 123, 114, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(210, 153, 34, 0.2); color: var(--med); border: 1px solid var(--med); }}
        .badge-low {{ background: rgba(88, 166, 255, 0.2); color: var(--low); border: 1px solid var(--low); }}
        .badge-reachable {{ background: rgba(248, 81, 73, 0.25); color: #f85149; border: 1px solid #f85149; }}
        .badge-unreachable {{ background: rgba(63, 185, 80, 0.15); color: var(--safe); border: 1px solid var(--safe); }}
        .badge-muted {{ background: var(--border); color: var(--text-muted); }}
        .cat-permissive {{ background: rgba(63, 185, 80, 0.2); color: var(--safe); }}
        .cat-weak {{ background: rgba(210, 153, 34, 0.2); color: var(--med); }}
        .cat-strong {{ background: rgba(255, 85, 85, 0.2); color: var(--crit); font-weight: 700; }}
        .cat-unknown {{ background: var(--border); color: var(--text-muted); }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            margin-bottom: 12px;
            overflow: hidden;
            transition: border-color 0.2s;
        }}
        .card-header {{
            padding: 14px 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
            background: rgba(255, 255, 255, 0.01);
        }}
        .card-header:hover {{ background: var(--surface-hover); }}
        .header-left {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
        .pkg-name {{ font-size: 15px; color: var(--heading); }}
        .vuln-id {{ color: var(--text-muted); font-size: 13px; font-family: var(--font-mono); }}
        .chevron {{ font-size: 12px; transition: transform 0.2s; color: var(--text-muted); }}
        .chevron.open {{ transform: rotate(180deg); }}
        .card-body {{ padding: 18px; border-top: 1px solid var(--border); display: none; }}
        .vuln-title {{ font-size: 16px; margin-bottom: 12px; color: var(--heading); }}
        .detail-row {{ margin-bottom: 10px; font-size: 14px; }}
        .path-code {{ background: rgba(255, 255, 255, 0.05); padding: 4px 8px; border-radius: 4px; font-family: var(--font-mono); font-size: 13px; }}
        .vuln-desc {{ margin-top: 4px; color: #adbac7; font-size: 13px; white-space: pre-line; }}
        .rem-box {{
            background: rgba(88, 166, 255, 0.1);
            border-left: 4px solid var(--primary);
            padding: 12px 14px;
            border-radius: 4px;
            margin: 14px 0;
            display: flex;
            gap: 10px;
            font-size: 14px;
        }}
        .rem-warn {{ background: rgba(210, 153, 34, 0.1); border-color: var(--med); }}
        .call-site {{
            background: #090d13;
            border: 1px solid #f8514944;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 14px;
        }}
        .site-loc {{ font-size: 13px; color: #ff7b72; margin-bottom: 6px; }}
        pre {{ overflow-x: auto; font-family: var(--font-mono); font-size: 12px; color: #f0f6fc; }}
        .ref-container {{ display: flex; flex-direction: column; gap: 4px; margin-top: 4px; }}
        .ref-link {{ color: var(--primary); text-decoration: none; font-size: 13px; word-break: break-all; }}
        .ref-link:hover {{ text-decoration: underline; }}
        .section {{ margin-top: 36px; }}
        .section h2 {{ font-size: 20px; color: var(--heading); margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
        .lic-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: hidden;
            font-size: 14px;
        }}
        .lic-table th, .lic-table td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }}
        .lic-table th {{ background: rgba(255, 255, 255, 0.03); color: var(--text-muted); font-size: 12px; text-transform: uppercase; }}
        .stats-row {{ display: flex; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; }}
        .stat-pill {{ background: var(--surface); border: 1px solid var(--border); padding: 6px 12px; border-radius: 16px; font-size: 13px; }}
        .stat-safe {{ color: var(--safe); }}
        .stat-warn {{ color: var(--med); }}
        .stat-danger {{ color: var(--crit); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ Vexa SCA Security Report</h1>
                <div style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">Project: <strong>{project_name}</strong> ({manifest_display})</div>
            </div>
            <div class="header-meta">
                <div>Engine: <strong>Vexa SCA Rust Core 1.0</strong></div>
                <div>Generated: {timestamp}</div>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-val">{scanned_total}</div>
                <div class="stat-label">Scanned Packages</div>
            </div>
            <div class="stat-card">
                <div class="stat-val val-crit">{critical_count}</div>
                <div class="stat-label">Critical Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-val val-high">{high_count}</div>
                <div class="stat-label">High Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-val val-med">{medium_count}</div>
                <div class="stat-label">Medium Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-val val-reach">{reachable_count}</div>
                <div class="stat-label">🚨 Reachable In Code</div>
            </div>
            <div class="stat-card">
                <div class="stat-val" style="color: var(--safe);">{unreachable_count}</div>
                <div class="stat-label">🛡️ Unreachable (Low Risk)</div>
            </div>
        </div>

        <div class="controls">
            <input type="text" id="searchBox" class="search-box" placeholder="Search by package, CVE, GHSA, or title..." oninput="applyFilters()">
            <button class="filter-btn active" onclick="setFilter('all', this)">All ({total_vulns})</button>
            <button class="filter-btn" onclick="setFilter('reachable', this)">🚨 Reachable ({reachable_count})</button>
            <button class="filter-btn" onclick="setFilter('critical', this)">Critical ({critical_count})</button>
            <button class="filter-btn" onclick="setFilter('high', this)">High ({high_count})</button>
            <button class="filter-btn" onclick="setFilter('medium', this)">Medium ({medium_count})</button>
            <button class="filter-btn" onclick="setFilter('low', this)">Low ({low_count})</button>
        </div>

        <div id="cardsContainer">
            {vuln_cards_html}
        </div>

        {licenses_section}

        {suppressed_section}
    </div>

    <script>
        let currentFilter = 'all';

        function toggleCard(idx) {{
            const body = document.getElementById('body-' + idx);
            const chevron = document.getElementById('chevron-' + idx);
            if (!body) return;
            const isOpen = body.style.display === 'block';
            body.style.display = isOpen ? 'none' : 'block';
            chevron.classList.toggle('open', !isOpen);
        }}

        function setFilter(filterType, btn) {{
            currentFilter = filterType;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            if (btn) btn.classList.add('active');
            applyFilters();
        }}

        function applyFilters() {{
            const query = (document.getElementById('searchBox').value || '').toLowerCase();
            const cards = document.querySelectorAll('.vuln-card');

            cards.forEach(card => {{
                const text = card.textContent.toLowerCase();
                const sev = card.getAttribute('data-sev');
                const reach = card.getAttribute('data-reach');

                const matchesQuery = query === '' || text.includes(query);
                let matchesFilter = true;

                if (currentFilter === 'reachable') {{
                    matchesFilter = reach === 'reachable';
                }} else if (currentFilter === 'critical') {{
                    matchesFilter = sev === 'critical';
                }} else if (currentFilter === 'high') {{
                    matchesFilter = sev === 'high';
                }} else if (currentFilter === 'medium') {{
                    matchesFilter = sev === 'medium';
                }} else if (currentFilter === 'low') {{
                    matchesFilter = sev === 'low';
                }}

                card.style.display = (matchesQuery && matchesFilter) ? 'block' : 'none';
            }});
        }}
    </script>
</body>
</html>"#,
        project_name = html_escape(project_name),
        manifest_display = html_escape(&manifest_display),
        timestamp = timestamp,
        scanned_total = scan_result.scanned_packages_count,
        critical_count = critical_count,
        high_count = high_count,
        medium_count = medium_count,
        low_count = low_count,
        reachable_count = reachable_count,
        unreachable_count = unreachable_count,
        total_vulns = scan_result.vulnerabilities.len(),
        vuln_cards_html = vuln_cards_html,
        licenses_section = licenses_section,
        suppressed_section = suppressed_section
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SeverityInfo, SeverityLevel, VulnerabilityFinding};

    #[test]
    fn test_format_html_report_rendering() {
        let mut scan_result = ScanResult {
            scanned_packages_count: 10,
            ..Default::default()
        };
        scan_result.vulnerabilities.push(VulnerabilityFinding {
            id: "GHSA-35jh-r3h4-6jhm".to_string(),
            title: "Command Injection in lodash".to_string(),
            package: "lodash".to_string(),
            version: "4.17.15".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "lodash@4.17.15".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::Critical,
                score: 9.8,
                vector: None,
            },
            cve: Some("CVE-2021-23337".to_string()),
            cwes: vec!["CWE-78".to_string()],
            fixed_in: vec!["4.17.21".to_string()],
            is_transitive: false,
            paths: vec![vec![
                "my-app@1.0.0".to_string(),
                "lodash@4.17.15".to_string(),
            ]],
            details: Some("Command injection in template function".to_string()),
            references: vec!["https://nvd.nist.gov".to_string()],
            reachability: None,
            ..Default::default()
        });

        let html = format_html_report(
            &scan_result,
            &[],
            &[],
            None,
            "test-app",
            Some(Path::new("package-lock.json")),
        );

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Vexa SCA Security Report"));
        assert!(html.contains("test-app"));
        assert!(html.contains("Command Injection in lodash"));
        assert!(html.contains("CVE-2021-23337"));
        assert!(html.contains("badge-critical"));
    }

    #[test]
    fn test_html_multi_version_and_license_badges() {
        use crate::licenses::license_scanner::{
            LicenseAudit, LicenseRisk, LicenseSummary, PackageLicenseResult,
        };

        let mut scan_result = ScanResult::default();
        scan_result.vulnerabilities.push(VulnerabilityFinding {
            id: "VULN-1".to_string(),
            title: "H2 vuln 1".to_string(),
            package: "h2".to_string(),
            version: "0.4.13".to_string(),
            pkg_id: "h2@0.4.13".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::Medium,
                score: 5.5,
                vector: None,
            },
            ..Default::default()
        });
        scan_result.vulnerabilities.push(VulnerabilityFinding {
            id: "VULN-2".to_string(),
            title: "H2 vuln 2".to_string(),
            package: "h2".to_string(),
            version: "0.3.27".to_string(),
            pkg_id: "h2@0.3.27".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::Medium,
                score: 5.5,
                vector: None,
            },
            ..Default::default()
        });

        let rems = vec![
            RemediationAction {
                package: "h2".to_string(),
                current_version: "0.4.13".to_string(),
                is_transitive: true,
                target_version: Some("0.4.16".to_string()),
                action_type: "UPGRADE_TRANSITIVE".to_string(),
                advice: "Introduced by hyper-rustls".to_string(),
                resolved_vulnerability_count: 1,
                vulnerability_ids: vec!["VULN-1".to_string()],
                highest_severity: None,
            },
            RemediationAction {
                package: "h2".to_string(),
                current_version: "0.3.27".to_string(),
                is_transitive: true,
                target_version: Some("0.4.16".to_string()),
                action_type: "UPGRADE_TRANSITIVE".to_string(),
                advice: "Introduced by jsonschema".to_string(),
                resolved_vulnerability_count: 1,
                vulnerability_ids: vec!["VULN-2".to_string()],
                highest_severity: None,
            },
        ];

        let audit = LicenseAudit {
            summary: LicenseSummary::default(),
            results: vec![
                PackageLicenseResult {
                    package: "colored".to_string(),
                    version: "2.2.0".to_string(),
                    ecosystem: "crates.io".to_string(),
                    license: "MPL-2.0".to_string(),
                    category: LicenseCategory::WeakCopyleft,
                    risk: LicenseRisk {
                        level: "MEDIUM".to_string(),
                        score: 2,
                    },
                    ..Default::default()
                },
                PackageLicenseResult {
                    package: "tokio".to_string(),
                    version: "1.0.0".to_string(),
                    ecosystem: "crates.io".to_string(),
                    license: "MIT".to_string(),
                    category: LicenseCategory::Permissive,
                    risk: LicenseRisk {
                        level: "LOW".to_string(),
                        score: 0,
                    },
                    ..Default::default()
                },
            ],
        };

        let html = format_html_report(&scan_result, &[], &rems, Some(&audit), "app", None);
        assert!(html.contains("Introduced by hyper-rustls"));
        assert!(html.contains("Introduced by jsonschema"));
        assert!(html.contains("cat-weak"));
        assert!(html.contains("cat-permissive"));
    }
}
