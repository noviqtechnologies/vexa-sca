use crate::core::dep_graph::DepGraph;
use crate::licenses::license_scanner::LicenseAudit;
use crate::scanner::vuln_scanner::ScanResult;
use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[value(rename_all = "lower")]
pub enum SbomFormat {
    #[value(name = "cyclonedx", alias = "cdx")]
    CycloneDx,
    #[value(name = "spdx")]
    Spdx,
}

impl SbomFormat {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        let up = s.trim().to_uppercase();
        if up.contains("CYCLONE") || up.contains("CDX") {
            Some(SbomFormat::CycloneDx)
        } else if up.contains("SPDX") {
            Some(SbomFormat::Spdx)
        } else {
            None
        }
    }
}

/// Generates a standard CycloneDX v1.5 JSON Software Bill of Materials (SBOM)
pub fn format_cyclonedx_sbom(
    dep_graph: &DepGraph,
    scan_result: Option<&ScanResult>,
    license_audit: Option<&LicenseAudit>,
) -> String {
    let timestamp = Utc::now().to_rfc3339();

    // Map licenses by package id (name@version)
    let license_map: HashMap<String, String> = if let Some(audit) = license_audit {
        audit
            .results
            .iter()
            .map(|r| (format!("{}@{}", r.package, r.version), r.license.clone()))
            .collect()
    } else {
        HashMap::new()
    };

    // Deterministic serial number from root_node_id and timestamp
    let mut hasher = Sha256::new();
    hasher.update(dep_graph.root_node_id.as_bytes());
    hasher.update(timestamp.as_bytes());
    let hash_hex = hex::encode(hasher.finalize());
    let serial_number = format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hash_hex[0..8],
        &hash_hex[8..12],
        &hash_hex[12..16],
        &hash_hex[16..20],
        &hash_hex[20..32]
    );

    let root_pkg = &dep_graph.root_pkg;

    let metadata_component = json!({
        "type": "application",
        "name": root_pkg.name,
        "version": root_pkg.version,
        "purl": root_pkg.purl,
        "bom-ref": dep_graph.root_node_id.clone()
    });

    let mut components = Vec::new();
    let all_nodes = dep_graph.get_all_nodes();

    for node in &all_nodes {
        if node.node_id == dep_graph.root_node_id {
            continue;
        }

        if let Some(pkg) = dep_graph.get_pkg(&node.pkg_id) {
            let pkg_key = format!("{}@{}", pkg.name, pkg.version);
            let lic = license_map.get(&pkg_key);

            let mut comp_obj = json!({
                "type": "library",
                "name": pkg.name,
                "version": pkg.version,
                "purl": pkg.purl,
                "bom-ref": node.node_id.clone(),
                "scope": if node.info.scope == "dev" { "optional" } else { "required" }
            });

            if let Some(l) = lic {
                if l.contains(" OR ") || l.contains(" AND ") || l.contains('/') {
                    let sanitized = l.replace('/', " OR ");
                    comp_obj["licenses"] = json!([
                        {
                            "expression": sanitized
                        }
                    ]);
                } else if l.to_uppercase() == "UNKNOWN" {
                    comp_obj["licenses"] = json!([
                        {
                            "license": {
                                "name": "UNKNOWN"
                            }
                        }
                    ]);
                } else {
                    comp_obj["licenses"] = json!([
                        {
                            "license": {
                                "id": l
                            }
                        }
                    ]);
                }
            }

            if let Some(integrity) = &node.info.integrity {
                let alg = if integrity.starts_with("sha512-") || integrity.len() == 128 {
                    "SHA-512"
                } else if integrity.starts_with("sha256-") || integrity.len() == 64 {
                    "SHA-256"
                } else if integrity.starts_with("sha1-") || integrity.len() == 40 {
                    "SHA-1"
                } else {
                    "SHA-256"
                };
                let clean_hash = integrity
                    .trim_start_matches("sha512-")
                    .trim_start_matches("sha256-")
                    .trim_start_matches("sha1-");

                comp_obj["hashes"] = json!([
                    {
                        "alg": alg,
                        "content": clean_hash
                    }
                ]);
            }

            components.push(comp_obj);
        }
    }

    // Build dependency relationships
    let mut dependencies = Vec::new();
    for node in &all_nodes {
        dependencies.push(json!({
            "ref": node.node_id,
            "dependsOn": node.deps
        }));
    }

    // Optional vulnerabilities block
    let mut vulnerabilities = Vec::new();
    if let Some(sr) = scan_result {
        for v in &sr.vulnerabilities {
            let mut rating = json!({
                "source": { "name": "NVD" },
                "score": v.severity.score,
                "severity": v.severity.level.as_str().to_lowercase(),
                "method": "CVSSv3"
            });
            if let Some(vec) = &v.severity.vector {
                rating["vector"] = json!(vec);
            }
            let ratings = vec![rating];

            let target_ref = all_nodes
                .iter()
                .find(|n| {
                    if let Some(pkg) = dep_graph.get_pkg(&n.pkg_id) {
                        pkg.name == v.package && pkg.version == v.version
                    } else {
                        false
                    }
                })
                .map(|n| n.node_id.clone())
                .unwrap_or_else(|| {
                    let prefix = if !dep_graph.pkg_manager.name.is_empty() {
                        dep_graph.pkg_manager.name.as_str()
                    } else {
                        "cargo"
                    };
                    format!("{}:{}@{}", prefix, v.package, v.version)
                });

            let mut vuln_obj = json!({
                "id": v.cve.as_deref().unwrap_or(&v.id),
                "source": {
                    "name": if v.id.starts_with("GHSA") { "GitHub Advisory Database" } else { "OSV" },
                    "url": v.references.first().cloned().unwrap_or_else(|| "https://osv.dev".to_string())
                },
                "ratings": ratings,
                "description": v.details.as_deref().unwrap_or(&v.title),
                "affects": [
                    {
                        "ref": target_ref
                    }
                ]
            });

            // Add CWEs if available
            let cwe_ids: Vec<u32> = v
                .cwes
                .iter()
                .filter_map(|c| {
                    c.trim_start_matches("CWE-")
                        .trim_start_matches("cwe-")
                        .parse::<u32>()
                        .ok()
                })
                .collect();
            if !cwe_ids.is_empty() {
                vuln_obj["cwes"] = json!(cwe_ids);
            }

            // VEX / Reachability analysis state (FR-009: do not emit not_affected without positive proof)
            if let Some(reach) = &v.reachability {
                use crate::types::ReachabilityStatus;
                let state = match reach.status {
                    ReachabilityStatus::Reachable => "exploitable",
                    ReachabilityStatus::Unreachable => "in_triage",
                    ReachabilityStatus::Unknown => "in_triage",
                };
                let mut analysis = json!({
                    "state": state
                });
                if reach.status == ReachabilityStatus::Reachable {
                    analysis["detail"] =
                        json!("Direct call site detected to vulnerable symbol in analyzed source.");
                } else {
                    analysis["detail"] =
                        json!("Under triage; inconclusive evidence in current analysis scope.");
                }
                vuln_obj["analysis"] = analysis;
            }

            vulnerabilities.push(vuln_obj);
        }
    }

    let mut cyclonedx = json!({
        "$schema": "http://cyclonedx.org/schema/bom-1.5.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Vexa",
                    "name": "vexa-sca",
                    "version": "1.0.0"
                }
            ],
            "component": metadata_component
        },
        "components": components,
        "dependencies": dependencies
    });

    if !vulnerabilities.is_empty() {
        cyclonedx["vulnerabilities"] = json!(vulnerabilities);
    }

    serde_json::to_string_pretty(&cyclonedx).unwrap_or_else(|_| "{}".to_string())
}

/// Sanitizes license string for SPDX 2.3 expression compliance
fn sanitize_spdx_license(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("UNKNOWN") {
        "NOASSERTION".to_string()
    } else if trimmed.contains('/') {
        trimmed.replace(" / ", " OR ").replace('/', " OR ")
    } else {
        trimmed.to_string()
    }
}

/// Generates a standard SPDX v2.3 JSON Software Bill of Materials (SBOM)
pub fn format_spdx_sbom(
    dep_graph: &DepGraph,
    scan_result: Option<&ScanResult>,
    license_audit: Option<&LicenseAudit>,
) -> String {
    let timestamp = Utc::now().to_rfc3339();

    let root_pkg = &dep_graph.root_pkg;

    let doc_namespace = format!(
        "https://spdx.org/spdxdocs/{}-{}-{}",
        root_pkg.name.replace(['/', '\\'], "-"),
        root_pkg.version,
        Utc::now().format("%Y%m%d%H%M%S")
    );

    let license_map: HashMap<String, String> = if let Some(audit) = license_audit {
        audit
            .results
            .iter()
            .map(|r| (format!("{}@{}", r.package, r.version), r.license.clone()))
            .collect()
    } else {
        HashMap::new()
    };

    let mut packages = Vec::new();
    let mut relationships = Vec::new();

    let root_spdx_id = "SPDXRef-RootPackage".to_string();

    // Document describes root
    relationships.push(json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_spdx_id.clone()
    }));

    // Add root package (with NTIA and SPDX mandatory fields)
    packages.push(json!({
        "SPDXID": root_spdx_id.clone(),
        "name": root_pkg.name,
        "versionInfo": root_pkg.version,
        "supplier": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "copyrightText": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": root_pkg.purl
            }
        ]
    }));

    let all_nodes = dep_graph.get_all_nodes();
    let mut node_to_spdx: HashMap<String, String> = HashMap::new();
    node_to_spdx.insert(dep_graph.root_node_id.clone(), root_spdx_id);

    let mut counter = 1;
    for node in &all_nodes {
        if node.node_id == dep_graph.root_node_id {
            continue;
        }

        if let Some(pkg) = dep_graph.get_pkg(&node.pkg_id) {
            let spdx_id = format!("SPDXRef-Package-{}", counter);
            counter += 1;
            node_to_spdx.insert(node.node_id.clone(), spdx_id.clone());

            let pkg_key = format!("{}@{}", pkg.name, pkg.version);
            let raw_lic = license_map
                .get(&pkg_key)
                .map(|s| s.as_str())
                .unwrap_or("NOASSERTION");
            let lic = sanitize_spdx_license(raw_lic);

            let mut external_refs = vec![json!({
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": pkg.purl
            })];

            // If scan_result is available, link security advisories affecting this component
            if let Some(sr) = scan_result {
                for v in &sr.vulnerabilities {
                    if v.package == pkg.name && v.version == pkg.version {
                        let ref_loc = v.references.first().cloned().unwrap_or_else(|| {
                            if v.id.starts_with("GHSA") {
                                format!("https://github.com/advisories/{}", v.id)
                            } else {
                                format!("https://osv.dev/vulnerability/{}", v.id)
                            }
                        });
                        external_refs.push(json!({
                            "referenceCategory": "SECURITY",
                            "referenceType": "advisory",
                            "referenceLocator": ref_loc,
                            "comment": format!("{}: {}", v.id, v.title)
                        }));
                    }
                }
            }

            let mut pkg_obj = json!({
                "SPDXID": spdx_id,
                "name": pkg.name,
                "versionInfo": pkg.version,
                "supplier": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "copyrightText": "NOASSERTION",
                "licenseConcluded": lic,
                "licenseDeclared": lic,
                "externalRefs": external_refs
            });

            // Add artifact verification checksum if available
            if let Some(integrity) = &node.info.integrity {
                let (alg, val) = if let Some(stripped) = integrity.strip_prefix("sha512-") {
                    ("SHA512", stripped)
                } else if let Some(stripped) = integrity.strip_prefix("sha256-") {
                    ("SHA256", stripped)
                } else if integrity.len() == 64 {
                    ("SHA256", integrity.as_str())
                } else if integrity.len() == 128 {
                    ("SHA512", integrity.as_str())
                } else {
                    ("SHA256", integrity.as_str())
                };

                pkg_obj["checksums"] = json!([
                    {
                        "algorithm": alg,
                        "checksumValue": val
                    }
                ]);
            }

            packages.push(pkg_obj);
        }
    }

    // Map dependencies to SPDX relationships
    for node in &all_nodes {
        if let Some(from_id) = node_to_spdx.get(&node.node_id) {
            for child_id in &node.deps {
                if let Some(to_id) = node_to_spdx.get(child_id) {
                    relationships.push(json!({
                        "spdxElementId": from_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": to_id
                    }));
                }
            }
        }
    }

    let spdx_doc = json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root_pkg.name,
        "documentNamespace": doc_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": [
                "Tool: vexa-sca-1.0.0",
                "Organization: Vexa"
            ]
        },
        "packages": packages,
        "relationships": relationships
    });

    serde_json::to_string_pretty(&spdx_doc).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dep_graph::{NodeInfo, PkgManagerInfo};
    use crate::types::PkgInfo;
    use serde_json::Value;

    fn build_test_graph() -> DepGraph {
        let root = PkgInfo::new("test-app", "1.0.0", "npm");
        let mut graph = DepGraph::new(
            root,
            PkgManagerInfo {
                name: "npm".to_string(),
                version: "8.0.0".to_string(),
            },
        );

        let lodash = PkgInfo::new("lodash", "4.17.15", "npm");
        graph.add_pkg(lodash.clone());
        let node_id = "npm:lodash@4.17.15".to_string();
        graph.add_node(
            node_id.clone(),
            lodash.id.clone(),
            NodeInfo {
                scope: "prod".to_string(),
                path: None,
                integrity: None,
            },
        );
        let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);

        graph
    }

    #[test]
    fn test_cyclonedx_sbom_generation() {
        let graph = build_test_graph();
        let cdx_json = format_cyclonedx_sbom(&graph, None, None);
        let parsed: Value = serde_json::from_str(&cdx_json).expect("valid CycloneDX JSON");

        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");
        assert_eq!(parsed["components"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["components"][0]["name"], "lodash");
        assert_eq!(parsed["components"][0]["version"], "4.17.15");
        assert_eq!(parsed["components"][0]["purl"], "pkg:npm/lodash@4.17.15");
    }

    #[test]
    fn test_spdx_sbom_generation() {
        let graph = build_test_graph();
        let spdx_json = format_spdx_sbom(&graph, None, None);
        let parsed: Value = serde_json::from_str(&spdx_json).expect("valid SPDX JSON");

        assert_eq!(parsed["spdxVersion"], "SPDX-2.3");
        assert_eq!(parsed["dataLicense"], "CC0-1.0");
        let pkgs = parsed["packages"].as_array().unwrap();
        assert!(pkgs.len() >= 2);
        // Verify NTIA Minimum Elements and SPDX 2.3 mandatory fields
        assert_eq!(pkgs[0]["supplier"], "NOASSERTION");
        assert_eq!(pkgs[0]["copyrightText"], "NOASSERTION");
        assert_eq!(pkgs[1]["supplier"], "NOASSERTION");
        assert_eq!(pkgs[1]["copyrightText"], "NOASSERTION");
    }

    #[test]
    fn test_spdx_sbom_compliance_and_security_advisories() {
        use crate::licenses::license_scanner::{
            LicenseAudit, LicenseCategory, LicenseRisk, PackageLicenseResult,
        };
        use crate::types::{SeverityInfo, SeverityLevel, VulnerabilityFinding};

        let root = PkgInfo::new("agentcontrol", "1.0.95", "cargo");
        let mut graph = DepGraph::new(
            root,
            PkgManagerInfo {
                name: "cargo".to_string(),
                version: "1.90.0".to_string(),
            },
        );

        let pkg = PkgInfo::new("jsonwebtoken", "9.3.1", "cargo");
        graph.add_pkg(pkg.clone());
        let node_id = "cargo:jsonwebtoken@9.3.1".to_string();
        graph.add_node(
            node_id.clone(),
            pkg.id.clone(),
            NodeInfo {
                scope: "prod".to_string(),
                path: None,
                integrity: Some(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                ),
            },
        );
        let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);

        let scan_result = ScanResult {
            vulnerabilities: vec![VulnerabilityFinding {
                id: "CVE-2026-25537".to_string(),
                title: "Type confusion in jsonwebtoken".to_string(),
                package: "jsonwebtoken".to_string(),
                version: "9.3.1".to_string(),
                ecosystem: "cargo".to_string(),
                pkg_id: "crates.io/jsonwebtoken@9.3.1".to_string(),
                severity: SeverityInfo {
                    level: SeverityLevel::High,
                    score: 7.5,
                    vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".to_string()),
                },
                cve: Some("CVE-2026-25537".to_string()),
                cwes: vec!["CWE-843".to_string()],
                fixed_in: vec![],
                is_transitive: false,
                paths: vec![],
                details: Some("Validation logic bypass".to_string()),
                references: vec!["https://github.com/Keats/jsonwebtoken".to_string()],
                reachability: None,
                aliases: vec![],
                advisory_category: Default::default(),
                epss: None,
                fingerprint: "test-fp-1".to_string(),
                usage_signal: crate::types::UsageSignal::Unknown,
                reason_code: None,
                priority_score: 5.0,
                is_new: true,
            }],
            ..Default::default()
        };

        let license_audit = LicenseAudit {
            summary: Default::default(),
            results: vec![PackageLicenseResult {
                package: "jsonwebtoken".to_string(),
                version: "9.3.1".to_string(),
                ecosystem: "cargo".to_string(),
                license: "MIT/Apache-2.0".to_string(), // Slashes should be sanitized to "MIT OR Apache-2.0"
                category: LicenseCategory::Permissive,
                risk: LicenseRisk {
                    level: "LOW".to_string(),
                    score: 0,
                },
                ..Default::default()
            }],
        };

        let spdx_json = format_spdx_sbom(&graph, Some(&scan_result), Some(&license_audit));
        let parsed: Value = serde_json::from_str(&spdx_json).expect("valid SPDX JSON");

        let pkgs = parsed["packages"].as_array().unwrap();
        let target_pkg = pkgs
            .iter()
            .find(|p| p["name"] == "jsonwebtoken")
            .expect("jsonwebtoken package");

        // Verify license was sanitized from "MIT/Apache-2.0" to "MIT OR Apache-2.0"
        assert_eq!(target_pkg["licenseConcluded"], "MIT OR Apache-2.0");
        assert_eq!(target_pkg["licenseDeclared"], "MIT OR Apache-2.0");

        // Verify checksums
        assert_eq!(target_pkg["checksums"][0]["algorithm"], "SHA256");
        assert_eq!(
            target_pkg["checksums"][0]["checksumValue"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Verify security advisory externalRefs
        let refs = target_pkg["externalRefs"].as_array().unwrap();
        let sec_ref = refs
            .iter()
            .find(|r| r["referenceCategory"] == "SECURITY")
            .expect("security externalRef");
        assert_eq!(sec_ref["referenceType"], "advisory");
        assert_eq!(
            sec_ref["referenceLocator"],
            "https://github.com/Keats/jsonwebtoken"
        );
    }

    #[test]
    fn test_cyclonedx_sbom_affects_ref_and_spdx_expression() {
        use crate::licenses::license_scanner::{
            LicenseAudit, LicenseCategory, LicenseRisk, PackageLicenseResult,
        };
        use crate::types::{SeverityInfo, SeverityLevel, VulnerabilityFinding};

        let root = PkgInfo::new("agentcontrol", "1.0.95", "cargo");
        let mut graph = DepGraph::new(
            root,
            PkgManagerInfo {
                name: "cargo".to_string(),
                version: "1.90.0".to_string(),
            },
        );

        let pkg = PkgInfo::new("jsonwebtoken", "9.3.1", "cargo");
        graph.add_pkg(pkg.clone());
        let node_id = "cargo:jsonwebtoken@9.3.1".to_string();
        graph.add_node(
            node_id.clone(),
            pkg.id.clone(),
            NodeInfo {
                scope: "prod".to_string(),
                path: None,
                integrity: Some(
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                ),
            },
        );
        let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);

        let scan_result = ScanResult {
            vulnerabilities: vec![VulnerabilityFinding {
                id: "CVE-2026-25537".to_string(),
                title: "Type confusion in jsonwebtoken".to_string(),
                package: "jsonwebtoken".to_string(),
                version: "9.3.1".to_string(),
                ecosystem: "cargo".to_string(),
                pkg_id: "crates.io/jsonwebtoken@9.3.1".to_string(),
                severity: SeverityInfo {
                    level: SeverityLevel::High,
                    score: 7.5,
                    vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".to_string()),
                },
                cve: Some("CVE-2026-25537".to_string()),
                cwes: vec!["CWE-843".to_string()],
                fixed_in: vec![],
                is_transitive: false,
                paths: vec![],
                details: Some("Validation logic bypass".to_string()),
                references: vec!["https://github.com/Keats/jsonwebtoken".to_string()],
                reachability: None,
                aliases: vec![],
                advisory_category: Default::default(),
                epss: None,
                fingerprint: "test-fp-2".to_string(),
                usage_signal: crate::types::UsageSignal::Unknown,
                reason_code: None,
                priority_score: 5.0,
                is_new: true,
            }],
            ..Default::default()
        };

        let license_audit = LicenseAudit {
            summary: Default::default(),
            results: vec![PackageLicenseResult {
                package: "jsonwebtoken".to_string(),
                version: "9.3.1".to_string(),
                ecosystem: "cargo".to_string(),
                license: "(MIT OR Apache-2.0) AND Unicode-3.0".to_string(),
                category: LicenseCategory::Permissive,
                risk: LicenseRisk {
                    level: "LOW".to_string(),
                    score: 0,
                },
                ..Default::default()
            }],
        };

        let cdx_json = format_cyclonedx_sbom(&graph, Some(&scan_result), Some(&license_audit));
        let parsed: Value = serde_json::from_str(&cdx_json).expect("valid CycloneDX JSON");

        // Verify component bom-ref and hash
        let comp = &parsed["components"][0];
        assert_eq!(comp["bom-ref"], "cargo:jsonwebtoken@9.3.1");
        assert_eq!(
            comp["licenses"][0]["expression"],
            "(MIT OR Apache-2.0) AND Unicode-3.0"
        );
        assert_eq!(comp["hashes"][0]["alg"], "SHA-256");

        // Verify vulnerability affects matches bom-ref exactly!
        let vuln = &parsed["vulnerabilities"][0];
        assert_eq!(vuln["id"], "CVE-2026-25537");
        assert_eq!(vuln["affects"][0]["ref"], "cargo:jsonwebtoken@9.3.1");
        assert_eq!(
            vuln["ratings"][0]["vector"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        );
        assert_eq!(vuln["cwes"][0], 843);
    }
}
