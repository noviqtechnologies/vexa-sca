use crate::core::dep_graph::DepGraph;
use crate::licenses::license_scanner::LicenseAudit;
use crate::scanner::vuln_scanner::ScanResult;
use chrono::Utc;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    CycloneDx,
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
                comp_obj["licenses"] = json!([
                    {
                        "license": {
                            "id": l
                        }
                    }
                ]);
            }

            if let Some(integrity) = &node.info.integrity {
                comp_obj["hashes"] = json!([
                    {
                        "alg": "SHA-512",
                        "content": integrity
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
            let mut ratings = Vec::new();
            ratings.push(json!({
                "source": { "name": "NVD" },
                "score": v.severity.score,
                "severity": v.severity.level.as_str().to_lowercase(),
                "method": "CVSSv3"
            }));

            vulnerabilities.push(json!({
                "id": v.cve.as_deref().unwrap_or(&v.id),
                "source": {
                    "name": if v.id.starts_with("GHSA") { "GitHub Advisory Database" } else { "OSV" },
                    "url": v.references.first().cloned().unwrap_or_else(|| "https://osv.dev".to_string())
                },
                "ratings": ratings,
                "description": v.details.as_deref().unwrap_or(&v.title),
                "affects": [
                    {
                        "ref": format!("{}@{}", v.package, v.version)
                    }
                ]
            }));
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

/// Generates a standard SPDX v2.3 JSON Software Bill of Materials (SBOM)
pub fn format_spdx_sbom(
    dep_graph: &DepGraph,
    license_audit: Option<&LicenseAudit>,
) -> String {
    let timestamp = Utc::now().to_rfc3339();

    let root_pkg = &dep_graph.root_pkg;

    let doc_namespace = format!(
        "https://spdx.org/spdxdocs/{}-{}-{}",
        root_pkg.name.replace('/', "-"),
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

    // Add root package
    packages.push(json!({
        "SPDXID": root_spdx_id.clone(),
        "name": root_pkg.name,
        "versionInfo": root_pkg.version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
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
            let lic = license_map
                .get(&pkg_key)
                .cloned()
                .unwrap_or_else(|| "NOASSERTION".to_string());

            packages.push(json!({
                "SPDXID": spdx_id,
                "name": pkg.name,
                "versionInfo": pkg.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "licenseConcluded": lic,
                "licenseDeclared": lic,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": pkg.purl
                    }
                ]
            }));
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
                "Tool: vexa-sca-1.0.0"
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
        let spdx_json = format_spdx_sbom(&graph, None);
        let parsed: Value = serde_json::from_str(&spdx_json).expect("valid SPDX JSON");

        assert_eq!(parsed["spdxVersion"], "SPDX-2.3");
        assert_eq!(parsed["dataLicense"], "CC0-1.0");
        assert!(parsed["packages"].as_array().unwrap().len() >= 2);
    }
}
