#![forbid(unsafe_code)]

use crate::patcher::lockfile_patcher::LockfilePatcher;
use crate::scanner::kev::CisaKevCatalog;
use crate::scanner::vuln_scanner::VulnScanner;
use crate::supply_chain::local_analyzer::LocalSupplyChainAnalyzer;
use crate::types::RemediationAction;
use crate::{scan_project, ScanOptions};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

pub struct McpServer;

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl McpServer {
    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();

        for line_res in stdin.lock().lines() {
            let line = line_res?;
            let line_trimmed = line.trim();
            if line_trimmed.is_empty() {
                continue;
            }

            let req: JsonRpcRequest = match serde_json::from_str(line_trimmed) {
                Ok(r) => r,
                Err(e) => {
                    let err_resp = json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": { "code": -32700, "message": format!("Parse error: {}", e) }
                    });
                    stdout.write_all(serde_json::to_string(&err_resp)?.as_bytes())?;
                    stdout.write_all(b"\n")?;
                    stdout.flush()?;
                    continue;
                }
            };

            let maybe_resp = Self::handle_request(req).await;
            if let Some(resp) = maybe_resp {
                let serialized = serde_json::to_string(&resp)?;
                stdout.write_all(serialized.as_bytes())?;
                stdout.write_all(b"\n")?;
                stdout.flush()?;
            }
        }

        Ok(())
    }

    async fn handle_request(req: JsonRpcRequest) -> Option<JsonRpcResponse> {
        let method = req.method.as_str();

        match method {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "vexa-sca",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                });
                Some(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(result),
                    error: None,
                })
            }
            "notifications/initialized" => {
                // MCP client notification, no response required
                None
            }
            "ping" => Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id: req.id,
                result: Some(json!({})),
                error: None,
            }),
            "tools/list" => {
                let tools = json!({
                    "tools": [
                        {
                            "name": "vexa_check_package",
                            "description": "Check a package coordinate for known vulnerabilities, CISA KEV status, and supply chain threats.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "package": { "type": "string", "description": "Package name (e.g. lodash, axios, flask, tokio)" },
                                    "version": { "type": "string", "description": "Package version (e.g. 4.17.20)" },
                                    "ecosystem": { "type": "string", "description": "Ecosystem: npm, PyPI, Go, crates.io, Maven" }
                                },
                                "required": ["package", "version", "ecosystem"]
                            }
                        },
                        {
                            "name": "vexa_scan_workspace",
                            "description": "Perform comprehensive SCA and AST reachability analysis on a project workspace directory.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "path": { "type": "string", "description": "Directory path to scan (defaults to current directory '.')" },
                                    "reachable_only": { "type": "boolean", "description": "Only return vulnerabilities with verified execution call paths" }
                                }
                            }
                        },
                        {
                            "name": "vexa_explain_finding",
                            "description": "Get deep explanation, CVSS/EPSS scores, reachability evidence, and remediation advice for a vulnerability ID.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "finding_id": { "type": "string", "description": "Advisory ID or CVE (e.g. CVE-2021-44228, GHSA-35jh-r3h4-6jhm, SC-001)" }
                                },
                                "required": ["finding_id"]
                            }
                        },
                        {
                            "name": "vexa_remediate_manifest",
                            "description": "Apply automated security patch / version upgrade to lockfile or manifest.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "manifest_path": { "type": "string", "description": "Path to project manifest or lockfile" },
                                    "package": { "type": "string", "description": "Package name to upgrade" },
                                    "target_version": { "type": "string", "description": "Safe target version to bump to" }
                                },
                                "required": ["manifest_path", "package", "target_version"]
                            }
                        }
                    ]
                });
                Some(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(tools),
                    error: None,
                })
            }
            "tools/call" => {
                let name = req
                    .params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let args = req.params.get("arguments").cloned().unwrap_or(json!({}));

                let tool_output = Self::execute_tool(name, args).await;

                Some(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: req.id,
                    result: Some(json!({
                        "content": [
                            {
                                "type": "text",
                                "text": tool_output
                            }
                        ]
                    })),
                    error: None,
                })
            }
            _ => Some(JsonRpcResponse {
                jsonrpc: "2.0",
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {}", method),
                }),
            }),
        }
    }

    async fn execute_tool(name: &str, args: serde_json::Value) -> String {
        match name {
            "vexa_check_package" => {
                let pkg = args.get("package").and_then(|p| p.as_str()).unwrap_or("");
                let ver = args.get("version").and_then(|v| v.as_str()).unwrap_or("");
                let eco = args
                    .get("ecosystem")
                    .and_then(|e| e.as_str())
                    .unwrap_or("npm");

                if pkg.is_empty() || ver.is_empty() {
                    return "Error: package and version arguments are required".to_string();
                }

                let mut out = format!("### Security Assessment for {}@{} ({})\n\n", pkg, ver, eco);

                // Check supply chain typosquatting
                let sc = LocalSupplyChainAnalyzer::check_package(pkg, ver, eco);
                if !sc.is_empty() {
                    out.push_str("⚠️ **Supply Chain Findings:**\n");
                    for f in sc {
                        out.push_str(&format!(
                            "- [{}] {}: {}\n",
                            f.rule_id, f.signal_name, f.message
                        ));
                    }
                    out.push('\n');
                }

                // Check CISA KEV and OSV
                let kev_catalog =
                    CisaKevCatalog::load_or_fetch(Path::new(".sca-cache"), None).await;
                let scanner = VulnScanner::new(None);
                let root_pkg = crate::types::PkgInfo::new("check-target", "1.0.0", eco);
                let mut graph = crate::core::dep_graph::DepGraph::new(
                    root_pkg,
                    crate::core::dep_graph::PkgManagerInfo {
                        name: eco.to_string(),
                        version: "1.0".to_string(),
                    },
                );
                let target_pkg = crate::types::PkgInfo::new(pkg, ver, eco);
                graph.add_pkg(target_pkg.clone());
                let node_id = format!("{}:{}@{}", eco, pkg, ver);
                graph.add_node(
                    node_id.clone(),
                    target_pkg.id,
                    crate::core::dep_graph::NodeInfo {
                        scope: "prod".to_string(),
                        path: None,
                        integrity: None,
                    },
                );
                let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);

                match scanner.scan_graph(&graph).await {
                    Ok(scan_res) => {
                        let vulns = scan_res.vulnerabilities;
                        if vulns.is_empty() {
                            out.push_str(
                                "✅ No known vulnerabilities found in public advisory databases.\n",
                            );
                        } else {
                            out.push_str(&format!(
                                "Found **{}** vulnerabilities:\n\n",
                                vulns.len()
                            ));
                            for v in &vulns {
                                let kev_flag = if let Some(cve) = &v.cve {
                                    if kev_catalog.is_kev(cve) {
                                        " 🔥 **[CISA KEV EXPLOITED]**"
                                    } else {
                                        ""
                                    }
                                } else {
                                    ""
                                };

                                out.push_str(&format!(
                                    "- **{}** (Severity: {:?}, Score: {:.1}){}{}\n  Fix available: {}\n  Details: {}\n\n",
                                    v.id,
                                    v.severity.level,
                                    v.priority_score,
                                    kev_flag,
                                    v.cve.as_ref().map(|c| format!(" [{}]", c)).unwrap_or_default(),
                                    if v.fixed_in.is_empty() { "None".to_string() } else { v.fixed_in.join(", ") },
                                    v.title
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        out.push_str(&format!("Advisory check failed: {}\n", e));
                    }
                }

                out
            }
            "vexa_scan_workspace" => {
                let target = args.get("path").and_then(|p| p.as_str()).unwrap_or(".");
                let reachable_only = args
                    .get("reachable_only")
                    .and_then(|r| r.as_bool())
                    .unwrap_or(false);

                let scan_opts = ScanOptions {
                    dev: true,
                    reachable_only,
                    severity_threshold: None,
                    ignore_unfixed: false,
                    policy_file: None,
                    timeout_secs: 120,
                    licenses: true,
                    allow_unavailable: true,
                    baseline_file: None,
                    is_ci_profile: false,
                    max_source_files: Some(5000),
                };

                match scan_project(Path::new(target), scan_opts).await {
                    Ok(result) => {
                        let mut out =
                            format!("### Vexa SCA Workspace Scan Results for '{}'\n\n", target);
                        out.push_str(&format!(
                            "- **Ecosystem Manifest:** {:?}\n- **Scanned Packages:** {}\n- **Vulnerabilities Found:** {}\n",
                            result.manifest_type,
                            result.scan_result.scanned_packages_count,
                            result.scan_result.vulnerabilities.len()
                        ));

                        if !result.scan_result.vulnerabilities.is_empty() {
                            out.push_str("\n| Severity | Package | Vulnerability | Reachability | Fixed In |\n| :--- | :--- | :--- | :--- | :--- |\n");
                            for f in result.scan_result.vulnerabilities.iter().take(20) {
                                let reach_status = f
                                    .reachability
                                    .as_ref()
                                    .map(|r| format!("{:?}", r.status))
                                    .unwrap_or_else(|| "UNKNOWN".to_string());
                                out.push_str(&format!(
                                    "| {:?} | {} | {} | {} | {} |\n",
                                    f.severity.level,
                                    f.package,
                                    f.id,
                                    reach_status,
                                    if f.fixed_in.is_empty() {
                                        "None".to_string()
                                    } else {
                                        f.fixed_in.join(", ")
                                    }
                                ));
                            }
                            if result.scan_result.vulnerabilities.len() > 20 {
                                out.push_str(&format!(
                                    "\n*...and {} more vulnerabilities*\n",
                                    result.scan_result.vulnerabilities.len() - 20
                                ));
                            }
                        }

                        // Also run local supply chain rules
                        let sc_findings =
                            LocalSupplyChainAnalyzer::scan_workspace(Path::new(target));
                        if !sc_findings.is_empty() {
                            out.push_str(&format!(
                                "\n### Supply Chain Threat Detections ({})\n\n",
                                sc_findings.len()
                            ));
                            for sc in sc_findings.iter().take(10) {
                                out.push_str(&format!(
                                    "- **[{}] {}** ({:?}): {} (at {})\n",
                                    sc.rule_id,
                                    sc.signal_name,
                                    sc.severity,
                                    sc.message,
                                    sc.file_path.as_deref().unwrap_or("unknown")
                                ));
                            }
                        }

                        out
                    }
                    Err(e) => format!("Scan failed: {}", e),
                }
            }
            "vexa_explain_finding" => {
                let finding_id = args
                    .get("finding_id")
                    .and_then(|f| f.as_str())
                    .unwrap_or("");
                if finding_id.is_empty() {
                    return "Error: finding_id argument is required".to_string();
                }

                // Check if it's a Supply Chain rule
                if finding_id.starts_with("SC-") {
                    return match finding_id {
                        "SC-001" => "SC-001 (install_script_execution): Detects preinstall, install, or postinstall hooks. Third-party packages executing lifecycle scripts during install present severe supply chain risk.".to_string(),
                        "SC-002" => "SC-002 (install_script_network_egress): Package install scripts make active network requests (curl, wget, net.connect). Frequently used by malicious packages to drop secondary payloads or exfiltrate environment data.".to_string(),
                        "SC-006" => "SC-006 (env_credential_harvesting): Module accesses sensitive keys like AWS_SECRET, GITHUB_TOKEN, or NPM_TOKEN and opens outbound sockets.".to_string(),
                        "SC-008" => "SC-008 (trojan_source_bidi): Unicode bidirectional override characters used to visually reorder code while altering compiler interpretation.".to_string(),
                        "SC-010" => "SC-010 (typosquat_top_10k): Package name is visually or phonetically adjacent to a top 10,000 registry dependency.".to_string(),
                        "SC-013" => "SC-013 (reverse_shell_signature): Detected explicit command-line or socket reverse shell payload.".to_string(),
                        _ => format!("Rule {}: Behavioral supply chain detection rule enforcing local zero-trust security.", finding_id),
                    };
                }

                format!(
                    "### Explanation for Vulnerability {}\n\nVexa SCA computes a deterministic priority score combining CVSS severity, transitive depth, CISA KEV exploitation status, and AST positive-proof reachability.\nTo remediate, upgrade to the latest fixed patch release or apply lockfile overrides.",
                    finding_id
                )
            }
            "vexa_remediate_manifest" => {
                let manifest = args
                    .get("manifest_path")
                    .and_then(|m| m.as_str())
                    .unwrap_or("");
                let pkg = args.get("package").and_then(|p| p.as_str()).unwrap_or("");
                let target_ver = args
                    .get("target_version")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                if manifest.is_empty() || pkg.is_empty() || target_ver.is_empty() {
                    return "Error: manifest_path, package, and target_version are required"
                        .to_string();
                }

                let path = PathBuf::from(manifest);
                let dir = if path.is_file() {
                    path.parent().unwrap_or(Path::new("."))
                } else {
                    &path
                };

                let action = RemediationAction {
                    package: pkg.to_string(),
                    current_version: "*".to_string(),
                    is_transitive: false,
                    target_version: Some(target_ver.to_string()),
                    action_type: "UPGRADE_DIRECT".to_string(),
                    advice: format!("Upgrade {} to {}", pkg, target_ver),
                    resolved_vulnerability_count: 1,
                    vulnerability_ids: vec![],
                    highest_severity: None,
                };

                match LockfilePatcher::apply_fixes(dir, &[action], false) {
                    Ok(res) => format!(
                        "Successfully patched manifest. Modified: {}, Backup: {:?}",
                        res.modified, res.backup_file
                    ),
                    Err(e) => format!("Failed to patch manifest: {}", e),
                }
            }
            _ => format!("Unknown tool: {}", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mcp_initialize() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: json!({}),
        };
        let resp = McpServer::handle_request(req)
            .await
            .expect("should return response");
        assert_eq!(resp.jsonrpc, "2.0");
        assert_eq!(resp.id, Some(json!(1)));
        let res = resp.result.expect("result must be present");
        assert_eq!(
            res.get("serverInfo").unwrap().get("name").unwrap(),
            "vexa-sca"
        );
    }

    #[tokio::test]
    async fn test_mcp_tools_list() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: "tools/list".to_string(),
            params: json!({}),
        };
        let resp = McpServer::handle_request(req)
            .await
            .expect("should return response");
        let res = resp.result.unwrap();
        let tools = res.get("tools").unwrap().as_array().unwrap();
        let tool_names: Vec<&str> = tools
            .iter()
            .map(|t| t.get("name").unwrap().as_str().unwrap())
            .collect();
        assert!(tool_names.contains(&"vexa_check_package"));
        assert!(tool_names.contains(&"vexa_scan_workspace"));
        assert!(tool_names.contains(&"vexa_explain_finding"));
        assert!(tool_names.contains(&"vexa_remediate_manifest"));
    }

    #[tokio::test]
    async fn test_mcp_explain_supply_chain_rule() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(3)),
            method: "tools/call".to_string(),
            params: json!({
                "name": "vexa_explain_finding",
                "arguments": {
                    "finding_id": "SC-008"
                }
            }),
        };
        let resp = McpServer::handle_request(req)
            .await
            .expect("should return response");
        let res = resp.result.unwrap();
        let content = res.get("content").unwrap().as_array().unwrap();
        let text = content[0].get("text").unwrap().as_str().unwrap();
        assert!(text.contains("trojan_source_bidi"));
    }
}
