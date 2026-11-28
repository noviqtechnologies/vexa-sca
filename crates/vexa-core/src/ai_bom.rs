#![forbid(unsafe_code)]

//! Shared CycloneDX v1.6 AI-BOM / SBOM schema types and cross-OS MCP config discovery
//! consumed by `vexa-sca`, `vexa-arc`, and `vexa-sca-cloud`.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CycloneDxBom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub metadata: BomMetadata,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<BomComponent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<BomService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomMetadata {
    pub timestamp: String,
    pub tools: Vec<BomTool>,
    pub component: BomRootComponent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomRootComponent {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomComponent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<BomProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BomService {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(rename = "x-trust-boundary", skip_serializing_if = "Option::is_none")]
    pub x_trust_boundary: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<BomProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BomProperty {
    pub name: String,
    pub value: String,
}

/// Canonical MCP server entry discovered from IDE/agent configuration files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveredMcpConfig {
    pub name: String,
    pub source_file: String,
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub env_keys: Vec<String>,
}

/// Standard workspace-relative MCP configuration file paths across Claude, Cursor,
/// VS Code, Windsurf, and OpenCode.
pub const MCP_CONFIG_REL_PATHS: &[&str] = &[
    "mcp.json",
    ".mcp.json",
    ".claude.json",
    "claude_desktop_config.json",
    ".claude/mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp.json",
    "opencode.json",
    ".opencode/mcp.json",
];

/// Discovers and parses MCP server definitions from standard workspace config files.
pub fn discover_mcp_configs(root: &Path) -> Vec<DiscoveredMcpConfig> {
    let mut out = Vec::new();

    for rel_str in MCP_CONFIG_REL_PATHS {
        let mut path = root.to_path_buf();
        for seg in rel_str.split('/') {
            path.push(seg);
        }
        if !path.is_file() {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                continue;
            }
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) else {
            continue;
        };
        let Some(servers) = val
            .get("mcpServers")
            .or_else(|| val.get("mcp"))
            .or_else(|| val.get("servers"))
            .and_then(|s| s.as_object())
        else {
            continue;
        };

        for (srv_name, srv_val) in servers {
            let command = srv_val
                .get("command")
                .and_then(|c| c.as_str())
                .map(|s| s.to_string());
            let args: Vec<String> = srv_val
                .get("args")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let url = srv_val
                .get("url")
                .or_else(|| srv_val.get("serverUrl"))
                .and_then(|u| u.as_str())
                .map(|s| s.to_string());
            let env_keys: Vec<String> = srv_val
                .get("env")
                .and_then(|e| e.as_object())
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            let transport = if url.is_some() { "http" } else { "stdio" }.to_string();

            out.push(DiscoveredMcpConfig {
                name: srv_name.clone(),
                source_file: (*rel_str).to_string(),
                transport,
                command,
                args,
                url,
                env_keys,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_mcp_configs_across_clients() {
        let dir = std::env::temp_dir().join("vexa_core_ai_bom_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".cursor")).unwrap();
        fs::write(
            dir.join("claude_desktop_config.json"),
            r#"{"mcpServers":{"fs":{"command":"npx","args":["-y","@mcp/fs"]}}}"#,
        )
        .unwrap();
        fs::write(
            dir.join(".cursor").join("mcp.json"),
            r#"{"mcpServers":{"remote":{"url":"https://mcp.example.com/sse"}}}"#,
        )
        .unwrap();

        let found = discover_mcp_configs(&dir);
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(found.len(), 2);
        assert!(found
            .iter()
            .any(|m| m.name == "fs" && m.source_file == "claude_desktop_config.json"));
        assert!(found
            .iter()
            .any(|m| m.name == "remote" && m.transport == "http"));
    }
}
