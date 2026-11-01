#![forbid(unsafe_code)]

use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use serde_json::Value;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct YarnLockParser;

#[derive(Default, Debug, Clone)]
struct YarnEntry {
    version: String,
    dependencies: HashMap<String, String>,
}

impl YarnLockParser {
    pub fn parse(project_dir: &Path, include_dev: bool) -> Result<DepGraph, String> {
        let manifest_path = project_dir.join("package.json");
        let lockfile_path = project_dir.join("yarn.lock");

        if !manifest_path.exists() {
            return Err(format!(
                "package.json not found in {}",
                project_dir.display()
            ));
        }
        if !lockfile_path.exists() {
            return Err(format!("yarn.lock not found in {}", project_dir.display()));
        }

        let manifest_str = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("Failed to read package.json: {}", e))?;
        let lockfile_str = fs::read_to_string(&lockfile_path)
            .map_err(|e| format!("Failed to read yarn.lock: {}", e))?;

        let manifest: Value = serde_json::from_str(&manifest_str)
            .map_err(|e| format!("Invalid JSON in package.json: {}", e))?;

        let project_name = manifest
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                project_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("app")
            });
        let project_version = manifest
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");

        let is_berry = lockfile_str.contains("__metadata:");
        let yarn_ver = if is_berry { "berry" } else { "1.x" };

        let root_pkg = PkgInfo::new(project_name, project_version, "npm");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "yarn".to_string(),
                version: yarn_ver.to_string(),
            },
        );

        let entries = if is_berry {
            Self::parse_yarn_berry_content(&lockfile_str)?
        } else {
            Self::parse_yarn_lock_content(&lockfile_str)
        };

        let mut spec_to_node_id: HashMap<String, String> = HashMap::new();

        for (spec, data) in &entries {
            let name = match Self::extract_pkg_name_from_spec(spec) {
                Some(n) => n,
                None => continue,
            };
            let version = &data.version;
            if name.is_empty() || version.is_empty() {
                continue;
            }

            let pkg_info = PkgInfo::new(&name, version, "npm");
            graph.add_pkg(pkg_info.clone());

            let node_id = format!("yarn:{}@{}", name, version);
            spec_to_node_id.insert(spec.clone(), node_id.clone());
            // Also index without `@npm:` protocol for direct dependency lookup
            let normalized_spec = spec.replace("@npm:", "@");
            if normalized_spec != *spec {
                spec_to_node_id.insert(normalized_spec, node_id.clone());
            }

            graph.add_node(
                node_id,
                pkg_info.id,
                NodeInfo {
                    scope: "prod".to_string(),
                    path: None,
                    integrity: None,
                },
            );
        }

        // Direct deps
        let mut root_deps = HashMap::new();
        if let Some(deps) = manifest.get("dependencies").and_then(|d| d.as_object()) {
            for (k, v) in deps {
                root_deps.insert(k.clone(), v.as_str().unwrap_or("").to_string());
            }
        }
        if include_dev {
            if let Some(dev) = manifest.get("devDependencies").and_then(|d| d.as_object()) {
                for (k, v) in dev {
                    root_deps.insert(k.clone(), v.as_str().unwrap_or("").to_string());
                }
            }
        }

        for (dep_name, dep_range) in root_deps {
            let clean_range = dep_range.strip_prefix("npm:").unwrap_or(&dep_range);
            let query_spec = if dep_range.starts_with("npm:") {
                clean_range.to_string()
            } else {
                format!("{}@{}", dep_name, clean_range)
            };
            if let Some(child_node_id) = spec_to_node_id.get(&query_spec) {
                let _ = graph.add_edge(&graph.root_node_id.clone(), child_node_id);
            }
        }

        // Transitive deps
        for (spec, data) in &entries {
            let parent_node_id = match spec_to_node_id.get(spec) {
                Some(id) => id.clone(),
                None => continue,
            };

            for (child_name, child_range) in &data.dependencies {
                let clean_range = child_range.strip_prefix("npm:").unwrap_or(child_range);
                let child_spec = format!("{}@{}", child_name, clean_range);
                if let Some(child_node_id) = spec_to_node_id.get(&child_spec) {
                    let _ = graph.add_edge(&parent_node_id, child_node_id);
                }
            }
        }

        Ok(graph)
    }

    /// Extracts canonical npm package name from a Yarn descriptor such as:
    /// - `lodash@^4.17.15` -> `lodash`
    /// - `lodash@npm:^4.17.15` -> `lodash`
    /// - `@babel/core@npm:^7.20.0` -> `@babel/core`
    /// - `my-lodash@npm:lodash@^4.17.15` -> `lodash`
    pub fn extract_pkg_name_from_spec(spec: &str) -> Option<String> {
        let trimmed = spec.trim().trim_matches('"');
        if trimmed.is_empty() || trimmed == "__metadata" {
            return None;
        }

        // Handle `alias@npm:real-pkg@range` or `pkg@npm:range`
        if let Some(npm_idx) = trimmed.find("@npm:") {
            let after_npm = &trimmed[npm_idx + 5..];
            // If `after_npm` contains another `@` (not at index 0 for scoped pkg), it's `real-pkg@range`
            if let Some(at_pos) = after_npm[1..].find('@').map(|i| i + 1) {
                let real_pkg = &after_npm[..at_pos];
                if !real_pkg.is_empty() {
                    return Some(real_pkg.to_string());
                }
            }
            let pkg_part = &trimmed[..npm_idx];
            if !pkg_part.is_empty() {
                return Some(pkg_part.to_string());
            }
        }

        if let Some(idx) = trimmed.rfind('@') {
            if idx > 0 {
                return Some(trimmed[..idx].to_string());
            }
        }
        None
    }

    fn parse_yarn_berry_content(content: &str) -> Result<HashMap<String, YarnEntry>, String> {
        crate::parsers::validate_yaml_content_safety(content)?;
        let parsed: YamlValue = serde_yaml::from_str(content)
            .map_err(|e| format!("Invalid YAML in Yarn Berry lockfile: {}", e))?;
        crate::parsers::check_yaml_depth(&parsed, 0)?;

        let mut map: HashMap<String, YarnEntry> = HashMap::new();
        let Some(root_map) = parsed.as_mapping() else {
            return Ok(map);
        };

        for (k, v) in root_map {
            let Some(key_str) = k.as_str() else {
                continue;
            };
            if key_str == "__metadata" {
                continue;
            }
            let Some(entry_map) = v.as_mapping() else {
                continue;
            };
            let version = entry_map
                .get(YamlValue::String("version".to_string()))
                .and_then(|ver| ver.as_str())
                .unwrap_or("")
                .to_string();
            if version.is_empty() || version == "0.0.0-use.local" {
                continue;
            }

            let mut dependencies = HashMap::new();
            if let Some(deps_map) = entry_map
                .get(YamlValue::String("dependencies".to_string()))
                .and_then(|d| d.as_mapping())
            {
                for (dk, dv) in deps_map {
                    if let (Some(d_name), Some(d_ver)) = (dk.as_str(), dv.as_str()) {
                        dependencies.insert(
                            d_name.to_string(),
                            d_ver.strip_prefix("npm:").unwrap_or(d_ver).to_string(),
                        );
                    }
                }
            }

            let entry = YarnEntry {
                version,
                dependencies,
            };

            for spec in key_str.split(',') {
                let clean_spec = spec.trim().trim_matches('"');
                if !clean_spec.is_empty() {
                    map.insert(clean_spec.to_string(), entry.clone());
                }
            }
        }

        Ok(map)
    }

    fn parse_yarn_lock_content(content: &str) -> HashMap<String, YarnEntry> {
        let mut map: HashMap<String, YarnEntry> = HashMap::new();
        let lines: Vec<&str> = content.lines().collect();

        let mut current_keys: Vec<String> = Vec::new();
        let mut current_data = YarnEntry::default();

        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                i += 1;
                continue;
            }

            if !line.starts_with("  ") && (line.contains(':') || line.ends_with(',')) {
                if !current_keys.is_empty() {
                    for k in &current_keys {
                        map.insert(k.clone(), current_data.clone());
                    }
                }
                current_keys = line
                    .trim_end_matches(':')
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .collect();
                current_data = YarnEntry::default();
                i += 1;
                continue;
            }

            if line.starts_with("  version ") {
                let ver = trimmed
                    .trim_start_matches("version ")
                    .trim()
                    .trim_matches('"');
                current_data.version = ver.to_string();
            } else if line.starts_with("  dependencies:") {
                let mut j = i + 1;
                while j < lines.len() && lines[j].starts_with("    ") {
                    let dep_line = lines[j].trim();
                    let parts: Vec<&str> = dep_line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let name = parts[0].trim_matches('"');
                        let req = parts[1].trim_matches('"');
                        current_data
                            .dependencies
                            .insert(name.to_string(), req.to_string());
                    }
                    j += 1;
                }
                i = j.saturating_sub(1);
            }

            i += 1;
        }

        if !current_keys.is_empty() {
            for k in &current_keys {
                map.insert(k.clone(), current_data.clone());
            }
        }

        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yarn_berry_v2_v4_and_npm_alias_parsing() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_yarn_berry_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let pkg_json = r#"{
            "name": "berry-app",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "^4.17.15",
                "custom-minimist": "npm:minimist@^1.2.5"
            }
        }"#;

        let berry_lock = r#"# This file is generated by running "yarn install" inside your project.
__metadata:
  version: 8
  cacheKey: 10c0

"lodash@npm:^4.17.15":
  version: 4.17.15
  resolution: "lodash@npm:4.17.15"
  checksum: 10c0/abcdef

"custom-minimist@npm:minimist@^1.2.5":
  version: 1.2.5
  resolution: "minimist@npm:1.2.5"
  checksum: 10c0/123456
"#;

        fs::write(temp_dir.join("package.json"), pkg_json).unwrap();
        fs::write(temp_dir.join("yarn.lock"), berry_lock).unwrap();

        let graph = YarnLockParser::parse(&temp_dir, true).expect("should parse Yarn Berry");
        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(
            names.contains(&"minimist"),
            "npm: alias must resolve to canonical package 'minimist'"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
