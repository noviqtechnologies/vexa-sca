use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use serde_json::Value;
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

        let root_pkg = PkgInfo::new(project_name, project_version, "npm");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "yarn".to_string(),
                version: "1.x".to_string(),
            },
        );

        let entries = Self::parse_yarn_lock_content(&lockfile_str);
        let mut spec_to_node_id: HashMap<String, String> = HashMap::new();

        for (spec, data) in &entries {
            // spec e.g. "lodash@^4.17.15" -> extract name
            let name = match spec.rfind('@') {
                Some(idx) if idx > 0 => &spec[..idx],
                _ => continue,
            };
            let version = &data.version;
            if name.is_empty() || version.is_empty() {
                continue;
            }

            let pkg_info = PkgInfo::new(name, version, "npm");
            graph.add_pkg(pkg_info.clone());

            let node_id = format!("yarn:{}@{}", name, version);
            spec_to_node_id.insert(spec.clone(), node_id.clone());

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
            let query_spec = format!("{}@{}", dep_name, dep_range);
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
                let child_spec = format!("{}@{}", child_name, child_range);
                if let Some(child_node_id) = spec_to_node_id.get(&child_spec) {
                    let _ = graph.add_edge(&parent_node_id, child_node_id);
                }
            }
        }

        Ok(graph)
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
