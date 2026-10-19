use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct PnpmLockParser;

impl PnpmLockParser {
    /// Parses package.json and pnpm-lock.yaml / pnpm-lock.yml into standard DepGraph schema.
    pub fn parse(project_dir: &Path, include_dev: bool) -> Result<DepGraph, String> {
        let manifest_path = project_dir.join("package.json");
        let lock_path_yaml = project_dir.join("pnpm-lock.yaml");
        let lock_path_yml = project_dir.join("pnpm-lock.yml");

        let lockfile_path = if lock_path_yaml.exists() {
            lock_path_yaml
        } else if lock_path_yml.exists() {
            lock_path_yml
        } else {
            return Err(format!("pnpm-lock.yaml not found in {}", project_dir.display()));
        };

        let (project_name, project_version, direct_deps) = if manifest_path.exists() {
            let manifest_str = fs::read_to_string(&manifest_path)
                .map_err(|e| format!("Failed to read package.json: {}", e))?;
            let manifest: JsonValue = serde_json::from_str(&manifest_str)
                .map_err(|e| format!("Invalid JSON in package.json: {}", e))?;

            let name = manifest
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    project_dir
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("app")
                })
                .to_string();

            let version = manifest
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string();

            let mut deps = HashMap::new();
            if let Some(d) = manifest.get("dependencies").and_then(|d| d.as_object()) {
                for (k, v) in d {
                    deps.insert(k.clone(), (v.as_str().unwrap_or("").to_string(), false));
                }
            }
            if include_dev {
                if let Some(dev) = manifest.get("devDependencies").and_then(|d| d.as_object()) {
                    for (k, v) in dev {
                        deps.insert(k.clone(), (v.as_str().unwrap_or("").to_string(), true));
                    }
                }
            }

            (name, version, deps)
        } else {
            let dir_name = project_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("app")
                .to_string();
            (dir_name, "0.0.0".to_string(), HashMap::new())
        };

        let lock_content = fs::read_to_string(&lockfile_path)
            .map_err(|e| format!("Failed to read {}: {}", lockfile_path.display(), e))?;

        let lock_yaml: YamlValue = serde_yaml::from_str(&lock_content)
            .map_err(|e| format!("Failed to parse YAML in {}: {}", lockfile_path.display(), e))?;

        let lockfile_ver = lock_yaml
            .get("lockfileVersion")
            .map(|v| match v {
                YamlValue::String(s) => s.clone(),
                YamlValue::Number(n) => n.to_string(),
                _ => "6.0".to_string(),
            })
            .unwrap_or_else(|| "6.0".to_string());

        let root_pkg = PkgInfo::new(&project_name, &project_version, "npm");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "pnpm".to_string(),
                version: lockfile_ver,
            },
        );

        // Map to keep track of name -> list of (version, node_id)
        let mut pkg_version_map: HashMap<String, Vec<(String, String)>> = HashMap::new();
        // Stores child edges to resolve: (parent_node_id, child_name, child_spec)
        let mut pending_edges: Vec<(String, String, String)> = Vec::new();

        // 1. Ingest all packages from "packages" map
        if let Some(packages) = lock_yaml.get("packages").and_then(|p| p.as_mapping()) {
            for (key_val, entry_val) in packages {
                let raw_key = match key_val {
                    YamlValue::String(s) => s.as_str(),
                    _ => continue,
                };

                let (pkg_name, pkg_version) = match Self::parse_package_key(raw_key) {
                    Some(parsed) => parsed,
                    None => continue,
                };

                let is_dev = entry_val
                    .get("dev")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if is_dev && !include_dev {
                    continue;
                }

                let pkg_info = PkgInfo::new(&pkg_name, &pkg_version, "npm");
                graph.add_pkg(pkg_info.clone());

                let node_id = format!("pnpm:{}@{}", pkg_name, pkg_version);
                graph.add_node(
                    node_id.clone(),
                    pkg_info.id.clone(),
                    NodeInfo {
                        scope: if is_dev { "dev".to_string() } else { "prod".to_string() },
                        path: None,
                        integrity: entry_val
                            .get("resolution")
                            .and_then(|r| r.get("integrity"))
                            .and_then(|i| i.as_str())
                            .map(|s| s.to_string()),
                    },
                );

                pkg_version_map
                    .entry(pkg_name.clone())
                    .or_default()
                    .push((pkg_version.clone(), node_id.clone()));

                // Collect dependencies of this package
                if let Some(deps) = entry_val.get("dependencies").and_then(|d| d.as_mapping()) {
                    for (dep_k, dep_v) in deps {
                        if let Some(dep_name) = dep_k.as_str() {
                            let dep_spec = match dep_v {
                                YamlValue::String(s) => s.as_str(),
                                _ => "",
                            };
                            pending_edges.push((node_id.clone(), dep_name.to_string(), dep_spec.to_string()));
                        }
                    }
                }
            }
        }

        // 2. Resolve internal child edges
        for (parent_node_id, child_name, child_spec) in pending_edges {
            if let Some(candidates) = pkg_version_map.get(&child_name) {
                // Find best matching version
                let matched_node = candidates
                    .iter()
                    .find(|(v, _)| child_spec.is_empty() || child_spec.contains(v) || v == &child_spec)
                    .map(|(_, id)| id)
                    .or_else(|| candidates.first().map(|(_, id)| id));

                if let Some(child_id) = matched_node {
                    let _ = graph.add_edge(&parent_node_id, child_id);
                }
            }
        }

        // 3. Connect root dependencies
        // Check manifest direct_deps first
        let mut root_connected = 0;
        for (dep_name, (dep_spec, _)) in &direct_deps {
            if let Some(candidates) = pkg_version_map.get(dep_name) {
                let matched = candidates
                    .iter()
                    .find(|(v, _)| dep_spec.is_empty() || dep_spec.contains(v) || v == dep_spec)
                    .map(|(_, id)| id)
                    .or_else(|| candidates.first().map(|(_, id)| id));

                if let Some(child_id) = matched {
                    let _ = graph.add_edge(&graph.root_node_id.clone(), child_id);
                    root_connected += 1;
                }
            }
        }

        // If no manifest or nothing was connected yet, check pnpm-lock top-level dependencies or importers['.']
        if root_connected == 0 {
            let mut top_deps = Vec::new();

            if let Some(deps) = lock_yaml.get("dependencies").and_then(|d| d.as_mapping()) {
                for (k, v) in deps {
                    if let Some(name) = k.as_str() {
                        let spec = match v {
                            YamlValue::String(s) => s.as_str(),
                            YamlValue::Mapping(m) => m.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                            _ => "",
                        };
                        top_deps.push((name.to_string(), spec.to_string()));
                    }
                }
            }

            if include_dev {
                if let Some(dev) = lock_yaml.get("devDependencies").and_then(|d| d.as_mapping()) {
                    for (k, v) in dev {
                        if let Some(name) = k.as_str() {
                            let spec = match v {
                                YamlValue::String(s) => s.as_str(),
                                YamlValue::Mapping(m) => m.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                                _ => "",
                            };
                            top_deps.push((name.to_string(), spec.to_string()));
                        }
                    }
                }
            }

            // Also check importers['.'] (pnpm v6 multi / v9)
            if let Some(importers) = lock_yaml.get("importers").and_then(|i| i.as_mapping()) {
                if let Some(dot) = importers.get(&YamlValue::String(".".to_string())).and_then(|d| d.as_mapping()) {
                    if let Some(deps) = dot.get("dependencies").and_then(|d| d.as_mapping()) {
                        for (k, v) in deps {
                            if let Some(name) = k.as_str() {
                                let spec = match v {
                                    YamlValue::String(s) => s.as_str(),
                                    YamlValue::Mapping(m) => m.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                                    _ => "",
                                };
                                top_deps.push((name.to_string(), spec.to_string()));
                            }
                        }
                    }
                }
            }

            for (dep_name, dep_spec) in top_deps {
                if let Some(candidates) = pkg_version_map.get(&dep_name) {
                    let matched = candidates
                        .iter()
                        .find(|(v, _)| dep_spec.is_empty() || dep_spec.contains(v) || v == &dep_spec)
                        .map(|(_, id)| id)
                        .or_else(|| candidates.first().map(|(_, id)| id));

                    if let Some(child_id) = matched {
                        let _ = graph.add_edge(&graph.root_node_id.clone(), child_id);
                    }
                }
            }
        }

        Ok(graph)
    }

    /// Extracts (package_name, version) from diverse pnpm package key patterns:
    /// - /lodash/4.17.15 (v5)
    /// - /lodash@4.17.15 (v6)
    /// - lodash@4.17.15 (v9)
    /// - /@babel/core/7.20.0 (v5 scoped)
    /// - /@babel/core@7.20.0 (v6 scoped)
    /// - @babel/core@7.20.0 (v9 scoped)
    /// - /react-dom@18.2.0(react@18.2.0) (peer dep suffix)
    /// - /react-dom/18.2.0_react@18.2.0 (v5 peer dep suffix)
    pub fn parse_package_key(raw_key: &str) -> Option<(String, String)> {
        let mut key = raw_key.trim();
        if key.starts_with('/') {
            key = &key[1..];
        }

        // Strip peer dependency parentheses: /react-dom@18.2.0(react@18.2.0) -> /react-dom@18.2.0
        if let Some(idx) = key.find('(') {
            key = &key[..idx];
        }

        // Strip trailing underscore peer annotations: /react-dom/18.2.0_react@18.2.0 -> /react-dom/18.2.0
        if let Some(idx) = key.find('_') {
            key = &key[..idx];
        }

        if key.is_empty() {
            return None;
        }

        if key.starts_with('@') {
            // Scoped package: @scope/name@version or @scope/name/version
            let slash_idx = key.find('/')?;
            let rest = &key[slash_idx + 1..];

            if let Some(at_idx) = rest.rfind('@') {
                let scope_and_name = &key[..slash_idx + 1 + at_idx];
                let version = &rest[at_idx + 1..];
                if !scope_and_name.is_empty() && !version.is_empty() {
                    return Some((scope_and_name.to_string(), version.to_string()));
                }
            } else if let Some(slash2_idx) = rest.rfind('/') {
                let scope_and_name = &key[..slash_idx + 1 + slash2_idx];
                let version = &rest[slash2_idx + 1..];
                if !scope_and_name.is_empty() && !version.is_empty() {
                    return Some((scope_and_name.to_string(), version.to_string()));
                }
            }
        } else {
            // Non-scoped package: lodash@4.17.15 or lodash/4.17.15
            if let Some(at_idx) = key.rfind('@') {
                let name = &key[..at_idx];
                let version = &key[at_idx + 1..];
                if !name.is_empty() && !version.is_empty() {
                    return Some((name.to_string(), version.to_string()));
                }
            } else if let Some(slash_idx) = key.rfind('/') {
                let name = &key[..slash_idx];
                let version = &key[slash_idx + 1..];
                if !name.is_empty() && !version.is_empty() {
                    return Some((name.to_string(), version.to_string()));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_package_key_variants() {
        assert_eq!(
            PnpmLockParser::parse_package_key("/lodash/4.17.15"),
            Some(("lodash".to_string(), "4.17.15".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/lodash@4.17.15"),
            Some(("lodash".to_string(), "4.17.15".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("lodash@4.17.15"),
            Some(("lodash".to_string(), "4.17.15".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/@babel/core/7.20.0"),
            Some(("@babel/core".to_string(), "7.20.0".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/@babel/core@7.20.0"),
            Some(("@babel/core".to_string(), "7.20.0".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("@babel/core@7.20.0"),
            Some(("@babel/core".to_string(), "7.20.0".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/react-dom@18.2.0(react@18.2.0)"),
            Some(("react-dom".to_string(), "18.2.0".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/react-dom/18.2.0_react@18.2.0"),
            Some(("react-dom".to_string(), "18.2.0".to_string()))
        );
    }
}
