#![forbid(unsafe_code)]

//! Shared pure-in-memory Python TOML lockfile (`uv.lock`, `poetry.lock`) graph parser.
//! Preserves real parent -> child dependency edges and `prod`/`dev` scopes without
//! touching the filesystem so CLI and Cloud GitHub App produce identical graphs.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PythonLockPackage {
    pub name: String,
    pub normalized_name: String,
    pub version: String,
    pub scope: String,
    pub is_direct: bool,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PythonLockGraph {
    pub packages: Vec<PythonLockPackage>,
    /// Directed `(parent_norm_name, child_norm_name)` edges between external packages.
    pub edges: Vec<(String, String)>,
}

#[inline]
pub fn normalize_python_pkg_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['_', '.'], "-")
}

/// Parses `uv.lock` or `poetry.lock` TOML content into a normalized graph with
/// true transitive edges, virtual root handling, and `prod`/`dev` scope resolution.
pub fn parse_python_toml_lock(content: &str) -> Result<PythonLockGraph, String> {
    let parsed: toml::Value =
        toml::from_str(content).map_err(|e| format!("Failed to parse Python lockfile TOML: {e}"))?;

    let Some(packages_arr) = parsed.get("package").and_then(|p| p.as_array()) else {
        return Ok(PythonLockGraph::default());
    };

    let mut pkg_map: HashMap<String, PythonLockPackage> = HashMap::new();
    let mut pkg_order: Vec<String> = Vec::new();
    let mut root_direct_norms: HashSet<String> = HashSet::new();
    let mut dev_dep_norms: HashSet<String> = HashSet::new();
    let mut raw_edges: Vec<(Option<String>, String)> = Vec::new();

    for pkg in packages_arr {
        let (Some(name), Some(version)) = (
            pkg.get("name").and_then(|n| n.as_str()),
            pkg.get("version").and_then(|v| v.as_str()),
        ) else {
            continue;
        };

        let is_virtual_root = pkg
            .get("source")
            .and_then(|s| s.as_table())
            .map(|t| {
                t.get("virtual").and_then(|v| v.as_str()) == Some(".")
                    || t.get("editable").and_then(|v| v.as_str()) == Some(".")
            })
            .unwrap_or(false);

        let parent_norm = if is_virtual_root {
            None
        } else {
            let norm = normalize_python_pkg_name(name);
            let is_dev_category = pkg
                .get("category")
                .and_then(|c| c.as_str())
                .map(|c| c.eq_ignore_ascii_case("dev"))
                .unwrap_or(false);
            let is_dev_groups = pkg
                .get("groups")
                .and_then(|g| g.as_array())
                .map(|arr| {
                    !arr.is_empty()
                        && arr.iter().all(|v| {
                            v.as_str()
                                .map(|s| !s.eq_ignore_ascii_case("main"))
                                .unwrap_or(false)
                        })
                })
                .unwrap_or(false);
            let scope = if is_dev_category || is_dev_groups {
                "dev".to_string()
            } else {
                "prod".to_string()
            };

            if !pkg_map.contains_key(&norm) {
                pkg_order.push(norm.clone());
            }
            pkg_map.insert(
                norm.clone(),
                PythonLockPackage {
                    name: name.to_string(),
                    normalized_name: norm.clone(),
                    version: version.to_string(),
                    scope,
                    is_direct: false,
                    dependencies: Vec::new(),
                },
            );
            Some(norm)
        };

        if let Some(deps_arr) = pkg.get("dependencies").and_then(|d| d.as_array()) {
            for dep in deps_arr {
                if let Some(dep_name) = dep.get("name").and_then(|n| n.as_str()) {
                    let child_norm = normalize_python_pkg_name(dep_name);
                    if parent_norm.is_none() {
                        root_direct_norms.insert(child_norm.clone());
                    }
                    raw_edges.push((parent_norm.clone(), child_norm));
                }
            }
        } else if let Some(deps_tbl) = pkg.get("dependencies").and_then(|d| d.as_table()) {
            for dep_name in deps_tbl.keys() {
                let child_norm = normalize_python_pkg_name(dep_name);
                if parent_norm.is_none() {
                    root_direct_norms.insert(child_norm.clone());
                }
                raw_edges.push((parent_norm.clone(), child_norm));
            }
        }

        if let Some(dev_tbl) = pkg.get("dev-dependencies").and_then(|d| d.as_table()) {
            for group_deps in dev_tbl.values() {
                if let Some(arr) = group_deps.as_array() {
                    for dep in arr {
                        if let Some(dep_name) = dep.get("name").and_then(|n| n.as_str()) {
                            let child_norm = normalize_python_pkg_name(dep_name);
                            dev_dep_norms.insert(child_norm.clone());
                            if parent_norm.is_none() {
                                root_direct_norms.insert(child_norm.clone());
                            }
                            raw_edges.push((parent_norm.clone(), child_norm));
                        }
                    }
                }
            }
        }
    }

    for dev_norm in &dev_dep_norms {
        if let Some(pkg) = pkg_map.get_mut(dev_norm) {
            pkg.scope = "dev".to_string();
        }
    }

    let mut edges: Vec<(String, String)> = Vec::new();
    let mut has_incoming: HashSet<String> = HashSet::new();

    for (parent_opt, child_norm) in raw_edges {
        if !pkg_map.contains_key(&child_norm) {
            continue;
        }
        if let Some(parent_norm) = parent_opt {
            if parent_norm != child_norm {
                if let Some(parent_pkg) = pkg_map.get_mut(&parent_norm) {
                    if !parent_pkg.dependencies.contains(&child_norm) {
                        parent_pkg.dependencies.push(child_norm.clone());
                    }
                }
                edges.push((parent_norm, child_norm.clone()));
                has_incoming.insert(child_norm);
            }
        }
    }

    let packages = pkg_order
        .into_iter()
        .filter_map(|norm| {
            let mut pkg = pkg_map.remove(&norm)?;
            pkg.is_direct = root_direct_norms.contains(&norm) || !has_incoming.contains(&norm);
            Some(pkg)
        })
        .collect();

    Ok(PythonLockGraph { packages, edges })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uv_lock_with_virtual_root_and_transitive_edges() {
        let src = r#"
[[package]]
name = "demo-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "fastapi" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "fastapi"
version = "0.115.0"
dependencies = [{ name = "starlette" }]

[[package]]
name = "starlette"
version = "0.40.0"

[[package]]
name = "pytest"
version = "8.3.0"
"#;
        let g = parse_python_toml_lock(src).expect("parse uv.lock");
        let by_name: HashMap<_, _> = g
            .packages
            .iter()
            .map(|p| (p.normalized_name.as_str(), p))
            .collect();
        assert!(by_name["fastapi"].is_direct);
        assert!(by_name["pytest"].is_direct);
        assert_eq!(by_name["pytest"].scope, "dev");
        assert!(!by_name["starlette"].is_direct);
        assert_eq!(by_name["fastapi"].dependencies, vec!["starlette"]);
    }
}
