use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct CargoLockParser;

#[derive(Debug, Deserialize)]
struct CargoLockToml {
    #[serde(default)]
    package: Vec<CargoPackage>,
}

#[derive(Debug, Deserialize, Clone)]
struct CargoPackage {
    name: String,
    version: String,
    #[serde(default)]
    dependencies: Vec<String>,
}

impl CargoLockParser {
    pub fn parse(path_or_dir: &Path) -> Result<DepGraph, String> {
        let lock_path = if path_or_dir.is_dir() {
            path_or_dir.join("Cargo.lock")
        } else {
            path_or_dir.to_path_buf()
        };

        if !lock_path.exists() {
            return Err(format!("Cargo.lock not found at {}", lock_path.display()));
        }

        let content = fs::read_to_string(&lock_path)
            .map_err(|e| format!("Failed to read Cargo.lock: {}", e))?;

        let parsed: CargoLockToml = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse Cargo.lock TOML: {}", e))?;

        if parsed.package.is_empty() {
            return Err("No packages found in Cargo.lock".to_string());
        }

        let root_pkg_data = &parsed.package[0];
        let root_pkg = PkgInfo::new(&root_pkg_data.name, &root_pkg_data.version, "crates.io");
        let mut graph = DepGraph::new(
            root_pkg.clone(),
            PkgManagerInfo {
                name: "cargo".to_string(),
                version: "lock".to_string(),
            },
        );

        let mut name_to_node_id = HashMap::new();

        // 1. Register all nodes
        for pkg in &parsed.package {
            if pkg.name == root_pkg.name && pkg.version == root_pkg.version {
                continue;
            }

            let pkg_info = PkgInfo::new(&pkg.name, &pkg.version, "crates.io");
            graph.add_pkg(pkg_info.clone());

            let node_id = format!("cargo:{}@{}", pkg.name, pkg.version);
            name_to_node_id.insert(pkg.name.clone(), node_id.clone());

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

        // 2. Connect dependencies
        for pkg in &parsed.package {
            let parent_node_id = if pkg.name == root_pkg.name && pkg.version == root_pkg.version {
                graph.root_node_id.clone()
            } else {
                match name_to_node_id.get(&pkg.name) {
                    Some(id) => id.clone(),
                    None => continue,
                }
            };

            for dep in &pkg.dependencies {
                // "bytes 1.4.0" or "bytes"
                let dep_name = dep.split_whitespace().next().unwrap_or(dep.as_str());
                if let Some(child_node_id) = name_to_node_id.get(dep_name) {
                    let _ = graph.add_edge(&parent_node_id, child_node_id);
                }
            }
        }

        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_lock_parser_fixture() {
        let fixture_dir = Path::new("test/fixtures/rust-app");
        let graph = CargoLockParser::parse(fixture_dir).expect("should parse Cargo.lock");

        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();

        assert!(names.contains(&"tokio"));
        assert!(names.contains(&"bytes"));

        let tokio = pkgs.iter().find(|p| p.name == "tokio").unwrap();
        assert_eq!(tokio.version, "1.28.0");
        assert_eq!(tokio.ecosystem, "crates.io");
    }
}
