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
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
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

        // Determine real root package
        let cargo_toml_path = lock_path
            .parent()
            .unwrap_or(Path::new("."))
            .join("Cargo.toml");
        let toml_pkg_name = if cargo_toml_path.exists() {
            fs::read_to_string(&cargo_toml_path)
                .ok()
                .and_then(|toml_str| {
                    let toml_val: Option<toml::Value> = toml::from_str(&toml_str).ok();
                    toml_val.and_then(|v| {
                        v.get("package")
                            .and_then(|p| p.get("name"))
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    })
                })
        } else {
            None
        };

        let dir_name = lock_path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str());

        let root_pkg_data = if let Some(ref name) = toml_pkg_name {
            parsed.package.iter().find(|p| &p.name == name)
        } else {
            None
        }
        .or_else(|| {
            if let Some(dname) = dir_name {
                parsed
                    .package
                    .iter()
                    .find(|p| p.source.is_none() && p.name == dname)
            } else {
                None
            }
        })
        .or_else(|| parsed.package.iter().find(|p| p.source.is_none()))
        .unwrap_or(&parsed.package[0]);

        let root_pkg = PkgInfo::new(&root_pkg_data.name, &root_pkg_data.version, "crates.io");
        let mut graph = DepGraph::new(
            root_pkg.clone(),
            PkgManagerInfo {
                name: "cargo".to_string(),
                version: "lock".to_string(),
            },
        );

        let mut name_to_node_id = HashMap::new();
        let mut name_and_ver_to_node_id = HashMap::new();

        // 1. Register all nodes
        for pkg in &parsed.package {
            if pkg.name == root_pkg.name && pkg.version == root_pkg.version {
                continue;
            }

            let pkg_info = PkgInfo::new(&pkg.name, &pkg.version, "crates.io");
            graph.add_pkg(pkg_info.clone());

            let node_id = format!("cargo:{}@{}", pkg.name, pkg.version);
            name_to_node_id.insert(pkg.name.clone(), node_id.clone());
            name_and_ver_to_node_id
                .insert((pkg.name.clone(), pkg.version.clone()), node_id.clone());

            graph.add_node(
                node_id,
                pkg_info.id,
                NodeInfo {
                    scope: "prod".to_string(),
                    path: None,
                    integrity: pkg.checksum.clone(),
                },
            );
        }

        // 2. Connect dependencies
        for pkg in &parsed.package {
            let parent_node_id = if pkg.name == root_pkg.name && pkg.version == root_pkg.version {
                graph.root_node_id.clone()
            } else {
                match name_and_ver_to_node_id.get(&(pkg.name.clone(), pkg.version.clone())) {
                    Some(id) => id.clone(),
                    None => match name_to_node_id.get(&pkg.name) {
                        Some(id) => id.clone(),
                        None => continue,
                    },
                }
            };

            for dep in &pkg.dependencies {
                // "bytes 1.4.0" or "bytes"
                let mut parts = dep.split_whitespace();
                let dep_name = parts.next().unwrap_or(dep.as_str());
                let dep_ver = parts.next();

                let child_node_id = if let Some(v) = dep_ver {
                    name_and_ver_to_node_id
                        .get(&(dep_name.to_string(), v.to_string()))
                        .or_else(|| name_to_node_id.get(dep_name))
                } else {
                    name_to_node_id.get(dep_name)
                };

                if let Some(cid) = child_node_id {
                    let _ = graph.add_edge(&parent_node_id, cid);
                }
            }
        }

        // 3. Connect other workspace root packages (source.is_none()) to root if not already reachable
        let root_id = graph.root_node_id.clone();
        for pkg in &parsed.package {
            if pkg.source.is_none()
                && (pkg.name != root_pkg.name || pkg.version != root_pkg.version)
            {
                if let Some(nid) =
                    name_and_ver_to_node_id.get(&(pkg.name.clone(), pkg.version.clone()))
                {
                    let _ = graph.add_edge(&root_id, nid);
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
