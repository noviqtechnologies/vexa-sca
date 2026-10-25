use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct PackageLockParser;

impl PackageLockParser {
    pub fn parse(project_dir: &Path, include_dev: bool) -> Result<DepGraph, String> {
        let lockfile_path = project_dir.join("package-lock.json");
        Self::parse_file(&lockfile_path, include_dev)
    }

    pub fn parse_file(lockfile_path: &Path, include_dev: bool) -> Result<DepGraph, String> {
        let project_dir = lockfile_path.parent().unwrap_or(lockfile_path);
        let manifest_path = project_dir.join("package.json");

        if !manifest_path.exists() {
            return Err(format!(
                "package.json not found in {}",
                project_dir.display()
            ));
        }
        if !lockfile_path.exists() {
            return Err(format!("{} not found", lockfile_path.display()));
        }

        let manifest_str = fs::read_to_string(&manifest_path)
            .map_err(|e| format!("Failed to read package.json: {}", e))?;
        let lockfile_str = fs::read_to_string(lockfile_path)
            .map_err(|e| format!("Failed to read package-lock.json: {}", e))?;

        let manifest: Value = serde_json::from_str(&manifest_str)
            .map_err(|e| format!("Invalid JSON in package.json: {}", e))?;
        let lockfile: Value = serde_json::from_str(&lockfile_str)
            .map_err(|e| format!("Invalid JSON in package-lock.json: {}", e))?;

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
        let lockfile_version = lockfile
            .get("lockfileVersion")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "npm".to_string(),
                version: lockfile_version.to_string(),
            },
        );

        if lockfile_version >= 2 && lockfile.get("packages").is_some() {
            Self::parse_v2_v3(&mut graph, &lockfile, &manifest, include_dev)?;
        } else if lockfile.get("dependencies").is_some() {
            Self::parse_v1(&mut graph, &lockfile, &manifest, include_dev)?;
        }

        Ok(graph)
    }

    fn parse_v2_v3(
        graph: &mut DepGraph,
        lockfile: &Value,
        manifest: &Value,
        include_dev: bool,
    ) -> Result<(), String> {
        let packages = match lockfile.get("packages").and_then(|p| p.as_object()) {
            Some(p) => p,
            None => return Ok(()),
        };

        let mut path_to_node_id: HashMap<String, String> = HashMap::new();

        // 1. Register all nodes & packages
        for (pkg_path, pkg_val) in packages {
            if pkg_path.is_empty() {
                continue; // root
            }

            let is_dev = pkg_val
                .get("dev")
                .and_then(|d| d.as_bool())
                .unwrap_or(false);
            if !include_dev && is_dev {
                continue;
            }

            let name = if let Some(n) = pkg_val.get("name").and_then(|n| n.as_str()) {
                n.to_string()
            } else if let Some(last) = pkg_path.split("node_modules/").last() {
                last.to_string()
            } else {
                continue;
            };

            let version = match pkg_val.get("version").and_then(|v| v.as_str()) {
                Some(v) => v.to_string(),
                None => continue,
            };

            let pkg_info = PkgInfo::new(name.clone(), version.clone(), "npm");
            graph.add_pkg(pkg_info.clone());

            let node_id = format!("npm:{}@{}", pkg_path, version);
            path_to_node_id.insert(pkg_path.clone(), node_id.clone());
            if !pkg_path.starts_with("node_modules/") {
                path_to_node_id.insert(name, node_id.clone());
            }

            graph.add_node(
                node_id,
                pkg_info.id,
                NodeInfo {
                    scope: if is_dev { "dev".into() } else { "prod".into() },
                    path: Some(pkg_path.clone()),
                    integrity: pkg_val
                        .get("integrity")
                        .and_then(|i| i.as_str())
                        .map(|s| s.to_string()),
                },
            );
        }

        // 2. Connect direct dependencies of the root project
        let mut root_deps = HashMap::new();
        if let Some(deps) = manifest.get("dependencies").and_then(|d| d.as_object()) {
            for (k, v) in deps {
                root_deps.insert(k.clone(), v.as_str().unwrap_or(""));
            }
        }
        if include_dev {
            if let Some(dev_deps) = manifest.get("devDependencies").and_then(|d| d.as_object()) {
                for (k, v) in dev_deps {
                    root_deps.insert(k.clone(), v.as_str().unwrap_or(""));
                }
            }
        }

        for dep_name in root_deps.keys() {
            let top_level_path = format!("node_modules/{}", dep_name);
            if let Some(top_node_id) = path_to_node_id.get(&top_level_path) {
                let _ = graph.add_edge(&graph.root_node_id.clone(), top_node_id);
            } else if let Some((_, ws_node_id)) = path_to_node_id.iter().find(|(path, _)| {
                !path.starts_with("node_modules/")
                    && (path.ends_with(&format!("/{}", dep_name)) || *path == dep_name)
            }) {
                let _ = graph.add_edge(&graph.root_node_id.clone(), ws_node_id);
            }
        }

        // Connect all workspace packages directly to root
        for (pkg_path, _) in packages {
            if !pkg_path.is_empty() && !pkg_path.starts_with("node_modules/") {
                if let Some(ws_node_id) = path_to_node_id.get(pkg_path) {
                    let _ = graph.add_edge(&graph.root_node_id.clone(), ws_node_id);
                }
            }
        }

        // 3. Connect transitive dependencies
        for (pkg_path, pkg_val) in packages {
            if pkg_path.is_empty() {
                continue;
            }
            let parent_node_id = match path_to_node_id.get(pkg_path) {
                Some(id) => id.clone(),
                None => continue,
            };

            let mut req_deps = HashMap::new();
            if let Some(d) = pkg_val.get("dependencies").and_then(|v| v.as_object()) {
                for (k, v) in d {
                    req_deps.insert(k.clone(), v.as_str().unwrap_or(""));
                }
            }
            if let Some(od) = pkg_val
                .get("optionalDependencies")
                .and_then(|v| v.as_object())
            {
                for (k, v) in od {
                    req_deps.insert(k.clone(), v.as_str().unwrap_or(""));
                }
            }

            if let Some(pd) = pkg_val.get("peerDependencies").and_then(|v| v.as_object()) {
                for (k, v) in pd {
                    req_deps.insert(k.clone(), v.as_str().unwrap_or(""));
                }
            }

            for req_name in req_deps.keys() {
                if let Some(child_id) =
                    Self::resolve_nearest_ancestor(pkg_path, req_name, &path_to_node_id)
                {
                    let _ = graph.add_edge(&parent_node_id, &child_id);
                }
            }
        }

        Ok(())
    }

    /// Resolves child dependency using npm nearest-ancestor node_modules lookup.
    /// Iteratively walks up directory parents from the requesting package's path
    /// to find the closest enclosing node_modules directory that contains the
    /// target package, correctly modeling duplicate-version graphs and workspaces.
    pub fn resolve_nearest_ancestor(
        pkg_path: &str,
        req_name: &str,
        path_to_node_id: &HashMap<String, String>,
    ) -> Option<String> {
        // 1. Direct nested under requesting package: pkg_path/node_modules/req_name
        let direct = format!("{}/node_modules/{}", pkg_path, req_name);
        if let Some(id) = path_to_node_id.get(&direct) {
            return Some(id.clone());
        }

        // 2. Hierarchical ancestor walk:
        // Continually strip path segments and check if that ancestor directory has a node_modules/req_name.
        let mut curr = pkg_path;
        while let Some(idx) = curr.rfind('/') {
            curr = &curr[..idx];
            let candidate = if curr.ends_with("node_modules") {
                format!("{}/{}", curr, req_name)
            } else {
                format!("{}/node_modules/{}", curr, req_name)
            };
            if let Some(id) = path_to_node_id.get(&candidate) {
                return Some(id.clone());
            }
        }

        // 3. Fallback to top-level root node_modules/req_name
        let top_level = format!("node_modules/{}", req_name);
        if let Some(id) = path_to_node_id.get(&top_level) {
            return Some(id.clone());
        }

        // 4. Fallback to workspace package name or path
        if let Some(id) = path_to_node_id.get(req_name) {
            return Some(id.clone());
        }
        path_to_node_id.iter().find_map(|(path, id)| {
            if !path.starts_with("node_modules/")
                && (path.ends_with(&format!("/{}", req_name)) || *path == req_name)
            {
                Some(id.clone())
            } else {
                None
            }
        })
    }

    fn parse_v1(
        graph: &mut DepGraph,
        lockfile: &Value,
        _manifest: &Value,
        include_dev: bool,
    ) -> Result<(), String> {
        let deps = match lockfile.get("dependencies").and_then(|d| d.as_object()) {
            Some(d) => d,
            None => return Ok(()),
        };

        fn traverse(
            deps: &serde_json::Map<String, Value>,
            parent_node_id: &str,
            current_path: &[String],
            include_dev: bool,
            graph: &mut DepGraph,
        ) {
            for (dep_name, dep_val) in deps {
                let is_dev = dep_val
                    .get("dev")
                    .and_then(|d| d.as_bool())
                    .unwrap_or(false);
                if !include_dev && is_dev {
                    continue;
                }

                let version = match dep_val.get("version").and_then(|v| v.as_str()) {
                    Some(v) => v,
                    None => continue,
                };

                let pkg_info = PkgInfo::new(dep_name, version, "npm");
                graph.add_pkg(pkg_info.clone());

                let mut path_vec = current_path.to_vec();
                path_vec.push(dep_name.clone());
                let node_path = path_vec.join(" > ");
                let node_id = format!("npm:{}@{}", node_path, version);

                graph.add_node(
                    node_id.clone(),
                    pkg_info.id,
                    NodeInfo {
                        scope: if is_dev { "dev".into() } else { "prod".into() },
                        path: None,
                        integrity: dep_val
                            .get("integrity")
                            .and_then(|i| i.as_str())
                            .map(|s| s.to_string()),
                    },
                );

                let _ = graph.add_edge(parent_node_id, &node_id);

                if let Some(sub_deps) = dep_val.get("dependencies").and_then(|d| d.as_object()) {
                    traverse(sub_deps, &node_id, &path_vec, include_dev, graph);
                }
            }
        }

        let root_id = graph.root_node_id.clone();
        traverse(deps, &root_id, &[], include_dev, graph);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_lock_parser_fixture() {
        let fixture_dir = Path::new("test/fixtures/npm-app");
        let graph = PackageLockParser::parse(fixture_dir, true).expect("should parse npm-app");

        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();

        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"minimist"));

        let lodash = pkgs.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.15");
    }

    #[test]
    fn test_resolve_nearest_ancestor_resolution() {
        let mut path_map = HashMap::new();
        // Top level: node_modules/shared@1.0.0
        path_map.insert(
            "node_modules/shared".to_string(),
            "npm:shared@1.0.0".to_string(),
        );
        // Nested under pkgA: node_modules/pkgA/node_modules/shared@2.0.0
        path_map.insert(
            "node_modules/pkgA/node_modules/shared".to_string(),
            "npm:pkgA/shared@2.0.0".to_string(),
        );
        // Deeply nested under pkgA/pkgB: node_modules/pkgA/node_modules/pkgB
        path_map.insert(
            "node_modules/pkgA/node_modules/pkgB".to_string(),
            "npm:pkgA/pkgB@1.0.0".to_string(),
        );
        // Another pkgC at top level: node_modules/pkgC
        path_map.insert(
            "node_modules/pkgC".to_string(),
            "npm:pkgC@1.0.0".to_string(),
        );

        // 1. pkgB inside pkgA requiring "shared" must resolve to pkgA's nearest ancestor shared (2.0.0), NOT root (1.0.0)
        let resolved = PackageLockParser::resolve_nearest_ancestor(
            "node_modules/pkgA/node_modules/pkgB",
            "shared",
            &path_map,
        );
        assert_eq!(resolved.as_deref(), Some("npm:pkgA/shared@2.0.0"));

        // 2. pkgC at top level requiring "shared" must resolve to root shared (1.0.0)
        let resolved_top =
            PackageLockParser::resolve_nearest_ancestor("node_modules/pkgC", "shared", &path_map);
        assert_eq!(resolved_top.as_deref(), Some("npm:shared@1.0.0"));
    }

    #[test]
    fn test_npm_v1_nested_duplicate_versions() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_v1_dup_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let pkg_json = r#"{"name":"v1-dup-app","version":"1.0.0"}"#;
        let lock_json = r#"{
            "name": "v1-dup-app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "parent-a": {
                    "version": "1.0.0",
                    "dependencies": {
                        "shared-transitive": {
                            "version": "1.0.0"
                        }
                    }
                },
                "parent-b": {
                    "version": "1.0.0",
                    "dependencies": {
                        "shared-transitive": {
                            "version": "2.0.0"
                        }
                    }
                }
            }
        }"#;

        std::fs::write(temp_dir.join("package.json"), pkg_json).unwrap();
        let lock_path = temp_dir.join("package-lock.json");
        std::fs::write(&lock_path, lock_json).unwrap();

        let graph = PackageLockParser::parse_file(&lock_path, true)
            .expect("v1 lockfile with nested duplicates must parse");

        let node_a = "npm:parent-a > shared-transitive@1.0.0";
        let node_b = "npm:parent-b > shared-transitive@2.0.0";
        assert!(
            graph.nodes.contains_key(node_a),
            "Node for shared-transitive v1 under parent-a must exist"
        );
        assert!(
            graph.nodes.contains_key(node_b),
            "Node for shared-transitive v2 under parent-b must exist"
        );

        // Assert both package versions are registered
        let pkgs = graph.get_all_pkgs();
        let versions: Vec<&str> = pkgs
            .iter()
            .filter(|p| p.name == "shared-transitive")
            .map(|p| p.version.as_str())
            .collect();
        assert!(versions.contains(&"1.0.0"));
        assert!(versions.contains(&"2.0.0"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
