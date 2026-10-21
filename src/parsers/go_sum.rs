use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub struct GoLockParser;

impl GoLockParser {
    pub fn parse(path_or_dir: &Path) -> Result<DepGraph, String> {
        let (project_dir, go_sum_path, go_mod_path) = if path_or_dir.is_dir() {
            (
                path_or_dir.to_path_buf(),
                path_or_dir.join("go.sum"),
                path_or_dir.join("go.mod"),
            )
        } else {
            let parent = path_or_dir.parent().unwrap_or(Path::new(".")).to_path_buf();
            (parent.clone(), parent.join("go.sum"), parent.join("go.mod"))
        };

        if !go_sum_path.exists() && !go_mod_path.exists() {
            return Err(format!(
                "Neither go.sum nor go.mod found in {}",
                project_dir.display()
            ));
        }

        let root_module_name = Self::read_root_module_name(&go_mod_path).unwrap_or_else(|| {
            project_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("go-app")
                .to_string()
        });

        let root_pkg = PkgInfo::new(root_module_name, "1.0.0", "Go");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "go".to_string(),
                version: "mod".to_string(),
            },
        );

        if go_sum_path.exists() {
            Self::parse_go_sum(&mut graph, &go_sum_path)?;
        } else {
            Self::parse_go_mod(&mut graph, &go_mod_path)?;
        }

        Ok(graph)
    }

    fn read_root_module_name(go_mod_path: &Path) -> Option<String> {
        if !go_mod_path.exists() {
            return None;
        }
        let content = fs::read_to_string(go_mod_path).ok()?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("module ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    return Some(parts[1].to_string());
                }
            }
        }
        None
    }

    fn parse_go_sum(graph: &mut DepGraph, go_sum_path: &Path) -> Result<(), String> {
        let content =
            fs::read_to_string(go_sum_path).map_err(|e| format!("Failed to read go.sum: {}", e))?;
        let mut seen = HashSet::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let pkg_name = parts[0];
                let mut raw_ver = parts[1];
                if raw_ver.ends_with("/go.mod") {
                    raw_ver = &raw_ver[..raw_ver.len() - 7];
                }
                let version = raw_ver.trim_start_matches('v');

                let key = format!("{}@{}", pkg_name, version);
                if !seen.contains(&key) {
                    seen.insert(key);

                    let pkg_info = PkgInfo::new(pkg_name, version, "Go");
                    graph.add_pkg(pkg_info.clone());

                    let node_id = format!("go:{}@{}", pkg_name, version);
                    graph.add_node(
                        node_id.clone(),
                        pkg_info.id,
                        NodeInfo {
                            scope: "prod".to_string(),
                            path: None,
                            integrity: None,
                        },
                    );

                    let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);
                }
            }
        }

        Ok(())
    }

    fn parse_go_mod(graph: &mut DepGraph, go_mod_path: &Path) -> Result<(), String> {
        let content =
            fs::read_to_string(go_mod_path).map_err(|e| format!("Failed to read go.mod: {}", e))?;
        let mut in_require = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }

            if trimmed == "require (" {
                in_require = true;
                continue;
            }
            if trimmed == ")" && in_require {
                in_require = false;
                continue;
            }

            let req_line = if in_require {
                Some(trimmed)
            } else if trimmed.starts_with("require ") {
                Some(trimmed.trim_start_matches("require ").trim())
            } else {
                None
            };

            if let Some(r) = req_line {
                let parts: Vec<&str> = r.split_whitespace().collect();
                if parts.len() >= 2 {
                    let pkg_name = parts[0];
                    let version = parts[1].trim_start_matches('v');

                    let pkg_info = PkgInfo::new(pkg_name, version, "Go");
                    graph.add_pkg(pkg_info.clone());

                    let node_id = format!("go:{}@{}", pkg_name, version);
                    graph.add_node(
                        node_id.clone(),
                        pkg_info.id,
                        NodeInfo {
                            scope: "prod".to_string(),
                            path: None,
                            integrity: None,
                        },
                    );

                    let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_go_lock_parser_fixture() {
        let fixture_dir = Path::new("test/fixtures/go-app");
        let graph = GoLockParser::parse(fixture_dir).expect("should parse go.sum");

        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();

        assert!(names.contains(&"github.com/gin-gonic/gin"));
        assert!(names.contains(&"golang.org/x/crypto"));

        let gin = pkgs
            .iter()
            .find(|p| p.name == "github.com/gin-gonic/gin")
            .unwrap();
        assert_eq!(gin.version, "1.7.0");
        assert_eq!(gin.ecosystem, "Go");
    }
}
