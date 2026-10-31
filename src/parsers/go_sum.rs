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

        if go_mod_path.exists() {
            Self::parse_go_mod(&mut graph, &go_mod_path)?;
            if go_sum_path.exists() {
                Self::enrich_integrity_from_go_sum(&mut graph, &go_sum_path)?;
            }
        } else if go_sum_path.exists() {
            Self::parse_go_sum(&mut graph, &go_sum_path)?;
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

    fn enrich_integrity_from_go_sum(graph: &mut DepGraph, go_sum_path: &Path) -> Result<(), String> {
        let content =
            fs::read_to_string(go_sum_path).map_err(|e| format!("Failed to read go.sum: {}", e))?;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 3 {
                let pkg_name = parts[0];
                let mut raw_ver = parts[1];
                if raw_ver.ends_with("/go.mod") {
                    raw_ver = &raw_ver[..raw_ver.len() - 7];
                }
                let version = raw_ver.trim_start_matches('v');
                let checksum = parts[2];

                let node_id = format!("go:{}@{}", pkg_name, version);
                if let Some(node) = graph.nodes.get_mut(&node_id) {
                    if node.info.integrity.is_none() {
                        node.info.integrity = Some(checksum.to_string());
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_go_mod(graph: &mut DepGraph, go_mod_path: &Path) -> Result<(), String> {
        let content =
            fs::read_to_string(go_mod_path).map_err(|e| format!("Failed to read go.mod: {}", e))?;

        let mut in_require = false;
        let mut in_replace = false;
        let mut in_exclude = false;

        let mut raw_requirements: Vec<(String, String)> = Vec::new();
        let mut replacements: Vec<(String, Option<String>, String, Option<String>)> = Vec::new();
        let mut exclusions: HashSet<(String, String)> = HashSet::new();

        for line in content.lines() {
            let mut trimmed = line.trim();
            if let Some(idx) = trimmed.find("//") {
                trimmed = trimmed[..idx].trim();
            }
            if trimmed.is_empty() {
                continue;
            }

            // Block boundaries
            if trimmed == "require (" {
                in_require = true;
                continue;
            }
            if trimmed == "replace (" {
                in_replace = true;
                continue;
            }
            if trimmed == "exclude (" {
                in_exclude = true;
                continue;
            }
            if trimmed == ")" {
                in_require = false;
                in_replace = false;
                in_exclude = false;
                continue;
            }

            // Require directives
            if in_require || trimmed.starts_with("require ") {
                let text = if in_require {
                    trimmed
                } else {
                    trimmed.trim_start_matches("require ").trim()
                };
                let parts: Vec<&str> = text.split_whitespace().collect();
                if parts.len() >= 2 {
                    let pkg = parts[0].to_string();
                    let ver = parts[1].trim_start_matches('v').to_string();
                    raw_requirements.push((pkg, ver));
                }
                continue;
            }

            // Replace directives: replace old [v1] => new [v2]
            if in_replace || trimmed.starts_with("replace ") {
                let text = if in_replace {
                    trimmed
                } else {
                    trimmed.trim_start_matches("replace ").trim()
                };
                if let Some((left, right)) = text.split_once("=>") {
                    let left_parts: Vec<&str> = left.split_whitespace().collect();
                    let right_parts: Vec<&str> = right.split_whitespace().collect();
                    if !left_parts.is_empty() && !right_parts.is_empty() {
                        let old_pkg = left_parts[0].to_string();
                        let old_ver = if left_parts.len() > 1 {
                            Some(left_parts[1].trim_start_matches('v').to_string())
                        } else {
                            None
                        };
                        let new_pkg = right_parts[0].to_string();
                        let new_ver = if right_parts.len() > 1 {
                            Some(right_parts[1].trim_start_matches('v').to_string())
                        } else {
                            None
                        };
                        replacements.push((old_pkg, old_ver, new_pkg, new_ver));
                    }
                }
                continue;
            }

            // Exclude directives: exclude pkg v1.2.3
            if in_exclude || trimmed.starts_with("exclude ") {
                let text = if in_exclude {
                    trimmed
                } else {
                    trimmed.trim_start_matches("exclude ").trim()
                };
                let parts: Vec<&str> = text.split_whitespace().collect();
                if parts.len() >= 2 {
                    let pkg = parts[0].to_string();
                    let ver = parts[1].trim_start_matches('v').to_string();
                    exclusions.insert((pkg, ver));
                }
                continue;
            }
        }

        // Apply exclusions and replacements
        for (pkg, ver) in raw_requirements {
            if exclusions.contains(&(pkg.clone(), ver.clone())) {
                continue;
            }

            // Check if there is a replacement
            let mut resolved_pkg = pkg.clone();
            let mut resolved_ver = ver.clone();

            for (old_p, old_v, new_p, new_v) in &replacements {
                if old_p == &pkg {
                    if let Some(ov) = old_v {
                        if ov == &ver {
                            resolved_pkg = new_p.clone();
                            if let Some(nv) = new_v {
                                resolved_ver = nv.clone();
                            }
                            break;
                        }
                    } else {
                        resolved_pkg = new_p.clone();
                        if let Some(nv) = new_v {
                            resolved_ver = nv.clone();
                        }
                        break;
                    }
                }
            }

            let pkg_info = PkgInfo::new(&resolved_pkg, &resolved_ver, "Go");
            graph.add_pkg(pkg_info.clone());

            let node_id = format!("go:{}@{}", resolved_pkg, resolved_ver);
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

    #[test]
    fn test_go_mod_replace_and_exclude() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_test_go_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let go_mod = temp_dir.join("go.mod");
        fs::write(
            &go_mod,
            r#"
module example.com/testservice

go 1.21

require (
    golang.org/x/crypto v0.1.0
    github.com/old/module v1.0.0
    github.com/bad/lib v0.5.0
)

replace github.com/old/module v1.0.0 => github.com/new/fork v2.0.0
exclude github.com/bad/lib v0.5.0
"#,
        )
        .unwrap();

        let graph = GoLockParser::parse(&temp_dir).expect("should parse go.mod");
        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();

        assert!(names.contains(&"golang.org/x/crypto"));
        assert!(names.contains(&"github.com/new/fork"));
        assert!(!names.contains(&"github.com/bad/lib"));
        assert!(!names.contains(&"github.com/old/module"));

        let fork = pkgs.iter().find(|p| p.name == "github.com/new/fork").unwrap();
        assert_eq!(fork.version, "2.0.0");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
