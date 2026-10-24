use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use std::fs;
use std::path::Path;

pub struct PythonRequirementsParser;

impl PythonRequirementsParser {
    pub fn parse(path_or_dir: &Path) -> Result<DepGraph, String> {
        let (project_dir, req_path) = if path_or_dir.is_dir() {
            (
                path_or_dir.to_path_buf(),
                path_or_dir.join("requirements.txt"),
            )
        } else {
            (
                path_or_dir.parent().unwrap_or(Path::new(".")).to_path_buf(),
                path_or_dir.to_path_buf(),
            )
        };

        if !req_path.exists() {
            return Err(format!(
                "requirements.txt not found at {}",
                req_path.display()
            ));
        }

        let content = fs::read_to_string(&req_path)
            .map_err(|e| format!("Failed to read requirements.txt: {}", e))?;

        let root_name = project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("python-app");

        let root_pkg = PkgInfo::new(root_name, "1.0.0", "PyPI");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "pip".to_string(),
                version: "requirements.txt".to_string(),
            },
        );

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Clean inline comments and environment markers: e.g. "flask==0.12.2 ; python_version >= '3.6'"
            let base = trimmed.split(';').next().unwrap_or("").trim();
            let base = base.split('#').next().unwrap_or("").trim();
            if base.is_empty() {
                continue;
            }

            let (name, version) = if let Some(idx) = base.find("==") {
                let (n, v) = base.split_at(idx);
                (n.trim(), v.trim_start_matches("==").trim())
            } else if let Some(idx) = base.find(">=") {
                let (n, v) = base.split_at(idx);
                (n.trim(), v.trim_start_matches(">=").trim())
            } else if let Some(idx) = base.find("~=") {
                let (n, v) = base.split_at(idx);
                (n.trim(), v.trim_start_matches("~=").trim())
            } else {
                (base, "*")
            };

            if !name.is_empty() {
                let pkg_info = PkgInfo::new(name, version, "PyPI");
                graph.add_pkg(pkg_info.clone());

                let node_id = format!("pip:{}@{}", name, version);
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

        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_requirements_parser_fixture() {
        let fixture_dir = Path::new("test/fixtures/python-app");
        let graph =
            PythonRequirementsParser::parse(fixture_dir).expect("should parse requirements.txt");

        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();

        assert!(names.contains(&"flask"));
        assert!(names.contains(&"requests"));

        let flask = pkgs.iter().find(|p| p.name == "flask").unwrap();
        assert_eq!(flask.version, "0.12.2");
    }
}
