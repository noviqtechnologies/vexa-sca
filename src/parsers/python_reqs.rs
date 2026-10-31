#![forbid(unsafe_code)]

use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::{PackageResolutionState, PkgInfo};
use std::fs;
use std::path::Path;

pub struct PythonRequirementsParser;

impl PythonRequirementsParser {
    pub fn parse(path_or_dir: &Path) -> Result<DepGraph, String> {
        let (project_dir, req_path) = if path_or_dir.is_dir() {
            // Check in priority order: uv.lock > poetry.lock > Pipfile.lock > requirements.txt
            if path_or_dir.join("uv.lock").exists() {
                (path_or_dir.to_path_buf(), path_or_dir.join("uv.lock"))
            } else if path_or_dir.join("poetry.lock").exists() {
                (path_or_dir.to_path_buf(), path_or_dir.join("poetry.lock"))
            } else if path_or_dir.join("Pipfile.lock").exists() {
                (path_or_dir.to_path_buf(), path_or_dir.join("Pipfile.lock"))
            } else {
                (
                    path_or_dir.to_path_buf(),
                    path_or_dir.join("requirements.txt"),
                )
            }
        } else {
            (
                path_or_dir.parent().unwrap_or(Path::new(".")).to_path_buf(),
                path_or_dir.to_path_buf(),
            )
        };

        if !req_path.exists() {
            return Err(format!(
                "Python manifest not found at {}",
                req_path.display()
            ));
        }

        let file_name = req_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if file_name == "uv.lock" || file_name == "poetry.lock" {
            Self::parse_toml_lockfile(&project_dir, &req_path, file_name)
        } else if file_name == "Pipfile.lock" {
            Self::parse_pipfile_lock(&project_dir, &req_path)
        } else {
            Self::parse_requirements_txt(&project_dir, &req_path, 0)
        }
    }

    fn parse_toml_lockfile(
        project_dir: &Path,
        lock_path: &Path,
        manager_name: &str,
    ) -> Result<DepGraph, String> {
        let content = fs::read_to_string(lock_path)
            .map_err(|e| format!("Failed to read {}: {}", lock_path.display(), e))?;

        let parsed: toml::Value = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse TOML in {}: {}", lock_path.display(), e))?;

        let root_name = project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("python-app");

        let root_pkg = PkgInfo::new(root_name, "1.0.0", "PyPI");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: manager_name.replace(".lock", ""),
                version: manager_name.to_string(),
            },
        );

        if let Some(packages) = parsed.get("package").and_then(|p| p.as_array()) {
            for pkg in packages {
                if let (Some(name), Some(version)) = (
                    pkg.get("name").and_then(|n| n.as_str()),
                    pkg.get("version").and_then(|v| v.as_str()),
                ) {
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
        }

        Ok(graph)
    }

    fn parse_pipfile_lock(project_dir: &Path, lock_path: &Path) -> Result<DepGraph, String> {
        let content = fs::read_to_string(lock_path)
            .map_err(|e| format!("Failed to read {}: {}", lock_path.display(), e))?;

        let parsed: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse JSON in {}: {}", lock_path.display(), e))?;

        let root_name = project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("python-app");

        let root_pkg = PkgInfo::new(root_name, "1.0.0", "PyPI");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "pipenv".to_string(),
                version: "Pipfile.lock".to_string(),
            },
        );

        let sections = ["default", "develop"];
        for section in sections {
            if let Some(pkgs) = parsed.get(section).and_then(|s| s.as_object()) {
                for (name, details) in pkgs {
                    let version_raw = details
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("*");
                    let clean_ver = version_raw.trim_start_matches("==").trim();

                    let pkg_info = PkgInfo::new(name, clean_ver, "PyPI");
                    graph.add_pkg(pkg_info.clone());

                    let node_id = format!("pip:{}@{}", name, clean_ver);
                    graph.add_node(
                        node_id.clone(),
                        pkg_info.id,
                        NodeInfo {
                            scope: if section == "default" {
                                "prod".to_string()
                            } else {
                                "dev".to_string()
                            },
                            path: None,
                            integrity: None,
                        },
                    );

                    let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);
                }
            }
        }

        Ok(graph)
    }

    fn parse_requirements_txt(
        project_dir: &Path,
        req_path: &Path,
        recursion_depth: usize,
    ) -> Result<DepGraph, String> {
        if recursion_depth > 5 {
            return Err("Maximum recursive requirements include depth (5) exceeded".to_string());
        }

        let content = fs::read_to_string(req_path)
            .map_err(|e| format!("Failed to read {}: {}", req_path.display(), e))?;

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

            // Support -r other.txt recursive includes (up to depth 5, canonicalized within repo root to prevent traversal)
            if let Some(included) = trimmed
                .strip_prefix("-r ")
                .or_else(|| trimmed.strip_prefix("--requirement "))
            {
                let included_path = req_path
                    .parent()
                    .unwrap_or(Path::new("."))
                    .join(included.trim());
                let root_canon = project_dir
                    .canonicalize()
                    .unwrap_or_else(|_| project_dir.to_path_buf());
                if let Ok(inc_canon) = included_path.canonicalize() {
                    if inc_canon.starts_with(&root_canon) && inc_canon.exists() && recursion_depth < 5 {
                        if let Ok(sub_graph) =
                            Self::parse_requirements_txt(project_dir, &inc_canon, recursion_depth + 1)
                        {
                            graph.merge(&sub_graph);
                        }
                    }
                }
                continue;
            }

            // Clean inline comments and environment markers: e.g. "flask==0.12.2 ; python_version >= '3.6'"
            let base = trimmed.split(';').next().unwrap_or("").trim();
            let base = base.split('#').next().unwrap_or("").trim();
            if base.is_empty() {
                continue;
            }

            let (name, resolution_state) = Self::parse_specifier(base);

            if !name.is_empty() {
                let version = match &resolution_state {
                    PackageResolutionState::Pinned(v) => v.clone(),
                    PackageResolutionState::UnpinnedRange { constraint } => {
                        eprintln!(
                            "WARNING: Completeness warning - package '{}' has unpinned range '{}' in {}. Querying lower bound as exact version is disabled.",
                            name, constraint, req_path.display()
                        );
                        "*".to_string()
                    }
                    PackageResolutionState::Unconstrained => {
                        eprintln!(
                            "WARNING: Completeness warning - package '{}' has unpinned/unconstrained version in {}.",
                            name, req_path.display()
                        );
                        "*".to_string()
                    }
                };

                let pkg_info = PkgInfo::new(name, &version, "PyPI");
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

    pub fn parse_specifier(base: &str) -> (&str, PackageResolutionState) {
        // Order matters: check "===" before "=="
        if let Some(idx) = base.find("===") {
            let (n, v) = base.split_at(idx);
            (
                n.trim(),
                PackageResolutionState::Pinned(v.trim_start_matches("===").trim().to_string()),
            )
        } else if let Some(idx) = base.find("==") {
            let (n, v) = base.split_at(idx);
            (
                n.trim(),
                PackageResolutionState::Pinned(v.trim_start_matches("==").trim().to_string()),
            )
        } else if let Some(idx) = base.find(">=") {
            let (n, v) = base.split_at(idx);
            (
                n.trim(),
                PackageResolutionState::UnpinnedRange {
                    constraint: v.trim().to_string(),
                },
            )
        } else if let Some(idx) = base.find("~=") {
            let (n, v) = base.split_at(idx);
            (
                n.trim(),
                PackageResolutionState::UnpinnedRange {
                    constraint: v.trim().to_string(),
                },
            )
        } else if let Some(idx) = base.find("<=") {
            let (n, v) = base.split_at(idx);
            (
                n.trim(),
                PackageResolutionState::UnpinnedRange {
                    constraint: v.trim().to_string(),
                },
            )
        } else if let Some(idx) = base.find('<') {
            let (n, v) = base.split_at(idx);
            (
                n.trim(),
                PackageResolutionState::UnpinnedRange {
                    constraint: v.trim().to_string(),
                },
            )
        } else if let Some(idx) = base.find('>') {
            let (n, v) = base.split_at(idx);
            (
                n.trim(),
                PackageResolutionState::UnpinnedRange {
                    constraint: v.trim().to_string(),
                },
            )
        } else if let Some(idx) = base.find("!=") {
            let (n, v) = base.split_at(idx);
            (
                n.trim(),
                PackageResolutionState::UnpinnedRange {
                    constraint: v.trim().to_string(),
                },
            )
        } else {
            (base.trim(), PackageResolutionState::Unconstrained)
        }
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

    #[test]
    fn test_parse_toml_uv_lock() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_test_uv_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let uv_lock = temp_dir.join("uv.lock");
        fs::write(
            &uv_lock,
            r#"
version = 1
revision = 1

[[package]]
name = "httpx"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pydantic"
version = "2.7.1"
source = { registry = "https://pypi.org/simple" }
"#,
        )
        .unwrap();

        let graph = PythonRequirementsParser::parse(&uv_lock).expect("should parse uv.lock");
        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"httpx"));
        assert!(names.contains(&"pydantic"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_python_specifier_pinning_and_unpinned_ranges() {
        let (name, state) = PythonRequirementsParser::parse_specifier("requests==2.31.0");
        assert_eq!(name, "requests");
        assert_eq!(state, PackageResolutionState::Pinned("2.31.0".to_string()));

        let (name, state) = PythonRequirementsParser::parse_specifier("urllib3===1.26.5");
        assert_eq!(name, "urllib3");
        assert_eq!(state, PackageResolutionState::Pinned("1.26.5".to_string()));

        let (name, state) = PythonRequirementsParser::parse_specifier("django>=4.2.0");
        assert_eq!(name, "django");
        assert_eq!(
            state,
            PackageResolutionState::UnpinnedRange {
                constraint: ">=4.2.0".to_string()
            }
        );

        let (name, state) = PythonRequirementsParser::parse_specifier("fastapi~=0.100.0");
        assert_eq!(name, "fastapi");
        assert_eq!(
            state,
            PackageResolutionState::UnpinnedRange {
                constraint: "~=0.100.0".to_string()
            }
        );

        let (name, state) = PythonRequirementsParser::parse_specifier("pytest<8.0.0");
        assert_eq!(name, "pytest");
        assert_eq!(
            state,
            PackageResolutionState::UnpinnedRange {
                constraint: "<8.0.0".to_string()
            }
        );
    }
}
