use crate::core::dep_graph::DepGraph;
use crate::parsers::cargo_lock::CargoLockParser;
use crate::parsers::go_sum::GoLockParser;
use crate::parsers::package_lock::PackageLockParser;
use crate::parsers::pnpm_lock::PnpmLockParser;
use crate::parsers::pom_xml::PomXmlParser;
use crate::parsers::python_reqs::PythonRequirementsParser;
use crate::parsers::yarn_lock::YarnLockParser;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ManifestType {
    #[serde(rename = "npm-shrinkwrap")]
    NpmShrinkwrap,
    #[serde(rename = "npm-package-lock")]
    NpmPackageLock,
    #[serde(rename = "yarn-lock")]
    YarnLock,
    #[serde(rename = "pnpm-lock")]
    PnpmLock,
    #[serde(rename = "python-requirements")]
    PythonRequirements,
    #[serde(rename = "rust-cargo-lock")]
    RustCargoLock,
    #[serde(rename = "go-mod-sum")]
    GoModSum,
    #[serde(rename = "java-maven-pom")]
    JavaMavenPom,
}

impl ManifestType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ManifestType::NpmShrinkwrap => "npm-shrinkwrap",
            ManifestType::NpmPackageLock => "npm-package-lock",
            ManifestType::YarnLock => "yarn-lock",
            ManifestType::PnpmLock => "pnpm-lock",
            ManifestType::PythonRequirements => "python-requirements",
            ManifestType::RustCargoLock => "rust-cargo-lock",
            ManifestType::GoModSum => "go-mod-sum",
            ManifestType::JavaMavenPom => "java-maven-pom",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WorkspaceProject {
    pub manifest_file: PathBuf,
    pub manifest_type: ManifestType,
    pub workspace_name: Option<String>,
    pub graph: DepGraph,
    pub parser_errors: Vec<String>,
}

pub struct DetectionResult {
    pub manifest_type: ManifestType,
    pub graph: DepGraph,
    pub manifest_file: PathBuf,
    pub discovered_projects: Vec<PathBuf>,
    pub projects: Vec<WorkspaceProject>,
    pub failed_manifests: Vec<(PathBuf, String)>,
    pub skipped_manifests: Vec<PathBuf>,
}

pub fn discover_manifests(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut results = Vec::new();
    discover_recursive(root, 0, max_depth, &mut results);
    results.sort();
    results
}

fn discover_recursive(dir: &Path, depth: usize, max_depth: usize, results: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let supported = [
        "npm-shrinkwrap.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "requirements.txt",
        "Cargo.lock",
        "go.sum",
        "pom.xml",
    ];

    for s in &supported {
        let p = dir.join(s);
        if p.is_file() {
            results.push(p);
        }
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.starts_with('.')
                    || name == "node_modules"
                    || name == "target"
                    || name == "vendor"
                    || name == "dist"
                    || name == "build"
                    || name == "inputs"
                    || name == "outputs"
                    || name == "completed"
                    || name == "fixtures"
                    || name == "test-fixtures"
                    || name == ".work"
                {
                    continue;
                }
                discover_recursive(&path, depth + 1, max_depth, results);
            }
        }
    }
}

pub fn parse_manifest_at(
    manifest_path: &Path,
    include_dev: bool,
) -> Result<(ManifestType, DepGraph), String> {
    let file_name = manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let parent_dir = manifest_path.parent().unwrap_or(manifest_path);

    match file_name {
        "npm-shrinkwrap.json" => {
            let graph = PackageLockParser::parse_file(manifest_path, include_dev)?;
            Ok((ManifestType::NpmShrinkwrap, graph))
        }
        "package-lock.json" => {
            let graph = PackageLockParser::parse_file(manifest_path, include_dev)?;
            Ok((ManifestType::NpmPackageLock, graph))
        }
        "yarn.lock" => {
            let graph = YarnLockParser::parse(parent_dir, include_dev)?;
            Ok((ManifestType::YarnLock, graph))
        }
        "pnpm-lock.yaml" | "pnpm-lock.yml" => {
            let graph = PnpmLockParser::parse(parent_dir, include_dev)?;
            Ok((ManifestType::PnpmLock, graph))
        }
        "requirements.txt" => {
            let graph = PythonRequirementsParser::parse(manifest_path)?;
            Ok((ManifestType::PythonRequirements, graph))
        }
        "Cargo.lock" => {
            let graph = CargoLockParser::parse(manifest_path)?;
            Ok((ManifestType::RustCargoLock, graph))
        }
        "go.sum" | "go.mod" => {
            let graph = GoLockParser::parse(parent_dir)?;
            Ok((ManifestType::GoModSum, graph))
        }
        "pom.xml" => {
            let graph = PomXmlParser::parse(manifest_path)?;
            Ok((ManifestType::JavaMavenPom, graph))
        }
        _ => Err(format!(
            "Unsupported manifest file: {}",
            manifest_path.display()
        )),
    }
}

fn collect_additional_discovered_projects(
    discovered_projects: &[PathBuf],
    primary_manifest: &Path,
    primary_graph: &mut DepGraph,
    projects: &mut Vec<WorkspaceProject>,
    failed_manifests: &mut Vec<(PathBuf, String)>,
    include_dev: bool,
) {
    let primary_canon = primary_manifest
        .canonicalize()
        .unwrap_or_else(|_| primary_manifest.to_path_buf());
    let primary_dir = primary_manifest
        .parent()
        .and_then(|d| d.canonicalize().ok())
        .unwrap_or_else(|| primary_manifest.to_path_buf());

    for p in discovered_projects {
        let p_canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        if p_canon == primary_canon {
            continue;
        }
        let p_dir = p.parent().and_then(|d| d.canonicalize().ok());
        if p_dir == Some(primary_dir.clone()) {
            continue; // Skip lower-precedence manifest in the exact same root directory
        }

        match parse_manifest_at(p, include_dev) {
            Ok((mtype, g)) => {
                primary_graph.merge(&g);
                projects.push(WorkspaceProject {
                    manifest_file: p.clone(),
                    manifest_type: mtype,
                    workspace_name: None,
                    graph: g,
                    parser_errors: vec![],
                });
            }
            Err(e) => {
                failed_manifests.push((p.clone(), e));
            }
        }
    }
}

pub fn detect_and_parse(project_dir: &Path, include_dev: bool) -> Result<DetectionResult, String> {
    let abs_path = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());

    // If a direct manifest file path is provided, parse it immediately
    if abs_path.is_file() {
        let (manifest_type, graph) = parse_manifest_at(&abs_path, include_dev)?;
        let project = WorkspaceProject {
            manifest_file: abs_path.clone(),
            manifest_type: manifest_type.clone(),
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        };
        return Ok(DetectionResult {
            manifest_type,
            graph,
            manifest_file: abs_path.clone(),
            discovered_projects: vec![abs_path],
            projects: vec![project],
            failed_manifests: vec![],
            skipped_manifests: vec![],
        });
    }

    let abs_dir = abs_path;
    let discovered_projects = discover_manifests(&abs_dir, 4);

    // Rule 3: npm-shrinkwrap.json takes authoritative precedence over package-lock.json
    let shrinkwrap = abs_dir.join("npm-shrinkwrap.json");
    if shrinkwrap.exists() {
        let mut graph = PackageLockParser::parse_file(&shrinkwrap, include_dev)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: shrinkwrap.clone(),
            manifest_type: ManifestType::NpmShrinkwrap,
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        collect_additional_discovered_projects(
            &discovered_projects,
            &shrinkwrap,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            include_dev,
        );
        return Ok(DetectionResult {
            manifest_type: ManifestType::NpmShrinkwrap,
            graph,
            manifest_file: shrinkwrap,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests: vec![],
        });
    }

    let npm_lock = abs_dir.join("package-lock.json");
    if npm_lock.exists() {
        let mut graph = PackageLockParser::parse(&abs_dir, include_dev)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: npm_lock.clone(),
            manifest_type: ManifestType::NpmPackageLock,
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        collect_additional_discovered_projects(
            &discovered_projects,
            &npm_lock,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            include_dev,
        );
        return Ok(DetectionResult {
            manifest_type: ManifestType::NpmPackageLock,
            graph,
            manifest_file: npm_lock,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests: vec![],
        });
    }

    let yarn_lock = abs_dir.join("yarn.lock");
    if yarn_lock.exists() {
        let mut graph = YarnLockParser::parse(&abs_dir, include_dev)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: yarn_lock.clone(),
            manifest_type: ManifestType::YarnLock,
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        collect_additional_discovered_projects(
            &discovered_projects,
            &yarn_lock,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            include_dev,
        );
        return Ok(DetectionResult {
            manifest_type: ManifestType::YarnLock,
            graph,
            manifest_file: yarn_lock,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests: vec![],
        });
    }

    let pnpm_lock_yaml = abs_dir.join("pnpm-lock.yaml");
    let pnpm_lock_yml = abs_dir.join("pnpm-lock.yml");
    if pnpm_lock_yaml.exists() || pnpm_lock_yml.exists() {
        let main_file = if pnpm_lock_yaml.exists() {
            pnpm_lock_yaml
        } else {
            pnpm_lock_yml
        };
        let mut graph = PnpmLockParser::parse(&abs_dir, include_dev)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: main_file.clone(),
            manifest_type: ManifestType::PnpmLock,
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        collect_additional_discovered_projects(
            &discovered_projects,
            &main_file,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            include_dev,
        );
        return Ok(DetectionResult {
            manifest_type: ManifestType::PnpmLock,
            graph,
            manifest_file: main_file,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests: vec![],
        });
    }

    let req_txt = abs_dir.join("requirements.txt");
    if req_txt.exists() {
        let mut graph = PythonRequirementsParser::parse(&req_txt)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: req_txt.clone(),
            manifest_type: ManifestType::PythonRequirements,
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        collect_additional_discovered_projects(
            &discovered_projects,
            &req_txt,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            include_dev,
        );
        return Ok(DetectionResult {
            manifest_type: ManifestType::PythonRequirements,
            graph,
            manifest_file: req_txt,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests: vec![],
        });
    }

    let cargo_lock = abs_dir.join("Cargo.lock");
    if cargo_lock.exists() {
        let mut graph = CargoLockParser::parse(&cargo_lock)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: cargo_lock.clone(),
            manifest_type: ManifestType::RustCargoLock,
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        collect_additional_discovered_projects(
            &discovered_projects,
            &cargo_lock,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            include_dev,
        );
        return Ok(DetectionResult {
            manifest_type: ManifestType::RustCargoLock,
            graph,
            manifest_file: cargo_lock,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests: vec![],
        });
    }

    let go_sum = abs_dir.join("go.sum");
    let go_mod = abs_dir.join("go.mod");
    if go_sum.exists() || go_mod.exists() {
        let main_file = if go_sum.exists() { go_sum } else { go_mod };
        let mut graph = GoLockParser::parse(&abs_dir)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: main_file.clone(),
            manifest_type: ManifestType::GoModSum,
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        collect_additional_discovered_projects(
            &discovered_projects,
            &main_file,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            include_dev,
        );
        return Ok(DetectionResult {
            manifest_type: ManifestType::GoModSum,
            graph,
            manifest_file: main_file,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests: vec![],
        });
    }

    let pom_xml = abs_dir.join("pom.xml");
    if pom_xml.exists() {
        let mut graph = PomXmlParser::parse(&pom_xml)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: pom_xml.clone(),
            manifest_type: ManifestType::JavaMavenPom,
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        collect_additional_discovered_projects(
            &discovered_projects,
            &pom_xml,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            include_dev,
        );
        return Ok(DetectionResult {
            manifest_type: ManifestType::JavaMavenPom,
            graph,
            manifest_file: pom_xml,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests: vec![],
        });
    }

    // Monorepo / subproject fallback: Parse all discovered manifests and capture failures
    if !discovered_projects.is_empty() {
        let mut parsed_projects = Vec::new();
        let mut failed_manifests = Vec::new();
        let mut merged_graph: Option<DepGraph> = None;
        let mut primary_manifest_type = ManifestType::NpmPackageLock;
        let mut primary_manifest_file = discovered_projects[0].clone();

        for manifest_path in &discovered_projects {
            match parse_manifest_at(manifest_path, include_dev) {
                Ok((mtype, graph)) => {
                    if parsed_projects.is_empty() {
                        primary_manifest_type = mtype.clone();
                        primary_manifest_file = manifest_path.clone();
                        merged_graph = Some(graph.clone());
                    } else if let Some(ref mut mg) = merged_graph {
                        mg.merge(&graph);
                    }
                    parsed_projects.push(WorkspaceProject {
                        manifest_file: manifest_path.clone(),
                        manifest_type: mtype,
                        workspace_name: None,
                        graph,
                        parser_errors: vec![],
                    });
                }
                Err(e) => {
                    failed_manifests.push((manifest_path.clone(), e));
                }
            }
        }

        if let Some(graph) = merged_graph {
            return Ok(DetectionResult {
                manifest_type: primary_manifest_type,
                graph,
                manifest_file: primary_manifest_file,
                discovered_projects,
                projects: parsed_projects,
                failed_manifests,
                skipped_manifests: vec![],
            });
        }

        if !failed_manifests.is_empty() {
            let first_err = &failed_manifests[0];
            return Err(format!(
                "Failed to parse manifest at {}: {}",
                first_err.0.display(),
                first_err.1
            ));
        }
    }

    // Check if subdirectories contain manifests to provide helpful monorepo guidance
    let mut sub_hints = Vec::new();
    let unbuilt_manifest_names = [
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "Cargo.toml",
        "requirements.txt",
        "go.mod",
        "pom.xml",
    ];

    if let Ok(entries) = std::fs::read_dir(&abs_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let dirname = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if dirname.starts_with('.') || dirname == "node_modules" || dirname == "target" {
                    continue;
                }
                for mf in &unbuilt_manifest_names {
                    if p.join(mf).exists() {
                        sub_hints.push(format!("{}/{}", dirname, mf));
                        break;
                    }
                }
            }
        }
    }

    let monorepo_msg = if !sub_hints.is_empty() {
        format!(
            "\n💡 Discovered subproject manifests: {}\n   Run vexa-sca directly in subdirectories or build root lockfiles.",
            sub_hints.join(", ")
        )
    } else {
        String::new()
    };

    Err(format!(
        "No supported lockfile found in {}. Supported: package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, go.sum, requirements.txt, pom.xml.{}",
        abs_dir.display(),
        monorepo_msg
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_manifests_multi_project() {
        let root = Path::new("test/fixtures");
        let discovered = discover_manifests(root, 3);
        assert!(!discovered.is_empty());
    }

    #[test]
    fn test_detect_and_parse_all_fixtures() {
        let npm_app = Path::new("test/fixtures/npm-app");
        let res = detect_and_parse(npm_app, true).unwrap();
        assert_eq!(res.manifest_type, ManifestType::NpmPackageLock);
        assert!(!res.projects.is_empty());

        let pnpm_app = Path::new("test/fixtures/pnpm-app");
        let res2 = detect_and_parse(pnpm_app, true).unwrap();
        assert_eq!(res2.manifest_type, ManifestType::PnpmLock);
        assert!(!res2.projects.is_empty());
    }

    #[test]
    fn test_npm_shrinkwrap_precedence_over_package_lock() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_shrinkwrap_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let pkg_json = r#"{"name":"test-shrinkwrap","version":"1.0.0"}"#;
        let shrinkwrap_json = r#"{
            "name": "test-shrinkwrap",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "packages": {
                "": { "name": "test-shrinkwrap", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.21" }
            }
        }"#;
        let package_lock_json = r#"{
            "name": "test-shrinkwrap",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "packages": {
                "": { "name": "test-shrinkwrap", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.15" }
            }
        }"#;

        std::fs::write(temp_dir.join("package.json"), pkg_json).unwrap();
        std::fs::write(temp_dir.join("npm-shrinkwrap.json"), shrinkwrap_json).unwrap();
        std::fs::write(temp_dir.join("package-lock.json"), package_lock_json).unwrap();

        let res = detect_and_parse(&temp_dir, true).unwrap();
        assert_eq!(
            res.manifest_type,
            ManifestType::NpmShrinkwrap,
            "npm-shrinkwrap must take precedence over package-lock"
        );
        let expected_file = temp_dir
            .join("npm-shrinkwrap.json")
            .canonicalize()
            .unwrap_or_else(|_| temp_dir.join("npm-shrinkwrap.json"));
        let actual_file = res
            .manifest_file
            .canonicalize()
            .unwrap_or_else(|_| res.manifest_file.clone());
        assert_eq!(actual_file, expected_file);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_monorepo_root_npm_plus_nested_pnpm() {
        let fixture_dir = Path::new("test/fixtures/monorepo-root-npm-plus-nested-pnpm");
        let res = detect_and_parse(fixture_dir, true)
            .expect("should detect and parse monorepo with root npm and nested pnpm");

        assert_eq!(res.manifest_type, ManifestType::NpmPackageLock);
        assert_eq!(
            res.projects.len(),
            2,
            "Both root npm and nested pnpm projects must be preserved"
        );

        let project_types: Vec<ManifestType> = res
            .projects
            .iter()
            .map(|p| p.manifest_type.clone())
            .collect();
        assert!(project_types.contains(&ManifestType::NpmPackageLock));
        assert!(project_types.contains(&ManifestType::PnpmLock));

        // Both packages should be merged into the dependency graph
        let pkgs = res.graph.get_all_pkgs();
        let pkg_names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(
            pkg_names.contains(&"lodash"),
            "Graph must contain root dependency lodash"
        );
        assert!(
            pkg_names.contains(&"minimist"),
            "Graph must contain nested dependency minimist"
        );
    }
}
