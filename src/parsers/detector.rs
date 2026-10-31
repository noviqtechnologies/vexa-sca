#![forbid(unsafe_code)]

use crate::core::dep_graph::DepGraph;
use crate::parsers::cargo_lock::CargoLockParser;
use crate::parsers::go_sum::GoLockParser;
use crate::parsers::package_lock::PackageLockParser;
use crate::parsers::pnpm_lock::PnpmLockParser;
use crate::parsers::pom_xml::PomXmlParser;
use crate::parsers::python_reqs::PythonRequirementsParser;
use crate::parsers::yarn_lock::YarnLockParser;
use crate::types::Ecosystem;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const MAX_MANIFEST_SIZE_BYTES: u64 = 15 * 1024 * 1024; // 15 MB payload cap

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum ManifestEcosystem {
    Npm,
    Python,
    Rust,
    Go,
    Maven,
}

impl From<ManifestEcosystem> for Ecosystem {
    fn from(eco: ManifestEcosystem) -> Self {
        match eco {
            ManifestEcosystem::Npm => Ecosystem::Npm,
            ManifestEcosystem::Python => Ecosystem::PyPi,
            ManifestEcosystem::Rust => Ecosystem::CratesIo,
            ManifestEcosystem::Go => Ecosystem::Go,
            ManifestEcosystem::Maven => Ecosystem::Maven,
        }
    }
}

pub fn ecosystem_for_manifest_name(file_name: &str) -> Option<ManifestEcosystem> {
    match file_name {
        "npm-shrinkwrap.json"
        | "package-lock.json"
        | "yarn.lock"
        | "pnpm-lock.yaml"
        | "pnpm-lock.yml" => Some(ManifestEcosystem::Npm),
        "requirements.txt" | "uv.lock" | "poetry.lock" | "Pipfile.lock" => {
            Some(ManifestEcosystem::Python)
        }
        "Cargo.lock" => Some(ManifestEcosystem::Rust),
        "go.mod" | "go.sum" => Some(ManifestEcosystem::Go),
        "pom.xml" | "gradle.lockfile" => Some(ManifestEcosystem::Maven),
        _ => None,
    }
}

pub fn manifest_priority_rank(file_name: &str) -> usize {
    match file_name {
        "npm-shrinkwrap.json" => 1,
        "package-lock.json" => 2,
        "pnpm-lock.yaml" | "pnpm-lock.yml" => 3,
        "yarn.lock" => 4,

        "uv.lock" => 1,
        "poetry.lock" => 2,
        "Pipfile.lock" => 3,
        "requirements.txt" => 4,

        "Cargo.lock" => 1,

        "go.mod" => 1,
        "go.sum" => 2,

        "gradle.lockfile" => 1,
        "pom.xml" => 2,

        _ => 99,
    }
}

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

#[derive(Debug, Clone)]
pub struct DiscoveredManifest {
    pub path: PathBuf,
    pub ecosystem: Ecosystem,
    pub manifest_type: ManifestType,
    pub graph: DepGraph,
}

#[derive(Debug, Clone)]
pub enum ParseError {
    NotFound(String),
    Io(String),
    Malformed(String),
    Unsupported(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(s) => write!(f, "Manifest not found: {}", s),
            Self::Io(s) => write!(f, "I/O error reading manifest: {}", s),
            Self::Malformed(s) => write!(f, "Malformed manifest: {}", s),
            Self::Unsupported(s) => write!(f, "Unsupported manifest: {}", s),
        }
    }
}

impl std::error::Error for ParseError {}

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
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "go.mod",
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
    if let Ok(metadata) = std::fs::metadata(manifest_path) {
        if metadata.len() > MAX_MANIFEST_SIZE_BYTES {
            return Err(format!(
                "Manifest {} exceeds maximum size limit of 15 MB",
                manifest_path.display()
            ));
        }
    }

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
        "requirements.txt" | "uv.lock" | "poetry.lock" | "Pipfile.lock" => {
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
    skipped_manifests: &mut Vec<PathBuf>,
    include_dev: bool,
) {
    let primary_canon = primary_manifest
        .canonicalize()
        .unwrap_or_else(|_| primary_manifest.to_path_buf());
    let primary_dir = primary_manifest
        .parent()
        .and_then(|d| d.canonicalize().ok())
        .unwrap_or_else(|| primary_manifest.to_path_buf());

    let primary_name = primary_manifest
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let primary_eco = ecosystem_for_manifest_name(primary_name);

    // Group candidates by (canonical_dir, ecosystem) to pick highest priority per ecosystem
    let mut selected_by_dir_eco: HashMap<PathBuf, HashMap<ManifestEcosystem, (PathBuf, usize)>> =
        HashMap::new();

    if let Some(eco) = primary_eco {
        let mut map = HashMap::new();
        map.insert(
            eco,
            (primary_canon.clone(), manifest_priority_rank(primary_name)),
        );
        selected_by_dir_eco.insert(primary_dir, map);
    }

    // Pass 1: Select highest-priority manifest per (dir, ecosystem)
    for p in discovered_projects {
        let p_canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        if p_canon == primary_canon {
            continue;
        }
        let Some(p_dir) = p.parent().and_then(|d| d.canonicalize().ok()) else {
            continue;
        };
        let p_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Some(p_eco) = ecosystem_for_manifest_name(p_name) else {
            continue;
        };
        let p_rank = manifest_priority_rank(p_name);

        let dir_map = selected_by_dir_eco.entry(p_dir).or_default();
        match dir_map.get(&p_eco) {
            Some((_curr_path, curr_rank)) if *curr_rank <= p_rank => {
                // Keep the higher or equal precedence manifest for this ecosystem in this dir
            }
            _ => {
                dir_map.insert(p_eco, (p_canon.clone(), p_rank));
            }
        }
    }

    // Pass 2: Parse all selected manifests, record skipped ones
    for p in discovered_projects {
        let p_canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        if p_canon == primary_canon {
            continue;
        }
        let Some(p_dir) = p.parent().and_then(|d| d.canonicalize().ok()) else {
            continue;
        };
        let p_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Some(p_eco) = ecosystem_for_manifest_name(p_name) else {
            continue;
        };

        if let Some(dir_map) = selected_by_dir_eco.get(&p_dir) {
            if let Some((selected_path, _)) = dir_map.get(&p_eco) {
                if selected_path == &p_canon {
                    // Selected manifest for this ecosystem in this directory -> parse and merge
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
                    continue;
                }
            }
        }

        // Otherwise skipped due to lower precedence for the same ecosystem in this directory
        skipped_manifests.push(p.clone());
    }
}

/// Discovers and parses all workspace manifests grouped by directory and ecosystem (DDD §3.1.1, BUG-001)
pub fn detect_workspace_manifests(root: &Path) -> Result<Vec<DiscoveredManifest>, ParseError> {
    let abs_path = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    if abs_path.is_file() {
        let (manifest_type, graph) =
            parse_manifest_at(&abs_path, false).map_err(ParseError::Malformed)?;
        let name = abs_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ecosystem = ecosystem_for_manifest_name(name)
            .map(Ecosystem::from)
            .unwrap_or(Ecosystem::Other("unknown".to_string()));
        return Ok(vec![DiscoveredManifest {
            path: abs_path,
            ecosystem,
            manifest_type,
            graph,
        }]);
    }

    let discovered = discover_manifests(&abs_path, 4);
    if discovered.is_empty() {
        return Err(ParseError::NotFound(format!(
            "No supported lockfile manifests found in {}",
            root.display()
        )));
    }

    let mut selected_by_dir_eco: HashMap<PathBuf, HashMap<ManifestEcosystem, (PathBuf, usize)>> =
        HashMap::new();

    for p in &discovered {
        let p_canon = p.canonicalize().unwrap_or_else(|_| p.clone());
        let Some(p_dir) = p.parent().and_then(|d| d.canonicalize().ok()) else {
            continue;
        };
        let p_name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Some(p_eco) = ecosystem_for_manifest_name(p_name) else {
            continue;
        };
        let p_rank = manifest_priority_rank(p_name);

        let dir_map = selected_by_dir_eco.entry(p_dir).or_default();
        match dir_map.get(&p_eco) {
            Some((_curr_path, curr_rank)) if *curr_rank <= p_rank => {}
            _ => {
                dir_map.insert(p_eco, (p_canon.clone(), p_rank));
            }
        }
    }

    let mut manifests = Vec::new();
    for (_dir, eco_map) in selected_by_dir_eco {
        for (eco, (selected_path, _)) in eco_map {
            match parse_manifest_at(&selected_path, false) {
                Ok((manifest_type, graph)) => {
                    manifests.push(DiscoveredManifest {
                        path: selected_path,
                        ecosystem: Ecosystem::from(eco),
                        manifest_type,
                        graph,
                    });
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to parse manifest {}: {}",
                        selected_path.display(),
                        e
                    );
                }
            }
        }
    }

    if manifests.is_empty() {
        return Err(ParseError::Malformed(format!(
            "Failed to parse any discovered manifests in {}",
            root.display()
        )));
    }

    manifests.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(manifests)
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

    // Look for root manifest candidates in canonical precedence order
    let root_candidates = [
        "npm-shrinkwrap.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "pnpm-lock.yml",
        "yarn.lock",
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "requirements.txt",
        "Cargo.lock",
        "go.mod",
        "go.sum",
        "pom.xml",
    ];

    let mut primary_manifest_path: Option<PathBuf> = None;
    for cand in &root_candidates {
        let p = abs_dir.join(cand);
        if p.exists() {
            primary_manifest_path = Some(p);
            break;
        }
    }

    if let Some(primary) = primary_manifest_path {
        let (primary_type, mut graph) = parse_manifest_at(&primary, include_dev)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: primary.clone(),
            manifest_type: primary_type.clone(),
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        let mut skipped_manifests = Vec::new();

        collect_additional_discovered_projects(
            &discovered_projects,
            &primary,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            &mut skipped_manifests,
            include_dev,
        );

        return Ok(DetectionResult {
            manifest_type: primary_type,
            graph,
            manifest_file: primary,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests,
        });
    }

    // Monorepo subproject fallback: no manifest at root, but discovered in subdirectories
    if !discovered_projects.is_empty() {
        let primary = discovered_projects[0].clone();
        let (primary_type, mut graph) = parse_manifest_at(&primary, include_dev)?;
        let mut projects = vec![WorkspaceProject {
            manifest_file: primary.clone(),
            manifest_type: primary_type.clone(),
            workspace_name: None,
            graph: graph.clone(),
            parser_errors: vec![],
        }];
        let mut failed_manifests = Vec::new();
        let mut skipped_manifests = Vec::new();

        collect_additional_discovered_projects(
            &discovered_projects,
            &primary,
            &mut graph,
            &mut projects,
            &mut failed_manifests,
            &mut skipped_manifests,
            include_dev,
        );

        return Ok(DetectionResult {
            manifest_type: primary_type,
            graph,
            manifest_file: primary,
            discovered_projects,
            projects,
            failed_manifests,
            skipped_manifests,
        });
    }

    // Helpful guidance when no supported manifest was found
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

    #[test]
    fn test_root_multi_ecosystem_npm_plus_cargo_merging() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_multi_eco_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let package_lock_json = r#"{
            "name": "fullstack-app",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "packages": {
                "": { "name": "fullstack-app", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.21" }
            }
        }"#;

        let cargo_lock = r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "fullstack-backend"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3fb1c873e1b9b056a4dc4c0c198b24c3ffa059243875552b2bd0933b1aee4ce2"
"#;

        std::fs::write(temp_dir.join("package.json"), r#"{"name":"fullstack-app"}"#).unwrap();
        std::fs::write(temp_dir.join("package-lock.json"), package_lock_json).unwrap();
        std::fs::write(temp_dir.join("Cargo.lock"), cargo_lock).unwrap();

        let res = detect_and_parse(&temp_dir, true)
            .expect("should detect and parse multi-ecosystem root manifests");

        // Both ecosystems must be detected and preserved in projects
        assert_eq!(
            res.projects.len(),
            2,
            "Both root npm and root Cargo must be scanned"
        );
        let project_types: Vec<ManifestType> = res
            .projects
            .iter()
            .map(|p| p.manifest_type.clone())
            .collect();
        assert!(project_types.contains(&ManifestType::NpmPackageLock));
        assert!(project_types.contains(&ManifestType::RustCargoLock));

        // Both packages should be present in the merged dependency graph
        let pkgs = res.graph.get_all_pkgs();
        let pkg_names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(
            pkg_names.contains(&"lodash"),
            "Merged graph must contain lodash from npm"
        );
        assert!(
            pkg_names.contains(&"serde"),
            "Merged graph must contain serde from crates.io"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_detect_workspace_manifests_contract() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_ws_manifests_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let package_lock_json = r#"{
            "name": "sample-app",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "packages": {
                "": { "name": "sample-app", "version": "1.0.0" },
                "node_modules/lodash": { "version": "4.17.21" }
            }
        }"#;
        std::fs::write(temp_dir.join("package.json"), r#"{"name":"sample-app"}"#).unwrap();
        std::fs::write(temp_dir.join("package-lock.json"), package_lock_json).unwrap();

        let manifests = detect_workspace_manifests(&temp_dir).expect("should discover manifests");
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].ecosystem, Ecosystem::Npm);
        assert_eq!(manifests[0].manifest_type, ManifestType::NpmPackageLock);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
