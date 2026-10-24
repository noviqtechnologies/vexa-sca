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

pub struct DetectionResult {
    pub manifest_type: ManifestType,
    pub graph: DepGraph,
    pub manifest_file: PathBuf,
    pub discovered_projects: Vec<PathBuf>,
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
                {
                    continue;
                }
                discover_recursive(&path, depth + 1, max_depth, results);
            }
        }
    }
}

pub fn detect_and_parse(project_dir: &Path, include_dev: bool) -> Result<DetectionResult, String> {
    let abs_dir = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());

    let discovered_projects = discover_manifests(&abs_dir, 4);

    let npm_lock = abs_dir.join("package-lock.json");
    if npm_lock.exists() {
        let graph = PackageLockParser::parse(&abs_dir, include_dev)?;
        return Ok(DetectionResult {
            manifest_type: ManifestType::NpmPackageLock,
            graph,
            manifest_file: npm_lock,
            discovered_projects,
        });
    }

    let yarn_lock = abs_dir.join("yarn.lock");
    if yarn_lock.exists() {
        let graph = YarnLockParser::parse(&abs_dir, include_dev)?;
        return Ok(DetectionResult {
            manifest_type: ManifestType::YarnLock,
            graph,
            manifest_file: yarn_lock,
            discovered_projects,
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
        let graph = PnpmLockParser::parse(&abs_dir, include_dev)?;
        return Ok(DetectionResult {
            manifest_type: ManifestType::PnpmLock,
            graph,
            manifest_file: main_file,
            discovered_projects,
        });
    }

    let req_txt = abs_dir.join("requirements.txt");
    if req_txt.exists() {
        let graph = PythonRequirementsParser::parse(&req_txt)?;
        return Ok(DetectionResult {
            manifest_type: ManifestType::PythonRequirements,
            graph,
            manifest_file: req_txt,
            discovered_projects,
        });
    }

    let cargo_lock = abs_dir.join("Cargo.lock");
    if cargo_lock.exists() {
        let graph = CargoLockParser::parse(&cargo_lock)?;
        return Ok(DetectionResult {
            manifest_type: ManifestType::RustCargoLock,
            graph,
            manifest_file: cargo_lock,
            discovered_projects,
        });
    }

    let go_sum = abs_dir.join("go.sum");
    let go_mod = abs_dir.join("go.mod");
    if go_sum.exists() || go_mod.exists() {
        let main_file = if go_sum.exists() { go_sum } else { go_mod };
        let graph = GoLockParser::parse(&abs_dir)?;
        return Ok(DetectionResult {
            manifest_type: ManifestType::GoModSum,
            graph,
            manifest_file: main_file,
            discovered_projects,
        });
    }

    let pom_xml = abs_dir.join("pom.xml");
    if pom_xml.exists() {
        let graph = PomXmlParser::parse(&pom_xml)?;
        return Ok(DetectionResult {
            manifest_type: ManifestType::JavaMavenPom,
            graph,
            manifest_file: pom_xml,
            discovered_projects,
        });
    }

    // Check if subdirectories contain manifests to provide helpful monorepo guidance
    let mut sub_hints = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&abs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let dirname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if dirname.starts_with('.')
                    || dirname == "node_modules"
                    || dirname == "target"
                    || dirname == "vendor"
                {
                    continue;
                }
                for manifest in &[
                    "package.json",
                    "package-lock.json",
                    "Cargo.toml",
                    "requirements.txt",
                    "go.mod",
                    "pom.xml",
                ] {
                    if path.join(manifest).exists() {
                        let rel = path.strip_prefix(&abs_dir).unwrap_or(&path);
                        sub_hints.push(format!("{}/{}", rel.display(), manifest));
                    }
                }
            }
        }
    }

    let mut err_msg = format!(
        "No supported lockfile found in {}. Supported: package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Cargo.lock, go.sum, pom.xml",
        abs_dir.display()
    );
    if !sub_hints.is_empty() {
        err_msg.push_str("\n\nDetected subproject manifests:");
        for hint in sub_hints {
            err_msg.push_str(&format!("\n  ↳ {}", hint));
        }
        err_msg.push_str("\nTip: Run vexa on the target subproject path directly (e.g. vexa fix <subproject-path>).");
    }

    Err(err_msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_and_parse_all_fixtures() {
        let npm_det = detect_and_parse(Path::new("test/fixtures/npm-app"), true).unwrap();
        assert_eq!(npm_det.manifest_type, ManifestType::NpmPackageLock);

        let py_det = detect_and_parse(Path::new("test/fixtures/python-app"), true).unwrap();
        assert_eq!(py_det.manifest_type, ManifestType::PythonRequirements);

        let go_det = detect_and_parse(Path::new("test/fixtures/go-app"), true).unwrap();
        assert_eq!(go_det.manifest_type, ManifestType::GoModSum);

        let rust_det = detect_and_parse(Path::new("test/fixtures/rust-app"), true).unwrap();
        assert_eq!(rust_det.manifest_type, ManifestType::RustCargoLock);

        let java_det = detect_and_parse(Path::new("test/fixtures/java-app"), true).unwrap();
        assert_eq!(java_det.manifest_type, ManifestType::JavaMavenPom);

        let pnpm_det = detect_and_parse(Path::new("test/fixtures/pnpm-app"), true).unwrap();
        assert_eq!(pnpm_det.manifest_type, ManifestType::PnpmLock);
        assert_eq!(pnpm_det.graph.get_all_pkgs().len(), 2);
    }

    #[test]
    fn test_discover_manifests_multi_project() {
        let discovered = discover_manifests(Path::new("test/fixtures"), 4);
        assert!(
            discovered.len() >= 5,
            "Must discover multiple fixture manifests"
        );
        let has_npm = discovered.iter().any(|p| p.ends_with("package-lock.json"));
        let has_cargo = discovered.iter().any(|p| p.ends_with("Cargo.lock"));
        let has_pnpm = discovered.iter().any(|p| p.ends_with("pnpm-lock.yaml"));
        assert!(has_npm && has_cargo && has_pnpm);
    }
}
