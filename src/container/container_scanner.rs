use crate::container::os_packages::{OsInfo, OsPackage, OsPackageDetector};
use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::licenses::license_scanner::{LicenseAudit, LicenseScanner};
use crate::scanner::vuln_scanner::{ScanResult, VulnScanner};
use crate::types::PkgInfo;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ContainerScanOutput {
    pub target: String,
    pub os_info: OsInfo,
    pub dep_graph: DepGraph,
    pub scan_result: ScanResult,
    pub license_audit: Option<LicenseAudit>,
    pub packages: Vec<OsPackage>,
}

pub struct ContainerScanner;

impl ContainerScanner {
    /// Scans a container target: directory, tar archive, or Dockerfile
    pub async fn scan_target(target_path: &Path) -> Result<ContainerScanOutput, String> {
        if !target_path.exists() {
            return Err(format!(
                "Target path '{}' does not exist",
                target_path.display()
            ));
        }

        let target_str = target_path.display().to_string();

        let (os_info, packages) = if target_path.is_file() {
            let file_name = target_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if file_name.ends_with(".tar")
                || file_name.ends_with(".tar.gz")
                || file_name.ends_with(".tgz")
            {
                OsPackageDetector::scan_tar_archive(target_path)?
            } else if file_name == "Dockerfile" || file_name.ends_with(".dockerfile") {
                Self::inspect_dockerfile(target_path)?
            } else {
                return Err(format!("Unsupported container file '{}'. Provide a .tar archive, Dockerfile, or rootfs directory.", target_path.display()));
            }
        } else {
            OsPackageDetector::scan_rootfs_dir(target_path)
        };

        if packages.is_empty() {
            eprintln!("Warning: No installed OS packages detected in {}. (Supported: Alpine apk, Debian/Ubuntu dpkg)", target_path.display());
        }

        // Build DepGraph from OS packages
        let root_name = format!("container-{}", os_info.id);
        let root_pkg = PkgInfo::new(&root_name, &os_info.version_id, &os_info.name);
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: os_info.id.clone(),
                version: os_info.version_id.clone(),
            },
        );

        for pkg in &packages {
            let pkg_info = PkgInfo::new(&pkg.name, &pkg.version, &pkg.ecosystem);
            graph.add_pkg(pkg_info.clone());

            let node_id = format!(
                "{}:{}@{}",
                pkg.ecosystem.to_lowercase(),
                pkg.name,
                pkg.version
            );
            graph.add_node(
                node_id.clone(),
                pkg_info.id.clone(),
                NodeInfo {
                    scope: "prod".to_string(),
                    path: None,
                    integrity: None,
                },
            );

            let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);
        }

        // Scan OS packages via VulnScanner against live OSV
        let scanner = VulnScanner::default();
        let scan_result = scanner.scan_graph(&graph).await?;

        // License audit
        let mut os_licenses = std::collections::HashMap::new();
        for pkg in &packages {
            if let Some(lic) = &pkg.license {
                os_licenses.insert(pkg.name.clone(), lic.clone());
                os_licenses.insert(format!("{}@{}", pkg.name, pkg.version), lic.clone());
            }
        }
        let license_audit = Some(LicenseScanner::scan_graph_licenses_with_overrides(
            &graph,
            target_path,
            Some(&os_licenses),
        ));

        Ok(ContainerScanOutput {
            target: target_str,
            os_info,
            dep_graph: graph,
            scan_result,
            license_audit,
            packages,
        })
    }

    /// Inspects Dockerfile FROM statements
    fn inspect_dockerfile(dockerfile_path: &Path) -> Result<(OsInfo, Vec<OsPackage>), String> {
        let content = fs::read_to_string(dockerfile_path)
            .map_err(|e| format!("Failed to read {}: {}", dockerfile_path.display(), e))?;

        let mut os_info = OsInfo {
            name: "Dockerfile Base".to_string(),
            version_id: "latest".to_string(),
            id: "dockerfile".to_string(),
        };

        let mut packages = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("FROM ") {
                let base_img = rest.split_whitespace().next().unwrap_or(rest).to_string();
                let lower = base_img.to_lowercase();

                let (name, ver, ecosystem) = if lower.contains("alpine") {
                    let ver = base_img.split(':').nth(1).unwrap_or("3.18");
                    (
                        "alpine-base".to_string(),
                        ver.to_string(),
                        "Alpine".to_string(),
                    )
                } else if lower.contains("debian") || lower.contains("ubuntu") {
                    let ver = base_img.split(':').nth(1).unwrap_or("11");
                    (
                        "debian-base".to_string(),
                        ver.to_string(),
                        "Debian".to_string(),
                    )
                } else {
                    let parts: Vec<&str> = base_img.split(':').collect();
                    let n = parts[0].to_string();
                    let v = parts.get(1).unwrap_or(&"latest").to_string();
                    (n, v, "Linux".to_string())
                };

                os_info.name = format!("Docker Base: {}", base_img);
                os_info.id = ecosystem.to_lowercase();
                os_info.version_id = ver.clone();

                packages.push(OsPackage {
                    name,
                    version: ver,
                    architecture: None,
                    license: None,
                    ecosystem,
                });
            }
        }

        Ok((os_info, packages))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_inspect_dockerfile() {
        let temp_dir = std::env::temp_dir().join("vexa-test-dockerfile");
        let _ = std::fs::create_dir_all(&temp_dir);
        let dockerfile_path = temp_dir.join("Dockerfile");
        let _ = std::fs::write(&dockerfile_path, "FROM alpine:3.18\nRUN apk add curl\n");

        let res = ContainerScanner::scan_target(&dockerfile_path).await;
        let _ = std::fs::remove_dir_all(&temp_dir);

        assert!(res.is_ok());
        let output = res.unwrap();
        assert_eq!(output.packages.len(), 1);
        assert_eq!(output.packages[0].ecosystem, "Alpine");
        assert_eq!(output.packages[0].version, "3.18");
    }
}
