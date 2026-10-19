use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use tar::Archive;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsPackage {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub license: Option<String>,
    pub ecosystem: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsInfo {
    pub name: String,
    pub version_id: String,
    pub id: String,
}

impl Default for OsInfo {
    fn default() -> Self {
        Self {
            name: "Linux".to_string(),
            version_id: "unknown".to_string(),
            id: "linux".to_string(),
        }
    }
}

pub struct OsPackageDetector;

impl OsPackageDetector {
    /// Detects OS info from /etc/os-release or equivalent
    pub fn parse_os_release(content: &str) -> OsInfo {
        let mut name = "Linux".to_string();
        let mut version_id = "unknown".to_string();
        let mut id = "linux".to_string();

        for line in content.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once('=') {
                let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
                match k {
                    "ID" => id = val.to_lowercase(),
                    "NAME" => name = val,
                    "VERSION_ID" => version_id = val,
                    _ => {}
                }
            }
        }

        OsInfo { name, version_id, id }
    }

    /// Parses Alpine Linux /lib/apk/db/installed
    pub fn parse_alpine_installed(content: &str) -> Vec<OsPackage> {
        let mut packages = Vec::new();
        let mut current_pkg: Option<String> = None;
        let mut current_ver: Option<String> = None;
        let mut current_arch: Option<String> = None;
        let mut current_lic: Option<String> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                if let (Some(name), Some(ver)) = (current_pkg.take(), current_ver.take()) {
                    packages.push(OsPackage {
                        name,
                        version: ver,
                        architecture: current_arch.take(),
                        license: current_lic.take(),
                        ecosystem: "Alpine".to_string(),
                    });
                }
                continue;
            }

            if let Some(rest) = line.strip_prefix("P:") {
                current_pkg = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("V:") {
                current_ver = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("A:") {
                current_arch = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("L:") {
                current_lic = Some(rest.trim().to_string());
            }
        }

        if let (Some(name), Some(ver)) = (current_pkg.take(), current_ver.take()) {
            packages.push(OsPackage {
                name,
                version: ver,
                architecture: current_arch.take(),
                license: current_lic.take(),
                ecosystem: "Alpine".to_string(),
            });
        }

        packages
    }

    /// Parses Debian/Ubuntu /var/lib/dpkg/status
    pub fn parse_debian_status(content: &str, os_id: &str) -> Vec<OsPackage> {
        let ecosystem = if os_id.contains("ubuntu") {
            "Ubuntu".to_string()
        } else {
            "Debian".to_string()
        };

        let mut packages = Vec::new();
        let mut current_pkg: Option<String> = None;
        let mut current_ver: Option<String> = None;
        let mut current_arch: Option<String> = None;
        let mut is_installed = false;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                if is_installed {
                    if let (Some(name), Some(ver)) = (current_pkg.take(), current_ver.take()) {
                        packages.push(OsPackage {
                            name,
                            version: ver,
                            architecture: current_arch.take(),
                            license: None,
                            ecosystem: ecosystem.clone(),
                        });
                    }
                } else {
                    current_pkg = None;
                    current_ver = None;
                    current_arch = None;
                }
                is_installed = false;
                continue;
            }

            if let Some(rest) = line.strip_prefix("Package:") {
                current_pkg = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Version:") {
                current_ver = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Architecture:") {
                current_arch = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("Status:") {
                if rest.contains("installed") && !rest.contains("not-installed") {
                    is_installed = true;
                }
            }
        }

        if is_installed {
            if let (Some(name), Some(ver)) = (current_pkg.take(), current_ver.take()) {
                packages.push(OsPackage {
                    name,
                    version: ver,
                    architecture: current_arch.take(),
                    license: None,
                    ecosystem,
                });
            }
        }

        packages
    }

    /// Scans a directory / rootfs for OS packages
    pub fn scan_rootfs_dir(dir: &Path) -> (OsInfo, Vec<OsPackage>) {
        let mut os_info = OsInfo::default();

        // 1. Try reading /etc/os-release or /usr/lib/os-release
        for rel_path in &["etc/os-release", "usr/lib/os-release"] {
            let full = dir.join(rel_path);
            if full.exists() {
                if let Ok(content) = fs::read_to_string(&full) {
                    os_info = Self::parse_os_release(&content);
                    break;
                }
            }
        }

        // 2. Try Alpine
        let alpine_db = dir.join("lib/apk/db/installed");
        if alpine_db.exists() {
            if let Ok(content) = fs::read_to_string(&alpine_db) {
                if os_info.id == "linux" {
                    os_info.name = "Alpine Linux".to_string();
                    os_info.id = "alpine".to_string();
                }
                return (os_info, Self::parse_alpine_installed(&content));
            }
        }

        // 3. Try Debian/Ubuntu
        let debian_status = dir.join("var/lib/dpkg/status");
        if debian_status.exists() {
            if let Ok(content) = fs::read_to_string(&debian_status) {
                return (os_info.clone(), Self::parse_debian_status(&content, &os_info.id));
            }
        }

        (os_info, Vec::new())
    }

    /// Scans a container archive (.tar or .tar.gz)
    pub fn scan_tar_archive(tar_path: &Path) -> Result<(OsInfo, Vec<OsPackage>), String> {
        let file = File::open(tar_path).map_err(|e| format!("Failed to open {}: {}", tar_path.display(), e))?;

        let is_gz = tar_path.to_string_lossy().ends_with(".gz") || tar_path.to_string_lossy().ends_with(".tgz");

        if is_gz {
            let gz = GzDecoder::new(file);
            let mut archive = Archive::new(gz);
            Self::extract_and_parse_tar(&mut archive)
        } else {
            let mut archive = Archive::new(file);
            Self::extract_and_parse_tar(&mut archive)
        }
    }

    fn extract_and_parse_tar<R: Read>(archive: &mut Archive<R>) -> Result<(OsInfo, Vec<OsPackage>), String> {
        let mut os_release_content = None;
        let mut apk_content = None;
        let mut dpkg_content = None;

        let entries = archive.entries().map_err(|e| format!("Failed to read tar entries: {}", e))?;

        for entry_res in entries {
            let mut entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path().map(|p| p.to_string_lossy().replace('\\', "/")).unwrap_or_default();

            if path.ends_with("etc/os-release") && os_release_content.is_none() {
                let mut buf = String::new();
                let _ = entry.read_to_string(&mut buf);
                os_release_content = Some(buf);
            } else if path.ends_with("lib/apk/db/installed") && apk_content.is_none() {
                let mut buf = String::new();
                let _ = entry.read_to_string(&mut buf);
                apk_content = Some(buf);
            } else if path.ends_with("var/lib/dpkg/status") && dpkg_content.is_none() {
                let mut buf = String::new();
                let _ = entry.read_to_string(&mut buf);
                dpkg_content = Some(buf);
            }
        }

        let os_info = if let Some(content) = os_release_content {
            Self::parse_os_release(&content)
        } else {
            OsInfo::default()
        };

        if let Some(apk) = apk_content {
            return Ok((os_info, Self::parse_alpine_installed(&apk)));
        }

        if let Some(dpkg) = dpkg_content {
            return Ok((os_info.clone(), Self::parse_debian_status(&dpkg, &os_info.id)));
        }

        Ok((os_info, Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_alpine_installed_content() {
        let content = r#"
P:musl
V:1.2.4-r2
A:x86_64
S:618496
I:618496
T:the musl c library
U:https://musl.libc.org/
L:MIT

P:busybox
V:1.36.1-r0
A:x86_64
S:968720
I:968720
T:Size optimized toolbox
U:https://busybox.net/
L:GPL-2.0-only
"#;
        let pkgs = OsPackageDetector::parse_alpine_installed(content);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "musl");
        assert_eq!(pkgs[0].version, "1.2.4-r2");
        assert_eq!(pkgs[0].ecosystem, "Alpine");
        assert_eq!(pkgs[0].license.as_deref(), Some("MIT"));

        assert_eq!(pkgs[1].name, "busybox");
        assert_eq!(pkgs[1].version, "1.36.1-r0");
    }

    #[test]
    fn test_parse_debian_status_content() {
        let content = r#"
Package: libc6
Status: install ok installed
Priority: required
Section: libs
Installed-Size: 11520
Architecture: amd64
Version: 2.31-13+deb11u7

Package: curl
Status: deinstall ok config-files
Version: 7.74.0-1.3+deb11u11
"#;
        let pkgs = OsPackageDetector::parse_debian_status(content, "debian");
        // curl is deinstalled, so only libc6 should match
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "libc6");
        assert_eq!(pkgs[0].version, "2.31-13+deb11u7");
        assert_eq!(pkgs[0].ecosystem, "Debian");
    }
}
