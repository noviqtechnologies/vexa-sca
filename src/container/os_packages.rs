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

type ManifestInspection = Option<(Vec<String>, Option<String>)>;

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

        OsInfo {
            name,
            version_id,
            id,
        }
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
            let lic = current_lic
                .take()
                .or_else(|| Self::get_standard_linux_license(&name).map(|s| s.to_string()));
            packages.push(OsPackage {
                name,
                version: ver,
                architecture: current_arch.take(),
                license: lic,
                ecosystem: "Alpine".to_string(),
            });
        }

        packages
    }

    /// Standard curated licenses for Linux base distribution packages (Debian/Ubuntu/Alpine)
    pub fn get_standard_linux_license(pkg_name: &str) -> Option<&'static str> {
        let p = pkg_name.trim().to_lowercase();
        let name = p.as_str();
        match name {
            // Permissive
            "curl" | "libcurl4" | "libcurl3-gnutls" | "libcurl4-openssl-dev" => Some("curl"),
            "openssl" | "libssl3" | "libssl1.1" => Some("Apache-2.0"),
            "dash" => Some("BSD-3-Clause"),
            "zlib1g" => Some("Zlib"),
            "libffi8" | "libffi7" => Some("MIT"),
            "libp11-kit0" => Some("BSD-3-Clause"),
            "libpsl5" => Some("MIT"),
            "libsqlite3-0" => Some("blessing"),
            "libncurses6" | "libncursesw6" | "libtinfo6" | "ncurses-base" | "ncurses-bin" => {
                Some("MIT")
            }
            "tzdata" => Some("public-domain"),
            "login" | "passwd" | "shadow" => Some("BSD-3-Clause"),
            "liblzma5" | "xz-utils" => Some("0BSD"),
            "libbz2-1.0" | "bzip2" => Some("bzip2"),
            "expat" | "libexpat1" => Some("MIT"),
            "pcre2" | "libpcre2-8-0" | "libpcre3" => Some("BSD-3-Clause"),

            // Weak Copyleft (LGPL, etc.)
            "libtasn1-6" => Some("LGPL-2.1-or-later"),
            "libgcrypt20" => Some("LGPL-2.1-or-later AND GPL-2.0-or-later"),
            "libgpg-error0" => Some("LGPL-2.1-or-later"),
            "libc6" | "libc-bin" | "libc-dev-bin" => Some("LGPL-2.1-or-later"),
            "libaudit1" | "libaudit-common" => Some("LGPL-2.1-or-later"),
            "libsystemd0" | "systemd" => Some("LGPL-2.1-or-later"),
            "libudev1" => Some("LGPL-2.1-or-later"),
            "libgmp10" => Some("LGPL-3.0-or-later OR GPL-2.0-or-later"),
            "libgnutls30" => Some("LGPL-2.1-or-later"),
            "libhogweed6" | "libnettle8" => Some("LGPL-3.0-or-later OR GPL-2.0-or-later"),
            "libidn2-0" => Some("LGPL-3.0-or-later OR GPL-2.0-or-later"),
            "libunistring2" | "libunistring5" => Some("LGPL-3.0-or-later OR GPL-2.0-or-later"),
            "libcrypt1" => Some("LGPL-2.1-or-later"),

            // Strong Copyleft (GPL)
            "coreutils" => Some("GPL-3.0-or-later"),
            "tar" => Some("GPL-3.0-or-later"),
            "gzip" => Some("GPL-3.0-or-later"),
            "bash" => Some("GPL-3.0-or-later"),
            "diffutils" => Some("GPL-3.0-or-later"),
            "findutils" => Some("GPL-3.0-or-later"),
            "sed" => Some("GPL-3.0-or-later"),
            "grep" => Some("GPL-3.0-or-later"),
            "gawk" | "mawk" => Some("GPL-3.0-or-later"),
            "apt" | "libapt-pkg6.0" => Some("GPL-2.0-or-later"),
            "dpkg" => Some("GPL-2.0-or-later"),
            "base-files" => Some("GPL-2.0-or-later"),
            "base-passwd" => Some("GPL-2.0-or-later"),
            "debianutils" => Some("GPL-2.0-or-later"),
            "util-linux" | "libblkid1" | "libmount1" | "libsmartcols1" | "libuuid1"
            | "bsdextrautils" | "fdisk" | "mount" => {
                Some("GPL-2.0-or-later AND LGPL-2.1-or-later AND BSD-4-Clause-UC")
            }
            "e2fsprogs" | "libcom-err2" | "libext2fs2" | "libss2" => {
                Some("GPL-2.0-or-later AND LGPL-2.0-or-later")
            }
            "libsepol2" | "libselinux1" => Some("GPL-2.0-or-later"),
            "libpam0g" | "libpam-runtime" | "libpam-modules" | "libpam-modules-bin" => {
                Some("BSD-3-Clause OR GPL-2.0-or-later")
            }
            "libcap2" | "libcap2-bin" => Some("GPL-2.0-only OR BSD-3-Clause"),
            "libattr1" => Some("GPL-2.0-or-later AND LGPL-2.1-or-later"),
            "ca-certificates" => Some("MPL-2.0 OR GPL-2.0-or-later"),
            "libreadline8" | "readline-common" => Some("GPL-3.0-or-later"),
            "perl-base" => Some("Artistic-1.0-Perl OR GPL-1.0-or-later"),
            "hostname" => Some("GPL-2.0-or-later"),
            "gpgv" => Some("GPL-3.0-or-later"),
            "adduser" => Some("GPL-2.0-or-later"),
            _ => None,
        }
    }

    /// Parses Debian/Ubuntu /var/lib/dpkg/status
    pub fn parse_debian_status(
        content: &str,
        os_id: &str,
        os_version: Option<&str>,
    ) -> Vec<OsPackage> {
        let ecosystem = if os_id.contains("ubuntu") {
            if let Some(ver) = os_version {
                if !ver.is_empty() && ver != "unknown" {
                    format!("Ubuntu:{}", ver)
                } else {
                    "Ubuntu".to_string()
                }
            } else {
                "Ubuntu".to_string()
            }
        } else if let Some(ver) = os_version {
            if !ver.is_empty() && ver != "unknown" {
                let major = ver.split('.').next().unwrap_or(ver);
                format!("Debian:{}", major)
            } else {
                "Debian".to_string()
            }
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
                        let lic = Self::get_standard_linux_license(&name).map(|s| s.to_string());
                        packages.push(OsPackage {
                            name,
                            version: ver,
                            architecture: current_arch.take(),
                            license: lic,
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
                let lic = Self::get_standard_linux_license(&name).map(|s| s.to_string());
                packages.push(OsPackage {
                    name,
                    version: ver,
                    architecture: current_arch.take(),
                    license: lic,
                    ecosystem,
                });
            }
        }

        packages
    }

    /// Parses embedded package-lock.json content
    pub fn parse_package_lock_content(content: &str, out: &mut Vec<OsPackage>) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(content) {
            if let Some(pkgs) = val.get("packages").and_then(|p| p.as_object()) {
                for (k, v) in pkgs {
                    if k.is_empty() {
                        continue;
                    }
                    let name = if let Some(stripped) = k.strip_prefix("node_modules/") {
                        stripped
                    } else {
                        k.as_str()
                    };
                    if let Some(ver) = v.get("version").and_then(|s| s.as_str()) {
                        out.push(OsPackage {
                            name: name.to_string(),
                            version: ver.to_string(),
                            architecture: None,
                            license: v
                                .get("license")
                                .and_then(|s| s.as_str())
                                .map(|s| s.to_string()),
                            ecosystem: "npm".to_string(),
                        });
                    }
                }
            } else if let Some(deps) = val.get("dependencies").and_then(|d| d.as_object()) {
                for (name, v) in deps {
                    if let Some(ver) = v.get("version").and_then(|s| s.as_str()) {
                        out.push(OsPackage {
                            name: name.clone(),
                            version: ver.to_string(),
                            architecture: None,
                            license: None,
                            ecosystem: "npm".to_string(),
                        });
                    }
                }
            }
        }
    }

    /// Parses embedded Cargo.lock content
    pub fn parse_cargo_lock_content(content: &str, out: &mut Vec<OsPackage>) {
        if let Ok(val) = toml::from_str::<toml::Value>(content) {
            if let Some(pkgs) = val.get("package").and_then(|p| p.as_array()) {
                for p in pkgs {
                    if let (Some(name), Some(ver)) = (
                        p.get("name").and_then(|s| s.as_str()),
                        p.get("version").and_then(|s| s.as_str()),
                    ) {
                        out.push(OsPackage {
                            name: name.to_string(),
                            version: ver.to_string(),
                            architecture: None,
                            license: None,
                            ecosystem: "crates.io".to_string(),
                        });
                    }
                }
            }
        }
    }

    /// Parses embedded requirements.txt content
    pub fn parse_requirements_txt_content(content: &str, out: &mut Vec<OsPackage>) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                continue;
            }
            if let Some((name, ver)) = line.split_once("==") {
                out.push(OsPackage {
                    name: name.trim().to_string(),
                    version: ver.trim().to_string(),
                    architecture: None,
                    license: None,
                    ecosystem: "PyPI".to_string(),
                });
            }
        }
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
                return (
                    os_info.clone(),
                    Self::parse_debian_status(&content, &os_info.id, Some(&os_info.version_id)),
                );
            }
        }

        (os_info, Vec::new())
    }

    /// Scans a container archive (.tar or .tar.gz)
    pub fn scan_tar_archive(tar_path: &Path) -> Result<(OsInfo, Vec<OsPackage>), String> {
        let is_gz = tar_path.to_string_lossy().ends_with(".gz")
            || tar_path.to_string_lossy().ends_with(".tgz");

        // Inspect manifest to detect Docker / OCI layered image archive
        let manifest_layers = Self::inspect_manifest(tar_path, is_gz)?;

        if let Some((ordered_layers, repo_tag)) = manifest_layers {
            Self::scan_layered_tar(tar_path, is_gz, ordered_layers, repo_tag)
        } else {
            // Flat rootfs archive
            let file = File::open(tar_path)
                .map_err(|e| format!("Failed to open {}: {}", tar_path.display(), e))?;
            if is_gz {
                let gz = GzDecoder::new(file);
                let mut archive = Archive::new(gz);
                Self::extract_and_parse_tar(&mut archive)
            } else {
                let mut archive = Archive::new(file);
                Self::extract_and_parse_tar(&mut archive)
            }
        }
    }

    fn inspect_manifest(tar_path: &Path, is_gz: bool) -> Result<ManifestInspection, String> {
        let file = File::open(tar_path)
            .map_err(|e| format!("Failed to open {}: {}", tar_path.display(), e))?;
        let mut manifest_content = None;
        let mut index_content = None;

        if is_gz {
            let gz = GzDecoder::new(file);
            let mut archive = Archive::new(gz);
            if let Ok(entries) = archive.entries() {
                for mut entry in entries.flatten() {
                    Self::check_entry(&mut entry, &mut manifest_content, &mut index_content);
                    if manifest_content.is_some() {
                        break;
                    }
                }
            }
        } else {
            let mut archive = Archive::new(file);
            if let Ok(entries) = archive.entries() {
                for mut entry in entries.flatten() {
                    Self::check_entry(&mut entry, &mut manifest_content, &mut index_content);
                    if manifest_content.is_some() {
                        break;
                    }
                }
            }
        }

        if let Some(content) = manifest_content {
            if let Ok(manifests) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                if let Some(first) = manifests.first() {
                    let repo_tag = first
                        .get("RepoTags")
                        .and_then(|t| t.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    if let Some(layers) = first.get("Layers").and_then(|l| l.as_array()) {
                        let layer_paths: Vec<String> = layers
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.replace('\\', "/")))
                            .collect();
                        if !layer_paths.is_empty() {
                            return Ok(Some((layer_paths, repo_tag)));
                        }
                    }
                }
            }
        }

        if let Some(content) = index_content {
            if let Ok(idx_val) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(manifests) = idx_val.get("manifests").and_then(|m| m.as_array()) {
                    if let Some(first_man) = manifests.first() {
                        if let Some(digest) = first_man.get("digest").and_then(|d| d.as_str()) {
                            let digest_blob =
                                format!("blobs/sha256/{}", digest.trim_start_matches("sha256:"));
                            return Ok(Some((vec![digest_blob], None)));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn check_entry<R: Read>(
        entry: &mut tar::Entry<'_, R>,
        man: &mut Option<String>,
        idx: &mut Option<String>,
    ) {
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        if path == "manifest.json" {
            let mut buf = String::new();
            let _ = entry.read_to_string(&mut buf);
            *man = Some(buf);
        } else if path == "index.json" && idx.is_none() {
            let mut buf = String::new();
            let _ = entry.read_to_string(&mut buf);
            *idx = Some(buf);
        }
    }

    fn scan_layered_tar(
        tar_path: &Path,
        is_gz: bool,
        ordered_layers: Vec<String>,
        repo_tag: Option<String>,
    ) -> Result<(OsInfo, Vec<OsPackage>), String> {
        let mut layer_map: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (idx, layer) in ordered_layers.iter().enumerate() {
            let norm = layer.replace('\\', "/");
            layer_map.insert(norm.clone(), idx);
            if let Some(filename) = norm.split('/').next_back() {
                layer_map.insert(filename.to_string(), idx);
            }
        }

        let file = File::open(tar_path)
            .map_err(|e| format!("Failed to open {}: {}", tar_path.display(), e))?;

        let mut latest_os_release: Option<(usize, String)> = None;
        let mut latest_dpkg: Option<(usize, String)> = None;
        let mut latest_apk: Option<(usize, String)> = None;
        let mut app_packages: Vec<OsPackage> = Vec::new();

        if is_gz {
            let gz = GzDecoder::new(file);
            let mut archive = Archive::new(gz);
            if let Ok(entries) = archive.entries() {
                for mut entry in entries.flatten() {
                    Self::process_outer_entry(
                        &mut entry,
                        &layer_map,
                        &mut latest_os_release,
                        &mut latest_dpkg,
                        &mut latest_apk,
                        &mut app_packages,
                    );
                }
            }
        } else {
            let mut archive = Archive::new(file);
            if let Ok(entries) = archive.entries() {
                for mut entry in entries.flatten() {
                    Self::process_outer_entry(
                        &mut entry,
                        &layer_map,
                        &mut latest_os_release,
                        &mut latest_dpkg,
                        &mut latest_apk,
                        &mut app_packages,
                    );
                }
            }
        }

        let mut os_info = if let Some((_, content)) = latest_os_release {
            Self::parse_os_release(&content)
        } else {
            OsInfo::default()
        };

        if let Some(tag) = repo_tag {
            if !tag.is_empty() && !os_info.name.contains(&tag) {
                os_info.name = format!("{} ({})", os_info.name, tag);
            }
        }

        let mut packages = Vec::new();

        if let Some((_, dpkg)) = latest_dpkg {
            packages.extend(Self::parse_debian_status(
                &dpkg,
                &os_info.id,
                Some(&os_info.version_id),
            ));
        } else if let Some((_, apk)) = latest_apk {
            packages.extend(Self::parse_alpine_installed(&apk));
        }

        packages.extend(app_packages);

        Ok((os_info, packages))
    }

    fn process_outer_entry<R: Read>(
        entry: &mut tar::Entry<'_, R>,
        layer_map: &std::collections::HashMap<String, usize>,
        latest_os_release: &mut Option<(usize, String)>,
        latest_dpkg: &mut Option<(usize, String)>,
        latest_apk: &mut Option<(usize, String)>,
        app_packages: &mut Vec<OsPackage>,
    ) {
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();

        let layer_idx = if let Some(&idx) = layer_map.get(&path) {
            Some(idx)
        } else if let Some(filename) = path.split('/').next_back() {
            if let Some(&idx) = layer_map.get(filename) {
                Some(idx)
            } else if path.starts_with("blobs/sha256/")
                || path.ends_with("/layer.tar")
                || path.ends_with(".tar")
                || path.ends_with(".tar.gz")
            {
                Some(0)
            } else {
                None
            }
        } else {
            None
        };

        let Some(idx) = layer_idx else { return };

        let mut magic = [0u8; 2];
        let n = match entry.read(&mut magic) {
            Ok(n) => n,
            Err(_) => return,
        };

        if n == 2 && magic == [0x1f, 0x8b] {
            let chained = std::io::Cursor::new(magic).chain(entry);
            let gz = GzDecoder::new(chained);
            let mut inner = Archive::new(gz);
            Self::inspect_inner_layer(
                &mut inner,
                idx,
                latest_os_release,
                latest_dpkg,
                latest_apk,
                app_packages,
            );
        } else {
            let chained = std::io::Cursor::new(magic[..n].to_vec()).chain(entry);
            let mut inner = Archive::new(chained);
            Self::inspect_inner_layer(
                &mut inner,
                idx,
                latest_os_release,
                latest_dpkg,
                latest_apk,
                app_packages,
            );
        }
    }

    fn inspect_inner_layer<R: Read>(
        inner: &mut Archive<R>,
        layer_idx: usize,
        latest_os_release: &mut Option<(usize, String)>,
        latest_dpkg: &mut Option<(usize, String)>,
        latest_apk: &mut Option<(usize, String)>,
        app_packages: &mut Vec<OsPackage>,
    ) {
        let entries = match inner.entries() {
            Ok(e) => e,
            Err(_) => return,
        };

        for mut entry in entries.flatten() {
            let path = entry
                .path()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();

            if path.ends_with("etc/os-release") || path.ends_with("usr/lib/os-release") {
                let should_read = latest_os_release
                    .as_ref()
                    .is_none_or(|(idx, _)| layer_idx >= *idx);
                if should_read {
                    let mut buf = String::new();
                    if entry.read_to_string(&mut buf).is_ok() {
                        *latest_os_release = Some((layer_idx, buf));
                    }
                }
            } else if path.ends_with("var/lib/dpkg/status") {
                let should_read = latest_dpkg
                    .as_ref()
                    .is_none_or(|(idx, _)| layer_idx >= *idx);
                if should_read {
                    let mut buf = String::new();
                    if entry.read_to_string(&mut buf).is_ok() {
                        *latest_dpkg = Some((layer_idx, buf));
                    }
                }
            } else if path.ends_with("lib/apk/db/installed") {
                let should_read = latest_apk.as_ref().is_none_or(|(idx, _)| layer_idx >= *idx);
                if should_read {
                    let mut buf = String::new();
                    if entry.read_to_string(&mut buf).is_ok() {
                        *latest_apk = Some((layer_idx, buf));
                    }
                }
            } else if path.ends_with("package-lock.json") {
                let mut buf = String::new();
                if entry.read_to_string(&mut buf).is_ok() {
                    Self::parse_package_lock_content(&buf, app_packages);
                }
            } else if path.ends_with("Cargo.lock") {
                let mut buf = String::new();
                if entry.read_to_string(&mut buf).is_ok() {
                    Self::parse_cargo_lock_content(&buf, app_packages);
                }
            } else if path.ends_with("requirements.txt") {
                let mut buf = String::new();
                if entry.read_to_string(&mut buf).is_ok() {
                    Self::parse_requirements_txt_content(&buf, app_packages);
                }
            }
        }
    }

    fn extract_and_parse_tar<R: Read>(
        archive: &mut Archive<R>,
    ) -> Result<(OsInfo, Vec<OsPackage>), String> {
        let mut os_release_content = None;
        let mut apk_content = None;
        let mut dpkg_content = None;

        let entries = archive
            .entries()
            .map_err(|e| format!("Failed to read tar entries: {}", e))?;

        for entry_res in entries {
            let mut entry = match entry_res {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry
                .path()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();

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
            return Ok((
                os_info.clone(),
                Self::parse_debian_status(&dpkg, &os_info.id, Some(&os_info.version_id)),
            ));
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
        let pkgs = OsPackageDetector::parse_debian_status(content, "debian", None);
        // curl is deinstalled, so only libc6 should match
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "libc6");
        assert_eq!(pkgs[0].version, "2.31-13+deb11u7");
        assert_eq!(pkgs[0].ecosystem, "Debian");
    }
}
