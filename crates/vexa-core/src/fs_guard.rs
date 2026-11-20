//! Cross-platform filesystem safety guards for CLI `init`, `audit`, and `scan`
//! commands across Windows, macOS, and Linux.
//!
//! Prevents accidental recursive traversal of user home directories (`~` /
//! `%USERPROFILE%`), filesystem roots (`/` / `C:\`), NTFS junctions/symlinks,
//! and heavy OS/cache directories.

use std::fs::DirEntry;
use std::path::{Path, PathBuf};

/// Returns the current user's home directory across Windows, macOS, and Linux.
pub fn user_home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(p) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(p));
        }
        if let (Some(drive), Some(path)) = (
            std::env::var_os("HOMEDRIVE").filter(|v| !v.is_empty()),
            std::env::var_os("HOMEPATH").filter(|v| !v.is_empty()),
        ) {
            let mut combined = drive;
            combined.push(path);
            return Some(PathBuf::from(combined));
        }
        std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }

    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
}

fn canonical_or_raw(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Returns `true` if `path` resolves to the current user's home directory.
pub fn is_home_dir(path: &Path) -> bool {
    let Some(home) = user_home_dir() else {
        return false;
    };
    let lhs = canonical_or_raw(path);
    let rhs = canonical_or_raw(&home);
    #[cfg(windows)]
    {
        lhs.to_string_lossy()
            .eq_ignore_ascii_case(&rhs.to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        lhs == rhs
    }
}

/// Returns `true` if `path` resolves to a filesystem root (e.g. `/` or `C:\`).
pub fn is_filesystem_root(path: &Path) -> bool {
    canonical_or_raw(path).parent().is_none()
}

/// Returns `true` if running an unbounded recursive directory scan on `path`
/// would traverse an entire user profile or filesystem root.
pub fn is_unsafe_recursive_scan_root(path: &Path) -> bool {
    is_home_dir(path) || is_filesystem_root(path)
}

/// Returns `true` if `path` contains common project/repository marker files.
pub fn looks_like_project_dir(path: &Path) -> bool {
    const MARKERS: &[&str] = &[
        ".git",
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "requirements.txt",
        "go.mod",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "composer.json",
        ".arc",
        ".vexa-sca",
    ];
    MARKERS.iter().any(|m| path.join(m).exists())
}

/// Returns `true` if `entry` is a symlink or (on Windows) an NTFS junction /
/// reparse point that must not be followed during recursive traversal.
pub fn is_symlink_or_reparse_point(entry: &DirEntry) -> bool {
    if let Ok(ft) = entry.file_type() {
        if ft.is_symlink() {
            return true;
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if let Ok(meta) = std::fs::symlink_metadata(entry.path()) {
            if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                return true;
            }
        }
    }

    false
}

/// Returns `true` if `dir_name` is a known heavy OS, package-cache, VCS, or
/// user-media directory that should be skipped during recursive scans across
/// Windows, macOS, and Linux.
pub fn is_os_heavy_dir(dir_name: &str) -> bool {
    matches!(
        dir_name.to_ascii_lowercase().as_str(),
        // VCS & build / language caches
        ".git"
            | ".hg"
            | ".svn"
            | "node_modules"
            | "target"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".tox"
            | ".pytest_cache"
            | ".mypy_cache"
            | ".cargo"
            | ".rustup"
            | ".npm"
            | ".nvm"
            | ".pnpm-store"
            | ".nuget"
            | ".gradle"
            | ".m2"
            | ".cache"
            | ".trash"
            // Windows OS / user profile heavy folders & legacy junctions
            | "appdata"
            | "application data"
            | "local settings"
            | "onedrive"
            | "$recycle.bin"
            | "system volume information"
            | "programdata"
            | "program files"
            | "program files (x86)"
            | "windows"
            // macOS OS / user profile heavy folders
            | "library"
            | "applications"
            // Linux OS / user profile heavy folders
            | "snap"
            | ".mozilla"
            | ".thunderbird"
            // User bulk media folders
            | "downloads"
            | "pictures"
            | "videos"
            | "movies"
            | "music"
            | "saved games"
            | "3d objects"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_home_and_root_as_unsafe_scan_roots() {
        if let Some(home) = user_home_dir() {
            assert!(is_home_dir(&home));
            assert!(is_unsafe_recursive_scan_root(&home));
        }

        let temp = std::env::temp_dir();
        // Temp dir should never be treated as the user's home directory
        assert!(!is_home_dir(&temp));
        assert!(!is_filesystem_root(&temp));

        #[cfg(windows)]
        assert!(is_filesystem_root(Path::new(r"C:\")));
        #[cfg(not(windows))]
        assert!(is_filesystem_root(Path::new("/")));
    }

    #[test]
    fn os_heavy_dir_skips_profile_folders_but_allows_project_folders() {
        assert!(is_os_heavy_dir("AppData"));
        assert!(is_os_heavy_dir("Library"));
        assert!(is_os_heavy_dir(".cargo"));
        assert!(is_os_heavy_dir("node_modules"));
        assert!(is_os_heavy_dir("OneDrive"));
        assert!(is_os_heavy_dir("Downloads"));

        // Must never skip legitimate project directories
        assert!(!is_os_heavy_dir("src"));
        assert!(!is_os_heavy_dir("public"));
        assert!(!is_os_heavy_dir("docs"));
        assert!(!is_os_heavy_dir("crates"));
        assert!(!is_os_heavy_dir(".cursor"));
        assert!(!is_os_heavy_dir(".claude"));
        assert!(!is_os_heavy_dir(".github"));
    }
}
