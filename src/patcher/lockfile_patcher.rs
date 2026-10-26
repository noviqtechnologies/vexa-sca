use crate::core::semver_utils::classify_semver_change;
use crate::types::{RemediationAction, SeverityLevel};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectUpgrade {
    pub package: String,
    pub from: String,
    pub to: String,
    pub section: String,
    #[serde(default)]
    pub vulnerability_ids: Vec<String>,
    #[serde(default)]
    pub highest_severity: Option<SeverityLevel>,
    #[serde(default)]
    pub is_breaking: bool,
    #[serde(default)]
    pub semver_change: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransitiveOverride {
    pub package: String,
    #[serde(default)]
    pub current_version: Option<String>,
    pub pinned_to: String,
    #[serde(default)]
    pub vulnerability_ids: Vec<String>,
    #[serde(default)]
    pub highest_severity: Option<SeverityLevel>,
    #[serde(default)]
    pub is_breaking: bool,
    #[serde(default)]
    pub semver_change: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnfixableItem {
    pub package: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PatchChanges {
    pub direct_upgrades: Vec<DirectUpgrade>,
    pub transitive_overrides: Vec<TransitiveOverride>,
    pub unfixable: Vec<UnfixableItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResult {
    pub modified: bool,
    pub backup_file: Option<PathBuf>,
    pub changes: PatchChanges,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManagerKind {
    Npm,
    Yarn,
    Pnpm,
}

pub struct LockfilePatcher;

impl LockfilePatcher {
    pub fn detect_package_manager(project_dir: &Path) -> PackageManagerKind {
        if project_dir.join("pnpm-lock.yaml").exists() || project_dir.join("pnpm-lock.yml").exists()
        {
            PackageManagerKind::Pnpm
        } else if project_dir.join("yarn.lock").exists() {
            PackageManagerKind::Yarn
        } else {
            PackageManagerKind::Npm
        }
    }

    pub fn preserve_version_intent(original_spec: &str, target_version: &str) -> String {
        let trimmed = original_spec.trim();
        if trimmed.starts_with('^') {
            format!("^{}", target_version)
        } else if trimmed.starts_with('~') {
            format!("~{}", target_version)
        } else if trimmed.starts_with(">=") {
            format!(">={}", target_version)
        } else if trimmed.starts_with('>') {
            format!(">{}", target_version)
        } else if trimmed.starts_with("<=") {
            format!("<={}", target_version)
        } else if trimmed.starts_with('<') {
            format!("<{}", target_version)
        } else if trimmed.starts_with("workspace:") {
            format!("workspace:^{}", target_version)
        } else if !trimmed.is_empty()
            && trimmed
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == '+')
        {
            // Exact pin (e.g. "4.17.15") -> preserve exact pin intent per P1 requirements
            target_version.to_string()
        } else {
            format!("^{}", target_version)
        }
    }

    pub fn apply_fixes(
        project_dir: &Path,
        remediations: &[RemediationAction],
        dry_run: bool,
    ) -> Result<PatchResult, String> {
        let pkg_json_path = project_dir.join("package.json");
        if !pkg_json_path.exists() {
            return Err(format!(
                "package.json not found in {}",
                project_dir.display()
            ));
        }

        let original_content = fs::read_to_string(&pkg_json_path)
            .map_err(|e| format!("Failed to read package.json: {}", e))?;
        let mut pkg_json: Value = serde_json::from_str(&original_content)
            .map_err(|e| format!("Invalid JSON in package.json: {}", e))?;

        let pm = Self::detect_package_manager(project_dir);
        let mut changes = PatchChanges::default();
        let mut modified = false;

        let dep_sections = [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ];

        for rem in remediations {
            let target_version = match &rem.target_version {
                Some(v) => v,
                None => {
                    changes.unfixable.push(UnfixableItem {
                        package: rem.package.clone(),
                        reason: "No non-vulnerable version available".to_string(),
                    });
                    continue;
                }
            };

            if !rem.is_transitive {
                let mut found = false;

                for section in &dep_sections {
                    if let Some(deps) = pkg_json.get_mut(*section).and_then(|d| d.as_object_mut()) {
                        if let Some(old_val) = deps.get(&rem.package).cloned() {
                            let old_ver = old_val.as_str().unwrap_or("").to_string();
                            let new_ver = Self::preserve_version_intent(&old_ver, target_version);
                            let (change, is_breaking) =
                                classify_semver_change(&old_ver, target_version);

                            deps.insert(rem.package.clone(), Value::String(new_ver.clone()));
                            changes.direct_upgrades.push(DirectUpgrade {
                                package: rem.package.clone(),
                                from: old_ver,
                                to: new_ver,
                                section: section.to_string(),
                                vulnerability_ids: rem.vulnerability_ids.clone(),
                                highest_severity: rem.highest_severity,
                                is_breaking,
                                semver_change: change.as_str().to_string(),
                            });
                            found = true;
                            modified = true;
                            break;
                        }
                    }
                }

                if !found {
                    // Manager-specific transitive override
                    let new_ver = format!("^{}", target_version);
                    Self::insert_manager_override(&mut pkg_json, pm, &rem.package, &new_ver);
                    let (change, is_breaking) =
                        classify_semver_change(&rem.current_version, target_version);
                    changes.transitive_overrides.push(TransitiveOverride {
                        package: rem.package.clone(),
                        current_version: Some(rem.current_version.clone()),
                        pinned_to: new_ver,
                        vulnerability_ids: rem.vulnerability_ids.clone(),
                        highest_severity: rem.highest_severity,
                        is_breaking,
                        semver_change: change.as_str().to_string(),
                    });
                    modified = true;
                }
            } else {
                let new_ver = format!("^{}", target_version);
                Self::insert_manager_override(&mut pkg_json, pm, &rem.package, &new_ver);
                let (change, is_breaking) =
                    classify_semver_change(&rem.current_version, target_version);
                changes.transitive_overrides.push(TransitiveOverride {
                    package: rem.package.clone(),
                    current_version: Some(rem.current_version.clone()),
                    pinned_to: new_ver,
                    vulnerability_ids: rem.vulnerability_ids.clone(),
                    highest_severity: rem.highest_severity,
                    is_breaking,
                    semver_change: change.as_str().to_string(),
                });
                modified = true;
            }
        }

        let backup_file = if modified && !dry_run {
            // Transactional update: Stage and validate formatted JSON first
            let updated_str = serde_json::to_string_pretty(&pkg_json)
                .map_err(|e| format!("Failed to format updated package.json: {}", e))?;
            let bak_path = project_dir.join("package.json.bak");

            // Write backup first with checked write
            fs::write(&bak_path, &original_content).map_err(|e| {
                format!("Failed to write backup file {}: {}", bak_path.display(), e)
            })?;

            // Write updated package.json atomically
            let updated_content = format!("{}\n", updated_str);
            if let Err(e) = atomic_replace_bytes(&pkg_json_path, updated_content.as_bytes()) {
                return Err(format!("Failed to write package.json: {}", e));
            }

            Some(bak_path)
        } else {
            None
        };

        Ok(PatchResult {
            modified,
            backup_file,
            changes,
            warnings: vec![],
        })
    }

    fn insert_manager_override(
        pkg_json: &mut Value,
        pm: PackageManagerKind,
        package: &str,
        pinned_to: &str,
    ) {
        match pm {
            PackageManagerKind::Npm => {
                if pkg_json.get("overrides").is_none() {
                    pkg_json["overrides"] = Value::Object(serde_json::Map::new());
                }
                if let Some(ov) = pkg_json
                    .get_mut("overrides")
                    .and_then(|o| o.as_object_mut())
                {
                    ov.insert(package.to_string(), Value::String(pinned_to.to_string()));
                }
            }
            PackageManagerKind::Yarn => {
                if pkg_json.get("resolutions").is_none() {
                    pkg_json["resolutions"] = Value::Object(serde_json::Map::new());
                }
                if let Some(res) = pkg_json
                    .get_mut("resolutions")
                    .and_then(|o| o.as_object_mut())
                {
                    res.insert(package.to_string(), Value::String(pinned_to.to_string()));
                }
            }
            PackageManagerKind::Pnpm => {
                if pkg_json.get("pnpm").is_none() {
                    pkg_json["pnpm"] = Value::Object(serde_json::Map::new());
                }
                if let Some(pnpm_obj) = pkg_json.get_mut("pnpm").and_then(|p| p.as_object_mut()) {
                    if pnpm_obj.get("overrides").is_none() {
                        pnpm_obj.insert(
                            "overrides".to_string(),
                            Value::Object(serde_json::Map::new()),
                        );
                    }
                    if let Some(ov) = pnpm_obj
                        .get_mut("overrides")
                        .and_then(|o| o.as_object_mut())
                    {
                        ov.insert(package.to_string(), Value::String(pinned_to.to_string()));
                    }
                }
            }
        }
    }

    /// Regenerates the lockfile by running the appropriate package-manager install
    /// command after `package.json` has been patched.
    pub fn regenerate_lockfile(project_dir: &Path) -> Result<String, String> {
        use std::process::Command;

        let (program, args): (&str, &[&str]) = if project_dir.join("pnpm-lock.yaml").exists()
            || project_dir.join("pnpm-lock.yml").exists()
        {
            (
                "pnpm",
                &["install", "--no-frozen-lockfile", "--ignore-scripts"],
            )
        } else if project_dir.join("yarn.lock").exists() {
            let is_classic = fs::read_to_string(project_dir.join("yarn.lock"))
                .map(|contents| contents.contains("yarn lockfile v1"))
                .unwrap_or(false);
            if is_classic {
                ("yarn", &["install", "--ignore-scripts"])
            } else {
                ("yarn", &["install", "--no-immutable", "--mode=skip-builds"])
            }
        } else {
            ("npm", &["install", "--ignore-scripts"])
        };

        let cmd_display = format!("{} {}", program, args.join(" "));

        #[cfg(windows)]
        let output = {
            // npm, pnpm, and Corepack commonly install Windows .cmd shims rather than .exe files.
            // The command and arguments above are fixed by this function, not user-supplied text.
            let mut command = Command::new("cmd.exe");
            command
                .arg("/d")
                .arg("/s")
                .arg("/c")
                .arg(&cmd_display)
                .current_dir(project_dir);
            command.output()
        }
        .map_err(|e| {
            format!(
                "Failed to run '{}': {}. Ensure {} is installed and on PATH.",
                cmd_display, e, program
            )
        })?;

        #[cfg(not(windows))]
        let output = Command::new(program)
            .args(args)
            .current_dir(project_dir)
            .output()
            .map_err(|e| {
                format!(
                    "Failed to run '{}': {}. Ensure {} is installed and on PATH.",
                    cmd_display, e, program
                )
            })?;

        if output.status.success() {
            Ok(cmd_display)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let diag = if !stderr.trim().is_empty() {
                stderr.trim().chars().take(800).collect::<String>()
            } else {
                stdout.trim().chars().take(800).collect::<String>()
            };
            Err(format!(
                "'{}' exited with status {}.\n{}",
                cmd_display,
                output.status.code().unwrap_or(-1),
                diag
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockfile_patcher_fixes_and_range_preservation() {
        let temp_dir = std::env::temp_dir().join("vexa-rust-patch-test");
        let _ = fs::create_dir_all(&temp_dir);

        let pkg_json_path = temp_dir.join("package.json");
        let initial = serde_json::json!({
            "name": "patch-test",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.15",
                "semver": "^7.3.0"
            }
        });
        fs::write(
            &pkg_json_path,
            serde_json::to_string_pretty(&initial).unwrap(),
        )
        .unwrap();

        let remediations = vec![
            RemediationAction {
                package: "lodash".to_string(),
                current_version: "4.17.15".to_string(),
                is_transitive: false,
                target_version: Some("4.17.21".to_string()),
                action_type: "UPGRADE_DIRECT".to_string(),
                advice: "".to_string(),
                resolved_vulnerability_count: 1,
                vulnerability_ids: vec![],
                highest_severity: None,
            },
            RemediationAction {
                package: "semver".to_string(),
                current_version: "7.3.0".to_string(),
                is_transitive: false,
                target_version: Some("7.5.4".to_string()),
                action_type: "UPGRADE_DIRECT".to_string(),
                advice: "".to_string(),
                resolved_vulnerability_count: 1,
                vulnerability_ids: vec![],
                highest_severity: None,
            },
            RemediationAction {
                package: "minimist".to_string(),
                current_version: "0.0.8".to_string(),
                is_transitive: true,
                target_version: Some("1.2.6".to_string()),
                action_type: "UPGRADE_TRANSITIVE".to_string(),
                advice: "".to_string(),
                resolved_vulnerability_count: 1,
                vulnerability_ids: vec![],
                highest_severity: None,
            },
        ];

        let res = LockfilePatcher::apply_fixes(&temp_dir, &remediations, false).unwrap();
        assert!(res.modified);
        assert!(res.backup_file.is_some());

        let updated_content = fs::read_to_string(&pkg_json_path).unwrap();
        let updated: Value = serde_json::from_str(&updated_content).unwrap();
        // Exact pin preserved for lodash
        assert_eq!(updated["dependencies"]["lodash"], "4.17.21");
        // Caret range preserved for semver
        assert_eq!(updated["dependencies"]["semver"], "^7.5.4");
        // Overrides created for transitive minimist
        assert_eq!(updated["overrides"]["minimist"], "^1.2.6");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_lockfile_patcher_manager_specific_pnpm_overrides() {
        let temp_dir = std::env::temp_dir().join("vexa-pnpm-patch-test");
        let _ = fs::create_dir_all(&temp_dir);

        let pkg_json_path = temp_dir.join("package.json");
        let initial = serde_json::json!({
            "name": "pnpm-test",
            "version": "1.0.0"
        });
        fs::write(
            &pkg_json_path,
            serde_json::to_string_pretty(&initial).unwrap(),
        )
        .unwrap();

        // Create mock pnpm-lock.yaml so detector identifies pnpm
        fs::write(temp_dir.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'").unwrap();

        let remediations = vec![RemediationAction {
            package: "minimist".to_string(),
            current_version: "0.0.8".to_string(),
            is_transitive: true,
            target_version: Some("1.2.6".to_string()),
            action_type: "UPGRADE_TRANSITIVE".to_string(),
            advice: "".to_string(),
            resolved_vulnerability_count: 1,
            vulnerability_ids: vec![],
            highest_severity: None,
        }];

        let res = LockfilePatcher::apply_fixes(&temp_dir, &remediations, false).unwrap();
        assert!(res.modified);

        let updated_content = fs::read_to_string(&pkg_json_path).unwrap();
        let updated: Value = serde_json::from_str(&updated_content).unwrap();
        // Must use pnpm.overrides for pnpm
        assert_eq!(updated["pnpm"]["overrides"]["minimist"], "^1.2.6");
        assert!(updated.get("overrides").is_none());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_lockfile_patcher_dry_run_leaves_filesystem_untouched() {
        let temp_dir = std::env::temp_dir().join("vexa-dry-run-patch-test");
        let _ = fs::create_dir_all(&temp_dir);

        let pkg_json_path = temp_dir.join("package.json");
        let initial_str = r#"{
  "name": "dry-run-test",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15"
  }
}"#;
        fs::write(&pkg_json_path, initial_str).unwrap();

        let remediations = vec![RemediationAction {
            package: "lodash".to_string(),
            current_version: "4.17.15".to_string(),
            is_transitive: false,
            target_version: Some("4.17.21".to_string()),
            action_type: "UPGRADE_DIRECT".to_string(),
            advice: "".to_string(),
            resolved_vulnerability_count: 1,
            vulnerability_ids: vec![],
            highest_severity: None,
        }];

        let res = LockfilePatcher::apply_fixes(&temp_dir, &remediations, true).unwrap();
        assert!(res.modified);
        assert!(res.backup_file.is_none());

        let after_content = fs::read_to_string(&pkg_json_path).unwrap();
        assert_eq!(
            after_content, initial_str,
            "Dry-run must not modify file content"
        );
        assert!(
            !temp_dir.join("package.json.bak").exists(),
            "Dry-run must not create backup file"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
#[derive(Debug)]
struct SnapshotFile {
    path: PathBuf,
    contents: Option<Vec<u8>>,
}

/// Captured package manifest and lockfile state used to roll back a failed install.
#[derive(Debug)]
pub struct LockfileProjectState {
    files: Vec<SnapshotFile>,
}

fn atomic_replace_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("manifest");
    let temp_path = path.with_file_name(format!(
        ".{}.vexa-{}-{}-{}.tmp",
        file_name,
        std::process::id(),
        sequence,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let write_result = (|| {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        temp.write_all(bytes)?;
        temp.sync_all()?;

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            #[link(name = "kernel32")]
            extern "system" {
                fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
            }
            const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
            const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
            let existing: Vec<u16> = temp_path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let new: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let ok = unsafe {
                MoveFileExW(
                    existing.as_ptr(),
                    new.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        #[cfg(not(windows))]
        std::fs::rename(&temp_path, path)?;

        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result
}

impl LockfilePatcher {
    /// Snapshot the files that `npm`, `pnpm`, or `yarn install` can rewrite.
    pub fn snapshot_project_state(project_dir: &Path) -> Result<LockfileProjectState, String> {
        let names = [
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "pnpm-lock.yml",
            "yarn.lock",
        ];
        let mut files = Vec::with_capacity(names.len());
        for name in names {
            let path = project_dir.join(name);
            let contents = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(format!("Failed to snapshot {}: {}", path.display(), error))
                }
            };
            files.push(SnapshotFile { path, contents });
        }
        Ok(LockfileProjectState { files })
    }

    /// Restore the captured manifest and lockfiles after a failed package-manager install.
    pub fn restore_project_state(snapshot: &LockfileProjectState) -> Result<(), String> {
        let mut errors = Vec::new();
        for file in &snapshot.files {
            let result = match &file.contents {
                Some(bytes) => atomic_replace_bytes(&file.path, bytes),
                None => match fs::remove_file(&file.path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error),
                },
            };
            if let Err(error) = result {
                errors.push(format!("{}: {}", file.path.display(), error));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!("Rollback failed for: {}", errors.join("; ")))
        }
    }
}

#[cfg(test)]
mod rollback_tests {
    use super::*;

    #[test]
    fn project_state_snapshot_restores_manifest_and_lockfiles() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "vexa-lockfile-rollback-{}-{}",
            std::process::id(),
            unique
        ));
        fs::create_dir_all(&dir).unwrap();
        let package_json = dir.join("package.json");
        let package_lock = dir.join("package-lock.json");
        fs::write(&package_json, br#"{"dependencies":{"left-pad":"1.3.0"}}"#).unwrap();
        fs::write(&package_lock, b"original lockfile").unwrap();

        let snapshot = LockfilePatcher::snapshot_project_state(&dir).unwrap();
        fs::write(&package_json, b"mutated manifest").unwrap();
        fs::write(&package_lock, b"mutated lockfile").unwrap();
        fs::write(dir.join("pnpm-lock.yaml"), b"created during failed install").unwrap();

        LockfilePatcher::restore_project_state(&snapshot).unwrap();
        assert_eq!(
            fs::read(&package_json).unwrap(),
            br#"{"dependencies":{"left-pad":"1.3.0"}}"#
        );
        assert_eq!(fs::read(&package_lock).unwrap(), b"original lockfile");
        assert!(!dir.join("pnpm-lock.yaml").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_performs_zero_disk_writes_and_no_backups() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("vexa-dry-run-{}", unique));
        fs::create_dir_all(&dir).unwrap();
        let pkg_path = dir.join("package.json");
        let initial_bytes = br#"{"name":"dry-run-app","dependencies":{"lodash":"4.17.15"}}"#;
        fs::write(&pkg_path, initial_bytes).unwrap();

        let rems = vec![RemediationAction {
            package: "lodash".to_string(),
            current_version: "4.17.15".to_string(),
            is_transitive: false,
            target_version: Some("4.17.21".to_string()),
            action_type: "UPGRADE_DIRECT".to_string(),
            advice: "Upgrade".to_string(),
            resolved_vulnerability_count: 1,
            vulnerability_ids: vec!["GHSA-35jh-r3h4-6jhm".to_string()],
            highest_severity: None,
        }];

        let result = LockfilePatcher::apply_fixes(&dir, &rems, true).unwrap();
        assert!(result.modified);
        assert!(result.backup_file.is_none());

        // Zero disk modifications
        assert_eq!(fs::read(&pkg_path).unwrap(), initial_bytes);
        assert!(!dir.join("package.json.bak").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_succeeds_in_path_with_spaces_and_special_chars() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "vexa test path with spaces and #special {}",
            unique
        ));
        fs::create_dir_all(&dir).unwrap();
        let pkg_json = dir.join("package.json");
        let pkg_lock = dir.join("package-lock.json");

        let original_json = br#"{"name":"spaced-app","version":"1.0.0"}"#;
        let original_lock = b"lockfile-initial-bytes-12345";
        fs::write(&pkg_json, original_json).unwrap();
        fs::write(&pkg_lock, original_lock).unwrap();

        let snapshot = LockfilePatcher::snapshot_project_state(&dir).unwrap();

        // Mutate files as a failing install would
        fs::write(&pkg_json, b"corrupted json").unwrap();
        fs::write(&pkg_lock, b"corrupted lockfile").unwrap();
        let extraneous = dir.join("pnpm-lock.yaml");
        fs::write(&extraneous, b"stray lockfile").unwrap();

        // Rollback
        LockfilePatcher::restore_project_state(&snapshot).unwrap();

        assert_eq!(fs::read(&pkg_json).unwrap(), original_json);
        assert_eq!(fs::read(&pkg_lock).unwrap(), original_lock);
        assert!(!extraneous.exists());

        let _ = fs::remove_dir_all(&dir);
    }
}
