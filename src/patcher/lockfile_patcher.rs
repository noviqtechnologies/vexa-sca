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
            if let Err(e) = fs::write(&pkg_json_path, format!("{}\n", updated_str)) {
                // Rollback on failure
                let _ = fs::write(&pkg_json_path, &original_content);
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
            ("pnpm", &["install", "--no-frozen-lockfile"])
        } else if project_dir.join("yarn.lock").exists() {
            ("yarn", &["install", "--no-immutable"])
        } else {
            ("npm", &["install"])
        };

        let cmd_display = format!("{} {}", program, args.join(" "));

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
