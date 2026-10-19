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

pub struct LockfilePatcher;

impl LockfilePatcher {
    pub fn apply_fixes(
        project_dir: &Path,
        remediations: &[RemediationAction],
        dry_run: bool,
    ) -> Result<PatchResult, String> {
        let pkg_json_path = project_dir.join("package.json");
        if !pkg_json_path.exists() {
            return Err(format!("package.json not found in {}", project_dir.display()));
        }

        let original_content = fs::read_to_string(&pkg_json_path)
            .map_err(|e| format!("Failed to read package.json: {}", e))?;
        let mut pkg_json: Value = serde_json::from_str(&original_content)
            .map_err(|e| format!("Invalid JSON in package.json: {}", e))?;

        let mut changes = PatchChanges::default();
        let mut modified = false;

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

            let new_ver = format!("^{}", target_version);

            if !rem.is_transitive {
                let mut found = false;

                if let Some(deps) = pkg_json.get_mut("dependencies").and_then(|d| d.as_object_mut()) {
                    if let Some(old_val) = deps.get(&rem.package).cloned() {
                        let old_ver = old_val.as_str().unwrap_or("").to_string();
                        let (change, is_breaking) = classify_semver_change(&old_ver, target_version);
                        deps.insert(rem.package.clone(), Value::String(new_ver.clone()));
                        changes.direct_upgrades.push(DirectUpgrade {
                            package: rem.package.clone(),
                            from: old_ver,
                            to: new_ver.clone(),
                            section: "dependencies".to_string(),
                            vulnerability_ids: rem.vulnerability_ids.clone(),
                            highest_severity: rem.highest_severity,
                            is_breaking,
                            semver_change: change.as_str().to_string(),
                        });
                        found = true;
                        modified = true;
                    }
                }

                if let Some(dev_deps) = pkg_json.get_mut("devDependencies").and_then(|d| d.as_object_mut()) {
                    if let Some(old_val) = dev_deps.get(&rem.package).cloned() {
                        let old_ver = old_val.as_str().unwrap_or("").to_string();
                        let (change, is_breaking) = classify_semver_change(&old_ver, target_version);
                        dev_deps.insert(rem.package.clone(), Value::String(new_ver.clone()));
                        changes.direct_upgrades.push(DirectUpgrade {
                            package: rem.package.clone(),
                            from: old_ver,
                            to: new_ver.clone(),
                            section: "devDependencies".to_string(),
                            vulnerability_ids: rem.vulnerability_ids.clone(),
                            highest_severity: rem.highest_severity,
                            is_breaking,
                            semver_change: change.as_str().to_string(),
                        });
                        found = true;
                        modified = true;
                    }
                }

                if !found {
                    // Add to overrides
                    Self::insert_override(&mut pkg_json, &rem.package, &new_ver);
                    let (change, is_breaking) = classify_semver_change(&rem.current_version, target_version);
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
                Self::insert_override(&mut pkg_json, &rem.package, &new_ver);
                let (change, is_breaking) = classify_semver_change(&rem.current_version, target_version);
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
            let bak_path = project_dir.join("package.json.bak");
            let _ = fs::write(&bak_path, &original_content);
            if let Ok(updated_str) = serde_json::to_string_pretty(&pkg_json) {
                let _ = fs::write(&pkg_json_path, format!("{}\n", updated_str));
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

    fn insert_override(pkg_json: &mut Value, package: &str, pinned_to: &str) {
        if pkg_json.get("overrides").is_none() {
            pkg_json["overrides"] = Value::Object(serde_json::Map::new());
        }
        if let Some(ov) = pkg_json.get_mut("overrides").and_then(|o| o.as_object_mut()) {
            ov.insert(package.to_string(), Value::String(pinned_to.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockfile_patcher_fixes() {
        let temp_dir = std::env::temp_dir().join("vexa-rust-patch-test");
        let _ = fs::create_dir_all(&temp_dir);

        let pkg_json_path = temp_dir.join("package.json");
        let initial = serde_json::json!({
            "name": "patch-test",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "4.17.15"
            }
        });
        fs::write(&pkg_json_path, serde_json::to_string_pretty(&initial).unwrap()).unwrap();

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
        assert_eq!(updated["dependencies"]["lodash"], "^4.17.21");
        assert_eq!(updated["overrides"]["minimist"], "^1.2.6");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
