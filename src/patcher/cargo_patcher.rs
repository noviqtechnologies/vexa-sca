use crate::core::semver_utils::classify_semver_change;
use crate::patcher::lockfile_patcher::{
    DirectUpgrade, PatchChanges, PatchResult, TransitiveOverride, UnfixableItem,
};
use crate::types::RemediationAction;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct CargoPatcher;

impl CargoPatcher {
    pub fn apply_fixes(
        project_dir: &Path,
        remediations: &[RemediationAction],
        dry_run: bool,
    ) -> Result<PatchResult, String> {
        let cargo_toml_path = project_dir.join("Cargo.toml");
        let cargo_lock_path = project_dir.join("Cargo.lock");

        if !cargo_toml_path.exists() && !cargo_lock_path.exists() {
            return Err(format!(
                "Neither Cargo.toml nor Cargo.lock found in {}",
                project_dir.display()
            ));
        }

        let mut changes = PatchChanges::default();
        let mut warnings = Vec::new();
        let mut modified = false;
        let mut backup_file: Option<PathBuf> = None;

        let original_toml_content = if cargo_toml_path.exists() {
            Some(
                fs::read_to_string(&cargo_toml_path)
                    .map_err(|e| format!("Failed to read Cargo.toml: {}", e))?,
            )
        } else {
            None
        };

        let mut current_toml_content = original_toml_content.clone();
        let mut toml_was_modified = false;
        let mut processed_packages = std::collections::HashSet::new();

        for rem in remediations {
            if !processed_packages.insert(&rem.package) {
                continue;
            }

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

            // 1. Check if package is a direct dependency in Cargo.toml
            let mut direct_updated = false;
            if let Some(content) = &current_toml_content {
                if let Some((updated_content, old_ver, section)) =
                    Self::update_direct_dep(content, &rem.package, target_version)
                {
                    let (change, is_breaking) = classify_semver_change(&old_ver, target_version);
                    current_toml_content = Some(updated_content);
                    changes.direct_upgrades.push(DirectUpgrade {
                        package: rem.package.clone(),
                        from: old_ver,
                        to: target_version.clone(),
                        section,
                        vulnerability_ids: rem.vulnerability_ids.clone(),
                        highest_severity: rem.highest_severity,
                        is_breaking,
                        semver_change: change.as_str().to_string(),
                    });
                    direct_updated = true;
                    toml_was_modified = true;
                    modified = true;
                }
            }

            // 2. If not a direct dependency in Cargo.toml, treat as transitive dependency
            if !direct_updated {
                let (change, is_breaking) = classify_semver_change(&rem.current_version, target_version);
                changes.transitive_overrides.push(TransitiveOverride {
                    package: rem.package.clone(),
                    current_version: Some(rem.current_version.clone()),
                    pinned_to: target_version.clone(),
                    vulnerability_ids: rem.vulnerability_ids.clone(),
                    highest_severity: rem.highest_severity,
                    is_breaking,
                    semver_change: change.as_str().to_string(),
                });
                modified = true;

                // If not dry-run and cargo CLI is available, attempt `cargo update -p <package> --precise <ver>`
                if !dry_run {
                    let output = Command::new("cargo")
                        .args(["update", "-p", &rem.package, "--precise", target_version])
                        .current_dir(project_dir)
                        .output();
                    if let Ok(out) = output {
                        if !out.status.success() {
                            let stderr_str = String::from_utf8_lossy(&out.stderr);
                            let first_line = stderr_str.lines().next().unwrap_or("cargo update failed");
                            warnings.push(format!("{}: {}", rem.package, first_line.trim()));
                        }
                    }
                }
            }
        }

        // Apply Cargo.toml changes if modified and not dry-run
        if toml_was_modified && !dry_run {
            if let (Some(orig), Some(updated)) = (&original_toml_content, &current_toml_content) {
                let bak_path = project_dir.join("Cargo.toml.bak");
                let _ = fs::write(&bak_path, orig);
                let _ = fs::write(&cargo_toml_path, updated);
                backup_file = Some(bak_path);
            }
        }

        Ok(PatchResult {
            modified,
            backup_file,
            changes,
            warnings,
        })
    }

    /// Finds and updates direct dependencies declared in Cargo.toml.
    /// Preserves existing formatting, indentation, and comments.
    pub fn update_direct_dep(
        toml_content: &str,
        package: &str,
        new_version: &str,
    ) -> Option<(String, String, String)> {
        let lines: Vec<&str> = toml_content.lines().collect();
        let mut new_lines = Vec::with_capacity(lines.len());
        let mut current_section = String::new();
        let mut replaced_info: Option<(String, String)> = None; // (old_ver, section)

        let section_re = Regex::new(r"^\s*\[(.*)\]\s*$").ok()?;
        let pkg_escaped = regex::escape(package);

        // Pattern 1: pkg = "1.0.0"
        let simple_dep_re =
            Regex::new(&format!(r#"^(\s*{}\s*=\s*")([^"]+)(".*)$"#, pkg_escaped)).ok()?;

        // Pattern 2: pkg = { version = "1.0.0", ... }
        let inline_dep_re = Regex::new(&format!(
            r#"^(\s*{}\s*=\s*\{{.*?\bversion\s*=\s*")([^"]+)(".*\}}.*)$"#,
            pkg_escaped
        ))
        .ok()?;

        // Pattern 3: pkg.version = "1.0.0"
        let dotted_dep_re =
            Regex::new(&format!(r#"^(\s*{}\.version\s*=\s*")([^"]+)(".*)$"#, pkg_escaped)).ok()?;

        // Pattern 4: inside [dependencies.pkg], version = "1.0.0"
        let table_version_re = Regex::new(r#"^(\s*version\s*=\s*")([^"]+)(".*)$"#).ok()?;

        for line in lines {
            if let Some(caps) = section_re.captures(line) {
                current_section = caps.get(1).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                new_lines.push(line.to_string());
                continue;
            }

            if replaced_info.is_some() {
                new_lines.push(line.to_string());
                continue;
            }

            let in_dep_section = current_section.ends_with("dependencies")
                || current_section == "dependencies"
                || current_section == "dev-dependencies"
                || current_section == "build-dependencies"
                || current_section.ends_with(".dependencies");

            if in_dep_section {
                if let Some(caps) = inline_dep_re.captures(line) {
                    let old_ver = caps[2].to_string();
                    let prefix = &caps[1];
                    let suffix = &caps[3];
                    let updated_line = format!("{}{}{}", prefix, new_version, suffix);
                    replaced_info = Some((old_ver, current_section.clone()));
                    new_lines.push(updated_line);
                    continue;
                }

                if let Some(caps) = simple_dep_re.captures(line) {
                    let old_ver = caps[2].to_string();
                    let prefix = &caps[1];
                    let suffix = &caps[3];
                    let updated_line = format!("{}{}{}", prefix, new_version, suffix);
                    replaced_info = Some((old_ver, current_section.clone()));
                    new_lines.push(updated_line);
                    continue;
                }

                if let Some(caps) = dotted_dep_re.captures(line) {
                    let old_ver = caps[2].to_string();
                    let prefix = &caps[1];
                    let suffix = &caps[3];
                    let updated_line = format!("{}{}{}", prefix, new_version, suffix);
                    replaced_info = Some((old_ver, current_section.clone()));
                    new_lines.push(updated_line);
                    continue;
                }
            }

            // Check if current section is [dependencies.pkg]
            if current_section == format!("dependencies.{}", package)
                || current_section == format!("dev-dependencies.{}", package)
                || current_section == format!("build-dependencies.{}", package)
                || current_section.ends_with(&format!(".dependencies.{}", package))
            {
                if let Some(caps) = table_version_re.captures(line) {
                    let old_ver = caps[2].to_string();
                    let prefix = &caps[1];
                    let suffix = &caps[3];
                    let updated_line = format!("{}{}{}", prefix, new_version, suffix);
                    replaced_info = Some((old_ver, current_section.clone()));
                    new_lines.push(updated_line);
                    continue;
                }
            }

            new_lines.push(line.to_string());
        }

        let (old_ver, section) = replaced_info?;
        let line_ending = if toml_content.contains("\r\n") { "\r\n" } else { "\n" };
        let mut final_content = new_lines.join(line_ending);
        if toml_content.ends_with("\r\n") {
            final_content.push_str("\r\n");
        } else if toml_content.ends_with('\n') {
            final_content.push('\n');
        }
        Some((final_content, old_ver, section))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_patcher_update_direct_deps() {
        let sample = r#"[package]
name = "test-pkg"
version = "0.1.0"

[dependencies]
# A comment here
anyhow = "1.0.70"
serde = { version = "1.0.100", features = ["derive"] }

[dev-dependencies]
tokio = "1.20.0"
"#;

        // Test simple dep update
        let (res1, old_ver1, sec1) =
            CargoPatcher::update_direct_dep(sample, "anyhow", "1.0.103").unwrap();
        assert_eq!(old_ver1, "1.0.70");
        assert_eq!(sec1, "dependencies");
        assert!(res1.contains("anyhow = \"1.0.103\""));
        assert!(res1.contains("# A comment here"));

        // Test inline table dep update
        let (res2, old_ver2, sec2) =
            CargoPatcher::update_direct_dep(sample, "serde", "1.0.197").unwrap();
        assert_eq!(old_ver2, "1.0.100");
        assert_eq!(sec2, "dependencies");
        assert!(res2.contains("serde = { version = \"1.0.197\", features = [\"derive\"] }"));

        // Test dev-dependencies update
        let (res3, old_ver3, sec3) =
            CargoPatcher::update_direct_dep(sample, "tokio", "1.38.0").unwrap();
        assert_eq!(old_ver3, "1.20.0");
        assert_eq!(sec3, "dev-dependencies");
        assert!(res3.contains("tokio = \"1.38.0\""));
    }

    #[test]
    fn test_cargo_patcher_apply_fixes_dry_run() {
        let temp_dir = std::env::temp_dir().join("vexa-cargo-patch-test");
        let _ = fs::create_dir_all(&temp_dir);

        let cargo_toml = temp_dir.join("Cargo.toml");
        let initial_toml = r#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
anyhow = "1.0.70"
"#;
        fs::write(&cargo_toml, initial_toml).unwrap();

        let remediations = vec![
            RemediationAction {
                package: "anyhow".to_string(),
                current_version: "1.0.70".to_string(),
                is_transitive: false,
                target_version: Some("1.0.103".to_string()),
                action_type: "UPGRADE_DIRECT".to_string(),
                advice: "".to_string(),
                resolved_vulnerability_count: 1,
                vulnerability_ids: vec!["RUSTSEC-2024-0045".to_string()],
                highest_severity: None,
            },
            RemediationAction {
                package: "rustls".to_string(),
                current_version: "0.23.40".to_string(),
                is_transitive: true,
                target_version: Some("0.23.46".to_string()),
                action_type: "UPGRADE_TRANSITIVE".to_string(),
                advice: "".to_string(),
                resolved_vulnerability_count: 1,
                vulnerability_ids: vec![],
                highest_severity: None,
            },
        ];

        let res = CargoPatcher::apply_fixes(&temp_dir, &remediations, true).unwrap();
        assert!(res.modified);
        assert_eq!(res.changes.direct_upgrades.len(), 1);
        assert_eq!(res.changes.direct_upgrades[0].package, "anyhow");
        assert_eq!(res.changes.direct_upgrades[0].to, "1.0.103");
        assert_eq!(res.changes.transitive_overrides.len(), 1);
        assert_eq!(res.changes.transitive_overrides[0].package, "rustls");
        assert_eq!(res.changes.transitive_overrides[0].pinned_to, "0.23.46");
        assert!(res.backup_file.is_none());

        // Ensure file was not modified in dry-run
        let unchanged = fs::read_to_string(&cargo_toml).unwrap();
        assert_eq!(unchanged, initial_toml);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
