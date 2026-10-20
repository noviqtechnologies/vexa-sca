use crate::core::semver_utils::classify_semver_change;
use crate::patcher::lockfile_patcher::{
    DirectUpgrade, PatchChanges, PatchResult, TransitiveOverride, UnfixableItem,
};
use crate::types::RemediationAction;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub struct PythonPatcher;

impl PythonPatcher {
    pub fn apply_fixes(
        project_dir: &Path,
        remediations: &[RemediationAction],
        dry_run: bool,
    ) -> Result<PatchResult, String> {
        let req_path = if project_dir.is_file() {
            project_dir.to_path_buf()
        } else {
            project_dir.join("requirements.txt")
        };

        if !req_path.exists() {
            return Err(format!("requirements.txt not found in {}", project_dir.display()));
        }

        let original_content = fs::read_to_string(&req_path)
            .map_err(|e| format!("Failed to read requirements.txt: {}", e))?;

        let mut changes = PatchChanges::default();
        let mut modified = false;
        let mut processed_packages = HashSet::new();

        // Detect line ending (CRLF vs LF)
        let line_ending = if original_content.contains("\r\n") {
            "\r\n"
        } else {
            "\n"
        };

        let mut lines: Vec<String> = original_content
            .lines()
            .map(|s| s.to_string())
            .collect();

        for rem in remediations {
            if !processed_packages.insert(rem.package.to_lowercase()) {
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

            // Attempt to update in-place if package exists in lines
            let mut found_index = None;
            let mut old_version_found = None;

            for (idx, line) in lines.iter().enumerate() {
                if let Some((pkg_name, old_ver, _)) = Self::parse_req_line(line) {
                    if Self::normalize_pkg_name(&pkg_name) == Self::normalize_pkg_name(&rem.package) {
                        found_index = Some(idx);
                        old_version_found = Some(old_ver);
                        break;
                    }
                }
            }

            if let Some(idx) = found_index {
                let old_ver = old_version_found.unwrap_or_else(|| rem.current_version.clone());
                let (change, is_breaking) = classify_semver_change(&old_ver, target_version);

                let updated_line = Self::update_req_line(&lines[idx], target_version);
                lines[idx] = updated_line;

                changes.direct_upgrades.push(DirectUpgrade {
                    package: rem.package.clone(),
                    from: old_ver,
                    to: target_version.clone(),
                    section: "requirements.txt".to_string(),
                    vulnerability_ids: rem.vulnerability_ids.clone(),
                    highest_severity: rem.highest_severity,
                    is_breaking,
                    semver_change: change.as_str().to_string(),
                });

                modified = true;
            } else if rem.is_transitive {
                // If transitive dependency, pin it at the end of requirements.txt
                let (change, is_breaking) = classify_semver_change(&rem.current_version, target_version);
                let pin_comment = format!("# Pinned by Vexa SCA to remediate transitive vulnerability");
                let pin_line = format!("{}=={}", rem.package, target_version);

                lines.push(pin_comment);
                lines.push(pin_line);

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
            } else {
                // Direct dependency not found in requirements.txt (e.g. dynamic or setup.py)
                changes.unfixable.push(UnfixableItem {
                    package: rem.package.clone(),
                    reason: format!("Dependency '{}' not found in requirements.txt", rem.package),
                });
            }
        }

        let mut backup_file: Option<PathBuf> = None;

        if modified && !dry_run {
            let bak_path = req_path.with_extension("txt.bak");
            let _ = fs::write(&bak_path, &original_content);

            let mut new_content = lines.join(line_ending);
            if original_content.ends_with('\n') {
                new_content.push_str(line_ending);
            }

            fs::write(&req_path, new_content)
                .map_err(|e| format!("Failed to write updated requirements.txt: {}", e))?;

            backup_file = Some(bak_path);
        }

        Ok(PatchResult {
            modified,
            backup_file,
            changes,
            warnings: vec![],
        })
    }

    /// Normalizes Python package name per PEP 503 (lowercased, '_' replaced with '-')
    pub fn normalize_pkg_name(name: &str) -> String {
        name.trim().to_lowercase().replace('_', "-")
    }

    /// Parses a line from requirements.txt, returning (package_name, version, operator)
    pub fn parse_req_line(line: &str) -> Option<(String, String, String)> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        // Split comments and environment markers
        let base = trimmed.split(';').next().unwrap_or("").trim();
        let base = base.split('#').next().unwrap_or("").trim();
        if base.is_empty() {
            return None;
        }

        // Operators in descending order of specificity
        let ops = ["==", ">=", "<=", "~=", "!=", "<", ">"];
        for op in &ops {
            if let Some(idx) = base.find(op) {
                let (name, rest) = base.split_at(idx);
                let ver = rest.trim_start_matches(op).trim();
                return Some((name.trim().to_string(), ver.to_string(), op.to_string()));
            }
        }

        None
    }

    /// Updates the version specification in a line while preserving indentation, comments, and markers
    pub fn update_req_line(line: &str, new_version: &str) -> String {
        // Find if line has an environment marker ';' or comment '#'
        let marker_pos = line.find(';');
        let comment_pos = line.find('#');

        let split_pos = match (marker_pos, comment_pos) {
            (Some(m), Some(c)) => Some(m.min(c)),
            (Some(m), None) => Some(m),
            (None, Some(c)) => Some(c),
            (None, None) => None,
        };

        let (spec_part, suffix_part) = match split_pos {
            Some(pos) => {
                let trimmed_spec = line[..pos].trim_end();
                let ws_and_suffix = &line[trimmed_spec.len()..];
                (trimmed_spec, ws_and_suffix)
            }
            None => (line.trim_end(), &line[line.trim_end().len()..]),
        };

        let ops = ["==", ">=", "<=", "~=", "!=", "<", ">"];
        for op in &ops {
            if let Some(idx) = spec_part.find(op) {
                let name = &spec_part[..idx];
                let after_op = &spec_part[idx + op.len()..];
                let leading_ws = if after_op.starts_with(' ') { " " } else { "" };
                return format!("{}{}{}{}{}", name, op, leading_ws, new_version, suffix_part);
            }
        }

        // Fallback: if no operator found, append ==new_version
        format!("{}=={}{}", spec_part.trim(), new_version, suffix_part)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SeverityLevel;

    #[test]
    fn test_python_patcher_parse_and_update() {
        let line1 = "flask==0.12.2";
        let parsed = PythonPatcher::parse_req_line(line1);
        assert_eq!(
            parsed,
            Some(("flask".to_string(), "0.12.2".to_string(), "==".to_string()))
        );
        let updated = PythonPatcher::update_req_line(line1, "3.1.3");
        assert_eq!(updated, "flask==3.1.3");

        let line2 = "requests >= 2.25.1 ; python_version >= '3.8' # main client";
        let updated2 = PythonPatcher::update_req_line(line2, "2.33.0");
        assert_eq!(
            updated2,
            "requests >= 2.33.0 ; python_version >= '3.8' # main client"
        );
    }

    #[test]
    fn test_python_patcher_apply_fixes_dry_run() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_py_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let req_file = temp_dir.join("requirements.txt");

        let initial_req = "# App dependencies\nflask==0.12.2\nrequests==2.25.1\n";
        fs::write(&req_file, initial_req).unwrap();

        let remediations = vec![
            RemediationAction {
                package: "flask".to_string(),
                current_version: "0.12.2".to_string(),
                is_transitive: false,
                target_version: Some("3.1.3".to_string()),
                action_type: "UPGRADE_DIRECT".to_string(),
                advice: "".to_string(),
                resolved_vulnerability_count: 4,
                vulnerability_ids: vec!["CVE-2023-30861".to_string()],
                highest_severity: Some(SeverityLevel::High),
            },
            RemediationAction {
                package: "urllib3".to_string(),
                current_version: "1.26.4".to_string(),
                is_transitive: true,
                target_version: Some("1.26.18".to_string()),
                action_type: "UPGRADE_TRANSITIVE".to_string(),
                advice: "".to_string(),
                resolved_vulnerability_count: 1,
                vulnerability_ids: vec!["CVE-2023-45803".to_string()],
                highest_severity: Some(SeverityLevel::Medium),
            },
        ];

        // 1. Dry run
        let res_dry = PythonPatcher::apply_fixes(&temp_dir, &remediations, true).unwrap();
        assert!(res_dry.modified);
        assert_eq!(res_dry.changes.direct_upgrades.len(), 1);
        assert_eq!(res_dry.changes.direct_upgrades[0].package, "flask");
        assert_eq!(res_dry.changes.direct_upgrades[0].to, "3.1.3");
        assert_eq!(res_dry.changes.transitive_overrides.len(), 1);
        assert_eq!(res_dry.changes.transitive_overrides[0].package, "urllib3");
        assert!(res_dry.backup_file.is_none());

        let unmod = fs::read_to_string(&req_file).unwrap();
        assert_eq!(unmod, initial_req);

        // 2. Real run
        let res_real = PythonPatcher::apply_fixes(&temp_dir, &remediations, false).unwrap();
        assert!(res_real.modified);
        assert!(res_real.backup_file.is_some());

        let modified_req = fs::read_to_string(&req_file).unwrap();
        assert!(modified_req.contains("flask==3.1.3"));
        assert!(modified_req.contains("urllib3==1.26.18"));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
