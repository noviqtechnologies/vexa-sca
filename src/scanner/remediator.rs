use crate::core::semver_utils::clean_or_coerce_version;
use crate::types::{RemediationAction, VulnerabilityFinding};
use std::collections::{BTreeSet, HashMap};

pub struct Remediator;

impl Remediator {
    pub fn generate_remediation(
        vulnerabilities: &[VulnerabilityFinding],
    ) -> Vec<RemediationAction> {
        let mut by_pkg: HashMap<String, Vec<&VulnerabilityFinding>> = HashMap::new();
        for v in vulnerabilities {
            by_pkg.entry(v.pkg_id.clone()).or_default().push(v);
        }

        let mut remediations = Vec::new();

        for (_pkg_id, vulns) in by_pkg {
            if vulns.is_empty() {
                continue;
            }

            let sample = vulns[0];
            let current_version = &sample.version;
            let is_transitive = sample.is_transitive;
            let current_semver = clean_or_coerce_version(current_version);

            let mut candidate_fixes = BTreeSet::new();
            for v in &vulns {
                for f in &v.fixed_in {
                    candidate_fixes.insert(f.clone());
                }
            }

            // Find valid upgrades greater than current
            let mut valid_upgrades: Vec<String> = candidate_fixes
                .into_iter()
                .filter(|fix| {
                    if let (Some(cur), Some(candidate)) =
                        (&current_semver, clean_or_coerce_version(fix))
                    {
                        candidate > *cur
                    } else {
                        false
                    }
                })
                .collect();

            valid_upgrades.sort_by(|a, b| {
                let va = clean_or_coerce_version(a);
                let vb = clean_or_coerce_version(b);
                match (va, vb) {
                    (Some(x), Some(y)) => x.cmp(&y),
                    _ => a.cmp(b),
                }
            });

            // Same-major preference per FR-020:
            let same_major_candidates: Vec<String> = if let Some(cur) = &current_semver {
                valid_upgrades
                    .iter()
                    .filter(|v| {
                        if let Some(cand) = clean_or_coerce_version(v) {
                            cand.major == cur.major
                        } else {
                            false
                        }
                    })
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };

            let (target_version, is_major_bump) = if !same_major_candidates.is_empty() {
                // Pick the upgrade within same major version to ensure all same-major vulns are addressed
                (same_major_candidates.last().cloned(), false)
            } else if let Some(highest) = valid_upgrades.last().cloned() {
                let is_bump = if let (Some(cur), Some(cand)) =
                    (&current_semver, clean_or_coerce_version(&highest))
                {
                    cand.major > cur.major
                } else {
                    false
                };
                (Some(highest), is_bump)
            } else {
                (None, false)
            };

            let (action_type, advice) = match &target_version {
                Some(target) => {
                    if !is_transitive {
                        let bump_warning = if is_major_bump {
                            "[MAJOR UPGRADE WARNING - Breaking change risk; review release notes before applying] "
                        } else {
                            ""
                        };
                        let direct_msg = match sample.ecosystem.as_str() {
                            "crates.io" => format!(
                                "{}Upgrade direct dependency \"{}\" from {} to {} in Cargo.toml.",
                                bump_warning, sample.package, current_version, target
                            ),
                            "Go" => format!(
                                "{}Upgrade direct dependency \"{}\" from {} to {} via 'go get {}@{}'.",
                                bump_warning, sample.package, current_version, target, sample.package, target
                            ),
                            "PyPI" => format!(
                                "{}Upgrade direct dependency \"{}\" from {} to {} in requirements.txt or pyproject.toml.",
                                bump_warning, sample.package, current_version, target
                            ),
                            _ => format!(
                                "{}Upgrade direct dependency \"{}\" from {} to {} via 'npm install {}@{}'.",
                                bump_warning, sample.package, current_version, target, sample.package, target
                            ),
                        };
                        let act = if is_major_bump {
                            "UPGRADE_DIRECT_MAJOR".to_string()
                        } else {
                            "UPGRADE_DIRECT".to_string()
                        };
                        (act, direct_msg)
                    } else {
                        let mut introducers = BTreeSet::new();
                        for v in &vulns {
                            for p in &v.paths {
                                if p.len() > 1 {
                                    introducers.insert(p[1].clone());
                                }
                            }
                        }
                        let introducer_list = if introducers.is_empty() {
                            "parent package".to_string()
                        } else {
                            introducers.into_iter().collect::<Vec<_>>().join(", ")
                        };

                        let trans_msg = match sample.ecosystem.as_str() {
                            "crates.io" => format!(
                                "Transitive vulnerability introduced by {}. Update via 'cargo update -p {} --precise {}' or specify in [patch.crates-io].",
                                introducer_list, sample.package, target
                            ),
                            "Go" => format!(
                                "Transitive vulnerability introduced by {}. Update via 'go get {}@{}' in go.mod.",
                                introducer_list, sample.package, target
                            ),
                            "PyPI" => format!(
                                "Transitive vulnerability introduced by {}. Pin {}=={} in requirements or lockfile.",
                                introducer_list, sample.package, target
                            ),
                            _ => format!(
                                "Transitive vulnerability introduced by {}. Run 'npm audit fix' (or 'npm update {}') or configure override \"{}\": \"{}\".",
                                introducer_list, sample.package, sample.package, target
                            ),
                        };

                        ("UPGRADE_TRANSITIVE".to_string(), trans_msg)
                    }
                }
                None => (
                    "NO_FIX_AVAILABLE".to_string(),
                    format!(
                        "No known patch available. Consider replacing or isolating package \"{}\".",
                        sample.package
                    ),
                ),
            };

            let mut highest_sev: Option<crate::types::SeverityLevel> = None;
            for v in &vulns {
                let s = v.severity.level;
                match highest_sev {
                    None => highest_sev = Some(s),
                    Some(cur) => {
                        if s.weight() > cur.weight() {
                            highest_sev = Some(s);
                        }
                    }
                }
            }

            remediations.push(RemediationAction {
                package: sample.package.clone(),
                current_version: current_version.clone(),
                is_transitive,
                target_version,
                action_type,
                advice,
                resolved_vulnerability_count: vulns.len(),
                vulnerability_ids: vulns.iter().map(|v| v.id.clone()).collect(),
                highest_severity: highest_sev,
            });
        }

        remediations.sort_by(|a, b| a.package.cmp(&b.package));
        remediations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SeverityInfo, SeverityLevel};

    #[test]
    fn test_remediator_picks_highest_required_upgrade() {
        let vuln1 = VulnerabilityFinding {
            id: "RUSTSEC-1".to_string(),
            title: "Issue 1".to_string(),
            package: "quinn-proto".to_string(),
            version: "0.11.16".to_string(),
            ecosystem: "crates.io".to_string(),
            pkg_id: "quinn-proto@0.11.16".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::Medium,
                score: 5.5,
                vector: None,
            },
            fixed_in: vec!["0.11.17".to_string()],
            is_transitive: true,
            paths: vec![vec![
                "my-app@1.0.0".to_string(),
                "quinn@0.11.11".to_string(),
                "quinn-proto@0.11.16".to_string(),
            ]],
            ..Default::default()
        };

        let vuln2 = VulnerabilityFinding {
            id: "RUSTSEC-2".to_string(),
            title: "Issue 2".to_string(),
            package: "quinn-proto".to_string(),
            version: "0.11.16".to_string(),
            ecosystem: "crates.io".to_string(),
            pkg_id: "quinn-proto@0.11.16".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::High,
                score: 7.5,
                vector: None,
            },
            fixed_in: vec!["0.11.18".to_string()],
            is_transitive: true,
            paths: vec![vec![
                "my-app@1.0.0".to_string(),
                "quinn@0.11.11".to_string(),
                "quinn-proto@0.11.16".to_string(),
            ]],
            ..Default::default()
        };

        let remediations = Remediator::generate_remediation(&[vuln1, vuln2]);
        assert_eq!(remediations.len(), 1);
        let rem = &remediations[0];
        assert_eq!(rem.package, "quinn-proto");
        assert_eq!(rem.target_version.as_deref(), Some("0.11.18"));
        assert!(rem.advice.contains("0.11.18"));
        assert_eq!(rem.resolved_vulnerability_count, 2);
    }

    #[test]
    fn test_remediator_prefers_same_major_over_breaking_jump() {
        let vuln = VulnerabilityFinding {
            id: "GHSA-test-major".to_string(),
            title: "Security Issue".to_string(),
            package: "example-lib".to_string(),
            version: "1.0.4".to_string(),
            ecosystem: "npm".to_string(),
            pkg_id: "npm/example-lib@1.0.4".to_string(),
            severity: SeverityInfo {
                level: SeverityLevel::High,
                score: 8.0,
                vector: None,
            },
            fixed_in: vec!["1.0.5".to_string(), "2.0.0".to_string()],
            is_transitive: false,
            paths: vec![vec![
                "my-app@1.0.0".to_string(),
                "example-lib@1.0.4".to_string(),
            ]],
            ..Default::default()
        };

        let remediations = Remediator::generate_remediation(&[vuln]);
        assert_eq!(remediations.len(), 1);
        let rem = &remediations[0];
        assert_eq!(rem.package, "example-lib");
        // Must choose same-major 1.0.5 instead of jumping to 2.0.0!
        assert_eq!(rem.target_version.as_deref(), Some("1.0.5"));
        assert_eq!(rem.action_type, "UPGRADE_DIRECT");
    }
}
