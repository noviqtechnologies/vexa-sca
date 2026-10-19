use crate::core::semver_utils::clean_or_coerce_version;
use crate::types::{RemediationAction, VulnerabilityFinding};
use std::collections::{BTreeSet, HashMap};

pub struct Remediator;

impl Remediator {
    pub fn generate_remediation(vulnerabilities: &[VulnerabilityFinding]) -> Vec<RemediationAction> {
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
                    if let (Some(cur), Some(candidate)) = (&current_semver, clean_or_coerce_version(fix)) {
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

            let target_version = valid_upgrades.first().cloned();

            let (action_type, advice) = match &target_version {
                Some(target) => {
                    if !is_transitive {
                        (
                            "UPGRADE_DIRECT".to_string(),
                            format!(
                                "Upgrade direct dependency \"{}\" from {} to {} in your manifest.",
                                sample.package, current_version, target
                            ),
                        )
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

                        (
                            "UPGRADE_TRANSITIVE".to_string(),
                            format!(
                                "Transitive vulnerability introduced by {}. Upgrade top-level parent or add package override \"{}\": \"{}\".",
                                introducer_list, sample.package, target
                            ),
                        )
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

            remediations.push(RemediationAction {
                package: sample.package.clone(),
                current_version: current_version.clone(),
                is_transitive,
                target_version,
                action_type,
                advice,
                resolved_vulnerability_count: vulns.len(),
                vulnerability_ids: vulns.iter().map(|v| v.id.clone()).collect(),
            });
        }

        remediations.sort_by(|a, b| a.package.cmp(&b.package));
        remediations
    }
}
