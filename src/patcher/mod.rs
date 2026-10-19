pub mod cargo_patcher;
pub mod lockfile_patcher;
pub mod pr_creator;

pub use cargo_patcher::CargoPatcher;
pub use lockfile_patcher::{
    DirectUpgrade, LockfilePatcher, PatchChanges, PatchResult, TransitiveOverride, UnfixableItem,
};
pub use pr_creator::{PrCreator, PrResult};

use crate::parsers::detector::ManifestType;
use crate::types::RemediationAction;
use std::path::Path;

/// Dispatches automated patching to the appropriate ecosystem patcher based on ManifestType.
pub fn apply_fixes(
    project_dir: &Path,
    manifest_type: &ManifestType,
    remediations: &[RemediationAction],
    dry_run: bool,
) -> Result<PatchResult, String> {
    match manifest_type {
        ManifestType::RustCargoLock => {
            CargoPatcher::apply_fixes(project_dir, remediations, dry_run)
        }
        ManifestType::NpmPackageLock | ManifestType::YarnLock | ManifestType::PnpmLock => {
            LockfilePatcher::apply_fixes(project_dir, remediations, dry_run)
        }
        ManifestType::PythonRequirements => Err(
            "Automated in-place patching for Python requirements.txt is not yet supported. Please review recommended package versions from the scan output.".to_string(),
        ),
        ManifestType::GoModSum => Err(
            "Automated in-place patching for go.mod/go.sum is not yet supported. Run 'go get <pkg>@<version>' for recommended upgrades.".to_string(),
        ),
        ManifestType::JavaMavenPom => Err(
            "Automated in-place patching for pom.xml is not yet supported. Update <version> tags in pom.xml with the recommended versions.".to_string(),
        ),
    }
}
