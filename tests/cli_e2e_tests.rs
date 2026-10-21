use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;
static INIT: Once = Once::new();

fn get_bin_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(name);
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

fn ensure_binaries_built() {
    INIT.call_once(|| {
        let bin = get_bin_path("vexa-sca");
        if !bin.exists() {
            let status = Command::new("cargo")
                .args(["build", "--bins"])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .status()
                .expect("cargo build --bins failed to execute");
            assert!(status.success(), "Failed to build test binaries");
        }
    });
}

#[test]
fn test_packaged_binaries_help_and_version() {
    ensure_binaries_built();
    for bin_name in &["vexa-sca", "vexa", "sca"] {
        let bin = get_bin_path(bin_name);
        assert!(bin.exists(), "Binary {:?} must exist", bin);

        // Test --help
        let help_output = Command::new(&bin)
            .arg("--help")
            .output()
            .unwrap_or_else(|e| panic!("Failed to run {:?} --help: {}", bin, e));
        assert!(
            help_output.status.success(),
            "{:?} --help should exit 0",
            bin_name
        );
        let help_str = String::from_utf8_lossy(&help_output.stdout);
        assert!(
            help_str.contains("Vexa SCA") || help_str.contains("Usage:"),
            "{:?} --help output missing expected header",
            bin_name
        );

        // Test --version
        let ver_output = Command::new(&bin)
            .arg("--version")
            .output()
            .unwrap_or_else(|e| panic!("Failed to run {:?} --version: {}", bin, e));
        assert!(
            ver_output.status.success(),
            "{:?} --version should exit 0",
            bin_name
        );
        let ver_str = String::from_utf8_lossy(&ver_output.stdout);
        assert!(
            ver_str.contains("1.0.0"),
            "{:?} --version should contain 1.0.0",
            bin_name
        );
    }
}

#[test]
fn test_cli_invalid_sbom_format_rejected_exit_code_2() {
    ensure_binaries_built();
    let bin = get_bin_path("vexa-sca");

    let output = Command::new(&bin)
        .args(["scan", "--sbom", "invalid_format"])
        .output()
        .expect("command failed");

    assert_eq!(
        output.status.code(),
        Some(2),
        "--sbom invalid_format must exit with code 2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value 'invalid_format'") || stderr.contains("invalid_format"),
        "stderr should inform about invalid sbom value, got: {}",
        stderr
    );
    assert!(
        stderr.contains("cyclonedx") || stderr.contains("spdx"),
        "stderr should list allowed values"
    );
}

#[test]
fn test_cli_invalid_epss_threshold_rejected_exit_code_2() {
    ensure_binaries_built();
    let bin = get_bin_path("vexa-sca");

    // Value > 1.0
    let out_high = Command::new(&bin)
        .args(["scan", "--epss-threshold", "2"])
        .output()
        .expect("command failed");
    assert_eq!(
        out_high.status.code(),
        Some(2),
        "--epss-threshold 2 must exit with code 2"
    );
    let err_high = String::from_utf8_lossy(&out_high.stderr);
    assert!(
        err_high.contains("between 0.0 and 1.0"),
        "Expected error message mentioning 0.0 and 1.0, got: {}",
        err_high
    );

    // Negative value
    let out_neg = Command::new(&bin)
        .args(["scan", "--epss-threshold", "-0.5"])
        .output()
        .expect("command failed");
    assert_eq!(out_neg.status.code(), Some(2));

    // Non-numeric value
    let out_str = Command::new(&bin)
        .args(["scan", "--epss-threshold", "abc"])
        .output()
        .expect("command failed");
    assert_eq!(out_str.status.code(), Some(2));
}

#[test]
fn test_cli_invalid_severity_threshold_rejected_exit_code_2() {
    ensure_binaries_built();
    let bin = get_bin_path("vexa-sca");

    let output = Command::new(&bin)
        .args(["scan", "--severity-threshold", "nonsense"])
        .output()
        .expect("command failed");

    assert_eq!(
        output.status.code(),
        Some(2),
        "--severity-threshold nonsense must exit with code 2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid severity threshold 'nonsense'") || stderr.contains("nonsense"),
        "stderr should mention invalid severity, got: {}",
        stderr
    );
}

#[test]
fn test_cli_invalid_fail_on_rejected_exit_code_2() {
    ensure_binaries_built();
    let bin = get_bin_path("vexa-sca");

    let output = Command::new(&bin)
        .args(["scan", "--fail-on", "nonsense"])
        .output()
        .expect("command failed");

    assert_eq!(
        output.status.code(),
        Some(2),
        "--fail-on nonsense must exit with code 2"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid fail-on value 'nonsense'") || stderr.contains("nonsense"),
        "stderr should mention invalid fail-on value, got: {}",
        stderr
    );
}

#[test]
fn test_cli_invalid_fail_on_licenses_rejected_exit_code_2() {
    ensure_binaries_built();
    let bin = get_bin_path("vexa-sca");

    let output = Command::new(&bin)
        .args(["licenses", "--fail-on", "nonsense"])
        .output()
        .expect("command failed");

    assert_eq!(
        output.status.code(),
        Some(2),
        "licenses --fail-on nonsense must exit with code 2"
    );
}

#[test]
fn test_cli_container_invalid_options_rejected_exit_code_2() {
    ensure_binaries_built();
    let bin = get_bin_path("vexa-sca");

    let out1 = Command::new(&bin)
        .args(["container", ".", "--sbom", "invalid_sbom"])
        .output()
        .expect("command failed");
    assert_eq!(out1.status.code(), Some(2));

    let out2 = Command::new(&bin)
        .args(["container", ".", "--fail-on", "nonsense"])
        .output()
        .expect("command failed");
    assert_eq!(out2.status.code(), Some(2));
}

#[test]
fn test_cli_scan_report_only_mode_exit_code_0() {
    ensure_binaries_built();
    let bin = get_bin_path("vexa-sca");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("test/fixtures/npm-app");

    // Without --report-only: npm-app is vulnerable, so exit code must be 1
    let normal_out = Command::new(&bin)
        .args(["scan", fixture.to_str().unwrap()])
        .output()
        .expect("command failed");
    assert_eq!(
        normal_out.status.code(),
        Some(1),
        "vulnerable scan should exit 1 by default"
    );

    // With --no-fail: must exit 0 while still outputting findings
    let no_fail_out = Command::new(&bin)
        .args(["scan", fixture.to_str().unwrap(), "--no-fail"])
        .output()
        .expect("command failed");
    assert_eq!(
        no_fail_out.status.code(),
        Some(0),
        "--no-fail scan should exit 0"
    );
    let stdout = String::from_utf8_lossy(&no_fail_out.stdout);
    assert!(
        stdout.contains("lodash"),
        "scan report should still contain findings"
    );

    // With alias --report-only: must exit 0
    let report_only_out = Command::new(&bin)
        .args(["scan", fixture.to_str().unwrap(), "--report-only"])
        .output()
        .expect("command failed");
    assert_eq!(
        report_only_out.status.code(),
        Some(0),
        "--report-only scan should exit 0"
    );
}

#[test]
fn test_cli_output_files_and_schema_validation() {
    ensure_binaries_built();
    let bin = get_bin_path("vexa-sca");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("test/fixtures/npm-app");
    let temp_dir = std::env::temp_dir().join(format!("vexa_cli_reports_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let sarif_path = temp_dir.join("results.sarif");
    let html_path = temp_dir.join("dashboard.html");
    let sbom_path = temp_dir.join("bom.json");
    let spdx_path = temp_dir.join("bom.spdx.json");

    let out = Command::new(&bin)
        .args([
            "scan",
            fixture.to_str().unwrap(),
            "--sarif-file",
            sarif_path.to_str().unwrap(),
            "--html-file",
            html_path.to_str().unwrap(),
            "--sbom-file",
            sbom_path.to_str().unwrap(),
            "--report-only",
        ])
        .output()
        .expect("command failed");
    assert_eq!(out.status.code(), Some(0));

    // 1. Verify SARIF Schema compliance
    assert!(sarif_path.exists());
    let sarif_content = fs::read_to_string(&sarif_path).unwrap();
    let sarif_val: serde_json::Value = serde_json::from_str(&sarif_content).unwrap();
    assert_eq!(sarif_val["version"], "2.1.0");
    assert!(sarif_val["$schema"]
        .as_str()
        .unwrap()
        .contains("sarif-schema-2.1.0.json"));
    let runs = sarif_val["runs"].as_array().expect("runs array");
    assert!(!runs.is_empty());
    assert_eq!(runs[0]["tool"]["driver"]["name"], "vexa-sca");
    assert!(!runs[0]["results"].as_array().unwrap().is_empty());

    // 2. Verify HTML report
    assert!(html_path.exists());
    let html_content = fs::read_to_string(&html_path).unwrap();
    assert!(html_content.contains("<!DOCTYPE html>"));
    assert!(html_content.contains("Vexa SCA Security Report"));
    assert!(html_content.contains("lodash"));

    // 3. Verify CycloneDX SBOM compliance
    assert!(sbom_path.exists());
    let cdx_content = fs::read_to_string(&sbom_path).unwrap();
    let cdx_val: serde_json::Value = serde_json::from_str(&cdx_content).unwrap();
    assert_eq!(cdx_val["bomFormat"], "CycloneDX");
    assert_eq!(cdx_val["specVersion"], "1.5");
    assert!(cdx_val["serialNumber"]
        .as_str()
        .unwrap()
        .starts_with("urn:uuid:"));
    assert!(!cdx_val["components"].as_array().unwrap().is_empty());

    // 4. Test SPDX SBOM output
    let spdx_out = Command::new(&bin)
        .args([
            "scan",
            fixture.to_str().unwrap(),
            "--sbom",
            "spdx",
            "--sbom-file",
            spdx_path.to_str().unwrap(),
            "--report-only",
        ])
        .output()
        .expect("command failed");
    assert_eq!(spdx_out.status.code(), Some(0));
    assert!(spdx_path.exists());
    let spdx_content = fs::read_to_string(&spdx_path).unwrap();
    let spdx_val: serde_json::Value = serde_json::from_str(&spdx_content).unwrap();
    assert_eq!(spdx_val["spdxVersion"], "SPDX-2.3");
    assert_eq!(spdx_val["dataLicense"], "CC0-1.0");
    assert_eq!(spdx_val["SPDXID"], "SPDXRef-DOCUMENT");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_lockfile_patching_and_backup_creation() {
    let temp_dir = std::env::temp_dir().join(format!("vexa_patch_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let fixture_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("test/fixtures/npm-app");
    let pkg_json_src = fixture_src.join("package.json");
    let lock_src = fixture_src.join("package-lock.json");

    let target_pkg = temp_dir.join("package.json");
    let target_lock = temp_dir.join("package-lock.json");

    fs::copy(&pkg_json_src, &target_pkg).unwrap();
    fs::copy(&lock_src, &target_lock).unwrap();

    let orig_pkg_content = fs::read_to_string(&target_pkg).unwrap();

    let remediations = vec![vexa_sca::types::RemediationAction {
        package: "lodash".to_string(),
        current_version: "4.17.15".to_string(),
        is_transitive: false,
        target_version: Some("4.17.21".to_string()),
        action_type: "UPGRADE_DIRECT".to_string(),
        advice: "Bump version to 4.17.21".to_string(),
        resolved_vulnerability_count: 2,
        vulnerability_ids: vec!["GHSA-35jh-r3h4-6jhm".to_string()],
        highest_severity: Some(vexa_sca::types::SeverityLevel::High),
    }];

    // Apply real fixes
    let res = vexa_sca::patcher::apply_fixes(
        &temp_dir,
        &vexa_sca::parsers::detector::ManifestType::NpmPackageLock,
        &remediations,
        false,
    )
    .expect("apply fixes should succeed");

    assert!(res.modified);
    assert!(res.backup_file.is_some());
    let backup_path = res.backup_file.unwrap();
    assert!(backup_path.exists());

    // Verify backup contains the exact original package.json
    let backup_content = fs::read_to_string(&backup_path).unwrap();
    assert_eq!(backup_content, orig_pkg_content);

    // Verify patched package.json has 4.17.21
    let patched_pkg = fs::read_to_string(&target_pkg).unwrap();
    assert!(patched_pkg.contains("4.17.21"));

    // Rollback test: restore from backup
    fs::copy(&backup_path, &target_pkg).unwrap();
    let restored = fs::read_to_string(&target_pkg).unwrap();
    assert_eq!(restored, orig_pkg_content);

    let _ = fs::remove_dir_all(&temp_dir);
}
