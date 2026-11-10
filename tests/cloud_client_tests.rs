#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use vexa_sca::cloud::auth::AuthManager;
use vexa_sca::cloud::bundle::{OfflineBundleVerifier, OfflineDbEnvelope};
use vexa_sca::cloud::client::CloudClient;
use vexa_sca::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use vexa_sca::scanner::vuln_scanner::ScanResult;
use vexa_sca::types::{
    PkgInfo, ReachabilityResult, ReachabilityStatus, SeverityInfo, SeverityLevel,
    VulnerabilityFinding,
};

#[test]
fn test_auth_manager_storage_lifecycle() {
    let temp_home = std::env::temp_dir().join("vexa_test_auth_lifecycle");
    let _ = std::fs::remove_dir_all(&temp_home);

    std::env::set_var("USERPROFILE", &temp_home);
    std::env::set_var("HOME", &temp_home);

    // Save token
    let token = "vexa_pat_7f9a8b1c2d3e4f5a6b7c8d9e";
    let res = AuthManager::save_token(token, Some("acme-corp"), Some("dev@acme.com"));
    assert!(res.is_ok());

    // Verify stored
    let creds = AuthManager::load_stored_credentials().expect("Credentials should exist");
    assert_eq!(creds.token, token);
    assert_eq!(creds.org_slug.as_deref(), Some("acme-corp"));
    assert_eq!(creds.user_email.as_deref(), Some("dev@acme.com"));

    // Verify logout
    let logout_res = AuthManager::logout().expect("Logout should succeed");
    assert!(logout_res);
    assert!(AuthManager::load_stored_credentials().is_none());

    // Verify offline / unverified status handling
    let _ = AuthManager::save_token("vexa_pat_test_offline_status", Some("test-org"), None);
    let unreachable_api = "http://127.0.0.1:59999/api/v1";
    let rt = tokio::runtime::Runtime::new().unwrap();
    let status = rt.block_on(AuthManager::check_status(Some(unreachable_api)));

    assert!(
        !status.authenticated,
        "Must NOT claim authenticated: true when cloud is unreachable"
    );
    assert!(
        !status.cloud_verified,
        "Must report cloud_verified: false when unreachable"
    );
    assert!(
        status.error_message.is_some(),
        "Must report clear notice of unreachable API"
    );
    assert_eq!(status.token_prefix.as_deref(), Some("vexa_pat_tes..."));

    let _ = AuthManager::logout();
    let _ = std::fs::remove_dir_all(&temp_home);
}

#[test]
fn test_cloud_facts_zero_code_schema() {
    let root = PkgInfo::new("my-service", "1.0.0", "npm");
    let mut graph = DepGraph::new(
        root.clone(),
        PkgManagerInfo {
            name: "npm".to_string(),
            version: "9.0.0".to_string(),
        },
    );

    let direct_pkg = PkgInfo::new("express", "4.18.2", "npm");
    graph.add_pkg(direct_pkg.clone());
    let direct_node_id = "npm:express@4.18.2".to_string();
    graph.add_node(
        direct_node_id.clone(),
        direct_pkg.id.clone(),
        NodeInfo {
            scope: "prod".to_string(),
            path: None,
            integrity: None,
        },
    );
    // Link root -> direct_pkg
    graph
        .nodes
        .get_mut(&graph.root_node_id)
        .unwrap()
        .deps
        .push(direct_node_id.clone());

    let transitive_pkg = PkgInfo::new("ms", "2.1.3", "npm");
    graph.add_pkg(transitive_pkg.clone());
    let transitive_node_id = "npm:ms@2.1.3".to_string();
    graph.add_node(
        transitive_node_id.clone(),
        transitive_pkg.id.clone(),
        NodeInfo {
            scope: "prod".to_string(),
            path: None,
            integrity: None,
        },
    );
    // Link direct_pkg -> transitive_pkg
    graph
        .nodes
        .get_mut(&direct_node_id)
        .unwrap()
        .deps
        .push(transitive_node_id);

    let mut scan_result = ScanResult::default();
    scan_result.vulnerabilities.push(VulnerabilityFinding {
        id: "GHSA-1234-5678".to_string(),
        title: "Prototype Pollution in Express".to_string(),
        package: "express".to_string(),
        version: "4.18.2".to_string(),
        ecosystem: "npm".to_string(),
        pkg_id: direct_pkg.id,
        severity: SeverityInfo {
            level: SeverityLevel::High,
            score: 7.5,
            vector: None,
        },
        cve: Some("CVE-2026-1234".to_string()),
        cwes: vec!["CWE-1321".to_string()],
        cwe_ids: vec!["CWE-1321".to_string()],
        owasp_category: Some("A03:2021-Injection".to_string()),
        is_kev: true,
        kev_date_added: Some("2026-03-01".to_string()),
        affected_symbols: vec!["express.urlencoded".to_string()],
        fixed_in: vec!["4.18.3".to_string()],
        is_transitive: false,
        paths: vec![],
        details: Some("Test vuln".to_string()),
        references: vec![],
        reachability: Some(ReachabilityResult {
            status: ReachabilityStatus::Reachable,
            is_direct_call: true,
            call_sites: vec![],
            target_functions: vec!["express.urlencoded".to_string()],
            reason_code: None,
            analyzer_version: "2.0.0".to_string(),
        }),
        aliases: vec![],
        advisory_category: Default::default(),
        epss: None,
        fingerprint: "fp123".to_string(),
        usage_signal: Default::default(),
        reason_code: None,
        priority_score: 80.0,
        is_new: false,
        ..Default::default()
    });

    let facts = CloudClient::extract_facts(&graph, &scan_result);

    assert_eq!(facts.project_name, "my-service");
    assert_eq!(facts.project_version, "1.0.0");
    assert_eq!(facts.ecosystem, "npm");
    assert_eq!(facts.total_packages, 2); // express, ms
    assert_eq!(facts.direct_dependencies, 1);
    assert_eq!(facts.transitive_dependencies, 1);
    assert_eq!(facts.reachable_vulnerabilities, 1);
    assert_eq!(facts.findings.len(), 1);
    assert!(facts.findings[0].is_kev);
    assert_eq!(facts.findings[0].reachability, "REACHABLE");

    // Test saving facts file
    let temp_dir = std::env::temp_dir().join("vexa_facts_test");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let saved = CloudClient::save_facts_file(&temp_dir, &facts);
    assert!(saved.is_ok());
    let facts_path = saved.unwrap();
    assert!(facts_path.exists());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_offline_bundle_verification_with_ed25519() {
    // Generate an ephemeral test Ed25519 keypair
    let rng_seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&rng_seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.as_bytes());

    let payload = r#"{"advisories": [{"id": "CVE-2026-9999", "package": "test-pkg", "severity": "CRITICAL"}]}"#;
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let payload_sha256 = hex::encode(hasher.finalize());

    let created_at = "2026-11-01T00:00:00Z";
    let message = format!("VEXA-OFFLINE-DB-V1:{}:{}", created_at, payload_sha256);
    let signature = signing_key.sign(message.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let envelope = OfflineDbEnvelope {
        format_version: 1,
        created_at: created_at.to_string(),
        issuer: "Vexa Security Authority".to_string(),
        advisory_count: 1,
        payload_sha256: payload_sha256.clone(),
        payload_json: payload.to_string(),
        signature_ed25519_hex: signature_hex,
    };

    let envelope_json = serde_json::to_string(&envelope).unwrap();

    // 1. Valid signature passes verification
    let res = OfflineBundleVerifier::verify_bundle_content(&envelope_json, Some(&pubkey_hex));
    assert!(res.is_ok(), "Expected valid bundle to pass verification");
    let (verified, _) = res.unwrap();
    assert_eq!(verified.advisory_count, 1);
    assert_eq!(verified.payload_sha256, payload_sha256);

    // 2. Tampered payload is caught by SHA-256 integrity check
    let mut tampered_envelope = envelope.clone();
    tampered_envelope.payload_json = r#"{"advisories": []}"#.to_string();
    let tampered_json = serde_json::to_string(&tampered_envelope).unwrap();
    let err_res = OfflineBundleVerifier::verify_bundle_content(&tampered_json, Some(&pubkey_hex));
    assert!(err_res.is_err());
    assert!(err_res.unwrap_err().contains("integrity mismatch"));

    // 3. Invalid signature is rejected
    let mut bad_sig_envelope = envelope;
    bad_sig_envelope.signature_ed25519_hex = "00".repeat(64);
    let bad_sig_json = serde_json::to_string(&bad_sig_envelope).unwrap();
    let bad_sig_res =
        OfflineBundleVerifier::verify_bundle_content(&bad_sig_json, Some(&pubkey_hex));
    assert!(bad_sig_res.is_err());
}

#[test]
fn test_facts_payload_v2_contains_zero_raw_source_code() {
    use vexa_sca::scanner::sast::SastScanner;
    use vexa_sca::scanner::secrets::SecretScanner;

    let temp_dir = std::env::temp_dir().join("vexa_facts_v2_zero_code_test");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(temp_dir.join("src")).unwrap();

    // Write a Python file with OS command injection and a secret
    let raw_code_line = "os.system(\"ping -c 4 \" + TOP_SECRET_INTERNAL_PAYLOAD)";
    let raw_secret = "AKIAIOSFODNN7EXAMPLE";
    let py_file = temp_dir.join("src").join("os-ijection.py");
    std::fs::write(
        &py_file,
        format!(
            "import os\nAWS_KEY = \"{}\"\ndef run(user_input):\n    {}\n",
            raw_secret, raw_code_line
        ),
    )
    .unwrap();

    let mut code_findings = SastScanner::scan_workspace(&temp_dir);
    code_findings.extend(SecretScanner::scan_workspace(&temp_dir));
    assert!(
        code_findings.len() >= 2,
        "Expected both SAST and SECRET findings"
    );

    let root = PkgInfo::new("sast", "0.1.0", "source");
    let graph = DepGraph::new(
        root,
        PkgManagerInfo {
            name: "source".to_string(),
            version: "1.0.0".to_string(),
        },
    );

    let scan_result = ScanResult {
        code_findings,
        ..Default::default()
    };

    let facts = CloudClient::extract_facts(&graph, &scan_result);
    assert_eq!(facts.version, 2);
    assert!(facts.code_findings.len() >= 2);
    assert!(
        facts
            .code_findings
            .iter()
            .all(|cf| !cf.file_path.contains('\\')),
        "All file_path entries must be normalized to POSIX forward slashes"
    );

    let serialized = serde_json::to_string_pretty(&facts).unwrap();
    assert!(
        !serialized.contains("TOP_SECRET_INTERNAL_PAYLOAD"),
        "Zero-Code-Sync Invariant violated: raw code line leaked into .vexa.facts.json"
    );
    assert!(
        !serialized.contains(raw_secret),
        "Zero-Code-Sync Invariant violated: unmasked secret leaked into .vexa.facts.json"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}
