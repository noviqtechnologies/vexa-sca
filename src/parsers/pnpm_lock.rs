use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Parse a pnpm lock file that may contain one or more YAML documents
/// (pnpm v9 lockfiles start with a bare `---` separator making them
/// multi-document streams). Returns the *first* non-null document that
/// contains `lockfileVersion`, falling back to the first document.
fn parse_pnpm_yaml_multidoc(content: &str) -> Result<YamlValue, String> {
    // serde_yaml Deserializer is an iterator over documents in a stream.
    let mut docs: Vec<YamlValue> = Vec::new();
    for doc in serde_yaml::Deserializer::from_str(content) {
        let val = YamlValue::deserialize(doc)
            .map_err(|e| format!("Failed to parse YAML document: {}", e))?;
        docs.push(val);
    }
    if docs.is_empty() {
        return Err("pnpm lockfile is empty".to_string());
    }
    // Prefer the document that has `lockfileVersion` (typically the second
    // document in v9 files where the first is an empty mapping from `---`).
    let chosen = docs
        .iter()
        .find(|d| d.get("lockfileVersion").is_some())
        .cloned()
        .unwrap_or_else(|| docs[0].clone());
    Ok(chosen)
}

/// Peer dependency pair extracted from pnpm snapshot key suffixes.
type PeerDep = (String, String);

/// Extract the version string from an importer dependency value.
/// Supports both plain string `"1.2.3"` and mapping `{specifier: "^1", version: "1.2.3"}`.
fn importer_dep_version(v: &YamlValue) -> &str {
    match v {
        YamlValue::String(s) => s.as_str(),
        YamlValue::Mapping(m) => m
            .get(YamlValue::String("version".to_string()))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        _ => "",
    }
}

pub struct PnpmLockParser;

impl PnpmLockParser {
    /// Parses package.json and pnpm-lock.yaml / pnpm-lock.yml into standard DepGraph schema.
    pub fn parse(project_dir: &Path, include_dev: bool) -> Result<DepGraph, String> {
        let manifest_path = project_dir.join("package.json");
        let lock_path_yaml = project_dir.join("pnpm-lock.yaml");
        let lock_path_yml = project_dir.join("pnpm-lock.yml");

        let lockfile_path = if lock_path_yaml.exists() {
            lock_path_yaml
        } else if lock_path_yml.exists() {
            lock_path_yml
        } else {
            return Err(format!(
                "pnpm-lock.yaml not found in {}",
                project_dir.display()
            ));
        };

        let (project_name, project_version, direct_deps) = if manifest_path.exists() {
            let manifest_str = fs::read_to_string(&manifest_path)
                .map_err(|e| format!("Failed to read package.json: {}", e))?;
            let manifest: JsonValue = serde_json::from_str(&manifest_str)
                .map_err(|e| format!("Invalid JSON in package.json: {}", e))?;

            let name = manifest
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| {
                    project_dir
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("app")
                })
                .to_string();

            let version = manifest
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("0.0.0")
                .to_string();

            let mut deps = HashMap::new();
            if let Some(d) = manifest.get("dependencies").and_then(|d| d.as_object()) {
                for (k, v) in d {
                    deps.insert(k.clone(), (v.as_str().unwrap_or("").to_string(), false));
                }
            }
            if include_dev {
                if let Some(dev) = manifest.get("devDependencies").and_then(|d| d.as_object()) {
                    for (k, v) in dev {
                        deps.insert(k.clone(), (v.as_str().unwrap_or("").to_string(), true));
                    }
                }
            }

            (name, version, deps)
        } else {
            let dir_name = project_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("app")
                .to_string();
            (dir_name, "0.0.0".to_string(), HashMap::new())
        };

        let lock_content = fs::read_to_string(&lockfile_path)
            .map_err(|e| format!("Failed to read {}: {}", lockfile_path.display(), e))?;

        let lock_yaml: YamlValue = parse_pnpm_yaml_multidoc(&lock_content)
            .map_err(|e| format!("Failed to parse YAML in {}: {}", lockfile_path.display(), e))?;

        let lockfile_ver = lock_yaml
            .get("lockfileVersion")
            .map(|v| match v {
                YamlValue::String(s) => s.clone(),
                YamlValue::Number(n) => n.to_string(),
                _ => "6.0".to_string(),
            })
            .unwrap_or_else(|| "6.0".to_string());

        let root_pkg = PkgInfo::new(&project_name, &project_version, "npm");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "pnpm".to_string(),
                version: lockfile_ver,
            },
        );

        // Map to keep track of name -> list of (version, node_id)
        let mut pkg_version_map: HashMap<String, Vec<(String, String)>> = HashMap::new();
        // Stores child edges to resolve: (parent_node_id, child_name, child_spec)
        let mut pending_edges: Vec<(String, String, String)> = Vec::new();
        // Workspace node_ids keyed by importer path (e.g. "packages/frontend")
        let mut workspace_node_ids: HashMap<String, String> = HashMap::new();

        // ------------------------------------------------------------------
        // Phase 1: collect integrity from `packages` into a side-map (v9)
        // ------------------------------------------------------------------
        let mut integrity_map: HashMap<String, String> = HashMap::new();
        if let Some(packages) = lock_yaml.get("packages").and_then(|p| p.as_mapping()) {
            for (key_val, entry_val) in packages {
                if let YamlValue::String(raw_key) = key_val {
                    if let Some(integ) = entry_val
                        .get("resolution")
                        .and_then(|r| r.get("integrity"))
                        .and_then(|i| i.as_str())
                    {
                        integrity_map.insert(raw_key.clone(), integ.to_string());
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // Phase 2: ingest nodes + edges from `snapshots` (v9) or `packages` (v5/v6).
        // We prefer `snapshots` when present (v9), fall back to `packages`.
        // ------------------------------------------------------------------
        let pkg_entries_key = if lock_yaml.get("snapshots").is_some() {
            "snapshots"
        } else {
            "packages"
        };

        if let Some(entries) = lock_yaml.get(pkg_entries_key).and_then(|p| p.as_mapping()) {
            for (key_val, entry_val) in entries {
                let raw_key = match key_val {
                    YamlValue::String(s) => s.as_str(),
                    _ => continue,
                };

                let (pkg_name, pkg_version, peer_deps) =
                    match Self::parse_package_key_with_peers(raw_key) {
                        Some(parsed) => parsed,
                        None => continue,
                    };

                // Dev flag: v5/v6 carry it in `packages`; v9 snapshots do not.
                let is_dev = entry_val
                    .get("dev")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if is_dev && !include_dev {
                    continue;
                }

                let pkg_info = PkgInfo::new(&pkg_name, &pkg_version, "npm");
                graph.add_pkg(pkg_info.clone());

                let node_id = format!("pnpm:{}@{}", pkg_name, pkg_version);

                // Resolve integrity: snapshot entry may have it directly, or from
                // the `packages` map collected in the first pass.
                let integrity = entry_val
                    .get("resolution")
                    .and_then(|r| r.get("integrity"))
                    .and_then(|i| i.as_str())
                    .map(|s| s.to_string())
                    .or_else(|| integrity_map.get(raw_key).cloned());

                graph.add_node(
                    node_id.clone(),
                    pkg_info.id.clone(),
                    NodeInfo {
                        scope: if is_dev {
                            "dev".to_string()
                        } else {
                            "prod".to_string()
                        },
                        path: None,
                        integrity,
                    },
                );

                pkg_version_map
                    .entry(pkg_name.clone())
                    .or_default()
                    .push((pkg_version.clone(), node_id.clone()));

                // --- Collect regular dependency edges ---
                for dep_section in &["dependencies", "optionalDependencies"] {
                    if let Some(deps) = entry_val.get(dep_section).and_then(|d| d.as_mapping()) {
                        for (dep_k, dep_v) in deps {
                            if let Some(dep_name) = dep_k.as_str() {
                                let dep_spec = dep_v.as_str().unwrap_or("");
                                pending_edges.push((
                                    node_id.clone(),
                                    dep_name.to_string(),
                                    dep_spec.to_string(),
                                ));
                            }
                        }
                    }
                }

                // --- peerDependencies section (declared in snapshots/packages entry) ---
                if let Some(peer_deps_map) = entry_val
                    .get("peerDependencies")
                    .and_then(|d| d.as_mapping())
                {
                    for (dep_k, dep_v) in peer_deps_map {
                        if let Some(dep_name) = dep_k.as_str() {
                            let dep_spec = dep_v.as_str().unwrap_or("");
                            pending_edges.push((
                                node_id.clone(),
                                dep_name.to_string(),
                                dep_spec.to_string(),
                            ));
                        }
                    }
                }

                // --- Peer deps extracted from snapshot key suffix, e.g.
                //     react-dom@18.2.0(react@18.2.0) -> edge from react-dom to react@18.2.0 ---
                for (peer_name, peer_ver) in peer_deps {
                    pending_edges.push((node_id.clone(), peer_name, peer_ver));
                }
            }
        }

        // ------------------------------------------------------------------
        // Phase 3: wire workspace sub-packages from ALL `importers` entries
        // ------------------------------------------------------------------
        if let Some(importers) = lock_yaml.get("importers").and_then(|i| i.as_mapping()) {
            for (imp_key, imp_val) in importers {
                let imp_path = match imp_key.as_str() {
                    Some(p) => p,
                    None => continue,
                };

                // Determine the node that owns this importer's deps
                let importer_node_id = if imp_path == "." {
                    graph.root_node_id.clone()
                } else {
                    // Register a synthetic workspace package node
                    let ws_name = imp_path.to_string();
                    let ws_node_id = format!("pnpm:{}@0.0.0", ws_name);
                    if !graph.nodes.contains_key(&ws_node_id) {
                        let ws_pkg = PkgInfo::new(&ws_name, "0.0.0", "npm");
                        graph.add_pkg(ws_pkg.clone());
                        graph.add_node(
                            ws_node_id.clone(),
                            ws_pkg.id.clone(),
                            NodeInfo {
                                scope: "prod".to_string(),
                                path: Some(imp_path.to_string()),
                                integrity: None,
                            },
                        );
                        // Connect workspace sub-package to root
                        let _ = graph.add_edge(&graph.root_node_id.clone(), &ws_node_id);
                    }
                    workspace_node_ids.insert(imp_path.to_string(), ws_node_id.clone());
                    ws_node_id
                };

                // Process each dep section in this importer
                for dep_section in &["dependencies", "devDependencies", "optionalDependencies"] {
                    if *dep_section == "devDependencies" && !include_dev {
                        continue;
                    }
                    let Some(deps) = imp_val.get(dep_section).and_then(|d| d.as_mapping()) else {
                        continue;
                    };
                    for (dep_k, dep_v) in deps {
                        let dep_name = match dep_k.as_str() {
                            Some(n) => n,
                            None => continue,
                        };
                        let spec = importer_dep_version(dep_v);

                        // Detect link: / workspace: references
                        if spec.starts_with("link:") || spec.starts_with("workspace:") {
                            // Resolve target path relative to the importer
                            let link_target = spec
                                .trim_start_matches("link:")
                                .trim_start_matches("workspace:");
                            let target_path = if link_target == "*"
                                || link_target == "^"
                                || link_target == "~"
                                || link_target.is_empty()
                            {
                                // workspace:* means "this package by name"; look it up by dep_name in workspace_node_ids
                                dep_name.to_string()
                            } else {
                                // Normalise path: strip leading "./"
                                let link_target = link_target.trim_start_matches("./");
                                if imp_path == "." {
                                    link_target.to_string()
                                } else {
                                    // resolve relative to importer dir
                                    format!("{}/{}", imp_path, link_target)
                                }
                            };

                            // Try to find the workspace node for this path
                            if let Some(ws_id) = workspace_node_ids.get(&target_path) {
                                let _ = graph.add_edge(&importer_node_id, ws_id);
                            } else {
                                // Queue for later resolution (workspace node may not be registered yet)
                                pending_edges.push((
                                    importer_node_id.clone(),
                                    dep_name.to_string(),
                                    format!("ws:{}", target_path),
                                ));
                            }
                        } else {
                            // Regular dep: resolve against pkg_version_map
                            pending_edges.push((
                                importer_node_id.clone(),
                                dep_name.to_string(),
                                spec.to_string(),
                            ));
                        }
                    }
                }
            }
        }

        // ------------------------------------------------------------------
        // Phase 4: resolve pending edges
        // ------------------------------------------------------------------
        for (parent_node_id, child_name, child_spec) in &pending_edges {
            // Handle workspace cross-reference edges queued as "ws:<path>"
            if let Some(ws_path) = child_spec.strip_prefix("ws:") {
                // Try by path first, then by name
                if let Some(ws_id) = workspace_node_ids.get(ws_path) {
                    let _ = graph.add_edge(parent_node_id, ws_id);
                } else if let Some(ws_id) = workspace_node_ids.get(child_name.as_str()) {
                    let _ = graph.add_edge(parent_node_id, ws_id);
                }
                continue;
            }

            if let Some(candidates) = pkg_version_map.get(child_name) {
                // Find best matching version
                let matched_node = candidates
                    .iter()
                    .find(|(v, _)| {
                        child_spec.is_empty() || child_spec.contains(v) || v == child_spec
                    })
                    .map(|(_, id)| id)
                    .or_else(|| candidates.first().map(|(_, id)| id));

                if let Some(child_id) = matched_node {
                    let _ = graph.add_edge(parent_node_id, child_id);
                }
            }
        }

        // ------------------------------------------------------------------
        // Phase 5: connect root direct deps from manifest or top-level lockfile
        // ------------------------------------------------------------------
        // Check manifest direct_deps first
        let mut root_connected = 0;
        for (dep_name, (dep_spec, _)) in &direct_deps {
            if let Some(candidates) = pkg_version_map.get(dep_name) {
                let matched = candidates
                    .iter()
                    .find(|(v, _)| dep_spec.is_empty() || dep_spec.contains(v) || v == dep_spec)
                    .map(|(_, id)| id)
                    .or_else(|| candidates.first().map(|(_, id)| id));

                if let Some(child_id) = matched {
                    let _ = graph.add_edge(&graph.root_node_id.clone(), child_id);
                    root_connected += 1;
                }
            }
        }

        // If no manifest or nothing was connected yet, check pnpm-lock top-level
        // dependencies or importers['.'] (handled above in phase 3 already, but
        // also check legacy top-level deps for v5/v6 without importers)
        if root_connected == 0 {
            let mut top_deps: Vec<(String, String)> = Vec::new();

            for dep_section in &["dependencies", "devDependencies"] {
                if *dep_section == "devDependencies" && !include_dev {
                    continue;
                }
                if let Some(deps) = lock_yaml.get(dep_section).and_then(|d| d.as_mapping()) {
                    for (k, v) in deps {
                        if let Some(name) = k.as_str() {
                            top_deps.push((name.to_string(), importer_dep_version(v).to_string()));
                        }
                    }
                }
            }

            for (dep_name, dep_spec) in top_deps {
                if let Some(candidates) = pkg_version_map.get(&dep_name) {
                    let matched = candidates
                        .iter()
                        .find(|(v, _)| {
                            dep_spec.is_empty() || dep_spec.contains(v) || v == &dep_spec
                        })
                        .map(|(_, id)| id)
                        .or_else(|| candidates.first().map(|(_, id)| id));

                    if let Some(child_id) = matched {
                        let _ = graph.add_edge(&graph.root_node_id.clone(), child_id);
                    }
                }
            }
        }

        Ok(graph)
    }

    /// Extracts `(package_name, version, peer_deps)` from diverse pnpm package key patterns.
    ///
    /// Supported formats:
    /// - `lodash@4.17.15` (v9)
    /// - `/lodash@4.17.15` (v6)
    /// - `/lodash/4.17.15` (v5)
    /// - `@babel/core@7.20.0` (v9 scoped)
    /// - `/@babel/core@7.20.0` (v6 scoped)
    /// - `/@babel/core/7.20.0` (v5 scoped)
    /// - `react-dom@18.2.0(react@18.2.0)` — v9 snapshot with peer suffix
    /// - `/react-dom/18.2.0_react@18.2.0` — v5 snapshot with underscore peer suffix
    ///
    /// The returned `peer_deps` vector contains `(peer_name, peer_version)` pairs
    /// extracted from the parenthetical or underscore suffix. These are pushed as
    /// real edges in the dependency graph rather than being silently stripped.
    pub fn parse_package_key_with_peers(raw_key: &str) -> Option<(String, String, Vec<PeerDep>)> {
        let mut key = raw_key.trim();
        if key.starts_with('/') {
            key = &key[1..];
        }

        // Extract peer dependency annotations from parenthetical suffix:
        // react-dom@18.2.0(react@18.2.0)(react-dom@18.2.0) -> peers = [(react, 18.2.0)]
        let mut peer_deps: Vec<(String, String)> = Vec::new();
        if let Some(paren_start) = key.find('(') {
            let peer_str = &key[paren_start + 1..];
            key = &key[..paren_start];
            // Each group is like "react@18.2.0)" or "react@18.2.0)(next@14.0.0)"
            for group in peer_str.split(')') {
                let group = group.trim_start_matches('(').trim();
                if group.is_empty() {
                    continue;
                }
                if let Some(at_pos) = group.rfind('@') {
                    let p_name = &group[..at_pos];
                    let p_ver = &group[at_pos + 1..];
                    if !p_name.is_empty() && !p_ver.is_empty() {
                        peer_deps.push((p_name.to_string(), p_ver.to_string()));
                    }
                }
            }
        }

        // Extract peer dependency annotations from underscore suffix (v5):
        // /react-dom/18.2.0_react@18.2.0 -> peers = [(react, 18.2.0)]
        if let Some(under_idx) = key.find('_') {
            // Only treat as peer suffix if the part after '_' looks like "name@ver"
            let suffix = &key[under_idx + 1..];
            if suffix.contains('@') {
                for group in suffix.split('_') {
                    if let Some(at_pos) = group.rfind('@') {
                        let p_name = &group[..at_pos];
                        let p_ver = &group[at_pos + 1..];
                        if !p_name.is_empty() && !p_ver.is_empty() {
                            peer_deps.push((p_name.to_string(), p_ver.to_string()));
                        }
                    }
                }
                key = &key[..under_idx];
            }
        }

        if key.is_empty() {
            return None;
        }

        let (name, version) = Self::split_name_version(key)?;
        Some((name, version, peer_deps))
    }

    /// Legacy wrapper — returns only (name, version), discarding peer deps.
    /// Retained for backwards-compatibility with existing unit tests.
    pub fn parse_package_key(raw_key: &str) -> Option<(String, String)> {
        Self::parse_package_key_with_peers(raw_key).map(|(name, version, _)| (name, version))
    }

    /// Split a stripped key (no leading `/`, no peer suffixes) into name + version.
    fn split_name_version(key: &str) -> Option<(String, String)> {
        if key.starts_with('@') {
            // Scoped package: @scope/name@version or @scope/name/version
            let slash_idx = key.find('/')?;
            let rest = &key[slash_idx + 1..];

            if let Some(at_idx) = rest.rfind('@') {
                let scope_and_name = &key[..slash_idx + 1 + at_idx];
                let version = &rest[at_idx + 1..];
                if !scope_and_name.is_empty() && !version.is_empty() {
                    return Some((scope_and_name.to_string(), version.to_string()));
                }
            } else if let Some(slash2_idx) = rest.rfind('/') {
                let scope_and_name = &key[..slash_idx + 1 + slash2_idx];
                let version = &rest[slash2_idx + 1..];
                if !scope_and_name.is_empty() && !version.is_empty() {
                    return Some((scope_and_name.to_string(), version.to_string()));
                }
            }
        } else {
            // Non-scoped package: lodash@4.17.15 or lodash/4.17.15
            if let Some(at_idx) = key.rfind('@') {
                let name = &key[..at_idx];
                let version = &key[at_idx + 1..];
                if !name.is_empty() && !version.is_empty() {
                    return Some((name.to_string(), version.to_string()));
                }
            } else if let Some(slash_idx) = key.rfind('/') {
                let name = &key[..slash_idx];
                let version = &key[slash_idx + 1..];
                if !name.is_empty() && !version.is_empty() {
                    return Some((name.to_string(), version.to_string()));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_package_key_variants() {
        assert_eq!(
            PnpmLockParser::parse_package_key("/lodash/4.17.15"),
            Some(("lodash".to_string(), "4.17.15".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/lodash@4.17.15"),
            Some(("lodash".to_string(), "4.17.15".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("lodash@4.17.15"),
            Some(("lodash".to_string(), "4.17.15".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/@babel/core/7.20.0"),
            Some(("@babel/core".to_string(), "7.20.0".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/@babel/core@7.20.0"),
            Some(("@babel/core".to_string(), "7.20.0".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("@babel/core@7.20.0"),
            Some(("@babel/core".to_string(), "7.20.0".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/react-dom@18.2.0(react@18.2.0)"),
            Some(("react-dom".to_string(), "18.2.0".to_string()))
        );
        assert_eq!(
            PnpmLockParser::parse_package_key("/react-dom/18.2.0_react@18.2.0"),
            Some(("react-dom".to_string(), "18.2.0".to_string()))
        );
    }

    /// Verify that peer dep suffixes in snapshot keys are extracted as (name, ver) pairs.
    #[test]
    fn test_parse_package_key_with_peers_extracts_peer_edges() {
        // v9 parenthetical: react-dom@18.2.0(react@18.2.0)
        let result = PnpmLockParser::parse_package_key_with_peers("react-dom@18.2.0(react@18.2.0)");
        assert!(result.is_some());
        let (name, ver, peers) = result.unwrap();
        assert_eq!(name, "react-dom");
        assert_eq!(ver, "18.2.0");
        assert_eq!(peers, vec![("react".to_string(), "18.2.0".to_string())]);

        // v5 underscore: /react-dom/18.2.0_react@18.2.0
        let result2 =
            PnpmLockParser::parse_package_key_with_peers("/react-dom/18.2.0_react@18.2.0");
        assert!(result2.is_some());
        let (name2, ver2, peers2) = result2.unwrap();
        assert_eq!(name2, "react-dom");
        assert_eq!(ver2, "18.2.0");
        assert_eq!(peers2, vec![("react".to_string(), "18.2.0".to_string())]);

        // multiple peers: pkg@1.0.0(react@18.2.0)(react-dom@18.2.0)
        let result3 = PnpmLockParser::parse_package_key_with_peers(
            "some-pkg@1.0.0(react@18.2.0)(react-dom@18.2.0)",
        );
        assert!(result3.is_some());
        let (_, _, peers3) = result3.unwrap();
        assert_eq!(peers3.len(), 2);
        assert!(peers3.contains(&("react".to_string(), "18.2.0".to_string())));
        assert!(peers3.contains(&("react-dom".to_string(), "18.2.0".to_string())));
    }

    /// Verify that a snapshot with peer suffix creates a graph edge from react-dom -> react.
    #[test]
    fn test_peer_dep_snapshot_creates_edge() {
        let tmp = std::env::temp_dir().join("vexa_pnpm_peer_edge_test");
        let _ = std::fs::create_dir_all(&tmp);

        let pkg_json = serde_json::json!({
            "name": "peer-test",
            "version": "1.0.0",
            "dependencies": { "react-dom": "^18.2.0" }
        });
        std::fs::write(
            tmp.join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap(),
        )
        .unwrap();

        // react-dom@18.2.0 depends on react@18.2.0 as peer, expressed in snapshot key suffix
        let lock = "---
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      react-dom:
        specifier: ^18.2.0
        version: 18.2.0(react@18.2.0)

packages:

  react-dom@18.2.0:
    resolution: {integrity: sha512-abc}

  react@18.2.0:
    resolution: {integrity: sha512-xyz}

snapshots:

  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0

  react@18.2.0: {}
";
        std::fs::write(tmp.join("pnpm-lock.yaml"), lock).unwrap();

        let graph =
            PnpmLockParser::parse(&tmp, true).expect("pnpm lockfile with peer deps must parse");

        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"react-dom"), "react-dom must be in graph");
        assert!(names.contains(&"react"), "react must be in graph");

        // react-dom node must have an edge to react
        let react_dom_node = graph
            .nodes
            .values()
            .find(|n| n.node_id == "pnpm:react-dom@18.2.0");
        assert!(react_dom_node.is_some(), "react-dom node must exist");
        let react_node_id = "pnpm:react@18.2.0".to_string();
        assert!(
            react_dom_node.unwrap().deps.contains(&react_node_id),
            "react-dom node must have edge to react@18.2.0"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Regression test: pnpm v9 lockfiles begin with a bare `---` YAML separator
    /// which makes them multi-document streams. The old `serde_yaml::from_str` call
    /// crashed with "more than one document is not supported". Verify the fixed
    /// multi-doc parser handles the v9 fixture without error and returns the packages.
    #[test]
    fn test_parse_pnpm_v9_multidoc_lockfile() {
        // Inline the v9 multi-document format so the test does not depend on the
        // filesystem fixture path (which varies by CWD in cargo test).
        let v9_content = "\
---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-abc123}\n\nsnapshots:\n\n  lodash@4.17.21: {}\n";

        let result = parse_pnpm_yaml_multidoc(v9_content);
        assert!(
            result.is_ok(),
            "pnpm v9 multi-document YAML must parse without error: {:?}",
            result.err()
        );
        let doc = result.unwrap();
        assert!(
            doc.get("lockfileVersion").is_some(),
            "Parsed document must contain 'lockfileVersion'"
        );
        assert!(
            doc.get("snapshots").is_some(),
            "Parsed document must contain 'snapshots' key for v9"
        );
    }

    /// Integration test: parse the v9 fixture file from disk and verify packages
    /// from `snapshots` are ingested into the dep graph.
    #[test]
    fn test_pnpm_v9_fixture_parses_packages() {
        // Write the fixture content inline to a temp dir so the test is hermetic
        let tmp = std::env::temp_dir().join("vexa_pnpm_v9_fixture_test");
        let _ = std::fs::create_dir_all(&tmp);

        let pkg_json = serde_json::json!({
            "name": "pnpm-v9-test",
            "version": "1.0.0",
            "dependencies": { "lodash": "^4.17.21", "minimist": "^1.2.8" }
        });
        std::fs::write(
            tmp.join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap(),
        )
        .unwrap();

        let v9_lock = "\
---\nlockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21\n      minimist:\n        specifier: ^1.2.8\n        version: 1.2.8\n\npackages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-abc}\n\n  minimist@1.2.8:\n    resolution: {integrity: sha512-xyz}\n\nsnapshots:\n\n  lodash@4.17.21: {}\n\n  minimist@1.2.8: {}\n";
        std::fs::write(tmp.join("pnpm-lock.yaml"), v9_lock).unwrap();

        let graph =
            PnpmLockParser::parse(&tmp, true).expect("pnpm v9 lockfile must parse without error");

        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"lodash"), "lodash must be in the dep graph");
        assert!(
            names.contains(&"minimist"),
            "minimist must be in the dep graph"
        );

        let lodash = pkgs.iter().find(|p| p.name == "lodash").unwrap();
        assert_eq!(lodash.version, "4.17.21");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Workspace importers test: verify that non-root importers (e.g. packages/frontend)
    /// are wired as workspace nodes and their link: / workspace: dependencies are connected.
    #[test]
    fn test_pnpm_workspace_importers_wired() {
        let tmp = std::env::temp_dir().join("vexa_pnpm_workspace_importers_test");
        let _ = std::fs::create_dir_all(&tmp);

        // Root package.json for the monorepo
        let pkg_json = serde_json::json!({
            "name": "my-monorepo",
            "version": "1.0.0"
        });
        std::fs::write(
            tmp.join("package.json"),
            serde_json::to_string_pretty(&pkg_json).unwrap(),
        )
        .unwrap();

        // pnpm v9 workspace lockfile with two importers:
        //   . (root) and packages/frontend
        // packages/frontend has a workspace: link to packages/shared
        let lock = "---
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21

  packages/frontend:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
      packages/shared:
        specifier: workspace:*
        version: link:../shared

  packages/shared:
    dependencies:
      minimist:
        specifier: ^1.2.8
        version: 1.2.8

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-abc}

  minimist@1.2.8:
    resolution: {integrity: sha512-xyz}

snapshots:

  lodash@4.17.21: {}

  minimist@1.2.8: {}
";
        std::fs::write(tmp.join("pnpm-lock.yaml"), lock).unwrap();

        let graph = PnpmLockParser::parse(&tmp, true).expect("pnpm workspace lockfile must parse");

        let node_ids: Vec<&str> = graph.nodes.keys().map(|s| s.as_str()).collect();

        // Workspace nodes must be registered
        assert!(
            node_ids.contains(&"pnpm:packages/frontend@0.0.0"),
            "packages/frontend workspace node must exist; got: {:?}",
            node_ids
        );
        assert!(
            node_ids.contains(&"pnpm:packages/shared@0.0.0"),
            "packages/shared workspace node must exist; got: {:?}",
            node_ids
        );

        // Root must have edges to workspace nodes
        let root_node = graph.nodes.get(&graph.root_node_id).unwrap();
        assert!(
            root_node
                .deps
                .contains(&"pnpm:packages/frontend@0.0.0".to_string()),
            "root must connect to packages/frontend"
        );
        assert!(
            root_node
                .deps
                .contains(&"pnpm:packages/shared@0.0.0".to_string()),
            "root must connect to packages/shared"
        );

        // lodash must be in the graph
        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"minimist"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
