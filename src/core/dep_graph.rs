use crate::types::PkgInfo;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkgManagerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
}

fn default_scope() -> String {
    "prod".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    #[serde(rename = "nodeId")]
    pub node_id: String,
    #[serde(rename = "pkgId")]
    pub pkg_id: String,
    pub info: NodeInfo,
    pub deps: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DepGraph {
    pub root_pkg: PkgInfo,
    pub root_node_id: String,
    pub pkg_manager: PkgManagerInfo,
    pub nodes: HashMap<String, GraphNode>,
    pub pkgs: HashMap<String, PkgInfo>,
    pub parents: HashMap<String, HashSet<String>>,
}

impl DepGraph {
    pub fn new(root_pkg: PkgInfo, pkg_manager: PkgManagerInfo) -> Self {
        let root_node_id = format!("root:{}@{}", root_pkg.name, root_pkg.version);
        let mut graph = Self {
            root_pkg: root_pkg.clone(),
            root_node_id: root_node_id.clone(),
            pkg_manager,
            nodes: HashMap::new(),
            pkgs: HashMap::new(),
            parents: HashMap::new(),
        };

        graph.add_pkg(root_pkg.clone());
        graph.add_node(
            root_node_id,
            root_pkg.id,
            NodeInfo {
                scope: "prod".to_string(),
                path: None,
                integrity: None,
            },
        );

        graph
    }

    pub fn add_pkg(&mut self, pkg: PkgInfo) -> String {
        let id = pkg.id.clone();
        self.pkgs.entry(id.clone()).or_insert(pkg);
        id
    }

    pub fn add_node(&mut self, node_id: String, pkg_id: String, info: NodeInfo) {
        if !self.nodes.contains_key(&node_id) {
            self.nodes.insert(
                node_id.clone(),
                GraphNode {
                    node_id: node_id.clone(),
                    pkg_id,
                    info,
                    deps: Vec::new(),
                },
            );
            self.parents.entry(node_id).or_default();
        }
    }

    pub fn add_edge(&mut self, from_node_id: &str, to_node_id: &str) -> Result<(), String> {
        if !self.nodes.contains_key(from_node_id) {
            return Err(format!(
                "Parent node \"{}\" does not exist in graph",
                from_node_id
            ));
        }
        if !self.nodes.contains_key(to_node_id) {
            return Err(format!(
                "Child node \"{}\" does not exist in graph",
                to_node_id
            ));
        }

        let parent = self.nodes.get_mut(from_node_id).unwrap();
        if !parent.deps.contains(&to_node_id.to_string()) {
            parent.deps.push(to_node_id.to_string());
        }

        self.parents
            .entry(to_node_id.to_string())
            .or_default()
            .insert(from_node_id.to_string());

        Ok(())
    }

    pub fn get_node(&self, node_id: &str) -> Option<&GraphNode> {
        self.nodes.get(node_id)
    }

    pub fn get_pkg(&self, pkg_id: &str) -> Option<&PkgInfo> {
        self.pkgs.get(pkg_id)
    }

    pub fn get_all_pkgs(&self) -> Vec<PkgInfo> {
        self.pkgs
            .values()
            .filter(|p| p.id != self.root_pkg.id)
            .cloned()
            .collect()
    }

    pub fn get_all_nodes(&self) -> Vec<GraphNode> {
        self.nodes.values().cloned().collect()
    }

    pub fn get_pkg_node_ids(&self, pkg_id: &str) -> Vec<String> {
        self.nodes
            .values()
            .filter(|n| n.pkg_id == pkg_id)
            .map(|n| n.node_id.clone())
            .collect()
    }

    pub fn is_transitive(&self, pkg_id: &str) -> bool {
        let root_node = match self.nodes.get(&self.root_node_id) {
            Some(n) => n,
            None => return false,
        };

        let direct_dep_pkg_ids: HashSet<String> = root_node
            .deps
            .iter()
            .filter_map(|dep_id| self.nodes.get(dep_id).map(|n| n.pkg_id.clone()))
            .collect();

        !direct_dep_pkg_ids.contains(pkg_id)
    }

    pub fn pkg_paths_to_root(&self, pkg_id: &str, limit: usize) -> Vec<Vec<PkgInfo>> {
        let target_node_ids = self.get_pkg_node_ids(pkg_id);
        let mut all_paths = Vec::new();

        for target_node_id in target_node_ids {
            let remaining = limit.saturating_sub(all_paths.len());
            if remaining == 0 {
                break;
            }
            let paths = self.find_paths_to_root_dfs(&target_node_id, remaining);
            for p in paths {
                all_paths.push(p);
                if all_paths.len() >= limit {
                    break;
                }
            }
            if all_paths.len() >= limit {
                break;
            }
        }

        all_paths
            .into_iter()
            .map(|node_path| {
                node_path
                    .into_iter()
                    .map(|node_id| {
                        if let Some(node) = self.nodes.get(&node_id) {
                            if let Some(pkg) = self.pkgs.get(&node.pkg_id) {
                                return pkg.clone();
                            }
                        }
                        PkgInfo::new(node_id.clone(), "*", "unknown")
                    })
                    .collect()
            })
            .collect()
    }

    fn find_paths_to_root_dfs(
        &self,
        current_node_id: &str,
        remaining_limit: usize,
    ) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        if remaining_limit == 0 {
            return paths;
        }

        let mut visited = HashSet::new();
        visited.insert(current_node_id.to_string());

        let mut current_path = Vec::new();
        self.dfs_traverse(
            current_node_id,
            &mut current_path,
            &mut visited,
            &mut paths,
            remaining_limit,
        );

        paths
    }

    fn dfs_traverse(
        &self,
        node_id: &str,
        current_path: &mut Vec<String>,
        visited: &mut HashSet<String>,
        paths: &mut Vec<Vec<String>>,
        limit: usize,
    ) {
        if paths.len() >= limit {
            return;
        }

        if node_id == self.root_node_id {
            let mut full_path = current_path.clone();
            full_path.push(node_id.to_string());
            full_path.reverse();
            paths.push(full_path);
            return;
        }

        if let Some(parent_ids) = self.parents.get(node_id) {
            for parent_id in parent_ids {
                if !visited.contains(parent_id) {
                    visited.insert(parent_id.clone());
                    current_path.push(node_id.to_string());

                    self.dfs_traverse(parent_id, current_path, visited, paths, limit);

                    current_path.pop();
                    visited.remove(parent_id);
                }
            }
        }
    }

    pub fn has_cycles(&self) -> bool {
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();

        for node_id in self.nodes.keys() {
            if !visited.contains(node_id) && self.cycle_dfs(node_id, &mut visited, &mut in_stack) {
                return true;
            }
        }

        false
    }

    fn cycle_dfs(
        &self,
        node_id: &str,
        visited: &mut HashSet<String>,
        in_stack: &mut HashSet<String>,
    ) -> bool {
        visited.insert(node_id.to_string());
        in_stack.insert(node_id.to_string());

        if let Some(node) = self.nodes.get(node_id) {
            for dep_id in &node.deps {
                if !visited.contains(dep_id) {
                    if self.cycle_dfs(dep_id, visited, in_stack) {
                        return true;
                    }
                } else if in_stack.contains(dep_id) {
                    return true;
                }
            }
        }

        in_stack.remove(node_id);
        false
    }

    pub fn to_json(&self) -> serde_json::Value {
        let pkgs_val: Vec<serde_json::Value> = self
            .pkgs
            .values()
            .map(|p| {
                serde_json::json!({
                    "id": p.id,
                    "info": {
                        "name": p.name,
                        "version": p.version,
                        "purl": p.purl,
                    }
                })
            })
            .collect();

        let nodes_val: Vec<serde_json::Value> = self
            .nodes
            .values()
            .map(|n| {
                serde_json::json!({
                    "nodeId": n.node_id,
                    "pkgId": n.pkg_id,
                    "info": n.info,
                    "deps": n.deps.iter().map(|id| serde_json::json!({ "nodeId": id })).collect::<Vec<_>>(),
                })
            })
            .collect();

        serde_json::json!({
            "schemaVersion": "1.2.0",
            "pkgManager": self.pkg_manager,
            "pkgs": pkgs_val,
            "graph": {
                "rootNodeId": self.root_node_id,
                "nodes": nodes_val,
            }
        })
    }

    /// Renders an industry-standard ASCII tree representation of the dependency graph.
    pub fn render_ascii_tree(&self, max_depth: Option<usize>) -> String {
        let mut out = String::new();
        let root_label = format!("{}@{}", self.root_pkg.name, self.root_pkg.version);
        out.push_str(&root_label);
        out.push('\n');

        let max_d = max_depth.unwrap_or(6);
        let mut visited_path = HashSet::new();
        visited_path.insert(self.root_node_id.clone());

        if let Some(root_node) = self.nodes.get(&self.root_node_id) {
            let mut sorted_deps = root_node.deps.clone();
            sorted_deps.sort();
            let total = sorted_deps.len();
            for (idx, child_id) in sorted_deps.into_iter().enumerate() {
                let is_last = idx + 1 == total;
                self.render_tree_dfs(
                    &child_id,
                    "",
                    is_last,
                    1,
                    max_d,
                    &mut visited_path,
                    &mut out,
                );
            }
        }

        out
    }

    #[allow(clippy::too_many_arguments)]
    fn render_tree_dfs(
        &self,
        node_id: &str,
        prefix: &str,
        is_last: bool,
        current_depth: usize,
        max_depth: usize,
        visited_path: &mut HashSet<String>,
        out: &mut String,
    ) {
        let branch = if is_last { "└── " } else { "├── " };
        let node = match self.nodes.get(node_id) {
            Some(n) => n,
            None => {
                out.push_str(&format!("{}{}{}\n", prefix, branch, node_id));
                return;
            }
        };

        let pkg_label = match self.pkgs.get(&node.pkg_id) {
            Some(p) => format!("{}@{}", p.name, p.version),
            None => node.pkg_id.clone(),
        };

        if visited_path.contains(node_id) {
            out.push_str(&format!("{}{}{} (*)\n", prefix, branch, pkg_label));
            return;
        }

        out.push_str(&format!("{}{}{}\n", prefix, branch, pkg_label));

        if current_depth >= max_depth {
            if !node.deps.is_empty() {
                let next_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
                out.push_str(&format!(
                    "{}└── ... ({} dependencies truncated)\n",
                    next_prefix,
                    node.deps.len()
                ));
            }
            return;
        }

        visited_path.insert(node_id.to_string());
        let next_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });

        let mut sorted_deps = node.deps.clone();
        sorted_deps.sort();
        let total = sorted_deps.len();

        for (idx, child_id) in sorted_deps.into_iter().enumerate() {
            let child_is_last = idx + 1 == total;
            self.render_tree_dfs(
                &child_id,
                &next_prefix,
                child_is_last,
                current_depth + 1,
                max_depth,
                visited_path,
                out,
            );
        }

        visited_path.remove(node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dep_graph_basic() {
        let root = PkgInfo::new("my-app", "1.0.0", "npm");
        let mut graph = DepGraph::new(
            root,
            PkgManagerInfo {
                name: "npm".into(),
                version: "1.0.0".into(),
            },
        );

        let dep1 = PkgInfo::new("express", "4.18.2", "npm");
        let pkg_id = graph.add_pkg(dep1.clone());
        graph.add_node(
            "node-express".into(),
            pkg_id,
            NodeInfo {
                scope: "prod".into(),
                path: None,
                integrity: None,
            },
        );
        graph
            .add_edge(&graph.root_node_id.clone(), "node-express")
            .unwrap();

        assert_eq!(graph.get_all_pkgs().len(), 1);
        assert!(!graph.is_transitive(&dep1.id));
    }

    #[test]
    fn test_dep_graph_transitive_and_paths() {
        let root = PkgInfo::new("my-app", "1.0.0", "npm");
        let mut graph = DepGraph::new(
            root,
            PkgManagerInfo {
                name: "npm".into(),
                version: "1.0.0".into(),
            },
        );

        let direct = PkgInfo::new("express", "4.18.2", "npm");
        let transitive = PkgInfo::new("qs", "6.11.0", "npm");

        graph.add_pkg(direct.clone());
        graph.add_pkg(transitive.clone());

        graph.add_node(
            "node-direct".into(),
            direct.id.clone(),
            NodeInfo {
                scope: "prod".into(),
                path: None,
                integrity: None,
            },
        );
        graph.add_node(
            "node-transitive".into(),
            transitive.id.clone(),
            NodeInfo {
                scope: "prod".into(),
                path: None,
                integrity: None,
            },
        );

        graph
            .add_edge(&graph.root_node_id.clone(), "node-direct")
            .unwrap();
        graph.add_edge("node-direct", "node-transitive").unwrap();

        assert!(graph.is_transitive(&transitive.id));

        let paths = graph.pkg_paths_to_root(&transitive.id, 10);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0][0].name, "my-app");
        assert_eq!(paths[0][1].name, "express");
        assert_eq!(paths[0][2].name, "qs");
    }

    #[test]
    fn test_dep_graph_cycle_detection() {
        let root = PkgInfo::new("cycle-app", "1.0.0", "npm");
        let mut graph = DepGraph::new(
            root,
            PkgManagerInfo {
                name: "npm".into(),
                version: "1.0.0".into(),
            },
        );

        let a = PkgInfo::new("a", "1.0.0", "npm");
        let b = PkgInfo::new("b", "1.0.0", "npm");

        graph.add_pkg(a.clone());
        graph.add_pkg(b.clone());

        graph.add_node(
            "node-a".into(),
            a.id.clone(),
            NodeInfo {
                scope: "prod".into(),
                path: None,
                integrity: None,
            },
        );
        graph.add_node(
            "node-b".into(),
            b.id.clone(),
            NodeInfo {
                scope: "prod".into(),
                path: None,
                integrity: None,
            },
        );

        graph
            .add_edge(&graph.root_node_id.clone(), "node-a")
            .unwrap();
        graph.add_edge("node-a", "node-b").unwrap();
        assert!(!graph.has_cycles());

        graph.add_edge("node-b", "node-a").unwrap();
        assert!(graph.has_cycles());
    }

    #[test]
    fn test_dep_graph_serialization() {
        let root = PkgInfo::new("schema-app", "1.0.0", "npm");
        let graph = DepGraph::new(
            root,
            PkgManagerInfo {
                name: "npm".into(),
                version: "1.0.0".into(),
            },
        );
        let json = graph.to_json();

        assert_eq!(json["schemaVersion"], "1.2.0");
        assert!(json["graph"]["rootNodeId"].is_string());
        assert!(json["graph"]["nodes"].is_array());
        assert!(json["pkgs"].is_array());
    }
}
