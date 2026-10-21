use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use regex::Regex;
use std::fs;
use std::path::Path;

pub struct PomXmlParser;

impl PomXmlParser {
    pub fn parse(path_or_dir: &Path) -> Result<DepGraph, String> {
        let (project_dir, pom_path) = if path_or_dir.is_dir() {
            (path_or_dir.to_path_buf(), path_or_dir.join("pom.xml"))
        } else {
            (
                path_or_dir.parent().unwrap_or(Path::new(".")).to_path_buf(),
                path_or_dir.to_path_buf(),
            )
        };

        if !pom_path.exists() {
            return Err(format!("pom.xml not found at {}", pom_path.display()));
        }

        let content =
            fs::read_to_string(&pom_path).map_err(|e| format!("Failed to read pom.xml: {}", e))?;

        let root_artifact = Self::extract_tag(&content, "artifactId").unwrap_or_else(|| {
            project_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("java-app")
                .to_string()
        });
        let root_version =
            Self::extract_tag(&content, "version").unwrap_or_else(|| "1.0.0".to_string());

        let root_pkg = PkgInfo::new(root_artifact, root_version, "Maven");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "maven".to_string(),
                version: "pom.xml".to_string(),
            },
        );

        let dep_regex = Regex::new(r"(?s)<dependency>([\s\S]*?)</dependency>").unwrap();
        for cap in dep_regex.captures_iter(&content) {
            let block = &cap[1];
            let group_id = Self::extract_tag(block, "groupId");
            let artifact_id = Self::extract_tag(block, "artifactId");
            let version =
                Self::extract_tag(block, "version").unwrap_or_else(|| "0.0.0".to_string());
            let scope = Self::extract_tag(block, "scope").unwrap_or_else(|| "prod".to_string());

            if let (Some(gid), Some(aid)) = (group_id, artifact_id) {
                let full_name = format!("{}:{}", gid, aid);
                let pkg_info = PkgInfo::new(&full_name, &version, "Maven");
                graph.add_pkg(pkg_info.clone());

                let node_id = format!("maven:{}@{}", full_name, version);
                graph.add_node(
                    node_id.clone(),
                    pkg_info.id,
                    NodeInfo {
                        scope,
                        path: None,
                        integrity: None,
                    },
                );

                let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);
            }
        }

        Ok(graph)
    }

    fn extract_tag(xml: &str, tag: &str) -> Option<String> {
        let pattern = format!(r"<{}>(?:\s*)([^<\s]+)(?:\s*)</{}>", tag, tag);
        if let Ok(re) = Regex::new(&pattern) {
            if let Some(cap) = re.captures(xml) {
                return Some(cap[1].to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pom_xml_parser_fixture() {
        let fixture_dir = Path::new("test/fixtures/java-app");
        let graph = PomXmlParser::parse(fixture_dir).expect("should parse pom.xml");

        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();

        assert!(names.contains(&"org.apache.logging.log4j:log4j-core"));
        assert!(names.contains(&"org.springframework.boot:spring-boot-starter-web"));

        let log4j = pkgs
            .iter()
            .find(|p| p.name == "org.apache.logging.log4j:log4j-core")
            .unwrap();
        assert_eq!(log4j.version, "2.14.1");
        assert_eq!(log4j.ecosystem, "Maven");
    }
}
