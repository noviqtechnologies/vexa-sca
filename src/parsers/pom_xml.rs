use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use regex::Regex;
use std::collections::HashMap;
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

        let mut properties = HashMap::new();
        let mut managed_versions = HashMap::new();

        // 1. Check parent POM relativePath if present
        Self::load_parent_pom(&pom_path, &content, &mut properties, &mut managed_versions);

        // 2. Load current POM properties
        Self::extract_properties(&content, &mut properties);

        let root_artifact = Self::extract_tag(&content, "artifactId").unwrap_or_else(|| {
            project_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("java-app")
                .to_string()
        });
        let root_group = Self::extract_tag(&content, "groupId").unwrap_or_else(|| "com.example".to_string());
        let root_version =
            Self::extract_tag(&content, "version").unwrap_or_else(|| "1.0.0".to_string());

        properties.insert("project.version".to_string(), root_version.clone());
        properties.insert("version".to_string(), root_version.clone());
        properties.insert("project.groupId".to_string(), root_group.clone());
        properties.insert("groupId".to_string(), root_group);
        properties.insert("project.artifactId".to_string(), root_artifact.clone());
        properties.insert("artifactId".to_string(), root_artifact.clone());

        // 3. Load dependencyManagement from current POM
        Self::extract_dependency_management(&content, &properties, &mut managed_versions);

        let root_pkg = PkgInfo::new(root_artifact, root_version, "Maven");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "maven".to_string(),
                version: "pom.xml".to_string(),
            },
        );

        // 4. Parse dependencies outside of dependencyManagement
        let content_without_dep_mgmt = if let Some(idx) = content.find("<dependencyManagement>") {
            if let Some(end_idx) = content.find("</dependencyManagement>") {
                format!("{}{}", &content[..idx], &content[end_idx + 23..])
            } else {
                content.clone()
            }
        } else {
            content.clone()
        };

        let dep_regex = Regex::new(r"(?s)<dependency>([\s\S]*?)</dependency>").unwrap();
        for cap in dep_regex.captures_iter(&content_without_dep_mgmt) {
            let block = &cap[1];
            let group_id = Self::extract_tag(block, "groupId").map(|g| Self::interpolate(&g, &properties));
            let artifact_id = Self::extract_tag(block, "artifactId").map(|a| Self::interpolate(&a, &properties));
            let mut version = Self::extract_tag(block, "version")
                .map(|v| Self::interpolate(&v, &properties));
            let scope = Self::extract_tag(block, "scope")
                .map(|s| Self::interpolate(&s, &properties))
                .unwrap_or_else(|| "prod".to_string());

            if let (Some(gid), Some(aid)) = (group_id, artifact_id) {
                if version.is_none() || version.as_deref() == Some("") || version.as_deref() == Some("unresolved") {
                    if let Some(mv) = managed_versions.get(&(gid.clone(), aid.clone())) {
                        version = Some(mv.clone());
                    }
                }
                let ver_str = version.unwrap_or_else(|| "unresolved".to_string());
                let full_name = format!("{}:{}", gid, aid);
                let pkg_info = PkgInfo::new(&full_name, &ver_str, "Maven");
                graph.add_pkg(pkg_info.clone());

                let node_id = format!("maven:{}@{}", full_name, ver_str);
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

    fn interpolate(val: &str, properties: &HashMap<String, String>) -> String {
        let mut result = val.to_string();
        for _ in 0..5 {
            let start = match result.find("${") {
                Some(s) => s,
                None => break,
            };
            let end = match result[start..].find('}') {
                Some(e) => start + e,
                None => break,
            };
            let prop_key = &result[start + 2..end];
            if let Some(prop_val) = properties.get(prop_key) {
                result.replace_range(start..=end, prop_val);
            } else {
                break;
            }
        }
        result
    }

    fn extract_properties(xml: &str, properties: &mut HashMap<String, String>) {
        if let Some(start) = xml.find("<properties>") {
            if let Some(end) = xml[start..].find("</properties>") {
                let props_block = &xml[start + 12..start + end];
                let prop_regex = Regex::new(r"<([a-zA-Z0-9_.-]+)>(?:\s*)([^<]*)(?:\s*)</([a-zA-Z0-9_.-]+)>").unwrap();
                for cap in prop_regex.captures_iter(props_block) {
                    if cap[1] == cap[3] {
                        let k = cap[1].to_string();
                        let v = cap[2].trim().to_string();
                        properties.insert(k, v);
                    }
                }
            }
        }
    }

    fn extract_dependency_management(
        xml: &str,
        properties: &HashMap<String, String>,
        managed_versions: &mut HashMap<(String, String), String>,
    ) {
        if let Some(start) = xml.find("<dependencyManagement>") {
            if let Some(end) = xml[start..].find("</dependencyManagement>") {
                let block = &xml[start..start + end + 23];
                let dep_regex = Regex::new(r"(?s)<dependency>([\s\S]*?)</dependency>").unwrap();
                for cap in dep_regex.captures_iter(block) {
                    let d_block = &cap[1];
                    let gid = Self::extract_tag(d_block, "groupId").map(|g| Self::interpolate(&g, properties));
                    let aid = Self::extract_tag(d_block, "artifactId").map(|a| Self::interpolate(&a, properties));
                    let ver = Self::extract_tag(d_block, "version").map(|v| Self::interpolate(&v, properties));
                    if let (Some(g), Some(a), Some(v)) = (gid, aid, ver) {
                        managed_versions.insert((g, a), v);
                    }
                }
            }
        }
    }

    fn load_parent_pom(
        pom_path: &Path,
        content: &str,
        properties: &mut HashMap<String, String>,
        managed_versions: &mut HashMap<(String, String), String>,
    ) {
        if let Some(parent_start) = content.find("<parent>") {
            if let Some(parent_end) = content[parent_start..].find("</parent>") {
                let parent_block = &content[parent_start..parent_start + parent_end + 9];
                let rel_path = Self::extract_tag(parent_block, "relativePath")
                    .unwrap_or_else(|| "../pom.xml".to_string());
                let parent_pom_path = pom_path.parent().unwrap_or(Path::new(".")).join(&rel_path);
                if parent_pom_path.is_file() {
                    if let Ok(parent_content) = fs::read_to_string(&parent_pom_path) {
                        Self::extract_properties(&parent_content, properties);
                        Self::extract_dependency_management(&parent_content, properties, managed_versions);
                    }
                }
            }
        }
    }

    fn extract_tag(xml: &str, tag: &str) -> Option<String> {
        let pattern = format!(r"<{}>(?:\s*)([^<]+)(?:\s*)</{}>", tag, tag);
        if let Ok(re) = Regex::new(&pattern) {
            if let Some(cap) = re.captures(xml) {
                return Some(cap[1].trim().to_string());
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

    #[test]
    fn test_pom_xml_property_interpolation_and_dep_mgmt() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_test_pom_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let pom = temp_dir.join("pom.xml");
        fs::write(
            &pom,
            r#"
<project>
  <groupId>com.acme</groupId>
  <artifactId>my-app</artifactId>
  <version>3.2.1</version>
  <properties>
    <guava.version>31.1-jre</guava.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>commons-io</groupId>
        <artifactId>commons-io</artifactId>
        <version>2.11.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
    <dependency>
      <groupId>commons-io</groupId>
      <artifactId>commons-io</artifactId>
    </dependency>
  </dependencies>
</project>
"#,
        )
        .unwrap();

        let graph = PomXmlParser::parse(&temp_dir).expect("should parse interpolated pom.xml");
        let pkgs = graph.get_all_pkgs();

        let guava = pkgs.iter().find(|p| p.name == "com.google.guava:guava").unwrap();
        assert_eq!(guava.version, "31.1-jre");

        let commons = pkgs.iter().find(|p| p.name == "commons-io:commons-io").unwrap();
        assert_eq!(commons.version, "2.11.0");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
