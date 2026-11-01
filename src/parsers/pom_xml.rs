#![forbid(unsafe_code)]

use crate::core::dep_graph::{DepGraph, NodeInfo, PkgManagerInfo};
use crate::types::PkgInfo;
use roxmltree::{Document, Node};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub struct PomXmlParser;

impl PomXmlParser {
    pub fn parse(path_or_dir: &Path) -> Result<DepGraph, String> {
        if path_or_dir.is_file() {
            let file_name = path_or_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if file_name == "gradle.lockfile" {
                let project_dir = path_or_dir.parent().unwrap_or(Path::new("."));
                return Self::parse_gradle_lockfile(project_dir, path_or_dir);
            }
        } else if path_or_dir.is_dir() {
            let gradle_lock = path_or_dir.join("gradle.lockfile");
            if gradle_lock.exists() {
                return Self::parse_gradle_lockfile(path_or_dir, &gradle_lock);
            }
        }

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

        if content.len() > crate::parsers::MAX_MANIFEST_SIZE_BYTES {
            return Err("pom.xml exceeds maximum size limit of 15 MB".to_string());
        }

        let doc = Document::parse(&content)
            .map_err(|e| format!("Failed to parse XML in {}: {}", pom_path.display(), e))?;
        let root = doc.root_element();

        let mut properties = HashMap::new();
        let mut managed_versions = HashMap::new();

        // 1. Check parent POM relativePath if present (bounded to 1 parent hop within workspace)
        Self::load_parent_pom(&pom_path, root, &mut properties, &mut managed_versions);

        // 2. Load current POM properties
        Self::extract_properties(root, &mut properties);

        let root_artifact = Self::child_text(root, "artifactId").unwrap_or_else(|| {
            project_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("java-app")
                .to_string()
        });
        let root_group = Self::child_text(root, "groupId")
            .or_else(|| {
                Self::find_child(root, "parent").and_then(|p| Self::child_text(p, "groupId"))
            })
            .unwrap_or_else(|| "com.example".to_string());
        let root_version = Self::child_text(root, "version")
            .or_else(|| {
                Self::find_child(root, "parent").and_then(|p| Self::child_text(p, "version"))
            })
            .unwrap_or_else(|| "1.0.0".to_string());

        properties.insert("project.version".to_string(), root_version.clone());
        properties.insert("version".to_string(), root_version.clone());
        properties.insert("project.groupId".to_string(), root_group.clone());
        properties.insert("groupId".to_string(), root_group);
        properties.insert("project.artifactId".to_string(), root_artifact.clone());
        properties.insert("artifactId".to_string(), root_artifact.clone());

        // 3. Load dependencyManagement from current POM
        Self::extract_dependency_management(root, &properties, &mut managed_versions);

        let root_pkg = PkgInfo::new(root_artifact, root_version, "Maven");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "maven".to_string(),
                version: "pom.xml".to_string(),
            },
        );

        // 4. Parse <dependencies> directly under <project> (excluding <dependencyManagement>)
        if let Some(deps_node) = Self::find_child(root, "dependencies") {
            for dep in deps_node
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == "dependency")
            {
                let group_id =
                    Self::child_text(dep, "groupId").map(|g| Self::interpolate(&g, &properties));
                let artifact_id =
                    Self::child_text(dep, "artifactId").map(|a| Self::interpolate(&a, &properties));
                let mut version =
                    Self::child_text(dep, "version").map(|v| Self::interpolate(&v, &properties));
                let scope = Self::child_text(dep, "scope")
                    .map(|s| Self::interpolate(&s, &properties))
                    .unwrap_or_else(|| "prod".to_string());

                if let (Some(gid), Some(aid)) = (group_id, artifact_id) {
                    if version.is_none()
                        || version.as_deref() == Some("")
                        || version.as_deref() == Some("unresolved")
                    {
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
        }

        Ok(graph)
    }

    pub fn parse_gradle_lockfile(project_dir: &Path, lock_path: &Path) -> Result<DepGraph, String> {
        let content = fs::read_to_string(lock_path)
            .map_err(|e| format!("Failed to read {}: {}", lock_path.display(), e))?;

        if content.len() > crate::parsers::MAX_MANIFEST_SIZE_BYTES {
            return Err("gradle.lockfile exceeds maximum size limit of 15 MB".to_string());
        }

        let root_name = project_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("gradle-app");

        let root_pkg = PkgInfo::new(root_name, "1.0.0", "Maven");
        let mut graph = DepGraph::new(
            root_pkg,
            PkgManagerInfo {
                name: "gradle".to_string(),
                version: "gradle.lockfile".to_string(),
            },
        );

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("empty=") {
                continue;
            }
            // Format: group:artifact:version=configurations (e.g. org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath)
            let coord_part = trimmed.split('=').next().unwrap_or(trimmed).trim();
            let parts: Vec<&str> = coord_part.split(':').collect();
            if parts.len() >= 3 {
                let group = parts[0].trim();
                let artifact = parts[1].trim();
                let version = parts[2].trim();
                if !group.is_empty() && !artifact.is_empty() && !version.is_empty() {
                    let full_name = format!("{}:{}", group, artifact);
                    let pkg_info = PkgInfo::new(&full_name, version, "Maven");
                    graph.add_pkg(pkg_info.clone());

                    let node_id = format!("maven:{}@{}", full_name, version);
                    graph.add_node(
                        node_id.clone(),
                        pkg_info.id,
                        NodeInfo {
                            scope: "prod".to_string(),
                            path: None,
                            integrity: None,
                        },
                    );
                    let _ = graph.add_edge(&graph.root_node_id.clone(), &node_id);
                }
            }
        }

        Ok(graph)
    }

    fn find_child<'a, 'input>(node: Node<'a, 'input>, tag: &str) -> Option<Node<'a, 'input>> {
        node.children()
            .find(|n| n.is_element() && n.tag_name().name() == tag)
    }

    fn child_text(node: Node<'_, '_>, tag: &str) -> Option<String> {
        Self::find_child(node, tag)
            .and_then(|n| n.text())
            .map(|t| t.trim().to_string())
            .filter(|s| !s.is_empty())
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

    fn extract_properties(root: Node<'_, '_>, properties: &mut HashMap<String, String>) {
        if let Some(props_node) = Self::find_child(root, "properties") {
            for prop in props_node.children().filter(|n| n.is_element()) {
                let key = prop.tag_name().name().to_string();
                if let Some(val) = prop.text() {
                    properties.insert(key, val.trim().to_string());
                }
            }
        }
    }

    fn extract_dependency_management(
        root: Node<'_, '_>,
        properties: &HashMap<String, String>,
        managed_versions: &mut HashMap<(String, String), String>,
    ) {
        if let Some(dm_node) = Self::find_child(root, "dependencyManagement") {
            if let Some(deps_node) = Self::find_child(dm_node, "dependencies") {
                for dep in deps_node
                    .children()
                    .filter(|n| n.is_element() && n.tag_name().name() == "dependency")
                {
                    let gid =
                        Self::child_text(dep, "groupId").map(|g| Self::interpolate(&g, properties));
                    let aid = Self::child_text(dep, "artifactId")
                        .map(|a| Self::interpolate(&a, properties));
                    let ver =
                        Self::child_text(dep, "version").map(|v| Self::interpolate(&v, properties));
                    if let (Some(g), Some(a), Some(v)) = (gid, aid, ver) {
                        managed_versions.insert((g, a), v);
                    }
                }
            }
        }
    }

    fn load_parent_pom(
        pom_path: &Path,
        root: Node<'_, '_>,
        properties: &mut HashMap<String, String>,
        managed_versions: &mut HashMap<(String, String), String>,
    ) {
        if let Some(parent_node) = Self::find_child(root, "parent") {
            let rel_path = Self::child_text(parent_node, "relativePath")
                .unwrap_or_else(|| "../pom.xml".to_string());
            let parent_pom_path = pom_path.parent().unwrap_or(Path::new(".")).join(&rel_path);
            if parent_pom_path.is_file() {
                if let Ok(parent_content) = fs::read_to_string(&parent_pom_path) {
                    if let Ok(parent_doc) = Document::parse(&parent_content) {
                        let parent_root = parent_doc.root_element();
                        Self::extract_properties(parent_root, properties);
                        Self::extract_dependency_management(
                            parent_root,
                            properties,
                            managed_versions,
                        );
                    }
                }
            }
        }
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

        let guava = pkgs
            .iter()
            .find(|p| p.name == "com.google.guava:guava")
            .unwrap();
        assert_eq!(guava.version, "31.1-jre");

        let commons = pkgs
            .iter()
            .find(|p| p.name == "commons-io:commons-io")
            .unwrap();
        assert_eq!(commons.version, "2.11.0");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_gradle_lockfile_parser() {
        let temp_dir =
            std::env::temp_dir().join(format!("vexa_test_gradle_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let lock = temp_dir.join("gradle.lockfile");
        fs::write(
            &lock,
            r#"# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.fasterxml.jackson.core:jackson-databind:2.13.4.2=compileClasspath,runtimeClasspath
org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath
empty=
"#,
        )
        .unwrap();

        let graph = PomXmlParser::parse(&lock).expect("should parse gradle.lockfile");
        let pkgs = graph.get_all_pkgs();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"com.fasterxml.jackson.core:jackson-databind"));
        assert!(names.contains(&"org.apache.logging.log4j:log4j-core"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_pom_xml_rejects_xxe_doctype() {
        let temp_dir = std::env::temp_dir().join(format!("vexa_test_xxe_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();
        let pom = temp_dir.join("pom.xml");
        fs::write(
            &pom,
            r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<project><groupId>x</groupId><artifactId>y</artifactId><version>&lol2;</version></project>
"#,
        )
        .unwrap();

        let res = PomXmlParser::parse(&pom);
        assert!(res.is_err(), "roxmltree must reject DOCTYPE / XXE payloads");
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
