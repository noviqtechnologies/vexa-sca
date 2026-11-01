#![forbid(unsafe_code)]

use vexa_sca::firewall::wrapper::FirewallWrapper;
use vexa_sca::parsers::{
    check_json_depth, check_yaml_depth, validate_yaml_content_safety, MAX_MANIFEST_SIZE_BYTES,
};

#[test]
fn test_yaml_anchor_explosion_detected() {
    // Billion laughs style YAML anchor expansion
    let malicious_yaml = r#"
a: &a ["lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h]
j: &j [*i,*i,*i,*i,*i]
k: &k [*j,*j,*j,*j,*j]
l: &l [*k,*k,*k,*k,*k]
m: &m [*l,*l,*l,*l,*l]
n: &n [*m,*m,*m,*m,*m]
o: &o [*n,*n,*n,*n,*n]
p: &p [*o,*o,*o,*o,*o]
q: &q [*p,*p,*p,*p,*p]
r: &r [*q,*q,*q,*q,*q]
s: &s [*r,*r,*r,*r,*r]
t: &t [*s,*s,*s,*s,*s]
u: &u [*t,*t,*t,*t,*t]
v: &v [*u,*u,*u,*u,*u]
w: &w [*v,*v,*v,*v,*v]
x: &x [*w,*w,*w,*w,*w]
y: &y [*x,*x,*x,*x,*x]
z: &z [*y,*y,*y,*y,*y]
"#;

    let res = validate_yaml_content_safety(malicious_yaml);
    assert!(
        res.is_err(),
        "Expected validate_yaml_content_safety to block YAML bomb"
    );
    let err = res.unwrap_err();
    assert!(err.contains("Billion Laughs"));
}

#[test]
fn test_safe_yaml_accepted() {
    let safe_yaml = r#"
lockfileVersion: '6.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21
"#;

    assert!(validate_yaml_content_safety(safe_yaml).is_ok());
}

#[test]
fn test_max_manifest_size_enforced() {
    let oversized_str = "a".repeat(MAX_MANIFEST_SIZE_BYTES + 10);
    let res = validate_yaml_content_safety(&oversized_str);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("exceeds maximum size limit"));
}

#[test]
fn test_json_recursion_depth_limit() {
    // Construct nested JSON > 64 levels deep
    let mut nested = serde_json::json!({"val": 1});
    for _ in 0..70 {
        nested = serde_json::json!({"child": nested});
    }

    let res = check_json_depth(&nested, 0);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .contains("Exceeded maximum JSON recursion depth of 64"));
}

#[test]
fn test_yaml_recursion_depth_limit() {
    // Construct nested YAML mapping > 64 levels deep
    let mut current = serde_yaml::Value::String("leaf".to_string());
    for i in 0..70 {
        let mut map = serde_yaml::Mapping::new();
        map.insert(serde_yaml::Value::String(format!("k{}", i)), current);
        current = serde_yaml::Value::Mapping(map);
    }

    let res = check_yaml_depth(&current, 0);
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .contains("Exceeded maximum YAML recursion depth of 64"));
}

#[test]
fn test_package_name_validation_against_flag_injection() {
    // Malicious inputs attempting flag or argument injection
    assert!(!FirewallWrapper::is_valid_package_name(
        "--extra-index-url",
        "PyPI"
    ));
    assert!(!FirewallWrapper::is_valid_package_name("-i", "PyPI"));
    assert!(!FirewallWrapper::is_valid_package_name(
        "--upload-pack",
        "npm"
    ));
    assert!(!FirewallWrapper::is_valid_package_name(
        "foo;rm -rf /",
        "npm"
    ));
    assert!(!FirewallWrapper::is_valid_package_name("foo`id`", "npm"));
    assert!(!FirewallWrapper::is_valid_package_name(
        "foo|cat /etc/passwd",
        "PyPI"
    ));
    assert!(!FirewallWrapper::is_valid_package_name(
        "@scope/-evil",
        "npm"
    ));
    assert!(!FirewallWrapper::is_valid_package_name("-evil/foo", "npm"));

    // Valid package names
    assert!(FirewallWrapper::is_valid_package_name("lodash", "npm"));
    assert!(FirewallWrapper::is_valid_package_name("@babel/core", "npm"));
    assert!(FirewallWrapper::is_valid_package_name("requests", "PyPI"));
    assert!(FirewallWrapper::is_valid_package_name("tokio", "crates.io"));
    assert!(FirewallWrapper::is_valid_package_name(
        "github.com/gin-gonic/gin",
        "Go"
    ));
}
