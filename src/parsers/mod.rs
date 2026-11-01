pub mod cargo_lock;
pub mod detector;
pub mod go_sum;
pub mod package_lock;
pub mod pnpm_lock;
pub mod pom_xml;
pub mod python_reqs;
pub mod yarn_lock;

pub const MAX_MANIFEST_SIZE_BYTES: usize = 15 * 1024 * 1024; // 15 MB payload cap per DDD §5 & §6
pub const MAX_RECURSION_DEPTH: usize = 64; // Max AST / nested structure recursion depth

/// Validate JSON AST depth does not exceed MAX_RECURSION_DEPTH (64)
pub fn check_json_depth(val: &serde_json::Value, current_depth: usize) -> Result<(), String> {
    if current_depth > MAX_RECURSION_DEPTH {
        return Err(format!(
            "Exceeded maximum JSON recursion depth of {}",
            MAX_RECURSION_DEPTH
        ));
    }
    match val {
        serde_json::Value::Array(arr) => {
            for item in arr {
                check_json_depth(item, current_depth + 1)?;
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                check_json_depth(item, current_depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validate YAML AST depth does not exceed MAX_RECURSION_DEPTH (64)
pub fn check_yaml_depth(val: &serde_yaml::Value, current_depth: usize) -> Result<(), String> {
    if current_depth > MAX_RECURSION_DEPTH {
        return Err(format!(
            "Exceeded maximum YAML recursion depth of {}",
            MAX_RECURSION_DEPTH
        ));
    }
    match val {
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                check_yaml_depth(item, current_depth + 1)?;
            }
        }
        serde_yaml::Value::Mapping(map) => {
            for item in map.values() {
                check_yaml_depth(item, current_depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validate YAML content against Billion Laughs / anchor explosion attacks
pub fn validate_yaml_content_safety(content: &str) -> Result<(), String> {
    if content.len() > MAX_MANIFEST_SIZE_BYTES {
        return Err(format!(
            "Payload exceeds maximum size limit of {} MB",
            MAX_MANIFEST_SIZE_BYTES / (1024 * 1024)
        ));
    }
    // Count YAML anchor (&name) and alias (*name) declarations to prevent Billion Laughs / entity expansion
    let mut anchor_count = 0;
    let mut alias_count = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        // Skip comment lines
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains(" &") || trimmed.starts_with('&') {
            anchor_count += 1;
        }
        if trimmed.contains(" *") || trimmed.starts_with('*') {
            alias_count += 1;
        }
    }

    if anchor_count > 25 || alias_count > 25 {
        return Err(
            "Suspicious YAML alias/anchor explosion detected (potential Billion Laughs attack)"
                .to_string(),
        );
    }
    Ok(())
}
