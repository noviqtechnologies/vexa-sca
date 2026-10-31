#![forbid(unsafe_code)]

/// Static catalog and classifier for CWE Top 25 (2025/2026) and OWASP Top 10 (2021).
/// Enables deterministic classification and posture reporting in CLI reports and dashboards.

pub const CWE_TOP_25: &[&str] = &[
    "CWE-787", // Out-of-bounds Write
    "CWE-79",  // Cross-site Scripting (XSS)
    "CWE-89",  // SQL Injection
    "CWE-416", // Use After Free
    "CWE-78",  // OS Command Injection
    "CWE-20",  // Improper Input Validation
    "CWE-125", // Out-of-bounds Read
    "CWE-22",  // Path Traversal
    "CWE-352", // Cross-Site Request Forgery (CSRF)
    "CWE-434", // Unrestricted Upload of File with Dangerous Type
    "CWE-862", // Missing Authorization
    "CWE-476", // NULL Pointer Dereference
    "CWE-287", // Improper Authentication
    "CWE-190", // Integer Overflow or Wraparound
    "CWE-502", // Deserialization of Untrusted Data
    "CWE-77",  // Command Injection
    "CWE-119", // Memory Buffer Errors
    "CWE-798", // Use of Hard-coded Credentials
    "CWE-918", // Server-Side Request Forgery (SSRF)
    "CWE-306", // Missing Authentication for Critical Function
    "CWE-362", // Race Condition
    "CWE-269", // Improper Privilege Management
    "CWE-94",  // Improper Control of Generation of Code (Code Injection)
    "CWE-863", // Incorrect Authorization
    "CWE-400", // Uncontrolled Resource Consumption
];

pub fn normalize_cwe_id(cwe: &str) -> String {
    let trimmed = cwe.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let upper = trimmed.to_uppercase();
    if upper.starts_with("CWE-") {
        upper
    } else if let Ok(num) = upper.parse::<u32>() {
        format!("CWE-{}", num)
    } else {
        upper
    }
}

pub fn is_cwe_top_25(cwe: &str) -> bool {
    let norm = normalize_cwe_id(cwe);
    CWE_TOP_25.contains(&norm.as_str())
}

pub fn map_cwe_to_owasp(cwe: &str) -> Option<&'static str> {
    let norm = normalize_cwe_id(cwe);
    match norm.as_str() {
        // A01:2021 - Broken Access Control
        "CWE-22" | "CWE-23" | "CWE-35" | "CWE-59" | "CWE-200" | "CWE-201" | "CWE-219"
        | "CWE-264" | "CWE-275" | "CWE-276" | "CWE-284" | "CWE-285" | "CWE-352" | "CWE-359"
        | "CWE-377" | "CWE-402" | "CWE-425" | "CWE-441" | "CWE-497" | "CWE-538" | "CWE-540"
        | "CWE-548" | "CWE-552" | "CWE-566" | "CWE-601" | "CWE-639" | "CWE-651" | "CWE-668"
        | "CWE-706" | "CWE-862" | "CWE-863" | "CWE-913" | "CWE-922" | "CWE-1275" => {
            Some("A01:2021-Broken Access Control")
        }

        // A02:2021 - Cryptographic Failures
        "CWE-261" | "CWE-296" | "CWE-310" | "CWE-311" | "CWE-312" | "CWE-319" | "CWE-321"
        | "CWE-322" | "CWE-323" | "CWE-324" | "CWE-325" | "CWE-326" | "CWE-327" | "CWE-328"
        | "CWE-329" | "CWE-330" | "CWE-331" | "CWE-335" | "CWE-336" | "CWE-337" | "CWE-338"
        | "CWE-340" | "CWE-347" | "CWE-798" => Some("A02:2021-Cryptographic Failures"),

        // A03:2021 - Injection
        "CWE-20" | "CWE-74" | "CWE-75" | "CWE-77" | "CWE-78" | "CWE-79" | "CWE-80" | "CWE-83"
        | "CWE-87" | "CWE-88" | "CWE-89" | "CWE-90" | "CWE-91" | "CWE-93" | "CWE-94"
        | "CWE-95" | "CWE-96" | "CWE-97" | "CWE-98" | "CWE-99" | "CWE-113" | "CWE-116"
        | "CWE-138" | "CWE-184" | "CWE-470" | "CWE-507" | "CWE-564" | "CWE-610" | "CWE-643"
        | "CWE-644" | "CWE-652" | "CWE-917" => Some("A03:2021-Injection"),

        // A04:2021 - Insecure Design
        "CWE-73" | "CWE-183" | "CWE-209" | "CWE-213" | "CWE-235" | "CWE-256" | "CWE-257"
        | "CWE-266" | "CWE-269" | "CWE-280" | "CWE-313" | "CWE-316" | "CWE-419" | "CWE-430"
        | "CWE-434" | "CWE-444" | "CWE-451" | "CWE-472" | "CWE-501" | "CWE-522" | "CWE-525"
        | "CWE-539" | "CWE-579" | "CWE-598" | "CWE-602" | "CWE-642" | "CWE-646" | "CWE-650"
        | "CWE-653" | "CWE-656" | "CWE-657" | "CWE-799" => Some("A04:2021-Insecure Design"),

        // A05:2021 - Security Misconfiguration
        "CWE-16" | "CWE-2" | "CWE-11" | "CWE-13" | "CWE-15" | "CWE-260" | "CWE-315"
        | "CWE-520" | "CWE-526" | "CWE-537" | "CWE-541" | "CWE-547" | "CWE-611" | "CWE-614"
        | "CWE-756" | "CWE-776" | "CWE-942" | "CWE-1004" | "CWE-1032" | "CWE-1174" => {
            Some("A05:2021-Security Misconfiguration")
        }

        // A06:2021 - Vulnerable and Outdated Components
        "CWE-1035" | "CWE-1104" | "CWE-937" | "CWE-1395" => {
            Some("A06:2021-Vulnerable and Outdated Components")
        }

        // A07:2021 - Identification and Authentication Failures
        "CWE-255" | "CWE-259" | "CWE-287" | "CWE-288" | "CWE-290" | "CWE-294" | "CWE-295"
        | "CWE-297" | "CWE-300" | "CWE-302" | "CWE-304" | "CWE-306" | "CWE-307" | "CWE-346"
        | "CWE-384" | "CWE-521" | "CWE-613" | "CWE-620" | "CWE-640" | "CWE-804"
        | "CWE-842" | "CWE-916" | "CWE-1021" | "CWE-1216" => {
            Some("A07:2021-Identification and Authentication Failures")
        }

        // A08:2021 - Software and Data Integrity Failures
        "CWE-345" | "CWE-353" | "CWE-426" | "CWE-494" | "CWE-502" | "CWE-565" | "CWE-784"
        | "CWE-829" | "CWE-830" | "CWE-915" => {
            Some("A08:2021-Software and Data Integrity Failures")
        }

        // A09:2021 - Security Logging and Monitoring Failures
        "CWE-117" | "CWE-223" | "CWE-532" | "CWE-778" => {
            Some("A09:2021-Security Logging and Monitoring Failures")
        }

        // A10:2021 - Server-Side Request Forgery (SSRF)
        "CWE-918" => Some("A10:2021-Server-Side Request Forgery (SSRF)"),

        // Memory safety / buffer overflows typically map to A03 or A08
        "CWE-119" | "CWE-120" | "CWE-125" | "CWE-787" | "CWE-416" | "CWE-476" | "CWE-190" => {
            Some("A03:2021-Injection")
        }

        _ => None,
    }
}

pub fn classify_cwes(raw_cwes: &[String]) -> (Vec<String>, Option<String>) {
    let mut normalized = Vec::new();
    let mut owasp_category = None;

    for raw in raw_cwes {
        let norm = normalize_cwe_id(raw);
        if !norm.is_empty() && !normalized.contains(&norm) {
            if owasp_category.is_none() {
                owasp_category = map_cwe_to_owasp(&norm).map(|s| s.to_string());
            }
            normalized.push(norm);
        }
    }

    (normalized, owasp_category)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cwe_top_25_recognition() {
        assert!(is_cwe_top_25("CWE-79"));
        assert!(is_cwe_top_25("cwe-787"));
        assert!(is_cwe_top_25("502"));
        assert!(!is_cwe_top_25("CWE-9999"));
    }

    #[test]
    fn test_owasp_top_10_mapping() {
        assert_eq!(
            map_cwe_to_owasp("CWE-79"),
            Some("A03:2021-Injection")
        );
        assert_eq!(
            map_cwe_to_owasp("CWE-502"),
            Some("A08:2021-Software and Data Integrity Failures")
        );
        assert_eq!(
            map_cwe_to_owasp("CWE-918"),
            Some("A10:2021-Server-Side Request Forgery (SSRF)")
        );
        assert_eq!(
            map_cwe_to_owasp("CWE-22"),
            Some("A01:2021-Broken Access Control")
        );
    }

    #[test]
    fn test_classify_cwes() {
        let raw = vec!["cwe-79".to_string(), "502".to_string(), "CWE-79".to_string()];
        let (cwes, owasp) = classify_cwes(&raw);
        assert_eq!(cwes.len(), 2);
        assert_eq!(cwes[0], "CWE-79");
        assert_eq!(cwes[1], "CWE-502");
        assert_eq!(owasp, Some("A03:2021-Injection".to_string()));
    }
}
