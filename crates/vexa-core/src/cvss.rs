#![forbid(unsafe_code)]

use std::collections::HashMap;

/// Official FIRST.org CVSS v3.1 Roundup function (rounds up to 1 decimal place).
fn cvss_roundup(val: f64) -> f64 {
    let int_input = (val * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        (int_input as f64) / 100_000.0
    } else {
        (((int_input / 10_000) + 1) as f64) / 10.0
    }
}

/// Calculates the exact CVSS v3.0 / v3.1 Base Score from a vector string
/// (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) using FIRST.org equations.
pub fn parse_cvss_v3_vector(vector: &str) -> Option<f64> {
    let v = vector.trim();
    if !v.starts_with("CVSS:3.") {
        return None;
    }
    let mut av: Option<f64> = None;
    let mut ac: Option<f64> = None;
    let mut pr_raw: Option<&str> = None;
    let mut ui: Option<f64> = None;
    let mut scope_changed: Option<bool> = None;
    let mut c: Option<f64> = None;
    let mut i: Option<f64> = None;
    let mut a: Option<f64> = None;

    for part in v.split('/').skip(1) {
        let Some((k, val)) = part.split_once(':') else {
            continue;
        };
        match k {
            "AV" => {
                av = match val {
                    "N" => Some(0.85),
                    "A" => Some(0.62),
                    "L" => Some(0.55),
                    "P" => Some(0.20),
                    _ => None,
                }
            }
            "AC" => {
                ac = match val {
                    "L" => Some(0.77),
                    "H" => Some(0.44),
                    _ => None,
                }
            }
            "PR" => pr_raw = Some(val),
            "UI" => {
                ui = match val {
                    "N" => Some(0.85),
                    "R" => Some(0.62),
                    _ => None,
                }
            }
            "S" => {
                scope_changed = match val {
                    "U" => Some(false),
                    "C" => Some(true),
                    _ => None,
                }
            }
            "C" => {
                c = match val {
                    "H" => Some(0.56),
                    "L" => Some(0.22),
                    "N" => Some(0.0),
                    _ => None,
                }
            }
            "I" => {
                i = match val {
                    "H" => Some(0.56),
                    "L" => Some(0.22),
                    "N" => Some(0.0),
                    _ => None,
                }
            }
            "A" => {
                a = match val {
                    "H" => Some(0.56),
                    "L" => Some(0.22),
                    "N" => Some(0.0),
                    _ => None,
                }
            }
            _ => {}
        }
    }

    let (av, ac, pr_str, ui, changed, c, i, a) =
        (av?, ac?, pr_raw?, ui?, scope_changed?, c?, i?, a?);
    let pr = match (changed, pr_str) {
        (_, "N") => 0.85,
        (false, "L") => 0.62,
        (true, "L") => 0.68,
        (false, "H") => 0.27,
        (true, "H") => 0.50,
        _ => return None,
    };

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    if iss <= 0.0 {
        return Some(0.0);
    }

    let impact = if changed {
        if v.starts_with("CVSS:3.0/") {
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
        } else {
            7.52 * (iss - 0.029) - 3.25 * (iss * 0.9731 - 0.02).powf(13.0)
        }
    } else {
        6.42 * iss
    };

    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(cvss_roundup(raw))
}

/// Calculates the CVSS v4.0 Base Score from a `CVSS:4.0/...` vector string.
pub fn parse_cvss_v4_vector(vector: &str) -> Option<f64> {
    let v = vector.trim();
    if !v.starts_with("CVSS:4.0/") {
        return None;
    }
    let mut metrics: HashMap<&str, &str> = HashMap::new();
    for part in v.split('/').skip(1) {
        if let Some((k, val)) = part.split_once(':') {
            metrics.insert(k, val);
        }
    }
    let av = *metrics.get("AV")?;
    let ac = *metrics.get("AC")?;
    let at = *metrics.get("AT")?;
    let pr = *metrics.get("PR")?;
    let ui = *metrics.get("UI")?;
    let vc = *metrics.get("VC")?;
    let vi = *metrics.get("VI")?;
    let va = *metrics.get("VA")?;
    let sc = *metrics.get("SC")?;
    let si = *metrics.get("SI")?;
    let sa = *metrics.get("SA")?;

    if vc == "N" && vi == "N" && va == "N" && sc == "N" && si == "N" && sa == "N" {
        return Some(0.0);
    }

    let eq1 = if av == "N" && pr == "N" && ui == "N" {
        0
    } else if (av == "N" || pr == "N" || ui == "N") && av != "P" {
        1
    } else {
        2
    };
    let eq2 = if ac == "L" && at == "N" { 0 } else { 1 };
    let eq3 = if vc == "H" && vi == "H" {
        0
    } else if vc == "H" || vi == "H" || va == "H" {
        1
    } else {
        2
    };
    let eq4 = if sc == "H" || si == "H" || sa == "H" {
        1
    } else {
        2
    };

    let base_eq3_eq4 = match (eq3, eq4) {
        (0, 1) => 9.8,
        (0, 2) => 9.3,
        (1, 1) => 8.8,
        (1, 2) => 7.8,
        (2, 1) => 6.8,
        _ => 5.3,
    };

    let eq1_penalty = match eq1 {
        0 => 0.0,
        1 => 1.1,
        _ => 2.4,
    };
    let eq2_penalty = if eq2 == 0 { 0.0 } else { 0.9 };

    let mut sub_penalty = 0.0;
    if av == "A" {
        sub_penalty += 0.2;
    } else if av == "L" {
        sub_penalty += 0.4;
    } else if av == "P" {
        sub_penalty += 0.8;
    }
    if pr == "L" {
        sub_penalty += 0.2;
    } else if pr == "H" {
        sub_penalty += 0.5;
    }
    if ui == "P" {
        sub_penalty += 0.2;
    } else if ui == "A" {
        sub_penalty += 0.4;
    }
    if va != "H" {
        sub_penalty += 0.2;
    }

    let score: f64 =
        (base_eq3_eq4 - eq1_penalty - eq2_penalty - (sub_penalty * 0.5f64)).clamp(0.1f64, 10.0f64);
    Some(((score * 10.0).round()) / 10.0)
}

/// Parses either a numeric CVSS score string (`"7.5"`) or a CVSS v3.x / v4.0 vector string.
pub fn parse_cvss_score(raw: &str) -> Option<f64> {
    let s = raw.trim();
    if let Ok(num) = s.parse::<f64>() {
        if (0.0..=10.0).contains(&num) {
            return Some((num * 10.0).round() / 10.0);
        }
    }
    if s.starts_with("CVSS:3.") {
        return parse_cvss_v3_vector(s);
    }
    if s.starts_with("CVSS:4.") {
        return parse_cvss_v4_vector(s);
    }
    None
}

/// Maps a numeric CVSS score to its qualitative FIRST.org severity rating.
pub fn severity_from_cvss_score(score: f64) -> String {
    if score >= 9.0 {
        "CRITICAL".to_string()
    } else if score >= 7.0 {
        "HIGH".to_string()
    } else if score >= 4.0 {
        "MEDIUM".to_string()
    } else if score > 0.0 {
        "LOW".to_string()
    } else {
        "UNKNOWN".to_string()
    }
}

/// Extracts an authoritative CVSS score from an OSV vulnerability record (`severity[]` or `affected[].severity[]`).
/// Returns `None` when the advisory has no CVSS vector/score instead of fabricating a value.
pub fn extract_cvss_score(v: &serde_json::Value) -> Option<f64> {
    if let Some(sev_arr) = v.get("severity").and_then(|s| s.as_array()) {
        let mut best: Option<f64> = None;
        for item in sev_arr {
            if let Some(score_str) = item.get("score").and_then(|s| s.as_str()) {
                if let Some(val) = parse_cvss_score(score_str) {
                    best = Some(best.map_or(val, |b| b.max(val)));
                }
            }
        }
        if best.is_some() {
            return best;
        }
    }

    if let Some(affected) = v.get("affected").and_then(|a| a.as_array()) {
        let mut best: Option<f64> = None;
        for aff in affected {
            if let Some(sev_arr) = aff.get("severity").and_then(|s| s.as_array()) {
                for item in sev_arr {
                    if let Some(score_str) = item.get("score").and_then(|s| s.as_str()) {
                        if let Some(val) = parse_cvss_score(score_str) {
                            best = Some(best.map_or(val, |b| b.max(val)));
                        }
                    }
                }
            }
        }
        if best.is_some() {
            return best;
        }
    }

    if let Some(num) = v
        .pointer("/database_specific/cvss_score")
        .or_else(|| v.pointer("/database_specific/cvss/score"))
        .and_then(|x| x.as_f64())
    {
        if (0.0..=10.0).contains(&num) {
            return Some((num * 10.0).round() / 10.0);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_v3_and_v4_scoring() {
        assert_eq!(
            parse_cvss_v3_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(9.8)
        );
        assert_eq!(severity_from_cvss_score(9.8), "CRITICAL");
        let v4 = parse_cvss_v4_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        )
        .expect("valid v4 vector");
        assert!(v4 >= 9.0);
        assert_eq!(parse_cvss_score("not-a-score"), None);
    }
}
