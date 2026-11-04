#![forbid(unsafe_code)]

use chrono::Utc;
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredentials {
    pub token: String,
    pub org_slug: Option<String>,
    pub user_email: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthStatusResponse {
    pub authenticated: bool,
    pub org_slug: Option<String>,
    pub user_email: Option<String>,
    pub tier: Option<String>,
    pub token_prefix: Option<String>,
}

pub const DEFAULT_API_BASE_URL: &str = "https://api.vexasec.io/sca/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTokenResponse {
    pub token: String,
    pub org_slug: Option<String>,
    pub user_email: Option<String>,
    pub tier: Option<String>,
}

/// Helper to launch the default system browser for OAuth device confirmation or dashboard viewing
pub fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "start", "", url])
            .spawn()
            .is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn().is_ok()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::process::Command::new("xdg-open")
            .arg(url)
            .spawn()
            .is_ok()
    }
}

pub struct AuthManager;

impl AuthManager {
    /// Resolve the cloud API base URL from override argument, environment variables
    /// (`VEXA_API_URL` or `VEXA_API_BASE_URL`), or fall back to `DEFAULT_API_BASE_URL`.
    pub fn resolve_api_base_url(override_url: Option<&str>) -> String {
        if let Some(url) = override_url {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        if let Ok(url) = std::env::var("VEXA_API_URL") {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        if let Ok(url) = std::env::var("VEXA_API_BASE_URL") {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        DEFAULT_API_BASE_URL.to_string()
    }
    /// Return the standard path to `~/.vexa/credentials.json`
    pub fn credentials_path() -> PathBuf {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".vexa").join("credentials.json")
    }

    /// Retrieve the active token from environment (`VEXA_TOKEN` / `VEXA_SCA_API_KEY`)
    /// or from stored `~/.vexa/credentials.json`.
    pub fn get_token() -> Option<String> {
        if let Ok(tok) = std::env::var("VEXA_TOKEN") {
            let t = tok.trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }
        if let Ok(tok) = std::env::var("VEXA_SCA_API_KEY") {
            let t = tok.trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }

        Self::load_stored_credentials().map(|c| c.token)
    }

    pub fn load_stored_credentials() -> Option<StoredCredentials> {
        let path = Self::credentials_path();
        if !path.exists() {
            return None;
        }
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn save_token(
        token: &str,
        org_slug: Option<&str>,
        user_email: Option<&str>,
    ) -> Result<(), String> {
        let path = Self::credentials_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create credentials directory: {}", e))?;
        }

        let creds = StoredCredentials {
            token: token.trim().to_string(),
            org_slug: org_slug.map(|s| s.to_string()),
            user_email: user_email.map(|s| s.to_string()),
            created_at: Utc::now().to_rfc3339(),
        };

        let json = serde_json::to_string_pretty(&creds)
            .map_err(|e| format!("Failed to serialize credentials: {}", e))?;
        fs::write(&path, json).map_err(|e| format!("Failed to write credentials: {}", e))?;

        Ok(())
    }

    pub fn logout() -> Result<bool, String> {
        let path = Self::credentials_path();
        if path.exists() {
            fs::remove_file(&path).map_err(|e| format!("Failed to delete credentials: {}", e))?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check authentication status against cloud API endpoint or local token check
    pub async fn check_status(api_base_url: Option<&str>) -> AuthStatusResponse {
        let token = Self::get_token();
        let Some(t) = token else {
            return AuthStatusResponse {
                authenticated: false,
                org_slug: None,
                user_email: None,
                tier: None,
                token_prefix: None,
            };
        };

        let prefix = if t.len() >= 12 {
            format!("{}...", &t[..12])
        } else {
            "token...".to_string()
        };

        let base_url = Self::resolve_api_base_url(api_base_url);
        let status_url = format!("{}/auth/status", base_url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_default();

        if let Ok(resp) = client
            .get(&status_url)
            .header("Authorization", format!("Bearer {}", t))
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(info) = resp.json::<serde_json::Value>().await {
                    let org_slug = info
                        .get("org_slug")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let user_email = info
                        .get("user_email")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let tier = info.get("tier").and_then(|v| v.as_str()).map(String::from);

                    return AuthStatusResponse {
                        authenticated: true,
                        org_slug,
                        user_email,
                        tier: tier.or_else(|| Some("Free".to_string())),
                        token_prefix: Some(prefix),
                    };
                }
            }
        }

        // If cloud API is offline or unreachable, return local token verification
        let stored = Self::load_stored_credentials();
        AuthStatusResponse {
            authenticated: true,
            org_slug: stored.as_ref().and_then(|s| s.org_slug.clone()),
            user_email: stored.as_ref().and_then(|s| s.user_email.clone()),
            tier: Some("Free / Local".to_string()),
            token_prefix: Some(prefix),
        }
    }

    /// Execute `vexa-sca auth login`
    pub async fn run_login(
        token_opt: Option<String>,
        api_base_url: Option<&str>,
    ) -> Result<(), String> {
        let base_url = Self::resolve_api_base_url(api_base_url);

        let token = if let Some(t) = token_opt {
            t.trim().to_string()
        } else {
            println!("{}", "Starting Vexa SCA Cloud Login...".cyan().bold());

            // Attempt RFC 8628 OAuth 2.0 Device Authorization Flow first
            let device_code_url = format!("{}/auth/device/code", base_url);
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(4))
                .build()
                .unwrap_or_default();

            let device_flow_result = async {
                let resp = match client
                    .post(&device_code_url)
                    .json(&serde_json::json!({
                        "client_id": "vexa-sca-cli",
                        "scope": "scan:write policy:read"
                    }))
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Device flow HTTP request failed: {e}");
                        return None;
                    }
                };

                if resp.status().is_success() {
                    resp.json::<DeviceCodeResponse>().await.ok()
                } else {
                    None
                }
            }
            .await;

            if let Some(dev_res) = device_flow_result {
                let verify_url = dev_res.verification_uri_complete.unwrap_or_else(|| {
                    format!("{}?code={}", dev_res.verification_uri, dev_res.user_code)
                });

                println!("\n{}", "To authenticate this terminal session:".bold());
                println!(
                    "  1. Confirm this 8-character code: {}",
                    dev_res.user_code.yellow().bold()
                );
                println!(
                    "  2. Visit verification URL: {}",
                    verify_url.cyan().underline()
                );

                println!("\nAttempting to open verification page in your default browser...");
                if open_browser(&verify_url) {
                    println!("{} Browser opened successfully.", "✔".green());
                } else {
                    println!(
                        "{} Could not auto-launch browser. Please copy and paste the link above.",
                        "•".yellow()
                    );
                }

                println!("Waiting for confirmation in browser (press Ctrl+C to cancel)...");

                let token_poll_url = format!("{}/auth/device/token", base_url);
                let poll_interval = if dev_res.interval > 0 {
                    dev_res.interval
                } else {
                    3
                };
                let max_attempts = (dev_res.expires_in.max(300) / poll_interval.max(1)) as usize;

                let mut obtained_token = None;
                for _ in 0..max_attempts {
                    tokio::time::sleep(std::time::Duration::from_secs(poll_interval)).await;
                    if let Ok(poll_resp) = client
                        .post(&token_poll_url)
                        .json(&serde_json::json!({
                            "device_code": dev_res.device_code
                        }))
                        .send()
                        .await
                    {
                        if poll_resp.status().is_success() {
                            if let Ok(token_info) = poll_resp.json::<DeviceTokenResponse>().await {
                                obtained_token = Some((
                                    token_info.token,
                                    token_info.org_slug,
                                    token_info.user_email,
                                ));
                                break;
                            }
                        } else if poll_resp.status() == reqwest::StatusCode::BAD_REQUEST {
                            if let Ok(err_body) = poll_resp.json::<serde_json::Value>().await {
                                let err_type =
                                    err_body.get("error").and_then(|e| e.as_str()).unwrap_or("");
                                if err_type == "expired_token" || err_type == "access_denied" {
                                    eprintln!(
                                        "{} Device code authorization was denied or expired.",
                                        "Error:".red().bold()
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }

                if let Some((tok, org, email)) = obtained_token {
                    Self::save_token(&tok, org.as_deref(), email.as_deref())?;
                    println!(
                        "\n{} Successfully authenticated with Vexa SCA Cloud!",
                        "✔".green().bold()
                    );
                    if let Some(o) = org {
                        println!("  Organization: {}", o.cyan());
                    }
                    if let Some(e) = email {
                        println!("  Account: {}", e.cyan());
                    }
                    println!(
                        "  Credentials stored at: {}",
                        Self::credentials_path().display()
                    );
                    println!(
                        "  You can now run: {} to stream scan results to your dashboard.",
                        "vexa-sca scan --upload".bold()
                    );
                    return Ok(());
                } else {
                    println!("\n{} Device flow timed out or was not confirmed. Falling back to manual token entry.", "•".yellow());
                }
            }

            // Fallback manual entry
            println!("Please paste your Vexa Personal Access Token (PAT) below (or press Ctrl+C to cancel):");
            let mut input = String::new();
            std::io::stdin()
                .read_line(&mut input)
                .map_err(|e| format!("Failed to read token from stdin: {}", e))?;
            input.trim().to_string()
        };

        if token.is_empty() {
            return Err("Token cannot be empty".to_string());
        }

        // Validate token format: starts with vexa_pat_ or valid Bearer prefix
        let is_pat = token.starts_with("vexa_pat_");
        if !is_pat && token.len() < 16 {
            return Err("Invalid token format. Vexa API tokens start with 'vexa_pat_'".to_string());
        }

        let base_url = Self::resolve_api_base_url(api_base_url);
        let status_url = format!("{}/auth/status", base_url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .unwrap_or_default();

        let mut org_slug = None;
        let mut user_email = None;

        if let Ok(resp) = client
            .get(&status_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(info) = resp.json::<serde_json::Value>().await {
                    org_slug = info
                        .get("org_slug")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    user_email = info
                        .get("user_email")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
        }

        Self::save_token(&token, org_slug.as_deref(), user_email.as_deref())?;

        println!(
            "{} Successfully authenticated with Vexa SCA Cloud!",
            "✔".green().bold()
        );
        if let Some(org) = org_slug {
            println!("  Organization: {}", org.cyan());
        }
        if let Some(email) = user_email {
            println!("  Account: {}", email.cyan());
        }
        println!(
            "  Credentials stored at: {}",
            Self::credentials_path().display()
        );
        println!(
            "  You can now run: {} to stream scan results to your dashboard.",
            "vexa-sca scan --upload".bold()
        );

        Ok(())
    }

    /// Execute `vexa-sca auth status`
    pub async fn run_status(api_base_url: Option<&str>) -> Result<(), String> {
        let status = Self::check_status(api_base_url).await;
        if status.authenticated {
            println!("{}", "Vexa SCA Authentication Status:".green().bold());
            println!("  Status: {}", "Authenticated".green());
            if let Some(prefix) = status.token_prefix {
                println!("  Token: {}", prefix);
            }
            if let Some(org) = status.org_slug {
                println!("  Organization: {}", org.cyan());
            }
            if let Some(email) = status.user_email {
                println!("  Account: {}", email.cyan());
            }
            if let Some(tier) = status.tier {
                println!("  Plan Tier: {}", tier.bold());
            }
            println!("  Credentials: {}", Self::credentials_path().display());
        } else {
            println!("{}", "Vexa SCA Authentication Status:".yellow().bold());
            println!("  Status: {}", "Unauthenticated (Local OSS Mode)".yellow());
            println!(
                "  Run '{}' to connect to Vexa SCA Cloud.",
                "vexa-sca auth login".cyan().bold()
            );
        }
        Ok(())
    }

    /// Execute `vexa-sca auth logout`
    pub fn run_logout() -> Result<(), String> {
        let removed = Self::logout()?;
        if removed {
            println!(
                "{} Logged out. Stored credentials removed.",
                "✔".green().bold()
            );
        } else {
            println!("{} No active stored credentials found.", "•".yellow());
        }
        Ok(())
    }
}
