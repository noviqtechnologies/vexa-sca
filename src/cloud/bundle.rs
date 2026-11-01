#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Embedded Vexa root public key for offline advisory bundle verification (Ed25519)
pub const VEXA_OFFLINE_ROOT_PUBKEY_HEX: &str =
    "a8e4b2d1c0f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a3928170615";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineDbEnvelope {
    pub format_version: u32,
    pub created_at: String,
    pub issuer: String,
    pub advisory_count: usize,
    pub payload_sha256: String,
    pub payload_json: String,
    pub signature_ed25519_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedOfflineDb {
    pub format_version: u32,
    pub created_at: String,
    pub issuer: String,
    pub advisory_count: usize,
    pub payload_sha256: String,
}

pub struct OfflineBundleVerifier;

impl OfflineBundleVerifier {
    /// Verify an offline advisory bundle file (.vexadb) using Ed25519 cryptographic signatures
    pub fn verify_bundle_file(
        bundle_path: &Path,
        override_pubkey_hex: Option<&str>,
    ) -> Result<(VerifiedOfflineDb, OfflineDbEnvelope), String> {
        if !bundle_path.exists() {
            return Err(format!(
                "Offline database bundle not found at {}",
                bundle_path.display()
            ));
        }

        let content = fs::read_to_string(bundle_path)
            .map_err(|e| format!("Failed to read offline database bundle: {}", e))?;

        Self::verify_bundle_content(&content, override_pubkey_hex)
    }

    /// Verify raw bundle JSON string
    pub fn verify_bundle_content(
        content: &str,
        override_pubkey_hex: Option<&str>,
    ) -> Result<(VerifiedOfflineDb, OfflineDbEnvelope), String> {
        let envelope: OfflineDbEnvelope = serde_json::from_str(content)
            .map_err(|e| format!("Invalid offline bundle JSON envelope: {}", e))?;

        if envelope.format_version != 1 {
            return Err(format!(
                "Unsupported bundle format version: {}",
                envelope.format_version
            ));
        }

        // 1. Verify SHA-256 integrity of advisory payload
        let mut hasher = Sha256::new();
        hasher.update(envelope.payload_json.as_bytes());
        let computed_sha256 = hex::encode(hasher.finalize());

        if computed_sha256 != envelope.payload_sha256 {
            return Err(format!(
                "Advisory bundle SHA-256 payload integrity mismatch (expected {}, computed {})",
                envelope.payload_sha256, computed_sha256
            ));
        }

        // 2. Resolve Ed25519 verifying public key
        let pubkey_hex = override_pubkey_hex.unwrap_or(VEXA_OFFLINE_ROOT_PUBKEY_HEX);
        let pubkey_bytes = hex::decode(pubkey_hex)
            .map_err(|e| format!("Invalid hex for offline root public key: {}", e))?;

        if pubkey_bytes.len() != 32 {
            return Err(format!(
                "Invalid public key length (expected 32 bytes, got {})",
                pubkey_bytes.len()
            ));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let verifying_key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|e| format!("Invalid Ed25519 public key: {}", e))?;

        // 3. Decode signature
        let sig_bytes = hex::decode(&envelope.signature_ed25519_hex)
            .map_err(|e| format!("Invalid signature hex in bundle: {}", e))?;

        if sig_bytes.len() != 64 {
            return Err(format!(
                "Invalid signature length (expected 64 bytes, got {})",
                sig_bytes.len()
            ));
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        // 4. Message canonical bytes: "VEXA-OFFLINE-DB-V1:{created_at}:{payload_sha256}"
        let signed_message = format!(
            "VEXA-OFFLINE-DB-V1:{}:{}",
            envelope.created_at, envelope.payload_sha256
        );

        verifying_key
            .verify(signed_message.as_bytes(), &signature)
            .map_err(|e| {
                format!(
                    "Ed25519 signature verification failed for offline advisory bundle: {}",
                    e
                )
            })?;

        let verified = VerifiedOfflineDb {
            format_version: envelope.format_version,
            created_at: envelope.created_at.clone(),
            issuer: envelope.issuer.clone(),
            advisory_count: envelope.advisory_count,
            payload_sha256: envelope.payload_sha256.clone(),
        };

        Ok((verified, envelope))
    }
}
