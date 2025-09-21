use anyhow::{Context, Result};
use base64_url as base64url;
use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Verify a WebAuthn assertion signature using Rust crypto
pub fn verify_assertion_signature(
    verifying_key: &VerifyingKey,
    authenticator_data: &str,
    client_data_json: &str,
    signature: &str,
) -> Result<bool> {
    // Decode inputs
    let auth_data_bytes = base64url::decode(authenticator_data)
        .context("Failed to decode authenticator data")?;
    let client_data_bytes = base64url::decode(client_data_json)
        .context("Failed to decode client data JSON")?;
    let signature_bytes = base64url::decode(signature)
        .context("Failed to decode signature")?;

    // Construct signed data: authenticator_data || sha256(client_data_json)
    let client_data_hash = Sha256::digest(&client_data_bytes);
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&auth_data_bytes);
    signed_data.extend_from_slice(&client_data_hash);

    // Parse DER signature
    let sig = Signature::from_der(&signature_bytes)
        .context("Failed to parse DER signature")?;

    // Verify signature
    match verifying_key.verify(&signed_data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}