use anyhow::{Context, Result};
use base64_url as base64url;
use ciborium::Value as CborValue;
use ecdsa::signature::Signer;
use p256::{
    ecdsa::{DerSignature, SigningKey, VerifyingKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SoftwareAuthenticator {
    credentials: Vec<StoredCredential>,
    counter: u32,
    // Map credential_id (base64) -> VerifyingKey for easy lookup
    pub verifying_keys: HashMap<String, VerifyingKey>,
}

#[derive(Debug, Clone)]
struct StoredCredential {
    credential_id: Vec<u8>,
    private_key: SigningKey,
    #[allow(dead_code)]
    public_key: VerifyingKey,
    #[allow(dead_code)]
    user_id: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientDataJson {
    #[serde(rename = "type")]
    pub typ: String,
    pub challenge: String,
    pub origin: String,
    #[serde(rename = "crossOrigin")]
    pub cross_origin: bool,
}

impl SoftwareAuthenticator {
    pub fn new() -> Self {
        Self {
            credentials: Vec::new(),
            counter: 0,
            verifying_keys: HashMap::new(),
        }
    }

    pub fn create_credential(
        &mut self,
        challenge: &[u8],
        user_id: &[u8],
        relying_party_id: &str,
        user_verification: bool,
    ) -> Result<(String, String, String, String)> {
        // Generate new key pair
        let private_key = SigningKey::random(&mut rand::thread_rng());
        let public_key = private_key.verifying_key();

        // Generate credential ID (random 64 bytes)
        let credential_id: Vec<u8> = (0..64).map(|_| rand::random::<u8>()).collect();

        // Store credential
        let credential_id_b64 = base64url::encode(&credential_id);
        self.verifying_keys.insert(credential_id_b64.clone(), public_key.clone());
        self.credentials.push(StoredCredential {
            credential_id: credential_id.clone(),
            private_key: private_key.clone(),
            public_key: public_key.clone(),
            user_id: user_id.to_vec(),
        });

        // Create client data JSON
        let client_data = ClientDataJson {
            typ: "webauthn.create".to_string(),
            challenge: base64url::encode(challenge),
            origin: "http://localhost".to_string(),
            cross_origin: false,
        };
        let client_data_json = serde_json::to_string(&client_data)?;
        let _client_data_hash = Sha256::digest(client_data_json.as_bytes());

        // Create authenticator data
        let rp_id_hash = Sha256::digest(relying_party_id.as_bytes());
        let flags = self.build_flags(true, user_verification, true, false);
        self.counter += 1;

        // Build attested credential data
        let aaguid = [0u8; 16]; // No AAGUID for software authenticator
        let credential_id_length = (credential_id.len() as u16).to_be_bytes();

        // Create COSE key (COSE_Key format for P-256)
        let public_key_bytes = public_key.to_sec1_bytes();
        let x_coord = &public_key_bytes[1..33];
        let y_coord = &public_key_bytes[33..65];

        let cose_key = self.build_cose_key(x_coord, y_coord)?;
        let cose_key_bytes = self.encode_cbor(&cose_key)?;

        // Build authenticator data
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(&aaguid);
        auth_data.extend_from_slice(&credential_id_length);
        auth_data.extend_from_slice(&credential_id);
        auth_data.extend_from_slice(&cose_key_bytes);

        // Create attestation object
        let mut attestation_map = Vec::new();
        attestation_map.push((CborValue::Text("fmt".to_string()), CborValue::Text("none".to_string())));
        attestation_map.push((CborValue::Text("attStmt".to_string()), CborValue::Map(Vec::new())));
        attestation_map.push((CborValue::Text("authData".to_string()), CborValue::Bytes(auth_data)));

        let attestation_object = self.encode_cbor(&CborValue::Map(attestation_map))?;

        Ok((
            base64url::encode(&credential_id),
            "public-key".to_string(),
            base64url::encode(&attestation_object),
            base64url::encode(client_data_json.as_bytes()),
        ))
    }

    pub fn create_assertion(
        &mut self,
        credential_id: &str,
        challenge: &[u8],
        relying_party_id: &str,
        user_verification: bool,
    ) -> Result<(String, String, String, String, String, Option<String>)> {
        // Find credential
        let credential_id_bytes = base64url::decode(credential_id)
            .context("Failed to decode credential ID")?;

        let credential = self.credentials
            .iter()
            .find(|c| c.credential_id == credential_id_bytes)
            .context("Credential not found")?
            .clone();

        // Create client data JSON
        let client_data = ClientDataJson {
            typ: "webauthn.get".to_string(),
            challenge: base64url::encode(challenge),
            origin: "http://localhost".to_string(),
            cross_origin: false,
        };
        let client_data_json = serde_json::to_string(&client_data)?;
        let client_data_hash = Sha256::digest(client_data_json.as_bytes());

        // Create authenticator data
        let rp_id_hash = Sha256::digest(relying_party_id.as_bytes());
        let flags = self.build_flags(true, user_verification, false, false);
        self.counter += 1;

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());

        // Sign the data
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(&auth_data);
        signature_data.extend_from_slice(&client_data_hash);

        let signature: DerSignature = credential.private_key.sign(&signature_data);

        Ok((
            credential_id.to_string(),
            "public-key".to_string(),
            base64url::encode(&auth_data),
            base64url::encode(client_data_json.as_bytes()),
            base64url::encode(&signature.to_bytes()),
            None, // user_handle can be null for non-resident keys
        ))
    }

    fn build_flags(&self, up: bool, uv: bool, at: bool, ed: bool) -> u8 {
        let mut flags = 0u8;
        if up { flags |= 0x01; }  // User present
        if uv { flags |= 0x04; }  // User verified
        if at { flags |= 0x40; }  // Attested credential data included
        if ed { flags |= 0x80; }  // Extension data included
        flags
    }

    fn build_cose_key(&self, x: &[u8], y: &[u8]) -> Result<CborValue> {
        let mut cose_key = Vec::new();

        // kty: EC2 (2)
        cose_key.push((CborValue::Integer(1.into()), CborValue::Integer(2.into())));
        // alg: ES256 (-7)
        cose_key.push((CborValue::Integer(3.into()), CborValue::Integer((-7).into())));
        // crv: P-256 (1)
        cose_key.push((CborValue::Integer((-1).into()), CborValue::Integer(1.into())));
        // x coordinate
        cose_key.push((CborValue::Integer((-2).into()), CborValue::Bytes(x.to_vec())));
        // y coordinate
        cose_key.push((CborValue::Integer((-3).into()), CborValue::Bytes(y.to_vec())));

        Ok(CborValue::Map(cose_key))
    }

    fn encode_cbor(&self, value: &CborValue) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes)
            .context("Failed to encode CBOR")?;
        Ok(bytes)
    }

    #[allow(dead_code)]
    pub fn get_stored_credential_ids(&self) -> Vec<String> {
        self.credentials
            .iter()
            .map(|c| base64url::encode(&c.credential_id))
            .collect()
    }
}