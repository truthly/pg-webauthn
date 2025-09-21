use crate::authenticator::SoftwareAuthenticator;
use crate::database::TestDatabase;
use crate::utils::{flip_bit_in_base64, format_string_diff, format_test_result, generate_challenge, generate_user_id};
use crate::verifier;
use anyhow::{Context, Result};

pub fn run_negative_tests(db: &mut TestDatabase, _debug: bool) -> Result<()> {
    println!("\n=== Running Negative Tests ===\n");

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: Bit flip in credential_id
    match test_bit_flip_credential_id(db) {
        Ok(_) => {
            println!("{}", format_test_result("Bit flip in credential_id", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("Bit flip in credential_id", false));
            eprintln!("  Error: {}", e);
            failed += 1;
        }
    }

    // Test 2: Bit flip in signature
    match test_bit_flip_signature(db) {
        Ok(_) => {
            println!("{}", format_test_result("Bit flip in signature", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("Bit flip in signature", false));
            eprintln!("  Error: {}", e);
            failed += 1;
        }
    }

    // Test 3: Bit flip in authenticator_data
    match test_bit_flip_authenticator_data(db) {
        Ok(_) => {
            println!("{}", format_test_result("Bit flip in authenticator_data", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("Bit flip in authenticator_data", false));
            eprintln!("  Error: {}", e);
            failed += 1;
        }
    }

    // Test 4: Bit flip in client_data_json
    match test_bit_flip_client_data_json(db) {
        Ok(_) => {
            println!("{}", format_test_result("Bit flip in client_data_json", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("Bit flip in client_data_json", false));
            eprintln!("  Error: {}", e);
            failed += 1;
        }
    }

    // Test 5: Challenge replay attack
    match test_challenge_replay(db) {
        Ok(_) => {
            println!("{}", format_test_result("Challenge replay attack prevention", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("Challenge replay attack prevention", false));
            eprintln!("  Error: {}", e);
            failed += 1;
        }
    }

    // Test 6: Expired challenge
    match test_expired_challenge(db) {
        Ok(_) => {
            println!("{}", format_test_result("Expired challenge rejection", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("Expired challenge rejection", false));
            eprintln!("  Error: {}", e);
            failed += 1;
        }
    }

    println!("\nNegative Tests: {} passed, {} failed", passed, failed);

    if failed > 0 {
        anyhow::bail!("Some negative tests failed");
    }

    Ok(())
}

fn test_bit_flip_credential_id(db: &mut TestDatabase) -> Result<()> {
    let mut authenticator = SoftwareAuthenticator::new();

    // Setup: Create a valid credential
    let challenge = generate_challenge();
    let user_id = generate_user_id();
    let user_name = "bitflip.credid@example.com";
    let rp_id = "localhost";

    db.client().execute(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => $6,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        &[&challenge.as_slice(), &user_name, &user_id.as_slice(), &"Bit Flip User", &"Test Corp", &rp_id],
    )?;

    let (credential_id, _credential_type, attestation_object, client_data_json) =
        authenticator.create_credential(&challenge, &user_id, rp_id, false)?;

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&credential_id, &attestation_object, &client_data_json],
    )?;

    // Test: Attempt authentication with flipped credential_id
    let auth_challenge = generate_challenge();
    db.client().execute(
        "SELECT webauthn.get_credentials(
            challenge => $1,
            user_name => $2,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => $3
        )",
        &[&auth_challenge.as_slice(), &user_name, &rp_id],
    )?;

    let (_, _cred_type, auth_data, client_json, signature, user_handle) =
        authenticator.create_assertion(&credential_id, &auth_challenge, rp_id, false)?;

    // Flip a bit in the credential_id
    let corrupted_credential_id = flip_bit_in_base64(&credential_id)?;

    // First verify with Rust crypto (using correct credential_id to get the key)
    let verifying_key = authenticator.verifying_keys.get(&credential_id)
        .context("VerifyingKey not found for credential")?;

    let rust_verified = verifier::verify_assertion_signature(
        verifying_key,
        &auth_data,
        &client_json,
        &signature,
    )?;

    println!("  Rust signature verification (with correct credential): {}",
             if rust_verified { "PASS ✓" } else { "FAIL ✗" });

    // Then verify with PostgreSQL using corrupted credential_id - should fail
    let result = db.client().query_opt(
        "SELECT webauthn.verify_assertion(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => $2,
            client_data_json => $3,
            signature => $4,
            user_handle => $5
        )",
        &[&corrupted_credential_id, &auth_data, &client_json, &signature, &user_handle],
    );

    match result {
        Err(_) => Ok(()), // Any error is good - corruption prevented authentication
        Ok(None) => Ok(()), // No row returned - credential not found
        Ok(Some(row)) => {
            let user_id_result: Option<Vec<u8>> = row.get(0);
            if user_id_result.is_none() {
                Ok(()) // NULL returned - verification failed
            } else {
                anyhow::bail!("Verification should have failed with corrupted credential_id\n\n\
                    {}\n\n\
                    Other parameters:\n\
                    - authenticator_data: {}\n\
                    - client_data_json: {}\n\
                    - signature: {}\n\
                    - user_handle: {:?}",
                    format_string_diff("credential_id", &credential_id, &corrupted_credential_id),
                    auth_data,
                    client_json,
                    signature,
                    user_handle
                )
            }
        }
    }
}

fn test_bit_flip_signature(db: &mut TestDatabase) -> Result<()> {
    let mut authenticator = SoftwareAuthenticator::new();

    // Setup: Create a valid credential
    let challenge = generate_challenge();
    let user_id = generate_user_id();
    let user_name = "bitflip.sig@example.com";
    let rp_id = "localhost";

    db.client().execute(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => $6,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        &[&challenge.as_slice(), &user_name, &user_id.as_slice(), &"Bit Flip Sig", &"Test Corp", &rp_id],
    )?;

    let (credential_id, _credential_type, attestation_object, client_data_json) =
        authenticator.create_credential(&challenge, &user_id, rp_id, false)?;

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&credential_id, &attestation_object, &client_data_json],
    )?;

    // Test: Attempt authentication with flipped signature
    let auth_challenge = generate_challenge();
    db.client().execute(
        "SELECT webauthn.get_credentials(
            challenge => $1,
            user_name => $2,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => $3
        )",
        &[&auth_challenge.as_slice(), &user_name, &rp_id],
    )?;

    let (cred_id, _cred_type, auth_data, client_json, signature, user_handle) =
        authenticator.create_assertion(&credential_id, &auth_challenge, rp_id, false)?;

    // Get the verifying key for Rust verification
    let verifying_key = authenticator.verifying_keys.get(&credential_id)
        .context("VerifyingKey not found for credential")?;

    // Flip a bit in the signature, ensuring it affects the decoded (r,s) values
    let mut corrupted_signature;
    loop {
        corrupted_signature = flip_bit_in_base64(&signature)?;

        // Check if the decoded (r,s) values actually changed
        let original_decoded = db.client().query_one(
            "SELECT webauthn.decode_asn1_der_signature(webauthn.base64url_decode($1))",
            &[&signature],
        )?;

        let original_rs: Option<Vec<u8>> = original_decoded.get(0);

        let corrupted_decoded_result = db.client().query_opt(
            "SELECT webauthn.decode_asn1_der_signature(webauthn.base64url_decode($1))",
            &[&corrupted_signature],
        );

        // If decoding fails, that's good - the signature is corrupted
        if corrupted_decoded_result.is_err() {
            break;
        }

        if let Ok(Some(corrupted_decoded)) = corrupted_decoded_result {
            let corrupted_rs: Option<Vec<u8>> = corrupted_decoded.get(0);

            // If either is NULL or they differ, we have a good corruption
            if original_rs != corrupted_rs {
                // Good! The bit flip changed the decoded signature or made it invalid
                break;
            }
        } else {
            // No row returned
            break;
        }
        // Otherwise, try again with a different random bit
    }

    // First verify with Rust crypto using corrupted signature
    let rust_result = verifier::verify_assertion_signature(
        verifying_key,
        &auth_data,
        &client_json,
        &corrupted_signature,
    );

    match rust_result {
        Ok(verified) => {
            println!("  Rust signature verification (corrupted signature): {}",
                     if verified { "PASS ✓ (unexpected!)" } else { "FAIL ✗ (expected)" });
        },
        Err(e) => {
            println!("  Rust signature verification (corrupted signature): FAIL ✗ (parse error: {}) - expected", e);
        }
    }

    // Then verify with PostgreSQL - should also fail
    let result = db.client().query_opt(
        "SELECT webauthn.verify_assertion(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => $2,
            client_data_json => $3,
            signature => $4,
            user_handle => $5
        )",
        &[&cred_id, &auth_data, &client_json, &corrupted_signature, &user_handle],
    );

    match result {
        Err(_) => Ok(()), // Any error is good - corruption prevented authentication
        Ok(None) => Ok(()), // Also acceptable - no row returned
        Ok(Some(row)) => {
            let user_id_result: Option<Vec<u8>> = row.get(0);
            if user_id_result.is_none() {
                Ok(()) // NULL returned - verification failed
            } else {
                anyhow::bail!("Verification should have failed with corrupted signature\n\n\
                    {}\n\n\
                    Other parameters:\n\
                    - credential_id: {}\n\
                    - authenticator_data: {}\n\
                    - client_data_json: {}\n\
                    - user_handle: {:?}",
                    format_string_diff("signature", &signature, &corrupted_signature),
                    cred_id,
                    auth_data,
                    client_json,
                    user_handle
                )
            }
        }
    }
}

fn test_bit_flip_authenticator_data(db: &mut TestDatabase) -> Result<()> {
    let mut authenticator = SoftwareAuthenticator::new();

    // Setup: Create a valid credential
    let challenge = generate_challenge();
    let user_id = generate_user_id();
    let user_name = "bitflip.authdata@example.com";
    let rp_id = "localhost";

    db.client().execute(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => $6,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        &[&challenge.as_slice(), &user_name, &user_id.as_slice(), &"Bit Flip AuthData", &"Test Corp", &rp_id],
    )?;

    let (credential_id, _credential_type, attestation_object, client_data_json) =
        authenticator.create_credential(&challenge, &user_id, rp_id, false)?;

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&credential_id, &attestation_object, &client_data_json],
    )?;

    // Test: Attempt authentication with flipped authenticator_data
    let auth_challenge = generate_challenge();
    db.client().execute(
        "SELECT webauthn.get_credentials(
            challenge => $1,
            user_name => $2,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => $3
        )",
        &[&auth_challenge.as_slice(), &user_name, &rp_id],
    )?;

    let (cred_id, _cred_type, auth_data, client_json, signature, user_handle) =
        authenticator.create_assertion(&credential_id, &auth_challenge, rp_id, false)?;

    // Get the verifying key for Rust verification
    let verifying_key = authenticator.verifying_keys.get(&credential_id)
        .context("VerifyingKey not found for credential")?;

    // Flip a bit in the authenticator_data
    let corrupted_auth_data = flip_bit_in_base64(&auth_data)?;

    // First verify with Rust crypto using corrupted auth data
    let rust_verified = verifier::verify_assertion_signature(
        verifying_key,
        &corrupted_auth_data,
        &client_json,
        &signature,
    )?;

    println!("  Rust signature verification (corrupted auth data): {}",
             if rust_verified { "PASS ✓ (unexpected!)" } else { "FAIL ✗ (expected)" });

    // Then verify with PostgreSQL - should also fail
    let result = db.client().query_opt(
        "SELECT webauthn.verify_assertion(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => $2,
            client_data_json => $3,
            signature => $4,
            user_handle => $5
        )",
        &[&cred_id, &corrupted_auth_data, &client_json, &signature, &user_handle],
    );

    match result {
        Err(_) => Ok(()), // Any error is good - corruption prevented authentication
        Ok(None) => Ok(()), // Also acceptable - no row returned
        Ok(Some(row)) => {
            let user_id_result: Option<Vec<u8>> = row.get(0);
            if user_id_result.is_none() {
                Ok(()) // NULL returned - verification failed
            } else {
                anyhow::bail!("Verification should have failed with corrupted authenticator_data\n\n\
                    {}\n\n\
                    Other parameters:\n\
                    - credential_id: {}\n\
                    - client_data_json: {}\n\
                    - signature: {}\n\
                    - user_handle: {:?}",
                    format_string_diff("authenticator_data", &auth_data, &corrupted_auth_data),
                    cred_id,
                    client_json,
                    signature,
                    user_handle
                )
            }
        }
    }
}

fn test_bit_flip_client_data_json(db: &mut TestDatabase) -> Result<()> {
    let mut authenticator = SoftwareAuthenticator::new();

    // Setup: Create a valid credential
    let challenge = generate_challenge();
    let user_id = generate_user_id();
    let user_name = "bitflip.clientdata@example.com";
    let rp_id = "localhost";

    db.client().execute(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => $6,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        &[&challenge.as_slice(), &user_name, &user_id.as_slice(), &"Bit Flip ClientData", &"Test Corp", &rp_id],
    )?;

    let (credential_id, _credential_type, attestation_object, client_data_json) =
        authenticator.create_credential(&challenge, &user_id, rp_id, false)?;

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&credential_id, &attestation_object, &client_data_json],
    )?;

    // Test: Attempt authentication with flipped client_data_json
    let auth_challenge = generate_challenge();
    db.client().execute(
        "SELECT webauthn.get_credentials(
            challenge => $1,
            user_name => $2,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => $3
        )",
        &[&auth_challenge.as_slice(), &user_name, &rp_id],
    )?;

    let (cred_id, _cred_type, auth_data, client_json, signature, user_handle) =
        authenticator.create_assertion(&credential_id, &auth_challenge, rp_id, false)?;

    // Get the verifying key for Rust verification
    let verifying_key = authenticator.verifying_keys.get(&credential_id)
        .context("VerifyingKey not found for credential")?;

    // Flip a bit in the client_data_json
    let corrupted_client_json = flip_bit_in_base64(&client_json)?;

    // First verify with Rust crypto using corrupted client data
    let rust_verified = verifier::verify_assertion_signature(
        verifying_key,
        &auth_data,
        &corrupted_client_json,
        &signature,
    )?;

    println!("  Rust signature verification (corrupted client data): {}",
             if rust_verified { "PASS ✓ (unexpected!)" } else { "FAIL ✗ (expected)" });

    // Then verify with PostgreSQL - should also fail
    let result = db.client().query_opt(
        "SELECT webauthn.verify_assertion(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => $2,
            client_data_json => $3,
            signature => $4,
            user_handle => $5
        )",
        &[&cred_id, &auth_data, &corrupted_client_json, &signature, &user_handle],
    );

    match result {
        Err(_) => Ok(()), // Any error is good - corruption prevented authentication
        Ok(None) => Ok(()), // NULL/no row is also acceptable
        Ok(Some(row)) => {
            let user_id_result: Option<Vec<u8>> = row.get(0);
            if user_id_result.is_none() {
                Ok(()) // NULL returned - verification failed
            } else {
                anyhow::bail!("Verification should have failed with corrupted client_data_json\n\n\
                    {}\n\n\
                    Other parameters:\n\
                    - credential_id: {}\n\
                    - authenticator_data: {}\n\
                    - signature: {}\n\
                    - user_handle: {:?}",
                    format_string_diff("client_data_json", &client_json, &corrupted_client_json),
                    cred_id,
                    auth_data,
                    signature,
                    user_handle
                )
            }
        }
    }
}

fn test_challenge_replay(db: &mut TestDatabase) -> Result<()> {
    let mut authenticator = SoftwareAuthenticator::new();

    // Setup: Create a valid credential
    let challenge = generate_challenge();
    let user_id = generate_user_id();
    let user_name = "replay@example.com";
    let rp_id = "localhost";

    db.client().execute(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => $6,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        &[&challenge.as_slice(), &user_name, &user_id.as_slice(), &"Replay User", &"Test Corp", &rp_id],
    )?;

    let (credential_id, _credential_type, attestation_object, client_data_json) =
        authenticator.create_credential(&challenge, &user_id, rp_id, false)?;

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&credential_id, &attestation_object, &client_data_json],
    )?;

    // First authentication attempt
    let auth_challenge = generate_challenge();
    db.client().execute(
        "SELECT webauthn.get_credentials(
            challenge => $1,
            user_name => $2,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => $3
        )",
        &[&auth_challenge.as_slice(), &user_name, &rp_id],
    )?;

    let (cred_id, _cred_type, auth_data, client_json, signature, user_handle) =
        authenticator.create_assertion(&credential_id, &auth_challenge, rp_id, false)?;

    // Get the verifying key for Rust verification
    let verifying_key = authenticator.verifying_keys.get(&credential_id)
        .context("VerifyingKey not found for credential")?;

    // First verify with Rust crypto
    let rust_verified = verifier::verify_assertion_signature(
        verifying_key,
        &auth_data,
        &client_json,
        &signature,
    )?;

    println!("  Rust signature verification (first attempt): {}",
             if rust_verified { "PASS ✓" } else { "FAIL ✗" });

    // Then verify with PostgreSQL - should succeed
    let result = db.client().query_one(
        "SELECT webauthn.verify_assertion(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => $2,
            client_data_json => $3,
            signature => $4,
            user_handle => $5
        )",
        &[&cred_id, &auth_data, &client_json, &signature, &user_handle],
    )?;

    let user_id_result: Vec<u8> = result.get(0);
    assert_eq!(user_id_result, user_id, "First verification should succeed");

    // Second attempt with same challenge (replay attack)
    // Rust verification should still pass (signature is valid)
    let rust_verified_replay = verifier::verify_assertion_signature(
        verifying_key,
        &auth_data,
        &client_json,
        &signature,
    )?;

    println!("  Rust signature verification (replay attempt): {}",
             if rust_verified_replay { "PASS ✓ (signature still valid)" } else { "FAIL ✗" });

    // But PostgreSQL should reject the replay
    let result = db.client().query_opt(
        "SELECT webauthn.verify_assertion(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => $2,
            client_data_json => $3,
            signature => $4,
            user_handle => $5
        )",
        &[&cred_id, &auth_data, &client_json, &signature, &user_handle],
    );

    match result {
        Err(_) => Ok(()), // Any error is good - replay attack prevented
        Ok(None) => Ok(()), // Also acceptable - no row returned
        Ok(Some(row)) => {
            let user_id_result: Option<Vec<u8>> = row.get(0);
            if user_id_result.is_none() {
                Ok(()) // NULL returned - replay prevented
            } else {
                anyhow::bail!("Replay attack should have been prevented\n\
                    Challenge being replayed: {:?}\n\
                    Parameters used:\n\
                    - credential_id: {}\n\
                    - authenticator_data: {}\n\
                    - client_data_json: {}\n\
                    - signature: {}\n\
                    - user_handle: {:?}",
                    auth_challenge,
                    cred_id,
                    auth_data,
                    client_json,
                    signature,
                    user_handle
                )
            }
        }
    }
}

fn test_expired_challenge(db: &mut TestDatabase) -> Result<()> {
    let mut authenticator = SoftwareAuthenticator::new();

    // Setup: Create a valid credential
    let challenge = generate_challenge();
    let user_id = generate_user_id();
    let user_name = "expired@example.com";
    let rp_id = "localhost";

    db.client().execute(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => $6,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '30 seconds'::interval
        )",
        &[&challenge.as_slice(), &user_name, &user_id.as_slice(), &"Expired User", &"Test Corp", &rp_id],
    )?;

    let (credential_id, _credential_type, attestation_object, client_data_json) =
        authenticator.create_credential(&challenge, &user_id, rp_id, false)?;

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&credential_id, &attestation_object, &client_data_json],
    )?;

    // Create challenge with very short timeout
    let auth_challenge = generate_challenge();
    db.client().execute(
        "SELECT webauthn.get_credentials(
            challenge => $1,
            user_name => $2,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '30 seconds'::interval,
            relying_party_id => $3,
            challenge_at => now() - '31 seconds'::interval
        )",
        &[&auth_challenge.as_slice(), &user_name, &rp_id],
    ).context("Failed to create expired challenge")?;

    let (cred_id, _cred_type, auth_data, client_json, signature, user_handle) =
        authenticator.create_assertion(&credential_id, &auth_challenge, rp_id, false)?;

    // Get the verifying key for Rust verification
    let verifying_key = authenticator.verifying_keys.get(&credential_id)
        .context("VerifyingKey not found for credential")?;

    // Rust verification should still pass (signature is valid)
    let rust_verified = verifier::verify_assertion_signature(
        verifying_key,
        &auth_data,
        &client_json,
        &signature,
    )?;

    println!("  Rust signature verification (expired challenge): {}",
             if rust_verified { "PASS ✓ (signature still valid)" } else { "FAIL ✗" });

    // But PostgreSQL should reject due to expired challenge
    let result = db.client().query_opt(
        "SELECT webauthn.verify_assertion(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => $2,
            client_data_json => $3,
            signature => $4,
            user_handle => $5,
            verified_at => now()
        )",
        &[&cred_id, &auth_data, &client_json, &signature, &user_handle],
    );

    match result {
        Err(_) => Ok(()), // Any error is good - expired challenge rejected
        Ok(None) => Ok(()), // Also acceptable - no row returned
        Ok(Some(row)) => {
            let user_id_result: Option<Vec<u8>> = row.get(0);
            if user_id_result.is_none() {
                Ok(()) // NULL returned - expired challenge rejected
            } else {
                anyhow::bail!("Expired challenge should have been rejected\n\
                    Challenge: {:?}\n\
                    Timeout was set to: 100ms\n\
                    Verification attempted after: sleeping 200ms\n\
                    Parameters used:\n\
                    - credential_id: {}\n\
                    - authenticator_data: {}\n\
                    - client_data_json: {}\n\
                    - signature: {}\n\
                    - user_handle: {:?}",
                    auth_challenge,
                    cred_id,
                    auth_data,
                    client_json,
                    signature,
                    user_handle
                )
            }
        }
    }
}