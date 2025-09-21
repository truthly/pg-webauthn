use crate::authenticator::SoftwareAuthenticator;
use crate::database::TestDatabase;
use crate::utils::{format_test_result, generate_challenge, generate_user_id};
use crate::verifier;
use anyhow::{Context, Result};
use serde_json::Value as JsonValue;

pub fn run_positive_tests(db: &mut TestDatabase, _debug: bool) -> Result<()> {
    println!("\n=== Running Positive Tests ===\n");

    let mut passed = 0;
    let mut failed = 0;

    // Test 1: Basic registration and authentication flow
    match test_basic_flow(db) {
        Ok(_) => {
            println!("{}", format_test_result("Basic registration and authentication flow", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("Basic registration and authentication flow", false));
            eprintln!("  Error: {:?}", e);
            failed += 1;
        }
    }

    // Test 2: Multiple credentials for same user
    match test_multiple_credentials(db) {
        Ok(_) => {
            println!("{}", format_test_result("Multiple credentials for same user", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("Multiple credentials for same user", false));
            eprintln!("  Error: {}", e);
            failed += 1;
        }
    }

    // Test 3: User verification levels
    match test_user_verification_levels(db) {
        Ok(_) => {
            println!("{}", format_test_result("User verification levels", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("User verification levels", false));
            eprintln!("  Error: {}", e);
            failed += 1;
        }
    }

    // Test 4: Timeout validation
    match test_timeout_validation(db) {
        Ok(_) => {
            println!("{}", format_test_result("Timeout validation", true));
            passed += 1;
        }
        Err(e) => {
            println!("{}", format_test_result("Timeout validation", false));
            eprintln!("  Error: {}", e);
            failed += 1;
        }
    }

    println!("\nPositive Tests: {} passed, {} failed", passed, failed);

    if failed > 0 {
        anyhow::bail!("Some positive tests failed");
    }

    Ok(())
}

fn test_basic_flow(db: &mut TestDatabase) -> Result<()> {
    let mut authenticator = SoftwareAuthenticator::new();

    // Generate test data
    let challenge = generate_challenge();
    let user_id = generate_user_id();
    let user_name = format!("test.user.{}@example.com", rand::random::<u32>());
    let user_display_name = "Test User";
    let rp_name = "Test Corp";
    let rp_id = "localhost";

    // Track all SQL statements for debugging
    let mut sql_history: Vec<String> = Vec::new();

    // Step 1: Initialize credential
    let init_sql = format!(
        "SELECT webauthn.init_credential(
            challenge => '\\x{}'::bytea,
            user_name => '{}',
            user_id => '\\x{}'::bytea,
            user_display_name => '{}',
            relying_party_name => '{}',
            relying_party_id => '{}',
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        hex::encode(&challenge),
        user_name,
        hex::encode(&user_id),
        user_display_name,
        rp_name,
        rp_id
    );
    sql_history.push(format!("-- Step 1: Initialize credential\n{}", init_sql));

    let row = db.debug_query_one(
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
        &[&challenge.as_slice(), &user_name.as_str(), &user_id.as_slice(), &user_display_name, &rp_name, &rp_id],
    ).map_err(|e| {
        anyhow::anyhow!("Failed to call init_credential: {}\n\n\
            SQL command that failed:\n{}\n\n\
            ========== COMPLETE SQL HISTORY FOR USER '{}' ==========\n\
            {}\n\
            ========================================================\n\n\
            You can copy and run these in psql to debug.",
            e,
            init_sql,
            user_name,
            sql_history.join("\n\n")
        )
    })?;

    let init_response: JsonValue = row.get(0);
    let public_key = &init_response["publicKey"];

    // Verify response structure
    assert!(public_key["challenge"].is_string(), "Challenge should be present");
    assert!(public_key["user"]["id"].is_string(), "User ID should be present");
    assert_eq!(public_key["user"]["name"], user_name);

    // Step 2: Create credential with authenticator
    let (credential_id, _credential_type, attestation_object, client_data_json) =
        authenticator.create_credential(&challenge, &user_id, rp_id, false)?;

    // Step 3: Store credential
    let store_sql = format!(
        "SELECT webauthn.store_credential(
            credential_id => '{}',
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => '{}',
            client_data_json => '{}'
        )",
        credential_id,
        attestation_object,
        client_data_json
    );
    sql_history.push(format!("-- Step 3: Store credential\n{}", store_sql));

    let row = db.debug_query_one(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&credential_id, &attestation_object, &client_data_json],
    ).map_err(|e| {
        anyhow::anyhow!("Failed to store credential: {}\n\n\
            SQL command that failed:\n{}\n\n\
            ========== COMPLETE SQL HISTORY FOR USER '{}' ==========\n\
            {}\n\
            ========================================================\n\n\
            You can copy and run these in psql to debug.",
            e,
            store_sql,
            user_name,
            sql_history.join("\n\n")
        )
    })?;

    let returned_user_id: Vec<u8> = row.get(0);
    assert_eq!(returned_user_id, user_id, "User ID should match");

    // Step 4: Get credentials for authentication
    let auth_challenge = generate_challenge();
    let get_creds_sql = format!(
        "SELECT webauthn.get_credentials(
            challenge => '\\x{}'::bytea,
            user_name => '{}',
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => '{}'
        )",
        hex::encode(&auth_challenge),
        user_name,
        rp_id
    );
    sql_history.push(format!("-- Step 4: Get credentials for authentication\n{}", get_creds_sql));

    let row = db.client().query_one(
        "SELECT webauthn.get_credentials(
            challenge => $1,
            user_name => $2,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => $3
        )",
        &[&auth_challenge.as_slice(), &user_name.as_str(), &rp_id],
    ).map_err(|e| {
        anyhow::anyhow!("Failed to call get_credentials: {}\n\n\
            SQL command that failed:\n{}\n\n\
            ========== COMPLETE SQL HISTORY FOR USER '{}' ==========\n\
            {}\n\
            ========================================================\n\n\
            You can copy and run these in psql to debug.",
            e,
            get_creds_sql,
            user_name,
            sql_history.join("\n\n")
        )
    })?;

    let get_response: JsonValue = row.get(0);
    let public_key = &get_response["publicKey"];

    // Verify credentials are returned
    let allow_credentials = &public_key["allowCredentials"];
    assert!(allow_credentials.is_array(), "allowCredentials should be an array");
    assert_eq!(allow_credentials.as_array().unwrap().len(), 1, "Should have one credential");
    assert_eq!(allow_credentials[0]["id"], credential_id);

    // Step 5: Create assertion with authenticator
    let (cred_id, _cred_type, auth_data, client_json, signature, user_handle) =
        authenticator.create_assertion(&credential_id, &auth_challenge, rp_id, false)?;

    // Step 6: Verify assertion - First with Rust, then with PostgreSQL

    // Get the verifying key from the authenticator
    let verifying_key = authenticator.verifying_keys.get(&credential_id)
        .context("Verifying key not found for credential")?;

    // First verify with Rust crypto
    let rust_verified = verifier::verify_assertion_signature(
        verifying_key,
        &auth_data,
        &client_json,
        &signature,
    )?;

    println!("  Rust signature verification: {}",
             if rust_verified { "PASS ✓" } else { "FAIL ✗" });
    sql_history.push(format!("-- Rust signature verification: {}",
                            if rust_verified { "PASS" } else { "FAIL" }));

    // Now verify with PostgreSQL
    let sql_command = format!(
        "SELECT webauthn.verify_assertion(
            credential_id => '{}',
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => '{}',
            client_data_json => '{}',
            signature => '{}',
            user_handle => {}
        )",
        cred_id,
        auth_data,
        client_json,
        signature,
        user_handle.as_ref().map_or("NULL".to_string(), |h| format!("'{}'", h))
    );
    sql_history.push(format!("-- Step 6: PostgreSQL verify assertion\n{}", sql_command.clone()));

    let pg_result = db.debug_query_one(
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

    match pg_result {
        Ok(row) => {
            let verified_user_id: Vec<u8> = row.get(0);
            println!("  PostgreSQL verification: PASS ✓");
            assert_eq!(verified_user_id, user_id, "Verified user ID should match");
        }
        Err(e) => {
            println!("  PostgreSQL verification: FAIL ✗");

            // Check if Rust and PostgreSQL disagree
            if rust_verified {
                println!("  ⚠️ MISMATCH: Rust passed but PostgreSQL failed!");
            }

            anyhow::bail!("Failed to verify assertion: PostgreSQL verification failed\n\n\
                Rust verification: {}\n\
                PostgreSQL error: {:#}\n\n\
                SQL command that failed:\n{}\n\n\
                ========== COMPLETE SQL HISTORY FOR USER '{}' ==========\n\
                {}\n\
                ========================================================\n\n\
                You can copy and run these in psql to debug.",
                if rust_verified { "PASS" } else { "FAIL" },
                e,
                sql_command,
                user_name,
                sql_history.join("\n\n")
            );
        }
    }

    Ok(())
}

fn test_multiple_credentials(db: &mut TestDatabase) -> Result<()> {
    let mut authenticator1 = SoftwareAuthenticator::new();
    let mut authenticator2 = SoftwareAuthenticator::new();

    let user_id = generate_user_id();
    let user_name = format!("multi.cred.{}@example.com", rand::random::<u32>());
    let user_display_name = "Multi Cred User";
    let rp_name = "Test Corp";
    let rp_id = "localhost";

    // Track all SQL statements for debugging
    let mut sql_history: Vec<String> = Vec::new();

    // Create first credential
    let challenge1 = generate_challenge();
    let sql1 = format!(
        "SELECT webauthn.init_credential(
            challenge => '\\x{}'::bytea,
            user_name => '{}',
            user_id => '\\x{}'::bytea,
            user_display_name => '{}',
            relying_party_name => '{}',
            relying_party_id => '{}',
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        hex::encode(&challenge1),
        user_name,
        hex::encode(&user_id),
        user_display_name,
        rp_name,
        rp_id
    );
    sql_history.push(format!("-- First credential init\n{}", sql1));

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
        &[&challenge1.as_slice(), &user_name.as_str(), &user_id.as_slice(), &user_display_name, &rp_name, &rp_id],
    )?;

    let (cred_id1, _cred_type1, attest_obj1, client_json1) =
        authenticator1.create_credential(&challenge1, &user_id, rp_id, false)?;

    let sql2 = format!(
        "SELECT webauthn.store_credential(
            credential_id => '{}',
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => '{}',
            client_data_json => '{}'
        )",
        cred_id1,
        attest_obj1,
        client_json1
    );
    sql_history.push(format!("-- Store first credential\n{}", sql2));

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&cred_id1, &attest_obj1, &client_json1],
    )?;

    // Create second credential
    let challenge2 = generate_challenge();
    let sql3 = format!(
        "SELECT webauthn.init_credential(
            challenge => '\\x{}'::bytea,
            user_name => '{}',
            user_id => '\\x{}'::bytea,
            user_display_name => '{}',
            relying_party_name => '{}',
            relying_party_id => '{}',
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        hex::encode(&challenge2),
        user_name,
        hex::encode(&user_id),
        user_display_name,
        rp_name,
        rp_id
    );
    sql_history.push(format!("-- Second credential init\n{}", sql3));

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
        &[&challenge2.as_slice(), &user_name.as_str(), &user_id.as_slice(), &user_display_name, &rp_name, &rp_id],
    )?;

    let (cred_id2, _cred_type2, attest_obj2, client_json2) =
        authenticator2.create_credential(&challenge2, &user_id, rp_id, false)?;

    let sql4 = format!(
        "SELECT webauthn.store_credential(
            credential_id => '{}',
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => '{}',
            client_data_json => '{}'
        )",
        cred_id2,
        attest_obj2,
        client_json2
    );
    sql_history.push(format!("-- Store second credential\n{}", sql4));

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&cred_id2, &attest_obj2, &client_json2],
    )?;

    // Get credentials - should return both
    let auth_challenge = generate_challenge();

    let get_creds_sql = format!(
        "SELECT webauthn.get_credentials(
            challenge => '\\x{}'::bytea,
            user_name => '{}',
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => '{}'
        )",
        hex::encode(&auth_challenge),
        user_name,
        rp_id
    );
    sql_history.push(format!("-- Get credentials for authentication\n{}", get_creds_sql));

    let row = db.client().query_one(
        "SELECT webauthn.get_credentials(
            challenge => $1,
            user_name => $2,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => $3
        )",
        &[&auth_challenge.as_slice(), &user_name.as_str(), &rp_id],
    )?;

    let response: JsonValue = row.get(0);
    let allow_credentials = &response["publicKey"]["allowCredentials"];

    assert!(allow_credentials.is_array());
    assert_eq!(allow_credentials.as_array().unwrap().len(), 2, "Should have two credentials");

    // Test authentication with first credential
    let (cred_id, _cred_type, auth_data, client_json, signature, user_handle) =
        authenticator1.create_assertion(&cred_id1, &auth_challenge, rp_id, false)?;

    // Get the verifying key from the first authenticator
    let verifying_key1 = authenticator1.verifying_keys.get(&cred_id1)
        .context("Verifying key not found for first credential")?;

    // First verify with Rust crypto
    let rust_verified = verifier::verify_assertion_signature(
        verifying_key1,
        &auth_data,
        &client_json,
        &signature,
    )?;

    println!("  First credential - Rust verification: {}",
             if rust_verified { "PASS ✓" } else { "FAIL ✗" });
    sql_history.push(format!("-- First credential - Rust verification: {}",
                            if rust_verified { "PASS" } else { "FAIL" }));

    // Debug: Decode signature to check format
    let sig_debug_sql = format!(
        "SELECT webauthn.decode_asn1_der_signature(webauthn.base64url_decode('{}'))",
        signature
    );
    sql_history.push(format!("-- Debug: Decode signature\n{}", sig_debug_sql));

    let sig_decoded = db.client().query_one(
        "SELECT webauthn.decode_asn1_der_signature(webauthn.base64url_decode($1))",
        &[&signature],
    ).map_err(|e| {
        anyhow::anyhow!("Failed to decode signature: {}", e)
    })?;

    let decoded_rs: Option<Vec<u8>> = sig_decoded.get(0);
    if let Some(rs) = decoded_rs {
        sql_history.push(format!("-- Signature decoded: (r,s) = \\x{}", hex::encode(&rs)));
    }

    // Now verify with PostgreSQL
    let sql_command = format!(
        "SELECT webauthn.verify_assertion(
            credential_id => '{}',
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => '{}',
            client_data_json => '{}',
            signature => '{}',
            user_handle => {}
        )",
        cred_id,
        auth_data,
        client_json,
        signature,
        user_handle.as_ref().map_or("NULL".to_string(), |h| format!("'{}'", h))
    );
    sql_history.push(format!("-- Verify first credential with PostgreSQL\n{}", sql_command.clone()));

    let pg_result = db.debug_query_one(
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

    match pg_result {
        Ok(row) => {
            let verified_user_id: Vec<u8> = row.get(0);
            println!("  First credential - PostgreSQL verification: PASS ✓");
            assert_eq!(verified_user_id, user_id, "Should authenticate with first credential");
        }
        Err(e) => {
            println!("  First credential - PostgreSQL verification: FAIL ✗");

            if rust_verified {
                println!("  ⚠️ MISMATCH: Rust passed but PostgreSQL failed!");
            }

            anyhow::bail!("Failed to verify first credential with PostgreSQL\n\n\
                Rust verification: {}\n\
                PostgreSQL error: {:#}\n\n\
                SQL command that failed:\n{}\n\n\
                ========== COMPLETE SQL HISTORY FOR USER '{}' ==========\n\
                {}\n\
                ========================================================\n\n\
                You can copy and run these in psql to debug.",
                if rust_verified { "PASS" } else { "FAIL" },
                e,
                sql_command,
                user_name,
                sql_history.join("\n\n")
            );
        }
    }

    // Test authentication with second credential - need new challenge
    let auth_challenge2 = generate_challenge();

    let get_creds_sql2 = format!(
        "SELECT webauthn.get_credentials(
            challenge => '\\x{}'::bytea,
            user_name => '{}',
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => '{}'
        )",
        hex::encode(&auth_challenge2),
        user_name,
        rp_id
    );
    sql_history.push(format!("-- Get credentials for second authentication\n{}", get_creds_sql2));

    db.client().execute(
        "SELECT webauthn.get_credentials(
            challenge => $1,
            user_name => $2,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            timeout => '5 minutes'::interval,
            relying_party_id => $3
        )",
        &[&auth_challenge2.as_slice(), &user_name.as_str(), &rp_id],
    )?;

    let (cred_id, _cred_type, auth_data, client_json, signature, user_handle) =
        authenticator2.create_assertion(&cred_id2, &auth_challenge2, rp_id, false)?;

    // Get the verifying key from the second authenticator
    let verifying_key2 = authenticator2.verifying_keys.get(&cred_id2)
        .context("Verifying key not found for second credential")?;

    // First verify with Rust crypto
    let rust_verified2 = verifier::verify_assertion_signature(
        verifying_key2,
        &auth_data,
        &client_json,
        &signature,
    )?;

    println!("  Second credential - Rust verification: {}",
             if rust_verified2 { "PASS ✓" } else { "FAIL ✗" });
    sql_history.push(format!("-- Second credential - Rust verification: {}",
                            if rust_verified2 { "PASS" } else { "FAIL" }));

    // Now verify with PostgreSQL
    let sql_command = format!(
        "SELECT webauthn.verify_assertion(
            credential_id => '{}',
            credential_type => 'public-key'::webauthn.credential_type,
            authenticator_data => '{}',
            client_data_json => '{}',
            signature => '{}',
            user_handle => {}
        )",
        cred_id,
        auth_data,
        client_json,
        signature,
        user_handle.as_ref().map_or("NULL".to_string(), |h| format!("'{}'", h))
    );
    sql_history.push(format!("-- Verify second credential with PostgreSQL\n{}", sql_command.clone()));

    let pg_result2 = db.debug_query_one(
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

    match pg_result2 {
        Ok(row) => {
            let verified_user_id: Vec<u8> = row.get(0);
            println!("  Second credential - PostgreSQL verification: PASS ✓");
            assert_eq!(verified_user_id, user_id, "Should authenticate with second credential");
        }
        Err(e) => {
            println!("  Second credential - PostgreSQL verification: FAIL ✗");

            if rust_verified2 {
                println!("  ⚠️ MISMATCH: Rust passed but PostgreSQL failed!");
            }

            anyhow::bail!("Failed to verify second credential with PostgreSQL\n\n\
                Rust verification: {}\n\
                PostgreSQL error: {:#}\n\n\
                SQL command that failed:\n{}\n\n\
                ========== COMPLETE SQL HISTORY FOR USER '{}' ==========\n\
                {}\n\
                ========================================================\n\n\
                You can copy and run these in psql to debug.",
                if rust_verified2 { "PASS" } else { "FAIL" },
                e,
                sql_command,
                user_name,
                sql_history.join("\n\n")
            );
        }
    }

    Ok(())
}

fn test_user_verification_levels(db: &mut TestDatabase) -> Result<()> {
    let mut authenticator = SoftwareAuthenticator::new();

    // Test with UV = discouraged
    let user_id1 = generate_user_id();
    let challenge1 = generate_challenge();
    db.client().execute(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => NULL,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        &[&challenge1.as_slice(), &"user.discouraged@example.com", &user_id1.as_slice(),
          &"UV Discouraged", &"Test Corp"],
    )?;

    let (cred_id1, _cred_type1, attest1, client1) =
        authenticator.create_credential(&challenge1, &user_id1, "localhost", false)?;

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&cred_id1, &attest1, &client1],
    )?;

    // Test with UV = preferred
    let user_id2 = generate_user_id();
    let challenge2 = generate_challenge();
    db.client().execute(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => NULL,
            require_resident_key => false,
            user_verification => 'preferred'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        &[&challenge2.as_slice(), &"user.preferred@example.com", &user_id2.as_slice(),
          &"UV Preferred", &"Test Corp"],
    )?;

    let (cred_id2, _cred_type2, attest2, client2) =
        authenticator.create_credential(&challenge2, &user_id2, "localhost", true)?;

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&cred_id2, &attest2, &client2],
    )?;

    // Test with UV = required
    let user_id3 = generate_user_id();
    let challenge3 = generate_challenge();
    db.client().execute(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => NULL,
            require_resident_key => false,
            user_verification => 'required'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '5 minutes'::interval
        )",
        &[&challenge3.as_slice(), &"user.required@example.com", &user_id3.as_slice(),
          &"UV Required", &"Test Corp"],
    )?;

    let (cred_id3, _cred_type3, attest3, client3) =
        authenticator.create_credential(&challenge3, &user_id3, "localhost", true)?;

    db.client().execute(
        "SELECT webauthn.store_credential(
            credential_id => $1,
            credential_type => 'public-key'::webauthn.credential_type,
            attestation_object => $2,
            client_data_json => $3
        )",
        &[&cred_id3, &attest3, &client3],
    )?;

    Ok(())
}

fn test_timeout_validation(db: &mut TestDatabase) -> Result<()> {
    let user_id = generate_user_id();
    let challenge = generate_challenge();

    // Test minimum timeout (30 seconds)
    let result = db.client().query_one(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => NULL,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '30 seconds'::interval
        )",
        &[&challenge.as_slice(), &"timeout.min@example.com", &user_id.as_slice(),
          &"Timeout Min", &"Test Corp"],
    );
    assert!(result.is_ok(), "30 second timeout should be valid");

    // Test maximum timeout (10 minutes)
    let challenge2 = generate_challenge();
    let result = db.client().query_one(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => NULL,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '10 minutes'::interval
        )",
        &[&challenge2.as_slice(), &"timeout.max@example.com", &user_id.as_slice(),
          &"Timeout Max", &"Test Corp"],
    );
    assert!(result.is_ok(), "10 minute timeout should be valid");

    // Test too short timeout (should fail)
    let challenge3 = generate_challenge();
    let result = db.client().query_one(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => NULL,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '29 seconds'::interval
        )",
        &[&challenge3.as_slice(), &"timeout.short@example.com", &user_id.as_slice(),
          &"Timeout Short", &"Test Corp"],
    );
    assert!(result.is_err(), "29 second timeout should fail");

    // Test too long timeout (should fail)
    let challenge4 = generate_challenge();
    let result = db.client().query_one(
        "SELECT webauthn.init_credential(
            challenge => $1,
            user_name => $2,
            user_id => $3,
            user_display_name => $4,
            relying_party_name => $5,
            relying_party_id => NULL,
            require_resident_key => false,
            user_verification => 'discouraged'::webauthn.user_verification_requirement,
            attestation => 'none'::webauthn.attestation_conveyance_preference,
            timeout => '11 minutes'::interval
        )",
        &[&challenge4.as_slice(), &"timeout.long@example.com", &user_id.as_slice(),
          &"Timeout Long", &"Test Corp"],
    );
    assert!(result.is_err(), "11 minute timeout should fail");

    Ok(())
}