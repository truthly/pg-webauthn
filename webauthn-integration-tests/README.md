# WebAuthn PostgreSQL Integration Tests

This directory contains a comprehensive Rust-based integration test suite for the pg-webauthn PostgreSQL extension.

## Overview

The test suite implements a software authenticator that generates real ECDSA P-256 key pairs and creates valid WebAuthn attestation objects and assertions. It tests both positive (successful) and negative (failure) scenarios to ensure the pg-webauthn extension correctly implements the WebAuthn protocol.

## Prerequisites

- PostgreSQL server running on localhost:5432
- User must have permission to create databases
- pg-webauthn extension must be installed on the system
- Rust toolchain installed

## Running the Tests

```bash
cd webauthn-integration-tests
cargo run
```

The test suite will:
1. Create a temporary test database
2. Install the webauthn extension with CASCADE
3. Run all positive and negative tests
4. Clean up the test database automatically

## Test Coverage

### Positive Tests
- **Basic registration and authentication flow**: Complete WebAuthn flow from credential creation to assertion verification
- **Multiple credentials per user**: Tests that users can register multiple authenticators
- **User verification levels**: Tests discouraged, preferred, and required user verification
- **Timeout validation**: Verifies timeout boundaries (30 seconds to 10 minutes)

### Negative Tests
- **Bit flip in credential_id**: Ensures corrupted credential IDs are rejected
- **Bit flip in signature**: Verifies invalid signatures fail verification
- **Bit flip in authenticator_data**: Tests data integrity validation
- **Bit flip in client_data_json**: Ensures client data corruption is detected
- **Challenge replay prevention**: Verifies challenges cannot be reused
- **Expired challenge rejection**: Tests that expired challenges are rejected

## Architecture

### Modules

- **`authenticator.rs`**: Software authenticator implementation
  - Generates ECDSA P-256 key pairs
  - Creates CBOR-encoded attestation objects
  - Signs assertions with proper WebAuthn format
  - Manages credential storage

- **`database.rs`**: PostgreSQL connection and test database management
  - Creates temporary test databases
  - Installs webauthn extension
  - Handles automatic cleanup

- **`utils.rs`**: Utility functions for testing
  - Bit flipping functions for negative tests
  - Random data generation
  - Test result formatting

- **`test_positive.rs`**: Positive test cases
- **`test_negative.rs`**: Negative test cases with bit flipping
- **`main.rs`**: Test runner and orchestration

## Implementation Details

The software authenticator implements:
- ECDSA P-256 key generation using the `p256` crate
- Proper CBOR encoding for attestation objects
- Authenticator data with correct flags (UP, UV, AT, ED)
- Client data JSON with proper WebAuthn types
- COSE key encoding for public keys
- DER-encoded signatures

## Environment Variables

- `USER`: PostgreSQL username (required)

## Exit Codes

- `0`: All tests passed
- `1`: One or more tests failed

## Debugging

If a test fails, the error message will indicate which test failed and why. The test database is automatically cleaned up even on failure, but you can modify `database.rs` to disable cleanup for debugging purposes by calling `db.disable_cleanup()`.

## Dependencies

Key Rust crates used:
- `postgres`: Synchronous PostgreSQL client
- `p256`: ECDSA P-256 cryptography
- `ciborium`: CBOR encoding/decoding
- `base64-url`: Base64URL encoding
- `sha2`: SHA-256 hashing
- `serde_json`: JSON handling