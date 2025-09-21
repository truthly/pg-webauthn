use anyhow::{Context, Result};
use base64_url as base64url;
use rand::Rng;

/// Flip a single bit in the given base64url-encoded string
pub fn flip_bit_in_base64(input: &str) -> Result<String> {
    let bytes = base64url::decode(input)
        .context("Failed to decode base64url")?;

    if bytes.is_empty() {
        return Ok(input.to_string());
    }

    let mut modified = bytes.clone();

    // Pick a random byte and bit to flip
    let byte_index = rand::thread_rng().gen_range(0..bytes.len());
    let bit_index = rand::thread_rng().gen_range(0..8);

    // Flip the bit
    modified[byte_index] ^= 1 << bit_index;

    Ok(base64url::encode(&modified))
}

/// Flip a specific bit at a given position
#[allow(dead_code)]
pub fn flip_bit_at_position(input: &str, byte_pos: usize, bit_pos: usize) -> Result<String> {
    let bytes = base64url::decode(input)
        .context("Failed to decode base64url")?;

    if byte_pos >= bytes.len() {
        anyhow::bail!("Byte position {} out of range (len: {})", byte_pos, bytes.len());
    }

    if bit_pos >= 8 {
        anyhow::bail!("Bit position {} out of range (must be 0-7)", bit_pos);
    }

    let mut modified = bytes.clone();
    modified[byte_pos] ^= 1 << bit_pos;

    Ok(base64url::encode(&modified))
}

/// Generate random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::random::<u8>()).collect()
}

/// Generate a random challenge
pub fn generate_challenge() -> Vec<u8> {
    generate_random_bytes(32)
}

/// Generate a random user ID
pub fn generate_user_id() -> Vec<u8> {
    generate_random_bytes(64)
}

/// Format test result for display
pub fn format_test_result(test_name: &str, passed: bool) -> String {
    let status = if passed { "✓ PASS" } else { "✗ FAIL" };
    let color = if passed { "\x1b[32m" } else { "\x1b[31m" };
    let reset = "\x1b[0m";
    format!("{}{}{}: {}", color, status, reset, test_name)
}

/// Assert that a database operation fails
#[allow(dead_code)]
pub fn assert_db_error(result: std::result::Result<postgres::Row, postgres::Error>, test_description: &str) -> Result<()> {
    match result {
        Ok(_) => anyhow::bail!("{} should have failed but succeeded", test_description),
        Err(_) => Ok(()),
    }
}

/// Assert that a database operation returns None/NULL
#[allow(dead_code)]
pub fn assert_returns_null(result: std::result::Result<postgres::Row, postgres::Error>, test_description: &str) -> Result<()> {
    match result {
        Ok(row) => {
            let user_id: Option<Vec<u8>> = row.try_get(0)?;
            if user_id.is_some() {
                anyhow::bail!("{} should have returned NULL but returned a value", test_description);
            }
            Ok(())
        }
        Err(e) => anyhow::bail!("{} failed with error: {}", test_description, e),
    }
}

/// Convert hex string to bytes for debugging
#[allow(dead_code)]
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).context("Failed to decode hex string")
}

/// Convert bytes to hex string for debugging
#[allow(dead_code)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Format a visual diff between two strings
pub fn format_string_diff(label: &str, original: &str, modified: &str) -> String {
    let max_len = original.len().max(modified.len());

    // Build diff line showing where characters differ
    let mut diff_line = String::new();
    let orig_chars: Vec<char> = original.chars().collect();
    let mod_chars: Vec<char> = modified.chars().collect();

    for i in 0..max_len {
        let orig_char = orig_chars.get(i);
        let mod_char = mod_chars.get(i);

        match (orig_char, mod_char) {
            (Some(o), Some(m)) if o == m => diff_line.push('.'),
            _ => diff_line.push('^'),
        }
    }

    format!(
        "Comparing {}:\n    Original:  {}\n    Corrupted: {}\n    Diff:      {}",
        label,
        original,
        modified,
        diff_line
    )
}