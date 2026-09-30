use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

const TEST_KEY: &str = "00112233445566778899aabbccddeeff";
const TEST_IV: &str = "aabbccddeeff00112233445566778899";

#[test]
fn test_cbc_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = "Test message for CBC mode round-trip verification";
    let test_id = "cbc_round_trip";
    fs::write(&format!("{}_plain.txt", test_id), plaintext)?;

    // Encrypt - Updated to use encrypt subcommand
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "encrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cbc", 
        "--key", TEST_KEY,
        "--input", &format!("{}_plain.txt", test_id),
        "--output", &format!("{}_encrypted.bin", test_id)
    ])
    .assert()
    .success();

    // Decrypt - Updated to use decrypt subcommand
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "decrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cbc",
        "--key", TEST_KEY,
        "--input", &format!("{}_encrypted.bin", test_id),
        "--output", &format!("{}_decrypted.txt", test_id)
    ])
    .assert()
    .success();

    // Verify
    let decrypted = fs::read_to_string(&format!("{}_decrypted.txt", test_id))?;
    assert_eq!(plaintext, decrypted);

    // Cleanup
    cleanup_files(&[
        &format!("{}_plain.txt", test_id),
        &format!("{}_encrypted.bin", test_id), 
        &format!("{}_decrypted.txt", test_id)
    ])?;
    Ok(())
}

#[test]
fn test_cfb_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = "Test message for CFB mode";
    let test_id = "cfb_round_trip";
    fs::write(&format!("{}_plain.txt", test_id), plaintext)?;

    // Encrypt
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "encrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cfb", 
        "--key", TEST_KEY,
        "--input", &format!("{}_plain.txt", test_id),
        "--output", &format!("{}_encrypted.bin", test_id)
    ])
    .assert()
    .success();

    // Decrypt  
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "decrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cfb",
        "--key", TEST_KEY,
        "--input", &format!("{}_encrypted.bin", test_id),
        "--output", &format!("{}_decrypted.txt", test_id)
    ])
    .assert()
    .success();

    // Verify
    let decrypted = fs::read_to_string(&format!("{}_decrypted.txt", test_id))?;
    assert_eq!(plaintext, decrypted);

    cleanup_files(&[
        &format!("{}_plain.txt", test_id),
        &format!("{}_encrypted.bin", test_id),
        &format!("{}_decrypted.txt", test_id)
    ])?;
    Ok(())
}

#[test]
fn test_ofb_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = "Test message for OFB mode";
    let test_id = "ofb_round_trip";
    fs::write(&format!("{}_plain.txt", test_id), plaintext)?;

    // Encrypt
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "encrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "ofb", 
        "--key", TEST_KEY,
        "--input", &format!("{}_plain.txt", test_id),
        "--output", &format!("{}_encrypted.bin", test_id)
    ])
    .assert()
    .success();

    // Decrypt  
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "decrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "ofb",
        "--key", TEST_KEY,
        "--input", &format!("{}_encrypted.bin", test_id),
        "--output", &format!("{}_decrypted.txt", test_id)
    ])
    .assert()
    .success();

    // Verify
    let decrypted = fs::read_to_string(&format!("{}_decrypted.txt", test_id))?;
    assert_eq!(plaintext, decrypted);

    cleanup_files(&[
        &format!("{}_plain.txt", test_id),
        &format!("{}_encrypted.bin", test_id),
        &format!("{}_decrypted.txt", test_id)
    ])?;
    Ok(())
}

#[test]
fn test_ctr_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = "Test message for CTR mode";
    let test_id = "ctr_round_trip";
    fs::write(&format!("{}_plain.txt", test_id), plaintext)?;

    // Encrypt
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "encrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "ctr", 
        "--key", TEST_KEY,
        "--input", &format!("{}_plain.txt", test_id),
        "--output", &format!("{}_encrypted.bin", test_id)
    ])
    .assert()
    .success();

    // Decrypt  
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "decrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "ctr",
        "--key", TEST_KEY,
        "--input", &format!("{}_encrypted.bin", test_id),
        "--output", &format!("{}_decrypted.txt", test_id)
    ])
    .assert()
    .success();

    // Verify
    let decrypted = fs::read_to_string(&format!("{}_decrypted.txt", test_id))?;
    assert_eq!(plaintext, decrypted);

    cleanup_files(&[
        &format!("{}_plain.txt", test_id),
        &format!("{}_encrypted.bin", test_id),
        &format!("{}_decrypted.txt", test_id)
    ])?;
    Ok(())
}

#[test]
fn test_iv_handling_decryption_with_explicit_iv() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = "Test IV handling with explicit IV";
    let test_id = "iv_explicit";
    fs::write(&format!("{}_plain.txt", test_id), plaintext)?;

    // Encrypt
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "encrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cbc", 
        "--key", TEST_KEY,
        "--input", &format!("{}_plain.txt", test_id),
        "--output", &format!("{}_encrypted.bin", test_id)
    ])
    .assert()
    .success();

    // Extract IV from encrypted file
    let encrypted_data = fs::read(&format!("{}_encrypted.bin", test_id))?;
    let file_iv = hex::encode(&encrypted_data[..16]);
    
    // Create a new file with just the ciphertext (no IV)
    let ciphertext_only = &encrypted_data[16..];
    fs::write(&format!("{}_ciphertext_only.bin", test_id), ciphertext_only)?;
    
    // Decrypt with explicit IV (using ciphertext-only file)
    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "decrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cbc",
        "--key", TEST_KEY,
        "--iv", &file_iv,
        "--input", &format!("{}_ciphertext_only.bin", test_id),
        "--output", &format!("{}_decrypted.txt", test_id)
    ])
    .assert()
    .success();

    // Verify
    let decrypted = fs::read_to_string(&format!("{}_decrypted.txt", test_id))?;
    assert_eq!(plaintext, decrypted);

    cleanup_files(&[
        &format!("{}_plain.txt", test_id),
        &format!("{}_encrypted.bin", test_id),
        &format!("{}_ciphertext_only.bin", test_id),
        &format!("{}_decrypted.txt", test_id)
    ])?;
    Ok(())
}

#[test]
fn test_short_file_error() -> Result<(), Box<dyn std::error::Error>> {
    let test_id = "short_file";
    // Create a file that's too short to contain IV
    fs::write(&format!("{}.bin", test_id), "short")?;

    let mut cmd = Command::cargo_bin("cryptocore")?;
    cmd.args(&[
        "decrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cbc",
        "--key", TEST_KEY,
        "--input", &format!("{}.bin", test_id)
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("too short").or(predicate::str::contains("IV")));

    fs::remove_file(&format!("{}.bin", test_id))?;
    Ok(())
}

#[test]
fn test_iv_ignored_during_encryption() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = "Test that IV is ignored during encryption";
    let test_id = "iv_ignored";
    fs::write(&format!("{}_plain.txt", test_id), plaintext)?;

    let mut cmd = Command::cargo_bin("cryptocore")?;
    let assert = cmd.args(&[
        "encrypt",  // Changed
        "--algorithm", "aes",
        "--mode", "cbc", 
        "--key", TEST_KEY,
        "--iv", TEST_IV,  // This should be ignored with a warning
        "--input", &format!("{}_plain.txt", test_id),
        "--output", &format!("{}_encrypted.bin", test_id)
    ])
    .assert();
    
    // Check that it succeeds but may print a warning
    assert.success();

    cleanup_files(&[
        &format!("{}_plain.txt", test_id), 
        &format!("{}_encrypted.bin", test_id)
    ])?;
    Ok(())
}

fn cleanup_files(files: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    for file in files {
        if fs::metadata(file).is_ok() {
            fs::remove_file(file)?;
        }
    }
    Ok(())
}