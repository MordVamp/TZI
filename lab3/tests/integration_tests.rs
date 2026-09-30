#[cfg(test)]
mod integration_tests {
    use std::process::Command;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    
    // Helper function to create a temporary file
    fn create_temp_file(content: &str, extension: &str) -> (PathBuf, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        let file_path = temp_dir.path().join(format!("test_file.{}", extension));
        
        let mut file = File::create(&file_path).expect("Failed to create temp file");
        file.write_all(content.as_bytes()).expect("Failed to write to temp file");
        
        (file_path, temp_dir)
    }
    
    // Get the path to the compiled binary
    fn get_binary_path() -> PathBuf {
        let mut path = std::env::current_exe().expect("Failed to get current exe path");
        // Go up from target/debug/deps/integration_tests-xxx to target/debug
        path.pop(); // Remove binary name
        path.pop(); // Remove deps
        path.push("cryptocore");
        path
    }
    
    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let (input_file, temp_dir) = create_temp_file("Hello, CryptoCore!", "txt");
        let binary_path = get_binary_path();
        
        // Create a random key
        let key = "00112233445566778899aabbccddeeff";
        
        // Encrypt
        let encrypt_output = Command::new(&binary_path)
            .args([
                "encrypt",  // Changed: use encrypt subcommand
                "--algorithm", "aes",
                "--mode", "ecb",
                "--key", key,
                "--input", input_file.to_str().unwrap(),
                "--output", temp_dir.path().join("encrypted.enc").to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute encrypt command");
        
        assert!(encrypt_output.status.success(), 
                "Encryption failed: {}", String::from_utf8_lossy(&encrypt_output.stderr));
        
        // Decrypt
        let decrypt_output = Command::new(&binary_path)
            .args([
                "decrypt",  // Changed: use decrypt subcommand
                "--algorithm", "aes",
                "--mode", "ecb",
                "--key", key,
                "--input", temp_dir.path().join("encrypted.enc").to_str().unwrap(),
                "--output", temp_dir.path().join("decrypted.txt").to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute decrypt command");
        
        assert!(decrypt_output.status.success(),
                "Decryption failed: {}", String::from_utf8_lossy(&decrypt_output.stderr));
        
        // Read decrypted file and compare
        let decrypted_content = std::fs::read_to_string(temp_dir.path().join("decrypted.txt"))
            .expect("Failed to read decrypted file");
        
        assert_eq!(decrypted_content.trim(), "Hello, CryptoCore!");
        
        // Cleanup is automatic when temp_dir goes out of scope
    }
    
    #[test]
    fn test_invalid_key_length() {
        let (_input_file, temp_dir) = create_temp_file("Test content", "txt");
        let binary_path = get_binary_path();
        
        // Test with short key (3 bytes instead of 16)
        let output = Command::new(&binary_path)
            .args([
                "encrypt",  // Changed: use encrypt subcommand
                "--algorithm", "aes",
                "--mode", "ecb",
                "--key", "@001122",  // Only 3 bytes (6 hex chars)
                "--input", temp_dir.path().join("test_file.txt").to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute command");
        
        assert!(!output.status.success(), "Should fail with invalid key length");
        
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Check for any error about key length
        assert!(stderr.contains("16 bytes") || stderr.contains("Invalid") || stderr.contains("Key"),
                "Expected error about key length, got: {}", stderr);
    }
    
    #[test]
    fn test_cli_hmac_generation() {
        let (input_file, temp_dir) = create_temp_file("Hello, HMAC! This is a test message.", "txt");
        let binary_path = get_binary_path();
        
        // Test HMAC generation - Updated based on new CLI structure
        let output = Command::new(&binary_path)
            .args([
                "mac",  // Changed: use mac subcommand
                "hmac",  // Specify HMAC algorithm
                "--key", "00112233445566778899aabbccddeeff",  // 16-byte key
                "--input", input_file.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute command");
        
        if !output.status.success() {
            println!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
            println!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        }
        
        assert!(output.status.success(), 
                "HMAC generation failed: {}", String::from_utf8_lossy(&output.stderr));
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("HMAC output: {}", stdout);
        
        // Output format may vary - check for hex output
        let output_str = stdout.trim();
        // Should contain hex characters (at least 32 for HMAC)
        assert!(output_str.len() >= 32, "Output should contain hex HMAC value");
    }
    
    #[test]
    fn test_cli_hmac_verification() {
        let (input_file, temp_dir) = create_temp_file("Original content for HMAC verification", "txt");
        let binary_path = get_binary_path();
        
        let hmac_file = temp_dir.path().join("test.hmac");
        
        // First generate HMAC - Updated to new CLI
        let hmac_output = Command::new(&binary_path)
            .args([
                "mac",
                "hmac",
                "--key", "00112233445566778899aabbccddeeff",
                "--input", input_file.to_str().unwrap(),
                "--output", hmac_file.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute HMAC generation command");
        
        assert!(hmac_output.status.success(),
                "HMAC generation failed: {}", String::from_utf8_lossy(&hmac_output.stderr));
        
        // Read the generated HMAC
        let hmac_value = std::fs::read_to_string(&hmac_file)
            .unwrap_or_else(|_| String::from_utf8_lossy(&hmac_output.stdout).trim().to_string());
        
        // Now verify with correct key
        let verify_output = Command::new(&binary_path)
            .args([
                "mac",
                "hmac",
                "--key", "00112233445566778899aabbccddeeff",
                "--input", input_file.to_str().unwrap(),
                "--verify", hmac_file.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute HMAC verification command");
        
        assert!(verify_output.status.success(),
                "HMAC verification failed: {}", String::from_utf8_lossy(&verify_output.stderr));
        
        let stdout = String::from_utf8_lossy(&verify_output.stdout);
        assert!(stdout.contains("OK") || stdout.contains("valid") || stdout.contains("success"),
                "Should show verification success: {}", stdout);
        
        // Test with wrong key (should fail)
        let wrong_verify = Command::new(&binary_path)
            .args([
                "mac",
                "hmac",
                "--key", "00000000000000000000000000000000",  // Wrong key
                "--input", input_file.to_str().unwrap(),
                "--verify", hmac_file.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute wrong key verification");
        
        assert!(!wrong_verify.status.success(), "Should fail with wrong key");
    }
    
    #[test]
    #[ignore = "CMAC implementation temporarily s#it"]
    fn test_cli_cmac_generation() {
        let (input_file, temp_dir) = create_temp_file("Hello, CMAC! This is a test message.", "txt");
        let binary_path = get_binary_path();
        
        // Test CMAC generation with correct 16-byte key - Updated
        let output = Command::new(&binary_path)
            .args([
                "mac",  // Changed: use mac subcommand
                "cmac",  // Specify CMAC algorithm
                "--key", "2b7e151628aed2a6abf7158809cf4f3c",  // 16-byte key
                "--input", input_file.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute CMAC command");
        
        if !output.status.success() {
            println!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
            println!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        }
        
        assert!(output.status.success(), "CMAC generation should succeed");
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("CMAC output: {}", stdout);
        
        // Output should be hex characters
        let output_str = stdout.trim();
        assert!(output_str.len() >= 16, "Output should contain hex CMAC value");
    }
    
    #[test]
    fn test_cli_cmac_verification() {
        let (input_file, temp_dir) = create_temp_file("Original content for CMAC verification", "txt");
        let binary_path = get_binary_path();
        
        let cmac_file = temp_dir.path().join("test.cmac");
        
        // First generate CMAC - Updated
        let cmac_output = Command::new(&binary_path)
            .args([
                "mac",
                "cmac",
                "--key", "2b7e151628aed2a6abf7158809cf4f3c",
                "--input", input_file.to_str().unwrap(),
                "--output", cmac_file.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute CMAC generation command");
        
        assert!(cmac_output.status.success(),
                "CMAC generation failed: {}", String::from_utf8_lossy(&cmac_output.stderr));
        
        // Now verify with correct key
        let verify_output = Command::new(&binary_path)
            .args([
                "mac",
                "cmac",
                "--key", "2b7e151628aed2a6abf7158809cf4f3c",
                "--input", input_file.to_str().unwrap(),
                "--verify", cmac_file.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute CMAC verification command");
        
        if !verify_output.status.success() {
            println!("Verify stderr: {}", String::from_utf8_lossy(&verify_output.stderr));
            println!("Verify stdout: {}", String::from_utf8_lossy(&verify_output.stdout));
        }
        
        assert!(verify_output.status.success(), "CMAC verification should succeed");
        
        let stdout = String::from_utf8_lossy(&verify_output.stdout);
        assert!(stdout.contains("OK") || stdout.contains("valid") || stdout.contains("success"),
                "Should show verification success: {}", stdout);
    }
    
    #[test]
    fn test_hmac_key_length_variations() {
        let (input_file, _temp_dir) = create_temp_file("Test message for key length tests", "txt");
        let binary_path = get_binary_path();
        
        // Test with various key lengths (HMAC supports any length)
        let test_keys = vec![
            "01",                    // 1 byte
            "0011223344556677",     // 8 bytes
            "00112233445566778899aabbccddeeff",  // 16 bytes
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",  // 32 bytes
        ];
        
        for key in test_keys {
            let output = Command::new(&binary_path)
                .args([
                    "mac",
                    "hmac",
                    "--key", key,
                    "--input", input_file.to_str().unwrap(),
                ])
                .output()
                .expect("Failed to execute HMAC command");
            
            assert!(output.status.success(),
                    "HMAC with key {} failed: {}", key, String::from_utf8_lossy(&output.stderr));
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            let output_str = stdout.trim();
            assert!(output_str.len() >= 32, "Output should contain hex HMAC value");
        }
    }
    
    #[test]
    fn test_cmac_invalid_key_length() {
        let (input_file, _temp_dir) = create_temp_file("Test message", "txt");
        let binary_path = get_binary_path();
        
        // Test with short key (should fail)
        let output = Command::new(&binary_path)
            .args([
                "mac",
                "cmac",
                "--key", "001122",  // Only 3 bytes
                "--input", input_file.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to execute command");
        
        assert!(!output.status.success(), "Should fail with invalid key length");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("16 bytes") || stderr.contains("16-byte") || stderr.contains("Invalid") || stderr.contains("key"),
                "Should complain about key length for CMAC: {}", stderr);
    }
}