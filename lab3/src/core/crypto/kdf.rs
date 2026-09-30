// kdf.rs - Fixed version
use crate::core::crypto::mac::hmac::Hmac;
use crate::error::{CryptoCoreError, Result};
use getrandom;
use std::time::Instant;

/// PBKDF2 (Password-Based Key Derivation Function 2) implementation
/// Follows RFC 2898 specification using HMAC-SHA256 as the PRF
pub struct Pbkdf2;

impl Pbkdf2 {
    /// Derive a key using PBKDF2-HMAC-SHA256
    ///
    /// # Arguments
    /// * `password` - The password to derive the key from
    /// * `salt` - The salt value (should be at least 8 bytes, recommended 16+ bytes)
    /// * `iterations` - Number of iterations (should be at least 100,000 for security)
    /// * `dklen` - Desired length of the derived key in bytes
    ///
    /// # Returns
    /// Derived key as a vector of bytes
    ///
    /// # Errors
    /// Returns `CryptoCoreError::InvalidArgument` if parameters are invalid
    pub fn derive_key(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Result<Vec<u8>> {
        // Validate parameters
        if password.is_empty() {
            return Err(CryptoCoreError::InvalidArgument(
                "Password cannot be empty".to_string(),
            ));
        }
        
        if salt.is_empty() {
            return Err(CryptoCoreError::InvalidArgument(
                "Salt cannot be empty".to_string(),
            ));
        }
        
        if iterations == 0 {
            return Err(CryptoCoreError::InvalidArgument(
                "Iteration count must be greater than 0".to_string(),
            ));
        }
        
        if dklen == 0 {
            return Err(CryptoCoreError::InvalidArgument(
                "Derived key length must be greater than 0".to_string(),
            ));
        }
        
        // SHA-256 produces 32-byte (256-bit) output
        let hlen = 32; // HMAC-SHA256 output size
        let mut derived_key = Vec::with_capacity(dklen);
        
        // Calculate number of blocks needed: ceil(dklen / hlen)
        let blocks_needed = (dklen + hlen - 1) / hlen;
        
        for i in 1..=blocks_needed {
            // Compute T_i = F(P, S, c, i)
            let block = Self::compute_block(password, salt, iterations, i as u32)?;
            
            // Append block to derived key
            derived_key.extend_from_slice(&block);
        }
        
        // Truncate to exactly dklen bytes
        derived_key.truncate(dklen);
        
        Ok(derived_key)
    }
    
    /// Compute a single block T_i = F(P, S, c, i)
    /// where F(P, S, c, i) = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
    /// U_1 = PRF(P, S || INT_32_BE(i))
    /// U_j = PRF(P, U_{j-1})
    fn compute_block(password: &[u8], salt: &[u8], iterations: u32, block_index: u32) -> Result<[u8; 32]> {
        // Create salt || INT_32_BE(i)
        let mut salt_with_index = Vec::with_capacity(salt.len() + 4);
        salt_with_index.extend_from_slice(salt);
        salt_with_index.extend_from_slice(&block_index.to_be_bytes());
        
        // Compute U_1 = HMAC(password, salt || INT_32_BE(i))
        let mut u_current = Hmac::compute(password, &salt_with_index);
        let mut t_i = u_current.clone(); // Start with U_1
        
        // Compute U_2 through U_c and XOR them together
        for _ in 2..=iterations {
            u_current = Hmac::compute(password, &u_current);
            
            // XOR u_current into t_i
            for j in 0..32 {
                t_i[j] ^= u_current[j];
            }
        }
        
        // Convert Vec<u8> to [u8; 32]
        let mut result = [0u8; 32];
        result.copy_from_slice(&t_i);
        Ok(result)
    }
    
    /// Generate a random salt of specified length
    pub fn generate_salt(length: usize) -> Result<Vec<u8>> {
        if length == 0 {
            return Err(CryptoCoreError::InvalidArgument(
                "Salt length must be greater than 0".to_string(),
            ));
        }
        
        let mut salt = vec![0u8; length];
        getrandom::fill(&mut salt)
            .map_err(|e| CryptoCoreError::Crypto(format!("Failed to generate random salt: {}", e)))?;
        
        Ok(salt)
    }
    
    /// Benchmark PBKDF2 performance
    pub fn benchmark(password: &[u8], salt: &[u8], iterations_list: &[u32]) -> Result<Vec<(u32, f64)>> {
        let mut results = Vec::new();
        
        for &iterations in iterations_list {
            let start = Instant::now();
            Self::derive_key(password, salt, iterations, 32)?;
            let duration = start.elapsed();
            
            results.push((iterations, duration.as_secs_f64()));
        }
        
        Ok(results)
    }
}

/// Key hierarchy function for deriving multiple keys from a master key
pub struct KeyHierarchy;

impl KeyHierarchy {
    /// Derive a key from a master key using a deterministic HMAC-based method
    ///
    /// # Arguments
    /// * `master_key` - The master key to derive from
    /// * `context` - Unique identifier for the key's purpose (e.g., "encryption", "authentication")
    /// * `length` - Desired length of the derived key in bytes
    ///
    /// # Returns
    /// Derived key as a vector of bytes
    ///
    /// # Security Note
    /// Different context strings produce completely different keys from the same master key
    pub fn derive_key(master_key: &[u8], context: &str, length: usize) -> Result<Vec<u8>> {
        if master_key.is_empty() {
            return Err(CryptoCoreError::InvalidArgument(
                "Master key cannot be empty".to_string(),
            ));
        }
        
        if context.is_empty() {
            return Err(CryptoCoreError::InvalidArgument(
                "Context string cannot be empty".to_string(),
            ));
        }
        
        if length == 0 {
            return Err(CryptoCoreError::InvalidArgument(
                "Derived key length must be greater than 0".to_string(),
            ));
        }
        
        let context_bytes = context.as_bytes();
        let mut derived = Vec::with_capacity(length);
        let mut counter: u32 = 1;
        
        // Generate enough blocks to satisfy the requested length
        while derived.len() < length {
            // T_i = HMAC(master_key, context || counter)
            let mut input = Vec::with_capacity(context_bytes.len() + 4);
            input.extend_from_slice(context_bytes);
            input.extend_from_slice(&counter.to_be_bytes());
            
            let block = Hmac::compute(master_key, &input);
            derived.extend_from_slice(&block);
            counter += 1;
        }
        
        // Truncate to exactly the requested length
        derived.truncate(length);
        Ok(derived)
    }
    
    /// Derive multiple keys for different purposes from the same master key
    pub fn derive_key_hierarchy(
        master_key: &[u8],
        contexts: &[(&str, usize)],
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let mut keys = Vec::new();
        
        for &(context, length) in contexts {
            let key = Self::derive_key(master_key, context, length)?;
            keys.push((context.to_string(), key));
        }
        
        Ok(keys)
    }
}

/// Convenience functions for common KDF operations
pub mod utils {
    use super::*;
    
    /// Derive an encryption key from a password
    pub fn derive_encryption_key(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<[u8; 32]> {
        let derived = Pbkdf2::derive_key(password, salt, iterations, 32)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived);
        Ok(key)
    }
    
    /// Derive separate keys for encryption and authentication from a master key
    pub fn derive_encryption_and_auth_keys(master_key: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        let encryption_key = KeyHierarchy::derive_key(master_key, "encryption", 32)?;
        let auth_key = KeyHierarchy::derive_key(master_key, "authentication", 32)?;
        
        let mut enc_key = [0u8; 32];
        let mut auth_key_array = [0u8; 32];
        
        enc_key.copy_from_slice(&encryption_key);
        auth_key_array.copy_from_slice(&auth_key);
        
        Ok((enc_key, auth_key_array))
    }
    
    /// Securely zero memory (attempt to prevent compiler optimizations)
    pub fn secure_zero_memory(data: &mut [u8]) {
        use std::ptr;
        use std::sync::atomic::{AtomicBool, Ordering};
        
        // Use volatile writes and memory barriers
        let len = data.len();
        let ptr = data.as_mut_ptr();
        
        unsafe {
            for i in 0..len {
                ptr::write_volatile(ptr.add(i) as *mut u8, 0);
            }
            
            // Compiler barrier to prevent reordering
            let dummy = AtomicBool::new(false);
            dummy.load(Ordering::SeqCst);
        }
    }
}