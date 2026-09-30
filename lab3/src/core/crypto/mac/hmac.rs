use crate::core::crypto::hash::Sha256;
use crate::error::{CryptoCoreError, Result};
use std::path::Path;

const BLOCK_SIZE: usize = 64; // SHA-256 block size
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

pub struct Hmac {
    key: Vec<u8>,
    inner_hash: Sha256,
    outer_hash_initialized: bool,
}

impl Hmac {
    pub fn new(key: &[u8]) -> Self {
        let processed_key = Self::process_key(key);
        
        let mut inner_hash = Sha256::new();
        
        // Create inner padded key
        let mut inner_pad = vec![0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            inner_pad[i] = processed_key[i] ^ IPAD;
        }
        inner_hash.update(&inner_pad);
        
        Self {
            key: processed_key,
            inner_hash,
            outer_hash_initialized: false,
        }
    }
    
    fn process_key(key: &[u8]) -> Vec<u8> {
        let mut processed = vec![0u8; BLOCK_SIZE];
        
        if key.len() > BLOCK_SIZE {
            // Hash key if it's longer than block size
            let mut hasher = Sha256::new();
            hasher.update(key);
            let hashed_key = hasher.finalize();
            processed[..32].copy_from_slice(&hashed_key);
            // Remainder is already zeros
        } else if key.len() < BLOCK_SIZE {
            // Pad with zeros if shorter than block size
            processed[..key.len()].copy_from_slice(key);
            // Remainder is already zeros
        } else {
            // Exact size
            processed.copy_from_slice(key);
        }
        
        processed
    }
    
    pub fn update(&mut self, data: &[u8]) {
        self.inner_hash.update(data);
    }
    
    pub fn finalize(self) -> [u8; 32] {
        // Finalize inner hash
        let inner_result = self.inner_hash.finalize();
        
        // Create outer hash with outer pad
        let mut outer_hash = Sha256::new();
        
        // Create outer padded key
        let mut outer_pad = vec![0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            outer_pad[i] = self.key[i] ^ OPAD;
        }
        outer_hash.update(&outer_pad);
        
        // Add inner result
        outer_hash.update(&inner_result);
        
        // Finalize outer hash
        outer_hash.finalize()
    }
    
    pub fn compute(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut hmac = Self::new(key);
        hmac.update(message);
        hmac.finalize()
    }
    
    // Streaming version for large files
    pub fn compute_file(key: &[u8], path: &Path) -> Result<[u8; 32]> {
        use std::fs::File;
        use std::io::Read;
        
        let mut hmac = Self::new(key);
        let mut file = File::open(path)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to open file: {}", e)))?;
        
        let mut buffer = [0u8; 4096];
        loop {
            let n = file.read(&mut buffer)
                .map_err(|e| CryptoCoreError::FileError(format!("Failed to read file: {}", e)))?;
            if n == 0 {
                break;
            }
            hmac.update(&buffer[..n]);
        }
        
        Ok(hmac.finalize())
    }
    
    pub fn verify(key: &[u8], message: &[u8], expected_hmac: &[u8]) -> bool {
        let computed = Self::compute(key, message);
        computed.as_slice() == expected_hmac
    }
    
    pub fn verify_file(key: &[u8], path: &Path, expected_hmac: &[u8]) -> Result<bool> {
        let computed = Self::compute_file(key, path)?;
        Ok(computed.as_slice() == expected_hmac)
    }
}