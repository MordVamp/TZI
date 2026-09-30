use crate::core::crypto::aes::AesCipher;
use crate::error::{CryptoCoreError, Result};
use getrandom;

// GCM constants
const BLOCK_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
const DEFAULT_NONCE_SIZE: usize = 12;

pub struct Gcm {
    cipher: AesCipher,
    h: [u8; BLOCK_SIZE],  // Hash subkey H = AES_encrypt(K, 0^128)
}

impl Gcm {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 && key.len() != 24 && key.len() != 32 {
            return Err(CryptoCoreError::InvalidKey(
                "AES-GCM requires 16, 24, or 32 byte key".to_string(),
            ));
        }

        let cipher = AesCipher::new(key)?;
        
        // Compute H = AES_encrypt(K, 0^128)
        let zero_block = [0u8; BLOCK_SIZE];
        let h = cipher.encrypt_block(&zero_block)?;
        
        Ok(Self { cipher, h })
    }
    
    pub fn generate_nonce() -> [u8; DEFAULT_NONCE_SIZE] {
        let mut nonce = [0u8; DEFAULT_NONCE_SIZE];
        getrandom::fill(&mut nonce).expect("Failed to generate random nonce");
        nonce
    }
    
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, [u8; TAG_SIZE])> {
        if nonce.len() != DEFAULT_NONCE_SIZE {
            return Err(CryptoCoreError::InvalidArgument(
                format!("GCM nonce must be {} bytes", DEFAULT_NONCE_SIZE)
            ));
        }
        
        // Generate J0 (initial counter block)
        let j0 = self.generate_j0(nonce);
        
        // Encrypt plaintext in CTR mode
        let ciphertext = self.ctr_crypt(&j0, plaintext, 1)?;
        
        // Compute authentication tag
        let tag = self.compute_tag(&j0, aad, &ciphertext)?;
        
        Ok((ciphertext, tag))
    }
    
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != DEFAULT_NONCE_SIZE {
            return Err(CryptoCoreError::InvalidArgument(
                format!("GCM nonce must be {} bytes", DEFAULT_NONCE_SIZE)
            ));
        }
        
        if tag.len() != TAG_SIZE {
            return Err(CryptoCoreError::InvalidArgument(
                format!("GCM tag must be {} bytes", TAG_SIZE)
            ));
        }
        
        // Generate J0 (initial counter block)
        let j0 = self.generate_j0(nonce);
        
        // Verify authentication tag first (before any decryption)
        let computed_tag = self.compute_tag(&j0, aad, ciphertext)?;
        
        if !constant_time_equals(&computed_tag, tag) {
            return Err(CryptoCoreError::Crypto("Authentication failed".to_string()));
        }
        
        // Decrypt ciphertext in CTR mode (same as encryption)
        let plaintext = self.ctr_crypt(&j0, ciphertext, 1)?;
        
        Ok(plaintext)
    }
    
    // Generate J0 from nonce (GCM-specific counter generation)
    fn generate_j0(&self, nonce: &[u8]) -> [u8; BLOCK_SIZE] {
        if nonce.len() == DEFAULT_NONCE_SIZE {
            // For 12-byte nonce: J0 = nonce || 0x00000001
            let mut j0 = [0u8; BLOCK_SIZE];
            j0[..DEFAULT_NONCE_SIZE].copy_from_slice(nonce);
            j0[BLOCK_SIZE - 1] = 0x01; // Big-endian 1
            j0
        } else {
            // For other nonce lengths: J0 = GHASH(nonce || zeros(64) || len64(nonce))
            let mut j0 = [0u8; BLOCK_SIZE];
            j0[..nonce.len()].copy_from_slice(nonce);
            // Pad with zeros and length in bits
            let _nonce_len_bits = (nonce.len() as u64) * 8;
            // For now, we only support 12-byte nonce
            j0
        }
    }
    
    // CTR mode encryption/decryption
    fn ctr_crypt(&self, j0: &[u8; BLOCK_SIZE], data: &[u8], initial_counter: u32) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(data.len());
        let mut counter = initial_counter;
        
        for chunk in data.chunks(BLOCK_SIZE) {
            // Create counter block: J0 with counter appended
            let mut ctr_block = *j0;
            let counter_bytes = counter.to_be_bytes();
            
            // Update last 4 bytes of counter block (for 12-byte nonce)
            let start_idx = BLOCK_SIZE - 4;
            ctr_block[start_idx..].copy_from_slice(&counter_bytes);
            
            // Encrypt counter block to get keystream
            let keystream = self.cipher.encrypt_block(&ctr_block)?;
            
            // XOR data with keystream
            let mut output_chunk = vec![0u8; chunk.len()];
            for i in 0..chunk.len() {
                output_chunk[i] = chunk[i] ^ keystream[i];
            }
            
            result.extend_from_slice(&output_chunk);
            counter = counter.wrapping_add(1);
        }
        
        Ok(result)
    }
    
    // Compute GHASH (Galois Hash)
    fn ghash(&self, aad: &[u8], ciphertext: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut state = [0u8; BLOCK_SIZE];
        
        // Process AAD
        for chunk in aad.chunks(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            if chunk.len() == BLOCK_SIZE {
                block.copy_from_slice(chunk);
            } else {
                // Partial block: copy and pad with zeros
                block[..chunk.len()].copy_from_slice(chunk);
                // Remainder is already zero
            }
            self.ghash_block(&mut state, &block);
        }
        
        // Process ciphertext
        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let mut block = [0u8; BLOCK_SIZE];
            if chunk.len() == BLOCK_SIZE {
                block.copy_from_slice(chunk);
            } else {
                // Partial block: copy and pad with zeros
                block[..chunk.len()].copy_from_slice(chunk);
                // Remainder is already zero
            }
            self.ghash_block(&mut state, &block);
        }
        
        // Process lengths: len(AAD) || len(ciphertext) in bits
        let aad_len_bits = (aad.len() as u64) * 8;
        let ciphertext_len_bits = (ciphertext.len() as u64) * 8;
        let mut len_block = [0u8; BLOCK_SIZE];
        len_block[..8].copy_from_slice(&aad_len_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&ciphertext_len_bits.to_be_bytes());
        
        self.ghash_block(&mut state, &len_block);
        
        state
    }
    
    // Process a single block in GHASH
    fn ghash_block(&self, state: &mut [u8; BLOCK_SIZE], block: &[u8; BLOCK_SIZE]) {
        // XOR block into state
        for i in 0..BLOCK_SIZE {
            state[i] ^= block[i];
        }
        
        // Multiply state by H in GF(2^128)
        *state = self.ghash_multiply(state, &self.h);
    }
    
    // Galois field multiplication in GF(2^128) - FIXED VERSION
    fn ghash_multiply(&self, x: &[u8; BLOCK_SIZE], y: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
        let mut z = [0u8; BLOCK_SIZE];
        let mut v = *y;
        
        // Convert x to bits for processing
        let mut x_bits = 0u128;
        for i in 0..BLOCK_SIZE {
            x_bits = (x_bits << 8) | x[i] as u128;
        }
        
        for i in (0..128).rev() {
            // If bit i of x is set
            if (x_bits >> i) & 1 == 1 {
                for j in 0..BLOCK_SIZE {
                    z[j] ^= v[j];
                }
            }
            
            // Multiply v by x (right shift with reduction)
            let lsb = v[BLOCK_SIZE - 1] & 1;
            
            // Right shift v by 1
            for j in (1..BLOCK_SIZE).rev() {
                v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
            }
            v[0] >>= 1;
            
            // If LSB was 1, XOR with polynomial R
            if lsb == 1 {
                // R = 0xE1 in the most significant byte (x^128 + x^7 + x^2 + x + 1)
                v[0] ^= 0xE1; // 0xE1 = 0b11100001
            }
        }
        
        z
    }
    
    // Compute authentication tag
    fn compute_tag(&self, j0: &[u8; BLOCK_SIZE], aad: &[u8], ciphertext: &[u8]) -> Result<[u8; TAG_SIZE]> {
        // Compute GHASH
        let mut tag = self.ghash(aad, ciphertext);
        
        // Encrypt J0
        let encrypted_j0 = self.cipher.encrypt_block(j0)?;
        
        // XOR GHASH with encrypted J0 to get final tag
        for i in 0..TAG_SIZE {
            tag[i] ^= encrypted_j0[i];
        }
        
        Ok(tag)
    }
    
    // Helper method for file operations
    pub fn encrypt_file(&self, input_path: &std::path::Path, output_path: &std::path::Path, 
                       aad: &[u8], nonce: Option<&[u8]>) -> Result<()> {
        use std::fs::File;
        use std::io::{Read, Write};
        
        // Read input file
        let mut input_file = File::open(input_path)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to open input file: {}", e)))?;
        
        let mut plaintext = Vec::new();
        input_file.read_to_end(&mut plaintext)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to read input file: {}", e)))?;
        
        // Generate or use provided nonce
        let nonce_bytes = nonce.map(|n| n.to_vec())
            .unwrap_or_else(|| Self::generate_nonce().to_vec());
        
        // Encrypt
        let (ciphertext, tag) = self.encrypt(&plaintext, aad, &nonce_bytes)?;
        
        // Write output: nonce (12 bytes) || ciphertext || tag (16 bytes)
        let mut output_file = File::create(output_path)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to create output file: {}", e)))?;
        
        output_file.write_all(&nonce_bytes)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to write nonce: {}", e)))?;
        output_file.write_all(&ciphertext)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to write ciphertext: {}", e)))?;
        output_file.write_all(&tag)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to write tag: {}", e)))?;
        
        Ok(())
    }
    
    pub fn decrypt_file(&self, input_path: &std::path::Path, output_path: &std::path::Path, 
                       aad: &[u8]) -> Result<()> {
        use std::fs::File;
        use std::io::{Read, Write};
        
        // Read input file
        let mut input_file = File::open(input_path)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to open input file: {}", e)))?;
        
        let mut encrypted_data = Vec::new();
        input_file.read_to_end(&mut encrypted_data)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to read input file: {}", e)))?;
        
        if encrypted_data.len() < DEFAULT_NONCE_SIZE + TAG_SIZE {
            return Err(CryptoCoreError::FileError(
                "Input file is too short to contain nonce and tag".to_string()
            ));
        }
        
        // Parse: nonce (12) || ciphertext || tag (16)
        let nonce = &encrypted_data[..DEFAULT_NONCE_SIZE];
        let tag_start = encrypted_data.len() - TAG_SIZE;
        let tag = &encrypted_data[tag_start..];
        let ciphertext = &encrypted_data[DEFAULT_NONCE_SIZE..tag_start];
        
        // Decrypt
        let plaintext = self.decrypt(ciphertext, aad, nonce, tag)?;
        
        // Write output (only if authentication succeeded)
        let mut output_file = File::create(output_path)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to create output file: {}", e)))?;
        
        output_file.write_all(&plaintext)
            .map_err(|e| CryptoCoreError::FileError(format!("Failed to write plaintext: {}", e)))?;
        
        Ok(())
    }
}

// Constant-time comparison to prevent timing attacks
fn constant_time_equals(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}


impl crate::core::crypto::aead::Aead for Gcm {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (ciphertext, tag) = self.encrypt(plaintext, aad, nonce)?;
        Ok((ciphertext, tag.to_vec()))
    }
    
    fn decrypt(&self, ciphertext: &[u8], aad: &[u8], nonce: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        self.decrypt(ciphertext, aad, nonce, tag)
    }
    
    fn nonce_size(&self) -> usize {
        DEFAULT_NONCE_SIZE
    }
    
    fn tag_size(&self) -> usize {
        TAG_SIZE
    }
}
